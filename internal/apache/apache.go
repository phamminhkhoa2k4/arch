// Package apache parses Apache httpd configuration into the small
// subset the scanner needs: virtual hosts, their server names and
// the reverse-proxy directives they declare. It reads files only and
// never executes anything from the config.
package apache

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultRoot is the Debian/Ubuntu main configuration.
const DefaultRoot = "/etc/apache2/apache2.conf"

// AltRoots are additional standard main configurations tried when
// the default path does not exist (Red Hat and friends).
var AltRoots = []string{"/etc/httpd/conf/httpd.conf"}

// FileError is one configuration problem at a known position.
type FileError struct {
	File string
	Line int
	Err  error
}

func (e FileError) Error() string { return fmt.Sprintf("%s:%d: %v", e.File, e.Line, e.Err) }

// Config is the extracted static graph of one Apache installation.
type Config struct {
	Routes []Route
	// Errors are syntax problems: the position that failed
	// contributes no route, the rest of the tree still does.
	Errors []FileError
	// Unreadable lists include targets that could not be read
	// (missing file or denied permission).
	Unreadable []FileError
	// vhosts collects every <VirtualHost> block so routes can
	// resolve their ServerName after the whole tree is parsed.
	vhosts []vhost
}

// Route is one reverse-proxy directive with its static shape.
type Route struct {
	File       string
	Line       int    // directive line
	VHost      string // "<VirtualHost ...>" address part, "" outside one
	ServerName string // the vhost's ServerName directive, resolved at load
	Path       string // source path (or pattern) the proxy matches
	Target     string // raw upstream target
	Ord        int    // 1-based order among routes of the same vhost+path
	vhostIdx   int    // index into the loader's vhost table, -1 global
}

// Key is the stable identity of the route: the same directive always
// produces the same key across rescans.
func (r *Route) Key() string {
	return "apache_route|" + strings.Join([]string{
		r.File, r.VHost, r.ServerName, r.Path, fmt.Sprintf("%d", r.Ord),
	}, "#")
}

// RawRef cites the file and line of the proxy directive for evidence.
func (r *Route) RawRef() string { return rawRef(r.File, r.Line) }

// Fingerprint hashes the static shape so a changed target shows up
// as a changed fingerprint. Line numbers and file digests are left
// out: moving a route within the file is not a route change.
func (r *Route) Fingerprint() string {
	return fingerprintOf(r.VHost, r.ServerName, r.Path, r.Target)
}

// rawRef renders file:line, or just the file when no line is known.
func rawRef(file string, line int) string {
	if line <= 0 {
		return file
	}
	return fmt.Sprintf("%s:%d", file, line)
}

// vhost is one <VirtualHost> block; routes reference it by index so
// a ServerName declared after the proxy lines still lands on them.
type vhost struct {
	header     string
	serverName string
}

// section is one open configuration section on the loader's stack.
type section struct {
	name     string
	args     string
	file     string
	line     int
	vhostIdx int // index into cfg.vhosts when this is a VirtualHost
}

// Load reads and parses one main configuration file and every file
// it includes. A read failure of the root propagates so the
// collector can report it as a blind spot.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	l := &loader{
		cfg:      cfg,
		root:     path,
		visited:  map[string]bool{},
		ordCount: map[string]int{},
	}
	l.parseFile(path, data)
	l.finish()
	return cfg, nil
}

// loader carries parse state across included files: the include
// cycle guard, the ServerRoot for relative includes, the section
// stack (sections may span include boundaries) and the route
// ordinal counter.
type loader struct {
	cfg        *Config
	root       string
	visited    map[string]bool
	stack      []section
	serverRoot string // "" until a ServerRoot directive sets it
	ordCount   map[string]int
}

// parseFile parses one file's text into the shared config. Read
// failures for included files are recorded so the scan reports a
// blind spot instead of dropping the rest silently.
func (l *loader) parseFile(path string, data []byte) {
	if l.visited[path] {
		return // include cycle or double include: one copy
	}
	l.visited[path] = true

	for _, ll := range logicalLines(string(data)) {
		text := ll.text
		if text == "" {
			continue
		}
		if text[0] == '<' {
			l.parseSectionTag(path, ll.line, text)
			continue
		}
		args := splitArgs(text)
		if len(args) == 0 {
			continue
		}
		switch {
		case strings.EqualFold(args[0], "ServerRoot"):
			if len(args) >= 2 {
				l.serverRoot = args[1]
			}
		case strings.EqualFold(args[0], "Include"),
			strings.EqualFold(args[0], "IncludeOptional"):
			l.parseInclude(path, ll.line, args)
		case strings.EqualFold(args[0], "ServerName"):
			if len(args) >= 2 {
				l.setServerName(args[1])
			}
		case strings.EqualFold(args[0], "ProxyPass"),
			strings.EqualFold(args[0], "ProxyPassMatch"):
			l.parseProxyPass(path, ll.line, args)
		}
	}
}

// parseSectionTag opens or closes one <Section> tag.
func (l *loader) parseSectionTag(file string, line int, text string) {
	isClose, name, args, unterminated := parseSection(text)
	if name == "" || name[0] == '!' {
		return // stray markup, not a configuration section
	}
	if isClose {
		if len(l.stack) == 0 || !strings.EqualFold(l.stack[len(l.stack)-1].name, name) {
			l.cfg.Errors = append(l.cfg.Errors, FileError{
				File: file, Line: line,
				Err: fmt.Errorf("closing </%s> does not match the open section", name),
			})
			return
		}
		l.stack = l.stack[:len(l.stack)-1]
		return
	}
	if unterminated {
		l.cfg.Errors = append(l.cfg.Errors, FileError{
			File: file, Line: line,
			Err: fmt.Errorf("<%s section without a closing >", name),
		})
		return
	}
	sec := section{name: name, args: args, file: file, line: line, vhostIdx: -1}
	if strings.EqualFold(name, "VirtualHost") {
		sec.vhostIdx = len(l.cfg.vhosts)
		l.cfg.vhosts = append(l.cfg.vhosts, vhost{header: args})
	}
	l.stack = append(l.stack, sec)
}

// parseInclude expands one Include/IncludeOptional directive.
func (l *loader) parseInclude(file string, line int, args []string) {
	optional := strings.EqualFold(args[0], "IncludeOptional")
	if len(args) < 2 {
		l.cfg.Errors = append(l.cfg.Errors, FileError{
			File: file, Line: line, Err: fmt.Errorf("%s without a path", args[0]),
		})
		return
	}
	matches, err := includeMatches(args[1], l.root, l.serverRoot)
	if err != nil {
		l.cfg.Errors = append(l.cfg.Errors, FileError{File: file, Line: line, Err: err})
		return
	}
	if len(matches) == 0 {
		if !optional {
			l.cfg.Unreadable = append(l.cfg.Unreadable, FileError{
				File: file, Line: line,
				Err: fmt.Errorf("include %q matched no file", args[1]),
			})
		}
		return
	}
	for _, m := range matches {
		data, rerr := os.ReadFile(m)
		if rerr != nil {
			l.cfg.Unreadable = append(l.cfg.Unreadable, FileError{File: m, Err: rerr})
			continue
		}
		l.parseFile(m, data)
	}
}

// includeMatches resolves an include pattern: absolute patterns are
// used as given, relative ones are tried against ServerRoot first
// and the main configuration's directory second. Glob matches are
// sorted for deterministic identity.
func includeMatches(pattern, root, serverRoot string) ([]string, error) {
	if filepath.IsAbs(pattern) {
		return filepath.Glob(pattern)
	}
	bases := []string{}
	if serverRoot != "" {
		bases = append(bases, serverRoot)
	}
	if dir := filepath.Dir(root); dir != serverRoot {
		bases = append(bases, dir)
	}
	for _, base := range bases {
		matches, err := filepath.Glob(filepath.Join(base, pattern))
		if err != nil {
			return nil, err
		}
		if len(matches) > 0 {
			sort.Strings(matches)
			return matches, nil
		}
	}
	return nil, nil
}

// setServerName records the directive on the innermost open
// virtual host, if any.
func (l *loader) setServerName(name string) {
	idx := l.currentVHost()
	if idx >= 0 {
		l.cfg.vhosts[idx].serverName = name
	}
}

// currentVHost returns the index of the innermost open VirtualHost
// section, or -1 outside one.
func (l *loader) currentVHost() int {
	for i := len(l.stack) - 1; i >= 0; i-- {
		if l.stack[i].vhostIdx >= 0 {
			return l.stack[i].vhostIdx
		}
	}
	return -1
}

// scopePath returns the path of the innermost scoping section
// (Location, Directory, Files, Proxy), for a ProxyPass that carries
// only its target.
func (l *loader) scopePath() (string, bool) {
	for i := len(l.stack) - 1; i >= 0; i-- {
		switch strings.ToLower(l.stack[i].name) {
		case "location", "locationmatch", "directory", "files", "proxy":
			return unquote(l.stack[i].args), true
		}
	}
	return "", false
}

// parseProxyPass records one ProxyPass/ProxyPassMatch directive as a
// route. Exclusions ("!") and balancer-scoped forms without a
// concrete target never become routes.
func (l *loader) parseProxyPass(file string, line int, args []string) {
	if len(args) < 2 {
		l.cfg.Errors = append(l.cfg.Errors, FileError{
			File: file, Line: line, Err: fmt.Errorf("%s without arguments", args[0]),
		})
		return
	}
	var path, target string
	switch {
	case len(args) == 2 && args[1] == "!":
		return // <Location> exclusion: no proxy here
	case len(args) == 2:
		// Inside a scoping section the single argument is the
		// target and the section supplies the path.
		scope, ok := l.scopePath()
		if !ok || !isTargetLike(args[1]) {
			l.cfg.Errors = append(l.cfg.Errors, FileError{
				File: file, Line: line,
				Err: fmt.Errorf("%s needs a path and a target", args[0]),
			})
			return
		}
		path, target = scope, args[1]
	default:
		if args[2] == "!" {
			return // path exclusion: no proxy here
		}
		if !isTargetLike(args[2]) {
			l.cfg.Errors = append(l.cfg.Errors, FileError{
				File: file, Line: line,
				Err: fmt.Errorf("%s target %q is not an address", args[0], args[2]),
			})
			return
		}
		path, target = args[1], args[2]
	}

	vh := l.currentVHost()
	ordKey := fmt.Sprintf("%d|%s", vh, path)
	l.ordCount[ordKey]++
	l.cfg.Routes = append(l.cfg.Routes, Route{
		File: file, Line: line, Path: path, Target: target,
		Ord: l.ordCount[ordKey], vhostIdx: vh,
	})
}

// finish resolves vhost references onto their routes and reports
// sections left open at the end of the root file.
func (l *loader) finish() {
	for i := range l.cfg.Routes {
		r := &l.cfg.Routes[i]
		if r.vhostIdx >= 0 {
			vh := l.cfg.vhosts[r.vhostIdx]
			r.VHost = vh.header
			r.ServerName = vh.serverName
		}
	}
	for _, sec := range l.stack {
		l.cfg.Errors = append(l.cfg.Errors, FileError{
			File: sec.file, Line: sec.line,
			Err: fmt.Errorf("<%s section is never closed", sec.name),
		})
	}
}

// isTargetLike reports whether an argument looks like an upstream
// address rather than a path.
func isTargetLike(s string) bool {
	return strings.Contains(s, "://") || strings.HasPrefix(s, "unix:")
}

// unquote strips one layer of surrounding double quotes.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// parseSection splits a section tag line: the closing flag, the
// section name, the argument text up to the ">", and whether the
// tag was left unterminated.
func parseSection(text string) (isClose bool, name, args string, unterminated bool) {
	body := text[1:] // caller guarantees a leading '<'
	if strings.HasPrefix(body, "/") {
		isClose = true
		body = body[1:]
	}
	i := 0
	for i < len(body) && body[i] != ' ' && body[i] != '\t' && body[i] != '>' {
		i++
	}
	name = body[:i]
	rest := body[i:]
	if isClose {
		return true, name, "", false
	}
	gt := strings.IndexByte(rest, '>')
	if gt < 0 {
		return false, name, strings.TrimSpace(rest), true
	}
	return false, name, strings.TrimSpace(rest[:gt]), false
}

// splitArgs splits a directive into arguments, honoring double
// quotes and backslash escapes inside them.
func splitArgs(s string) []string {
	var out []string
	var b strings.Builder
	inQuote := false
	started := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQuote = !inQuote
			started = true
		case c == '\\' && inQuote && i+1 < len(s):
			i++
			b.WriteByte(s[i])
			started = true
		case !inQuote && (c == ' ' || c == '\t'):
			if started {
				out = append(out, b.String())
				b.Reset()
				started = false
			}
		default:
			b.WriteByte(c)
			started = true
		}
	}
	if started {
		out = append(out, b.String())
	}
	return out
}

// logicalLine is one physical line after comment stripping and
// backslash continuation joining.
type logicalLine struct {
	text string
	line int // physical line where the logical line starts
}

// logicalLines joins continued lines and drops comments. A trailing
// backslash continues the line; # starts a comment outside quotes.
func logicalLines(src string) []logicalLine {
	var out []logicalLine
	var buf strings.Builder
	start := 0
	lineNo := 0
	cont := false
	for _, raw := range strings.Split(src, "\n") {
		lineNo++
		text := strings.TrimRight(stripComment(raw), " \t\r")
		more := strings.HasSuffix(text, "\\")
		if more {
			text = strings.TrimRight(strings.TrimSuffix(text, "\\"), " \t")
		}
		if !cont {
			start = lineNo
			buf.Reset()
		}
		text = strings.TrimLeft(text, " \t")
		if buf.Len() > 0 {
			buf.WriteByte(' ')
		}
		buf.WriteString(text)
		cont = more
		if !cont && buf.Len() > 0 {
			out = append(out, logicalLine{text: buf.String(), line: start})
		}
	}
	if cont && buf.Len() > 0 {
		out = append(out, logicalLine{text: buf.String(), line: start})
	}
	return out
}

// stripComment removes a # comment that is not inside a quoted string.
func stripComment(s string) string {
	inQuote := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			inQuote = !inQuote
		case '#':
			if !inQuote {
				return s[:i]
			}
		}
	}
	return s
}
