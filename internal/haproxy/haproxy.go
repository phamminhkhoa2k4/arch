// Package haproxy parses HAProxy configuration into the small subset
// the scanner needs: frontend, backend and listen sections with their
// binds, backend references and server addresses. It reads files only
// and never executes anything from the config.
package haproxy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// DefaultRoot is the standard HAProxy entry point.
const DefaultRoot = "/etc/haproxy/haproxy.cfg"

// AltRoots are additional standard locations tried when the default
// path does not exist (FreeBSD and Homebrew installs).
var AltRoots = []string{"/usr/local/etc/haproxy/haproxy.cfg"}

// FileError is one configuration problem at a known position.
type FileError struct {
	File string
	Line int
	Err  error
}

func (e FileError) Error() string { return fmt.Sprintf("%s:%d: %v", e.File, e.Line, e.Err) }

// Config is the extracted static graph of one HAProxy configuration.
type Config struct {
	Frontends []Frontend
	Backends  []Backend
	// Errors are configuration problems: the section that failed
	// contributes no inventory, every other section still does.
	Errors []FileError
}

// Frontend is one frontend or listen section: the addresses it binds
// and the backends it routes to. Listen sections declare their
// servers directly, which are recorded here too.
type Frontend struct {
	File           string
	Name           string
	Line           int // section header line
	Binds          []string
	DefaultBackend string
	UseBackends    []string
	Servers        []Server
}

// Backend is one backend section with every server it declares.
type Backend struct {
	File    string
	Name    string
	Line    int // section header line
	Servers []Server
}

// Server is one "server" directive: a name and its raw address.
type Server struct {
	Name string
	Addr string
	Line int
}

// Key is the stable identity of the frontend: the same section always
// produces the same key across rescans.
func (f *Frontend) Key() string {
	return "haproxy_frontend|" + f.File + "#" + f.Name
}

// RawRef cites the file and line of the section header for evidence.
func (f *Frontend) RawRef() string {
	return f.File + ":" + strconv.Itoa(f.Line)
}

// Fingerprint hashes the static shape so a changed section shows up
// as a changed fingerprint.
func (f *Frontend) Fingerprint() string {
	return fingerprintOf(
		f.Name,
		strings.Join(f.Binds, ","),
		f.DefaultBackend,
		strings.Join(f.UseBackends, ","),
		serversSig(f.Servers),
	)
}

// Key is the stable identity of the backend: names are unique across
// a HAProxy configuration, so the name alone identifies it.
func (b *Backend) Key() string { return "haproxy_backend|" + b.Name }

// RawRef cites the file and line of the section header for evidence.
func (b *Backend) RawRef() string {
	return b.File + ":" + strconv.Itoa(b.Line)
}

// Fingerprint hashes the static shape so a changed server list shows
// up as a changed fingerprint.
func (b *Backend) Fingerprint() string {
	return fingerprintOf(b.Name, serversSig(b.Servers))
}

// serversSig renders a server list as "name=addr" pairs.
func serversSig(servers []Server) string {
	parts := make([]string, 0, len(servers))
	for _, s := range servers {
		parts = append(parts, s.Name+"="+s.Addr)
	}
	return strings.Join(parts, ";")
}

// fingerprintOf hashes the rendered shape into a fingerprint string.
func fingerprintOf(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])
}

// sectionKind classifies a section header word.
type sectionKind int

const (
	secIgnore sectionKind = iota
	secFrontend
	secBackend
)

// sectionHeader maps a top-level keyword to the kind of section it
// opens. Sections the scanner does not model (global, defaults,
// userlist, ...) still end the current section so their directives
// are never mistaken for route inventory.
func sectionHeader(word string) (sectionKind, bool) {
	switch word {
	case "frontend", "listen":
		return secFrontend, true
	case "backend":
		return secBackend, true
	case "global", "defaults", "userlist", "peers", "peer",
		"resolvers", "cache", "program", "log-forward", "mail":
		return secIgnore, true
	}
	return secIgnore, false
}

// Load reads and parses one HAProxy configuration file. A read
// failure propagates so the collector can report it as a blind spot.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(path, string(data)), nil
}

// Parse turns one configuration file's text into sections. HAProxy
// ignores indentation, so sections are recognized by their header
// keyword; unknown directives are skipped.
func Parse(file, src string) *Config {
	cfg := &Config{}
	mode := secIgnore
	var curF *Frontend
	var curB *Backend

	push := func() {
		if curF != nil {
			cfg.Frontends = append(cfg.Frontends, *curF)
			curF = nil
		}
		if curB != nil {
			cfg.Backends = append(cfg.Backends, *curB)
			curB = nil
		}
	}

	for _, ll := range logicalLines(src) {
		words := strings.Fields(ll.text)
		if len(words) == 0 {
			continue
		}
		if kind, ok := sectionHeader(words[0]); ok {
			push()
			mode = kind
			if kind == secIgnore {
				continue
			}
			if len(words) < 2 {
				cfg.Errors = append(cfg.Errors, FileError{
					File: file, Line: ll.line,
					Err: fmt.Errorf("%s section without a name", words[0]),
				})
				mode = secIgnore
				continue
			}
			if kind == secFrontend {
				curF = &Frontend{File: file, Name: words[1], Line: ll.line}
			} else {
				curB = &Backend{File: file, Name: words[1], Line: ll.line}
			}
			continue
		}

		switch mode {
		case secFrontend:
			parseFrontendDirective(cfg, file, curF, words, ll.line)
		case secBackend:
			parseBackendDirective(cfg, file, curB, words, ll.line)
		}
	}
	push()
	return cfg
}

// parseFrontendDirective applies one directive of a frontend or listen
// section.
func parseFrontendDirective(cfg *Config, file string, f *Frontend, words []string, line int) {
	if f == nil {
		return
	}
	switch words[0] {
	case "bind":
		for _, a := range words[1:] {
			// The address list ends at the first option keyword:
			// addresses always carry a port separator or a path.
			if !isBindAddr(a) {
				break
			}
			f.Binds = append(f.Binds, a)
		}
	case "default_backend":
		if len(words) < 2 {
			cfg.Errors = append(cfg.Errors, FileError{
				File: file, Line: line, Err: fmt.Errorf("default_backend without a name"),
			})
			return
		}
		f.DefaultBackend = words[1]
	case "use_backend":
		if len(words) < 2 {
			cfg.Errors = append(cfg.Errors, FileError{
				File: file, Line: line, Err: fmt.Errorf("use_backend without a name"),
			})
			return
		}
		f.UseBackends = append(f.UseBackends, words[1])
	case "server":
		s, err := parseServer(words, line)
		if err != nil {
			cfg.Errors = append(cfg.Errors, FileError{File: file, Line: line, Err: err})
			return
		}
		f.Servers = append(f.Servers, s)
	}
}

// parseBackendDirective applies one directive of a backend section.
func parseBackendDirective(cfg *Config, file string, b *Backend, words []string, line int) {
	if b == nil || words[0] != "server" {
		return
	}
	s, err := parseServer(words, line)
	if err != nil {
		cfg.Errors = append(cfg.Errors, FileError{File: file, Line: line, Err: err})
		return
	}
	b.Servers = append(b.Servers, s)
}

// parseServer reads "server <name> <address>": the address is
// positional, everything after it is a runtime option.
func parseServer(words []string, line int) (Server, error) {
	if len(words) < 3 {
		return Server{}, fmt.Errorf("server directive without an address")
	}
	return Server{Name: words[1], Addr: words[2], Line: line}, nil
}

// isBindAddr reports whether a token is a bind address rather than an
// option keyword: addresses carry a port separator or are paths.
func isBindAddr(tok string) bool {
	return strings.Contains(tok, ":") || strings.HasPrefix(tok, "/")
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
