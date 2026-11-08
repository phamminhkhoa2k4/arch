// Package caddy parses Caddyfile configuration into the small subset
// the scanner needs: site blocks, reverse_proxy directives and their
// upstream targets. It reads files only and never executes anything
// from the config.
package caddy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultRoot is the standard Caddy entry point.
const DefaultRoot = "/etc/caddy/Caddyfile"

// AltRoots are additional standard locations tried when the default
// path does not exist (packaged installs that ship the file under
// /usr/share).
var AltRoots = []string{"/usr/share/caddy/Caddyfile"}

// FileError is one configuration problem at a known position.
type FileError struct {
	File string
	Line int
	Err  error
}

func (e FileError) Error() string { return fmt.Sprintf("%s:%d: %v", e.File, e.Line, e.Err) }

// Config is the extracted static graph of one Caddy installation.
type Config struct {
	Routes []Route
	// Errors are syntax problems: the file that failed contributes no
	// routes, every other file still does.
	Errors []FileError
	// Unreadable lists import targets that could not be read (missing
	// file or denied permission).
	Unreadable []FileError
}

// node is one parsed directive with its optional block.
type node struct {
	directive string
	args      []string
	line      int
	file      string
	children  []node
}

// tokKind classifies lexer output.
type tokKind int

const (
	tokWord tokKind = iota
	tokOpen
	tokClose
)

type token struct {
	kind tokKind
	val  string
	line int
}

// lex splits a Caddyfile into words and braces. Quoted strings ("
// and backtick) keep their spaces; # starts a comment outside quotes.
func lex(src string) ([]token, error) {
	var out []token
	line := 1
	i := 0
	for i < len(src) {
		c := src[i]
		switch c {
		case '\n':
			line++
			i++
		case ' ', '\t', '\r':
			i++
		case '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case '{', '}':
			out = append(out, token{kind: tokOpen, val: "{", line: line})
			if c == '}' {
				out[len(out)-1].kind = tokClose
				out[len(out)-1].val = "}"
			}
			i++
		case '"', '`':
			quote := c
			startLine := line
			i++
			var sb strings.Builder
			closed := false
			for i < len(src) {
				if src[i] == '\\' && quote == '"' && i+1 < len(src) {
					i++
					if src[i] == '\n' {
						line++
					}
					sb.WriteByte(src[i])
					i++
					continue
				}
				if src[i] == quote {
					closed = true
					i++
					break
				}
				if src[i] == '\n' {
					line++
				}
				sb.WriteByte(src[i])
				i++
			}
			if !closed {
				return nil, fmt.Errorf("line %d: unterminated quoted string", startLine)
			}
			out = append(out, token{kind: tokWord, val: sb.String(), line: startLine})
		default:
			start := i
			for i < len(src) && !strings.ContainsRune(" \t\r\n{}#", rune(src[i])) {
				i++
			}
			out = append(out, token{kind: tokWord, val: src[start:i], line: line})
		}
	}
	return out, nil
}

// parseNodes parses directives until EOF or — inside a block — the
// closing brace. A directive's arguments must sit on its own line;
// a brace opens a block whether it follows on the same line or the
// next one. A brace with no directive starts an anonymous block
// (Caddy's global options section).
func parseNodes(toks []token, file string, pos *int, inBlock bool, openLine int) ([]node, error) {
	var out []node
	for *pos < len(toks) {
		t := toks[*pos]
		if t.kind == tokClose {
			if inBlock {
				*pos++
				return out, nil
			}
			return nil, fmt.Errorf("%s:%d: unexpected }", file, t.line)
		}
		if t.kind == tokOpen {
			*pos++
			children, err := parseNodes(toks, file, pos, true, t.line)
			if err != nil {
				return nil, err
			}
			out = append(out, node{line: t.line, file: file, children: children})
			continue
		}
		n := node{directive: t.val, line: t.line, file: file}
		*pos++
		for *pos < len(toks) && toks[*pos].kind == tokWord && toks[*pos].line == n.line {
			n.args = append(n.args, toks[*pos].val)
			*pos++
		}
		if *pos < len(toks) && toks[*pos].kind == tokOpen {
			openAt := toks[*pos].line
			*pos++
			children, err := parseNodes(toks, file, pos, true, openAt)
			if err != nil {
				return nil, err
			}
			n.children = children
		}
		out = append(out, n)
	}
	if inBlock {
		return nil, fmt.Errorf("%s:%d: unclosed block opened at line %d", file, openLine, openLine)
	}
	return out, nil
}

// Loader reads Caddyfile trees from disk.
type Loader struct{}

// NewLoader returns a loader that reads real files.
func NewLoader() *Loader { return &Loader{} }

// Load parses the tree rooted at root. The root file's syntax errors
// and unreadable imports come back in Config; only a root that cannot
// be read at all fails the whole load. Never panics.
func (l *Loader) Load(root string) (*Config, error) {
	cfg := &Config{}
	digests := map[string]string{}
	visited := map[string]bool{}
	snippets := map[string][]node{}
	nodes, err := l.parseFile(root, root, visited, cfg, digests, snippets)
	if err != nil {
		return nil, err
	}
	cfg.collect(nodes, "", nil, false, digests, map[string]int{})
	return cfg, nil
}

// parseFile reads and parses one file and expands its import
// directives. Read failures for the root propagate; read failures
// for imports are recorded so the scan reports a blind spot instead
// of dropping the rest silently.
func (l *Loader) parseFile(path, root string, visited map[string]bool, cfg *Config, digests map[string]string, snippets map[string][]node) ([]node, error) {
	if visited[path] {
		return nil, nil // include cycle or double import: one copy
	}
	visited[path] = true
	data, err := os.ReadFile(path)
	if err != nil {
		if path == root {
			return nil, err
		}
		cfg.Unreadable = append(cfg.Unreadable, FileError{File: path, Err: err})
		return nil, nil
	}
	sum := sha256.Sum256(data)
	digests[path] = hex.EncodeToString(sum[:])

	toks, err := lex(string(data))
	if err != nil {
		cfg.Errors = append(cfg.Errors, FileError{File: path, Err: err})
		return nil, nil
	}
	pos := 0
	nodes, err := parseNodes(toks, path, &pos, false, 0)
	if err != nil {
		cfg.Errors = append(cfg.Errors, FileError{File: path, Line: errLine(err), Err: err})
		return nil, nil
	}
	return l.expandImports(nodes, path, root, visited, cfg, digests, snippets), nil
}

// expandImports replaces every import directive with the nodes of the
// files it names (glob-expanded, relative to the importing file and
// to the root Caddyfile), or with the body of a named snippet. Read
// failures for imports are recorded so the scan reports a blind spot
// instead of dropping the rest silently.
func (l *Loader) expandImports(nodes []node, file, root string, visited map[string]bool, cfg *Config, digests map[string]string, snippets map[string][]node) []node {
	// Register any snippet definitions found in this file before
	// resolving imports, so uses can be inlined in the same pass.
	for _, n := range nodes {
		if name, ok := snippetName(n.directive); ok {
			snippets[name] = n.children
		}
	}

	out := make([]node, 0, len(nodes))
	for _, n := range nodes {
		if n.directive != "import" {
			if len(n.children) > 0 {
				n.children = l.expandImports(n.children, n.file, root, visited, cfg, digests, snippets)
			}
			out = append(out, n)
			continue
		}
		if len(n.args) == 0 {
			cfg.Errors = append(cfg.Errors, FileError{
				File: n.file, Line: n.line, Err: fmt.Errorf("import without a path"),
			})
			continue
		}
		pattern := n.args[0]
		// A snippet name resolves to its body, inlined at this point.
		if name, ok := snippetName(pattern); ok {
			if defs, found := snippets[name]; found {
				out = append(out, l.expandImports(defs, n.file, root, visited, cfg, digests, snippets)...)
				continue
			}
		}
		matches, err := importMatches(pattern, n.file, root)
		if err != nil {
			cfg.Errors = append(cfg.Errors, FileError{File: n.file, Line: n.line, Err: err})
			continue
		}
		if len(matches) == 0 {
			cfg.Unreadable = append(cfg.Unreadable, FileError{
				File: n.file, Line: n.line,
				Err: fmt.Errorf("import %q matched no file", pattern),
			})
			continue
		}
		for _, m := range matches {
			children, err := l.parseFile(m, root, visited, cfg, digests, snippets)
			if err != nil {
				cfg.Errors = append(cfg.Errors, FileError{File: m, Err: err})
				continue
			}
			out = append(out, l.expandImports(children, m, root, visited, cfg, digests, snippets)...)
		}
	}
	return out
}

// snippetName returns the name of a snippet definition or reference:
// Caddy wraps the name in parentheses. Anything else is false.
func snippetName(s string) (string, bool) {
	if len(s) < 3 || s[0] != '(' || s[len(s)-1] != ')' {
		return "", false
	}
	return s[1 : len(s)-1], true
}

// isSnippetDef reports whether s names a snippet definition.
func isSnippetDef(s string) bool {
	_, ok := snippetName(s)
	return ok
}

// importMatches resolves an import pattern: relative patterns are
// tried against the importing file's directory first, then the root
// Caddyfile's directory; absolute patterns are used as given. Glob
// matches are sorted for deterministic identity.
func importMatches(pattern, from, root string) ([]string, error) {
	if filepath.IsAbs(pattern) {
		return filepath.Glob(pattern)
	}
	bases := []string{filepath.Dir(from)}
	if dir := filepath.Dir(root); dir != bases[0] {
		bases = append(bases, dir)
	}
	for _, base := range bases {
		if matches, err := filepath.Glob(filepath.Join(base, pattern)); err != nil {
			return nil, err
		} else if len(matches) > 0 {
			sort.Strings(matches)
			return matches, nil
		}
	}
	return nil, nil
}

// errLine extracts the line number embedded in a parse error.
func errLine(err error) int {
	var line int
	msg := err.Error()
	if i := strings.Index(msg, ":"); i >= 0 {
		rest := msg[i+1:]
		if j := strings.Index(rest, ":"); j >= 0 {
			_, _ = fmt.Sscanf(rest[:j], "%d", &line)
		}
	}
	return line
}

// collect walks the parsed tree and records every reverse_proxy as a
// route: the innermost site block header is its site, the chain of
// enclosing handle/route blocks its location. Blocks nested in the
// global options section or in a snippet definition never become
// sites: their content only materializes where the snippet is
// imported.
func (cfg *Config) collect(nodes []node, site string, locs []string, opaque bool, digests map[string]string, ord map[string]int) {
	for i := range nodes {
		n := &nodes[i]
		if n.directive == "reverse_proxy" {
			if site == "" {
				cfg.Errors = append(cfg.Errors, FileError{
					File: n.file, Line: n.line,
					Err: fmt.Errorf("reverse_proxy outside a site block"),
				})
				continue
			}
			r := cfg.newRoute(n, site, locs, digests, ord)
			cfg.Routes = append(cfg.Routes, r)
		}
		if len(n.children) > 0 {
			header := strings.TrimSpace(n.directive + " " + strings.Join(n.args, " "))
			switch {
			case opaque || n.directive == "":
				// Anonymous block: Caddy's global options section.
				cfg.collect(n.children, "", nil, true, digests, ord)
			case isSnippetDef(n.directive):
				// Snippet definition: content materializes at import sites.
				cfg.collect(n.children, "", nil, true, digests, ord)
			case site == "":
				cfg.collect(n.children, header, nil, false, digests, ord)
			default:
				childLocs := append(append([]string{}, locs...), header)
				cfg.collect(n.children, site, childLocs, false, digests, ord)
			}
		}
	}
}

// newRoute builds one route from a reverse_proxy directive.
func (cfg *Config) newRoute(n *node, site string, locs []string, digests map[string]string, ord map[string]int) Route {
	loc := strings.Join(locs, " ")
	ordKey := n.file + "\x00" + site + "\x00" + loc
	ord[ordKey]++
	r := Route{
		Site:       site,
		Location:   loc,
		File:       n.file,
		FileDigest: digests[n.file],
		Line:       n.line,
		Ord:        ord[ordKey],
		Targets:    upstreams(n),
	}
	return r
}

// upstreams extracts the proxy targets: leading matcher arguments
// are dropped, and a block-form directive without first-line
// upstreams falls back to its "to" subdirective.
func upstreams(n *node) []Target {
	args := n.args
	i := 0
	for i < len(args) && isMatcher(args[i]) {
		i++
	}
	var out []Target
	for _, a := range args[i:] {
		out = append(out, ParseTarget(a))
	}
	if len(out) == 0 {
		for _, c := range n.children {
			if c.directive == "to" && len(c.args) > 0 {
				for _, a := range c.args {
					out = append(out, ParseTarget(a))
				}
			}
		}
	}
	return out
}

// isMatcher reports whether a directive argument is a matcher rather
// than an upstream address: path matchers start with "/", named
// matchers with "@", inline matchers with "{".
func isMatcher(arg string) bool {
	return strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, "@") || strings.HasPrefix(arg, "{")
}
