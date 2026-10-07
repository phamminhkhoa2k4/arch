// Package nginx parses the nginx configuration tree into the small
// subset the scanner needs: locations with their proxy targets and
// upstream blocks. It wraps nginx-go-crossplane, only reads, and
// never executes anything from the config.
package nginx

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/nginxinc/nginx-go-crossplane"
)

// DefaultRoot is the standard nginx main configuration file.
const DefaultRoot = "/etc/nginx/nginx.conf"

// TargetKind classifies where a proxy directive points.
type TargetKind string

const (
	// TargetLocal points at this host: matchable against listeners.
	TargetLocal TargetKind = "local"
	// TargetHost points elsewhere: an upstream name or an external host.
	TargetHost TargetKind = "host"
	// TargetUnix points at a unix domain socket path.
	TargetUnix TargetKind = "unix"
	// TargetUnresolved contains a value static analysis refuses to guess.
	TargetUnresolved TargetKind = "unresolved"
)

// Target is one parsed proxy_pass/fastcgi_pass/server address.
type Target struct {
	Raw    string
	Kind   TargetKind
	Scheme string // http, https, ... (empty for bare addresses)
	Host   string
	Port   int    // 0 when unknown
	Socket string // unix path when Kind == TargetUnix
}

// Route is one location block with its optional proxy target.
type Route struct {
	File       string // source file of the location directive
	FileDigest string // sha256 of that file's content
	Line       int    // location directive line
	TargetLine int    // proxy/fastcgi directive line, 0 when none
	Listen     []string
	ServerName []string
	Location   string
	SetVars    []string
	Target     *Target
}

// Key is the deterministic identity of the route.
func (r *Route) Key() string {
	return "nginx_route|" + strings.Join([]string{
		r.File,
		strings.Join(r.Listen, ","),
		strings.Join(r.ServerName, " "),
		r.Location,
	}, "#")
}

// RawRef points back at the exact config line: the proxy directive
// when there is one, the location otherwise.
func (r *Route) RawRef() string {
	line := r.Line
	if r.TargetLine > 0 {
		line = r.TargetLine
	}
	return fmt.Sprintf("%s:%d", r.File, line)
}

// Fingerprint hashes the stable shape of the route so config drift
// shows up between scans.
func (r *Route) Fingerprint() string {
	target := ""
	if r.Target != nil {
		target = r.Target.Raw
	}
	return fingerprintOf(
		r.FileDigest,
		strings.Join(r.Listen, ","),
		strings.Join(r.ServerName, " "),
		r.Location,
		target,
	)
}

// Upstream is one upstream block with every server it declares.
type Upstream struct {
	File       string
	FileDigest string
	Line       int
	Name       string
	Servers    []string
}

// Key is the deterministic identity of the upstream.
func (u *Upstream) Key() string { return "nginx_upstream|" + u.Name }

// RawRef points at the upstream directive line.
func (u *Upstream) RawRef() string { return fmt.Sprintf("%s:%d", u.File, u.Line) }

// Fingerprint hashes the stable shape of the upstream block.
func (u *Upstream) Fingerprint() string {
	return fingerprintOf(u.FileDigest, u.Name, strings.Join(u.Servers, " "))
}

// FileError is one configuration error at a known position.
type FileError struct {
	File string
	Line int
	Err  error
}

func (e FileError) Error() string { return fmt.Sprintf("%s:%d: %v", e.File, e.Line, e.Err) }

// AccessLog is one access_log directive. Path is the log file nginx
// writes; Format is the named format when one is given ("" means the
// nginx built-in default, combined). Directives with the argument
// "off" are skipped: they disable logging instead of naming a file.
type AccessLog struct {
	File   string
	Line   int
	Path   string
	Format string
}

// Config is the extracted static graph of one nginx installation.
type Config struct {
	Routes     []Route
	Upstreams  []Upstream
	AccessLogs []AccessLog
	Errors     []FileError // syntax errors, never fatal to the caller
}

// Loader reads nginx configuration trees from disk.
type Loader struct{}

// NewLoader returns a loader that reads real files.
func NewLoader() *Loader { return &Loader{} }

// Load parses the tree rooted at root (normally DefaultRoot),
// following every include. A tree that cannot be read at all (root
// missing, include cycle) returns err; syntax errors inside files
// come back as Config.Errors with file:line positions. Never panics.
func (l *Loader) Load(root string) (*Config, error) {
	// Context and argument checks are skipped on purpose: this is a
	// structural extraction, not validation (nginx -t owns that) and
	// directives from modules unknown to the parser would otherwise
	// make valid configs fail. Lexer/parser errors (real syntax)
	// still surface with file:line.
	payload, err := crossplane.Parse(root, &crossplane.ParseOptions{
		SkipDirectiveContextCheck: true,
		SkipDirectiveArgsCheck:    true,
	})
	if err != nil {
		return nil, fmt.Errorf("parse nginx config %s: %w", root, err)
	}

	cfg := &Config{}
	for _, pe := range payload.Errors {
		fe := FileError{File: pe.File}
		if pe.Line != nil {
			fe.Line = *pe.Line
		}
		fe.Err = pe.Error
		cfg.Errors = append(cfg.Errors, fe)
	}

	l.walk(payload, 0, ctx{}, cfg, map[string]bool{}, map[string]string{})
	return cfg, nil
}

// ctx is the recursive walk state.
type ctx struct {
	file   string // file whose directives are being walked
	inHTTP bool
	srv    *serverAcc // non-nil inside a server block
	ups    *Upstream  // non-nil inside an upstream block
	loc    *Route     // non-nil inside a location block
	prefix string     // accumulated location path of parent locations
}

type serverAcc struct {
	listens   []string
	names     []string
	locations []*Route
}

// walk visits one parsed file of the payload. The same file visited
// twice (double include) is skipped: nginx would see identical
// duplicate content anyway.
func (l *Loader) walk(
	payload *crossplane.Payload,
	idx int,
	c ctx,
	cfg *Config,
	visited map[string]bool,
	digests map[string]string,
) {
	if idx < 0 || idx >= len(payload.Config) || visited[payload.Config[idx].File] {
		return
	}
	visited[payload.Config[idx].File] = true
	nc := c
	// Directive.File is only populated in combined mode; the file is
	// known from the config entry being walked instead.
	nc.file = payload.Config[idx].File
	l.walkBlock(payload, payload.Config[idx].Parsed, nc, cfg, visited, digests)
}

//nolint:gocyclo // config walking is inherently a long switch
func (l *Loader) walkBlock(
	payload *crossplane.Payload,
	dirs crossplane.Directives,
	c ctx,
	cfg *Config,
	visited map[string]bool,
	digests map[string]string,
) {
	for _, d := range dirs {
		if d == nil {
			continue
		}

		switch {
		case d.Directive == "include":
			for _, i := range d.Includes {
				l.walk(payload, i, c, cfg, visited, digests)
			}

		case d.Directive == "http" && d.IsBlock():
			nc := c
			nc.inHTTP = true
			nc.srv, nc.ups, nc.loc, nc.prefix = nil, nil, nil, ""
			l.walkBlock(payload, d.Block, nc, cfg, visited, digests)

		case d.Directive == "server" && c.ups != nil && len(d.Args) > 0:
			c.ups.Servers = append(c.ups.Servers, d.Args[0])

		case d.Directive == "server" && d.IsBlock() &&
			c.inHTTP && c.srv == nil && c.ups == nil:
			sa := &serverAcc{}
			nc := c
			nc.srv = sa
			nc.loc, nc.prefix = nil, ""
			l.walkBlock(payload, d.Block, nc, cfg, visited, digests)
			for _, r := range sa.locations {
				r.Listen = append([]string(nil), sa.listens...)
				r.ServerName = append([]string(nil), sa.names...)
				cfg.Routes = append(cfg.Routes, *r)
			}

		case d.Directive == "upstream" && d.IsBlock() &&
			c.inHTTP && c.srv == nil && c.ups == nil && len(d.Args) > 0:
			u := &Upstream{
				File:       c.file,
				FileDigest: l.digest(c.file, digests),
				Line:       d.Line,
				Name:       d.Args[0],
			}
			nc := c
			nc.ups = u
			nc.loc, nc.prefix = nil, ""
			l.walkBlock(payload, d.Block, nc, cfg, visited, digests)
			cfg.Upstreams = append(cfg.Upstreams, *u)

		case d.Directive == "location" && d.IsBlock() && c.srv != nil && len(d.Args) > 0:
			pattern := strings.Join(d.Args, " ")
			full := pattern
			if c.prefix != "" {
				full = c.prefix + " " + pattern
			}
			r := &Route{
				File:       c.file,
				FileDigest: l.digest(c.file, digests),
				Line:       d.Line,
				Location:   full,
			}
			c.srv.locations = append(c.srv.locations, r)
			nc := c
			nc.loc = r
			nc.prefix = full
			l.walkBlock(payload, d.Block, nc, cfg, visited, digests)

		case d.Directive == "listen" && c.srv != nil && len(d.Args) > 0:
			c.srv.listens = append(c.srv.listens, strings.Join(d.Args, " "))

		case d.Directive == "server_name" && c.srv != nil && len(d.Args) > 0:
			c.srv.names = append(c.srv.names, d.Args...)

		case d.Directive == "access_log" && len(d.Args) > 0 && d.Args[0] != "off":
			al := AccessLog{File: c.file, Line: d.Line, Path: d.Args[0]}
			if len(d.Args) > 1 {
				al.Format = d.Args[1]
			}
			cfg.AccessLogs = append(cfg.AccessLogs, al)

		case (d.Directive == "proxy_pass" || d.Directive == "fastcgi_pass") &&
			c.loc != nil && len(d.Args) > 0:
			if c.loc.Target == nil {
				t := ParseTarget(d.Args[0])
				c.loc.Target = &t
				c.loc.TargetLine = d.Line
			}

		case d.Directive == "set" && c.loc != nil && len(d.Args) > 0:
			c.loc.SetVars = append(c.loc.SetVars, strings.Join(d.Args, " "))

		case d.IsBlock() && (c.loc != nil || c.srv != nil):
			// Unknown nested blocks (if, limit_except, ...) inside a
			// server or location: keep walking with the same state.
			l.walkBlock(payload, d.Block, c, cfg, visited, digests)
		}
	}
}

// digest returns the sha256 of one file, computed once per Load.
func (l *Loader) digest(path string, cache map[string]string) string {
	if d, ok := cache[path]; ok {
		return d
	}
	b, err := os.ReadFile(path)
	if err != nil {
		cache[path] = ""
		return ""
	}
	sum := sha256.Sum256(b)
	d := hex.EncodeToString(sum[:])
	cache[path] = d
	return d
}

func fingerprintOf(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])
}

// hostName is the machine's own name, resolved once: local-target
// detection compares proxy hosts against it.
var hostName = func() string {
	name, err := os.Hostname()
	if err != nil {
		return ""
	}
	return name
}()

// ParseTarget classifies one proxy address: a variable, a unix
// socket, this host, or somewhere else (upstream name or external).
// Only reads the address, never resolves DNS.
func ParseTarget(raw string) Target {
	t := Target{Raw: raw}

	rest := raw
	if i := strings.Index(rest, "://"); i >= 0 {
		t.Scheme = strings.ToLower(rest[:i])
		rest = rest[i+3:]
		if strings.Contains(t.Scheme, "$") {
			// The scheme itself is computed at runtime.
			t.Kind = TargetUnresolved
			return t
		}
	}

	// unix:/path:/uri (proxy) or unix:/path (fastcgi). A variable
	// anywhere makes the socket dynamic too.
	if strings.HasPrefix(rest, "unix:") {
		if strings.Contains(rest, "$") {
			t.Kind = TargetUnresolved
			return t
		}
		t.Kind = TargetUnix
		p := rest[len("unix:"):]
		if i := strings.Index(p, ":"); i >= 0 {
			p = p[:i] // drop the :/uri suffix
		}
		t.Socket = p
		return t
	}

	// The authority ends at "/", "?" or — for scheme'd targets — at a
	// variable, because a runtime URI part cannot reach back into it.
	// A variable anywhere else (or without a scheme) makes the whole
	// target dynamic: report it, never guess.
	if i := strings.IndexAny(rest, "/?$"); i >= 0 {
		if rest[i] == '$' && t.Scheme == "" {
			t.Kind = TargetUnresolved
			return t
		}
		rest = rest[:i] // drop the URI part: host and port are all we match on
	}

	host, portStr, err := net.SplitHostPort(rest)
	if err != nil {
		host, portStr = strings.Trim(rest, "[]"), ""
	}
	host = strings.ToLower(host)

	if portStr != "" {
		t.Port, _ = strconv.Atoi(portStr)
	} else if t.Scheme == "http" {
		t.Port = 80
	} else if t.Scheme == "https" {
		t.Port = 443
	}

	t.Host = host
	switch {
	case host == "":
		// Nothing static to match on (empty authority, path only).
		t.Kind = TargetUnresolved
		t.Scheme, t.Port = "", 0
	case isLocalHost(host):
		t.Kind = TargetLocal
	default:
		t.Kind = TargetHost
	}
	return t
}

// isLocalHost reports whether a proxy host names this machine. The
// list is fixed by the plan: loopback forms, the wildcard bind
// addresses, and this machine's own hostname. Private network IPs
// are deliberately absent: without a gateway they say nothing about
// locality.
func isLocalHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0":
		return true
	}
	return hostName != "" && host == strings.ToLower(hostName)
}
