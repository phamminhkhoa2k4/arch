package caddy

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// sha256Hex hashes a rendered shape into the fingerprint string.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// TargetKind classifies where a reverse_proxy target points. The
// values mirror the nginx package so downstream consumers can treat
// both route families uniformly.
type TargetKind string

const (
	// TargetLocal points at this host: matchable against listeners.
	TargetLocal TargetKind = "local"
	// TargetHost points elsewhere: an external or named host.
	TargetHost TargetKind = "host"
	// TargetUnix points at a unix domain socket path.
	TargetUnix TargetKind = "unix"
	// TargetUnresolved contains a value static analysis refuses to
	// guess (placeholders, environment references, empty addresses).
	TargetUnresolved TargetKind = "unresolved"
)

// Target is one parsed upstream address of a reverse_proxy directive.
// Raw is always the configured value; Kind/Host/Port/Socket are the
// classification static analysis could prove.
type Target struct {
	Raw    string
	Kind   TargetKind
	Scheme string // http or https when a scheme was written
	Host   string // host part for local and host targets
	Port   int    // port when provable, 0 otherwise
	Socket string // absolute path for unix targets
}

// ParseTarget classifies one upstream address. Caddy accepts bare
// host:ports, urls, unix socket paths and placeholder forms; only the
// shapes static analysis can prove are classified, everything else
// stays unresolved so the collector reports a blind spot instead of
// guessing.
func ParseTarget(raw string) Target {
	t := Target{Raw: raw}
	s := strings.TrimSpace(raw)
	if s == "" {
		t.Kind = TargetUnresolved
		return t
	}
	// Placeholders ({env.X}, {$VAR}, {$X|default}) and env-style
	// references decide the address at runtime.
	if strings.ContainsAny(s, "{}") || strings.Contains(s, "$") {
		t.Kind = TargetUnresolved
		return t
	}
	// unix socket: unix//path or unix:/path (Caddy's URL form).
	if rest, ok := strings.CutPrefix(s, "unix//"); ok {
		t.Kind = TargetUnix
		t.Socket = socketPath(rest)
		return t
	}
	if strings.HasPrefix(s, "unix:") {
		t.Kind = TargetUnix
		t.Socket = socketPath(strings.TrimPrefix(s, "unix:"))
		return t
	}
	// A scheme-prefixed URL: the authority decides the target.
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			t.Kind = TargetUnresolved
			return t
		}
		t.Scheme = strings.ToLower(u.Scheme)
		host, port := splitHostPort(u.Host)
		t.Host = host
		t.Port = port
		t.Kind = classifyHost(host, port, t.Scheme)
		return t
	}
	// Bare address: host, host:port, or a path-like socket.
	if strings.HasPrefix(s, "/") {
		t.Kind = TargetUnix
		t.Socket = s
		return t
	}
	host, port := splitHostPort(s)
	if host == "" && port == 0 {
		t.Kind = TargetUnresolved
		return t
	}
	if strings.ContainsAny(host, " \t") {
		t.Kind = TargetUnresolved
		return t
	}
	t.Host = host
	t.Port = port
	t.Scheme = "http"
	t.Kind = classifyHost(host, port, "http")
	return t
}

// socketPath normalizes a unix socket path to an absolute one.
func socketPath(p string) string {
	if strings.HasPrefix(p, "/") {
		return p
	}
	return "/" + p
}

// splitHostPort splits "host:port", returning port 0 when absent or
// unparseable (a non-numeric port is left to the caller to reject).
func splitHostPort(s string) (string, int) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		// No port: the whole value is the host.
		return s, 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return host, 0
	}
	return host, port
}

// classifyHost decides local vs host vs unresolved. A loopback or
// wildcard bind address is this host; an empty host (":8080") is the
// local wildcard; anything else is a remote host. Ports without a
// scheme stay http (Caddy's default for bare addresses).
func classifyHost(host string, port int, scheme string) TargetKind {
	if host == "" {
		if port == 0 {
			return TargetUnresolved
		}
		return TargetLocal
	}
	if isLocalHost(host) {
		return TargetLocal
	}
	return TargetHost
}

// isLocalHost reports whether host denotes this machine: loopback
// names and addresses, or the wildcard bind addresses Caddy uses for
// listener matching.
func isLocalHost(host string) bool {
	h := strings.ToLower(host)
	if h == "localhost" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsUnspecified()
	}
	return false
}

// Route is one reverse_proxy directive with its static shape.
type Route struct {
	Site       string   // header of the innermost site block
	Location   string   // enclosing handle/route block headers, space-joined
	File       string   // source file of the directive
	FileDigest string   // sha256 of that file's content
	Line       int      // directive line
	Ord        int      // 1-based order among routes of the same site+location
	Targets    []Target // parsed upstream addresses
}

// Key is the stable identity of the route: the same directive always
// produces the same key across rescans.
func (r *Route) Key() string {
	return "caddy_route|" + r.File + "#" + r.Site + "#" + r.Location + "#" + strconv.Itoa(r.Ord)
}

// RawRef cites the file and line of the directive for evidence.
func (r *Route) RawRef() string {
	return r.File + ":" + strconv.Itoa(r.Line)
}

// Fingerprint hashes the static shape so a changed directive shows up
// as a changed fingerprint.
func (r *Route) Fingerprint() string {
	var b strings.Builder
	b.WriteString(r.Site)
	b.WriteByte(0)
	b.WriteString(r.Location)
	b.WriteByte(0)
	b.WriteString(strconv.Itoa(r.Line))
	b.WriteByte(0)
	for _, t := range r.Targets {
		b.WriteString(t.Raw)
		b.WriteByte(0)
	}
	sum := sha256Hex(b.String())
	return sum
}

// Name is the human-facing label: the location when the route sits in
// a handle/route block, the site header otherwise.
func (r *Route) Name() string {
	if r.Location != "" {
		return r.Location
	}
	return r.Site
}
