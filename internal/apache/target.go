package apache

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// sha256Hex hashes a rendered shape into the fingerprint string.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// fingerprintOf hashes the rendered shape into a fingerprint string.
func fingerprintOf(parts ...string) string {
	return sha256Hex(strings.Join(parts, "\x00"))
}

// TargetKind classifies where a reverse-proxy target points. The
// values mirror the nginx, caddy, haproxy and traefik packages so
// downstream consumers can treat every route family uniformly.
type TargetKind string

const (
	// TargetLocal points at this host: matchable against listeners.
	TargetLocal TargetKind = "local"
	// TargetHost points elsewhere: an external or named host.
	TargetHost TargetKind = "host"
	// TargetUnix points at a unix domain socket path.
	TargetUnix TargetKind = "unix"
	// TargetUnresolved contains a value static analysis refuses to
	// guess (placeholders, balancer URLs, missing addresses).
	TargetUnresolved TargetKind = "unresolved"
)

// Target is one parsed upstream address. Raw is always the
// configured value; Kind/Host/Port/Socket are the classification
// static analysis could prove.
type Target struct {
	Raw    string
	Kind   TargetKind
	Scheme string // http, https, ajp, ... when a scheme was written
	Host   string // host part for local and host targets
	Port   int    // port when provable, 0 otherwise
	Socket string // absolute path for unix targets
}

// urlSchemes are the proxy schemes Apache dials as a network
// connection; anything else (balancer://, session://) names an
// in-process facility static analysis cannot follow.
var urlSchemes = map[string]bool{
	"http": true, "https": true, "ajp": true,
	"fcgi": true, "scgi": true, "ws": true, "wss": true,
}

// ParseTarget classifies one ProxyPass target. Apache accepts full
// URLs, the unix:/path|url socket form and placeholder expressions;
// only the shapes static analysis can prove are classified,
// everything else stays unresolved so the collector reports a blind
// spot instead of guessing.
func ParseTarget(raw string) Target {
	t := Target{Raw: raw}
	s := strings.TrimSpace(raw)
	if s == "" {
		t.Kind = TargetUnresolved
		return t
	}
	// Placeholders ($VARIABLE, ${ENV}) decide the address at runtime.
	if strings.ContainsAny(s, "{}$") {
		t.Kind = TargetUnresolved
		return t
	}
	// unix:/path|http://host:port — the socket before the pipe is
	// the real target, the URL behind it only shapes the request.
	if strings.HasPrefix(s, "unix:") {
		pipe := strings.IndexByte(s, '|')
		if pipe < 0 {
			t.Kind = TargetUnresolved // the socket form requires a URL behind it
			return t
		}
		sock := strings.TrimPrefix(s[:pipe], "unix:")
		if sock == "" {
			t.Kind = TargetUnresolved
			return t
		}
		t.Kind = TargetUnix
		t.Socket = sock
		return t
	}
	// A full URL: the scheme decides whether it is dialable.
	if !strings.Contains(s, "://") {
		t.Kind = TargetUnresolved
		return t
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		t.Kind = TargetUnresolved
		return t
	}
	scheme := strings.ToLower(u.Scheme)
	if !urlSchemes[scheme] {
		t.Kind = TargetUnresolved // balancer:// and friends
		return t
	}
	t.Scheme = scheme
	host, port := splitHostPort(u.Host)
	if strings.ContainsAny(host, " \t") {
		t.Kind = TargetUnresolved
		return t
	}
	t.Host = host
	t.Port = port
	t.Kind = classifyHost(host, port)
	return t
}

// splitHostPort splits "host:port", returning port 0 when absent or
// unparseable (a bare address without a port keeps host and skips
// the listener match rather than guessing one).
func splitHostPort(s string) (string, int) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return s, 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return host, 0
	}
	return host, port
}

// classifyHost decides local vs host vs unresolved. An empty host
// with a port is the local wildcard; a loopback address or this
// machine's own name is local; anything else is a remote host.
func classifyHost(host string, port int) TargetKind {
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

// hostName is the machine's own name, resolved once: local-target
// detection compares proxy hosts against it.
var hostName = func() string {
	name, err := os.Hostname()
	if err != nil {
		return ""
	}
	return name
}()

// isLocalHost reports whether host denotes this machine: loopback
// names and addresses, or this host's own name. Private network IPs
// are deliberately absent: without a gateway they say nothing about
// locality.
func isLocalHost(host string) bool {
	h := strings.ToLower(host)
	if h == "localhost" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsUnspecified()
	}
	return hostName != "" && h == strings.ToLower(hostName)
}
