package traefik

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

// TargetKind classifies where a service target points. The values
// mirror the nginx, caddy and haproxy packages so downstream
// consumers can treat every route family uniformly.
type TargetKind string

const (
	// TargetLocal points at this host: matchable against listeners.
	TargetLocal TargetKind = "local"
	// TargetHost points elsewhere: an external or named host.
	TargetHost TargetKind = "host"
	// TargetUnix points at a unix domain socket path.
	TargetUnix TargetKind = "unix"
	// TargetUnresolved contains a value static analysis refuses to
	// guess (placeholders, missing schemes, empty addresses).
	TargetUnresolved TargetKind = "unresolved"
)

// Target is one parsed service target. Raw is always the configured
// value; Kind/Host/Port/Socket are the classification static analysis
// could prove.
type Target struct {
	Raw    string
	Kind   TargetKind
	Scheme string // http, https or h2c when a scheme was written
	Host   string // host part for local and host targets
	Port   int    // port when provable, 0 otherwise
	Socket string // absolute path for unix targets
}

// ParseURL classifies one http service server URL. Traefik requires
// a scheme on server URLs; only the shapes static analysis can prove
// are classified, everything else stays unresolved so the collector
// reports a blind spot instead of guessing.
func ParseURL(raw string) Target {
	t := Target{Raw: raw}
	s := strings.TrimSpace(raw)
	if s == "" {
		t.Kind = TargetUnresolved
		return t
	}
	// Placeholders decide the address at runtime.
	if strings.ContainsAny(s, "{}$") {
		t.Kind = TargetUnresolved
		return t
	}
	if !strings.Contains(s, "://") {
		// A server URL without a scheme is not dialed as one.
		t.Kind = TargetUnresolved
		return t
	}
	u, err := url.Parse(s)
	if err != nil {
		t.Kind = TargetUnresolved
		return t
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "unix" {
		if u.Path == "" {
			t.Kind = TargetUnresolved
			return t
		}
		t.Kind = TargetUnix
		t.Socket = u.Path
		return t
	}
	if scheme != "http" && scheme != "https" && scheme != "h2c" {
		t.Kind = TargetUnresolved
		return t
	}
	if u.Host == "" {
		t.Kind = TargetUnresolved
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

// ParseAddress classifies one tcp service server address: a bare
// host:port or a unix socket path.
func ParseAddress(raw string) Target {
	t := Target{Raw: raw}
	s := strings.TrimSpace(raw)
	if s == "" {
		t.Kind = TargetUnresolved
		return t
	}
	if strings.ContainsAny(s, "{}$") {
		t.Kind = TargetUnresolved
		return t
	}
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
// detection compares server hosts against it.
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
