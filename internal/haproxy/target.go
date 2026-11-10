package haproxy

import (
	"net"
	"os"
	"strconv"
	"strings"
)

// TargetKind classifies where a server address points. The values
// mirror the nginx and caddy packages so downstream consumers can
// treat every route family uniformly.
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

// Target is one parsed server address. Raw is always the configured
// value; Kind/Host/Port/Socket are the classification static analysis
// could prove.
type Target struct {
	Raw    string
	Kind   TargetKind
	Host   string // host part for local and host targets
	Port   int    // port when provable, 0 otherwise
	Socket string // absolute path for unix targets
}

// ParseTarget classifies one server address. HAProxy accepts bare
// host:ports, unix socket paths and environment references; only the
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
	// Environment references ($VAR) and placeholder forms decide the
	// address when HAProxy starts.
	if strings.ContainsAny(s, "{}") || strings.Contains(s, "$") {
		t.Kind = TargetUnresolved
		return t
	}
	// Server addresses are never URLs: refuse to reinterpret one.
	if strings.Contains(s, "://") {
		t.Kind = TargetUnresolved
		return t
	}
	// Unix socket path.
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
