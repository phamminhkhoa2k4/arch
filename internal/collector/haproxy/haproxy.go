// Package haproxy collects the HAProxy configuration inventory:
// frontend and backend entities, proxies_to edges against the listener
// snapshot, broken-route findings and blind spots for targets static
// analysis refuses to guess.
package haproxy

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"archaeologist/internal/collector"
	"archaeologist/internal/collector/listener"
	"archaeologist/internal/haproxy"
)

// Index supplies the listener snapshot gathered by earlier collectors;
// nil skips the edges and the absence findings that depend on it.
type Index interface {
	ListenerRows() ([]collector.ListenerRow, error)
}

// Collector turns one HAProxy configuration file into entities,
// edges, findings and blind spots.
type Collector struct {
	index Index
	root  string // chosen configuration entry point
}

// New creates a HAProxy collector. index may be nil (no proxies_to
// edges, no BROKEN_ROUTE for tcp targets — absence cannot be asserted
// without the snapshot).
func New(index Index) *Collector {
	return &Collector{index: index}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return "haproxy" }

// Version implements collector.Collector.
func (c *Collector) Version() string { return "1.0.0" }

// Collect parses the configuration once and writes entities, edges,
// findings and blind spots. A host without HAProxy installed yields
// nothing: that is not a gap, merely an absent collector.
func (c *Collector) Collect(ctx context.Context, sink collector.Sink) error {
	if c.root == "" {
		c.root = c.pickRoot()
	}
	if c.root == "" {
		return nil // not installed: no blind spot
	}

	cfg, err := haproxy.Load(c.root)
	if err != nil {
		return sink.AddBlindSpot(collector.BlindSpot{
			Channel: "haproxy",
			Reason:  "haproxy_config_unreadable",
			Detail: map[string]string{
				"file":  c.root,
				"error": err.Error(),
			},
		})
	}

	// Configuration errors never crash the scan: each one becomes a
	// blind spot while the sections that parsed still yield inventory.
	for _, fe := range cfg.Errors {
		if err := sink.AddBlindSpot(collector.BlindSpot{
			Channel: "haproxy",
			Reason:  "haproxy_config_parse_error",
			Detail: map[string]string{
				"file":  fe.File,
				"line":  strconv.Itoa(fe.Line),
				"error": fe.Err.Error(),
			},
		}); err != nil {
			return err
		}
	}

	byPort, err := c.listenerIndex()
	if err != nil {
		return err
	}

	refs := map[string]bool{}
	emit := func(ev collector.Evidence) error {
		if refs[ev.Ref] {
			return nil
		}
		refs[ev.Ref] = true
		return sink.AddEvidence(ev)
	}

	backendKeys := map[string]string{}
	for i := range cfg.Backends {
		backendKeys[cfg.Backends[i].Name] = cfg.Backends[i].Key()
	}

	// Backends first: frontends edge into them, so the destination
	// entities must exist before those edges land.
	for i := range cfg.Backends {
		if err := c.collectBackend(sink, &cfg.Backends[i], byPort, emit); err != nil {
			return err
		}
	}
	for i := range cfg.Frontends {
		if err := c.collectFrontend(sink, &cfg.Frontends[i], backendKeys, byPort, emit); err != nil {
			return err
		}
	}
	return nil
}

// pickRoot returns the first standard HAProxy configuration location
// that exists, or "" when HAProxy is not installed.
func (c *Collector) pickRoot() string {
	roots := []string{haproxy.DefaultRoot}
	roots = append(roots, haproxy.AltRoots...)
	for _, r := range roots {
		if _, err := os.Stat(r); err == nil {
			return r
		}
	}
	return ""
}

// collectFrontend writes one frontend or listen section: entity,
// evidence, the routing edges to its backends, then the findings its
// own servers (listen sections) allow.
func (c *Collector) collectFrontend(
	sink collector.Sink,
	f *haproxy.Frontend,
	backendKeys map[string]string,
	byPort map[portKey][]string,
	emit func(collector.Evidence) error,
) error {
	key := f.Key()
	if err := sink.UpsertEntity(collector.Entity{
		Kind:        "haproxy_frontend",
		Name:        f.Name,
		IdentityKey: key,
		Fingerprint: f.Fingerprint(),
		Attributes:  frontendAttrs(f),
	}); err != nil {
		return err
	}

	ref := "haproxy-frontend:" + key
	if err := emit(collector.Evidence{
		EntityIdentityKey: key,
		Polarity:          collector.PolarityNeutral,
		Channel:           "haproxy",
		Strength:          collector.StrengthDeterministic,
		ObservedAt:        nowRFC3339(),
		RawRef:            f.RawRef(),
		Ref:               ref,
		Value:             frontendAttrs(f),
	}); err != nil {
		return err
	}

	// Routing edges: only references that resolve to a backend parsed
	// from this file become edges; the rest stay visible as attributes
	// (a multi-file installation may define them elsewhere).
	for _, name := range backendRefs(f) {
		dst, ok := backendKeys[name]
		if !ok {
			continue
		}
		if err := sink.UpsertEdge(collector.Edge{
			SrcIdentityKey: key,
			DstIdentityKey: dst,
			Kind:           "proxies_to",
			Strength:       collector.StrengthDeterministic,
			EvidenceRef:    ref,
		}); err != nil {
			return err
		}
	}

	for _, s := range f.Servers {
		if err := c.handleServer(sink, key, ref, f.File, s, byPort); err != nil {
			return err
		}
	}
	return nil
}

// collectBackend writes one backend: entity, evidence, then the
// findings its server targets allow.
func (c *Collector) collectBackend(
	sink collector.Sink,
	b *haproxy.Backend,
	byPort map[portKey][]string,
	emit func(collector.Evidence) error,
) error {
	key := b.Key()
	attrs := backendAttrs(b)
	if err := sink.UpsertEntity(collector.Entity{
		Kind:        "haproxy_backend",
		Name:        b.Name,
		IdentityKey: key,
		Fingerprint: b.Fingerprint(),
		Attributes:  attrs,
	}); err != nil {
		return err
	}

	ref := "haproxy-backend:" + key
	if err := emit(collector.Evidence{
		EntityIdentityKey: key,
		Polarity:          collector.PolarityNeutral,
		Channel:           "haproxy",
		Strength:          collector.StrengthDeterministic,
		ObservedAt:        nowRFC3339(),
		RawRef:            b.RawRef(),
		Ref:               ref,
		Value:             attrs,
	}); err != nil {
		return err
	}

	for _, s := range b.Servers {
		if err := c.handleServer(sink, key, ref, b.File, s, byPort); err != nil {
			return err
		}
	}
	return nil
}

// handleServer classifies one server address of a section: a blind
// spot when static analysis refuses to guess, a broken-route finding
// when its target is provably missing, a proxies_to edge when a
// listener owns the port.
func (c *Collector) handleServer(
	sink collector.Sink,
	key, ref, file string,
	s haproxy.Server,
	byPort map[portKey][]string,
) error {
	t := haproxy.ParseTarget(s.Addr)
	switch t.Kind {
	case haproxy.TargetUnresolved:
		return sink.AddBlindSpot(collector.BlindSpot{
			EntityIdentityKey: key,
			Channel:           "haproxy",
			Reason:            "haproxy_target_unresolved",
			Detail: map[string]string{
				"server": s.Name,
				"target": s.Addr,
				"file":   file,
				"line":   strconv.Itoa(s.Line),
			},
		})
	case haproxy.TargetUnix:
		if st, err := os.Stat(t.Socket); err != nil || st.IsDir() {
			return sink.AddFinding(collector.Finding{
				EntityIdentityKey: key,
				Kind:              "BROKEN_ROUTE",
				Severity:          "warn",
				Detail: map[string]string{
					"server": s.Name,
					"target": s.Addr,
					"socket": t.Socket,
					"reason": "unix socket missing at scan time",
				},
				EvidenceRef: ref,
			})
		}
		return nil
	case haproxy.TargetLocal:
		if t.Port == 0 {
			return nil // no port: never guess one
		}
		keys := byPort[portKey{"tcp", t.Port}]
		if len(keys) == 0 {
			if c.index == nil {
				return nil
			}
			return sink.AddFinding(collector.Finding{
				EntityIdentityKey: key,
				Kind:              "BROKEN_ROUTE",
				Severity:          "warn",
				Detail: map[string]string{
					"server": s.Name,
					"target": s.Addr,
					"host":   t.Host,
					"port":   strconv.Itoa(t.Port),
					"reason": fmt.Sprintf("no listener on tcp/%d at scan time", t.Port),
				},
				EvidenceRef: ref,
			})
		}
		for _, lk := range keys {
			if err := sink.UpsertEdge(collector.Edge{
				SrcIdentityKey: key,
				DstIdentityKey: lk,
				Kind:           "proxies_to",
				Strength:       collector.StrengthDeterministic,
				EvidenceRef:    ref,
			}); err != nil {
				return err
			}
		}
		return nil
	default: // TargetHost
		// External server: recorded as scope in attrs, no edge.
		return nil
	}
}

// backendRefs lists the backend names a frontend routes to, deduped
// and in configuration order.
func backendRefs(f *haproxy.Frontend) []string {
	seen := map[string]bool{}
	var out []string
	for _, name := range append([]string{f.DefaultBackend}, f.UseBackends...) {
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// frontendAttrs renders the static shape of a frontend section.
func frontendAttrs(f *haproxy.Frontend) map[string]string {
	attrs := map[string]string{
		"file": f.File,
		"line": strconv.Itoa(f.Line),
		"name": f.Name,
		"bind": strings.Join(f.Binds, " "),
	}
	if f.DefaultBackend != "" {
		attrs["default_backend"] = f.DefaultBackend
	}
	if len(f.UseBackends) > 0 {
		attrs["use_backend"] = strings.Join(f.UseBackends, ",")
	}
	if len(f.Servers) > 0 {
		attrs["servers"] = serversAttr(f.Servers)
	}
	return attrs
}

// backendAttrs renders the static shape of a backend section.
func backendAttrs(b *haproxy.Backend) map[string]string {
	return map[string]string{
		"file":    b.File,
		"line":    strconv.Itoa(b.Line),
		"name":    b.Name,
		"servers": serversAttr(b.Servers),
	}
}

// serversAttr renders server declarations as "name=addr" pairs.
func serversAttr(servers []haproxy.Server) string {
	parts := make([]string, 0, len(servers))
	for _, s := range servers {
		parts = append(parts, s.Name+"="+s.Addr)
	}
	return strings.Join(parts, ";")
}

// portKey is one (protocol, port) pair of the listener snapshot.
type portKey struct {
	proto string
	port  int
}

// listenerIndex flattens the listener snapshot for port matching.
func (c *Collector) listenerIndex() (map[portKey][]string, error) {
	out := map[portKey][]string{}
	if c.index == nil {
		return out, nil
	}
	rows, err := c.index.ListenerRows()
	if err != nil {
		return nil, err
	}
	for _, lr := range rows {
		proto, _, port, _, err := listener.ParseIdentityKey(lr.IdentityKey)
		if err != nil {
			continue
		}
		pk := portKey{normProto(proto), port}
		out[pk] = append(out[pk], lr.IdentityKey)
	}
	return out, nil
}

// normProto folds the /proc-style family names (tcp6/udp6) onto the
// engine names (tcp/udp) so proxy targets match listeners on both
// address families.
func normProto(p string) string {
	return strings.TrimSuffix(p, "6")
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// compile-time interface check
var _ collector.Collector = (*Collector)(nil)
