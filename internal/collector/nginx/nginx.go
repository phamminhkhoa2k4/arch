// Package nginx collects the nginx configuration inventory: route and
// upstream entities, proxies_to edges against the listener snapshot,
// broken-route findings and blind spots for targets static analysis
// refuses to guess.
package nginx

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"archaeologist/internal/collector"
	"archaeologist/internal/collector/listener"
	"archaeologist/internal/nginx"
)

// Index supplies the listener snapshot gathered by earlier collectors;
// nil skips the edges and the absence findings that depend on it.
type Index interface {
	ListenerRows() ([]collector.ListenerRow, error)
}

// Collector turns the nginx configuration tree into entities, edges,
// findings and blind spots.
type Collector struct {
	loader *nginx.Loader
	index  Index
	root   string // configuration entry point, normally nginx.DefaultRoot
}

// New creates an nginx collector. loader may be nil (reads the default
// tree); index may be nil (no proxies_to edges, no BROKEN_ROUTE for
// tcp targets — absence cannot be asserted without the snapshot).
func New(loader *nginx.Loader, index Index) *Collector {
	if loader == nil {
		loader = nginx.NewLoader()
	}
	return &Collector{loader: loader, index: index, root: nginx.DefaultRoot}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return "nginx" }

// Version implements collector.Collector.
func (c *Collector) Version() string { return "1.0.0" }

// Collect parses the configuration once and writes entities, edges,
// findings and blind spots. An unreadable tree is returned so the run
// loop records one collector-level blind spot instead of guessing.
func (c *Collector) Collect(_ context.Context, sink collector.Sink) error {
	cfg, err := c.loader.Load(c.root)
	if err != nil {
		return fmt.Errorf("nginx config: %w", err)
	}

	// Syntax errors never crash the scan: each one becomes a blind
	// spot while the parts that parsed still yield routes.
	for _, fe := range cfg.Errors {
		if err := sink.AddBlindSpot(collector.BlindSpot{
			Channel: "nginx",
			Reason:  "nginx_config_parse_error",
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

	// Upstreams first: route to upstream edges need their entities.
	for i := range cfg.Upstreams {
		u := &cfg.Upstreams[i]
		key := u.Key()
		if err := sink.UpsertEntity(collector.Entity{
			Kind:        "nginx_upstream",
			Name:        u.Name,
			IdentityKey: key,
			Fingerprint: u.Fingerprint(),
			Attributes: map[string]string{
				"file":    u.File,
				"line":    strconv.Itoa(u.Line),
				"servers": strings.Join(u.Servers, ", "),
			},
		}); err != nil {
			return err
		}
		if err := emit(collector.Evidence{
			EntityIdentityKey: key,
			Polarity:          collector.PolarityNeutral,
			Channel:           "nginx",
			Strength:          collector.StrengthDeterministic,
			ObservedAt:        nowRFC3339(),
			RawRef:            u.RawRef(),
			Ref:               "nginx-upstream:" + key,
			Value: map[string]string{
				"name":    u.Name,
				"servers": strings.Join(u.Servers, ", "),
				"file":    u.File,
				"line":    strconv.Itoa(u.Line),
			},
		}); err != nil {
			return err
		}
	}

	for i := range cfg.Routes {
		if err := c.collectRoute(sink, &cfg.Routes[i], cfg, byPort, emit); err != nil {
			return err
		}
	}

	// Every server of an upstream gets its own edge: a pool is only
	// reachable through all of its members.
	for i := range cfg.Upstreams {
		u := &cfg.Upstreams[i]
		key := u.Key()
		for _, s := range u.Servers {
			t := nginx.ParseTarget(s)
			if t.Kind != nginx.TargetLocal || t.Port == 0 {
				continue // external member, or no static port to match
			}
			for _, lk := range byPort[portKey{"tcp", t.Port}] {
				if err := sink.UpsertEdge(collector.Edge{
					SrcIdentityKey: key,
					DstIdentityKey: lk,
					Kind:           "proxies_to",
					Strength:       collector.StrengthDeterministic,
					EvidenceRef:    "nginx-upstream:" + key,
				}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// collectRoute writes one location: entity, evidence, then the blind
// spot, edges or finding its target allows.
func (c *Collector) collectRoute(
	sink collector.Sink,
	r *nginx.Route,
	cfg *nginx.Config,
	byPort map[portKey][]string,
	emit func(collector.Evidence) error,
) error {
	key := r.Key()
	attrs := routeAttrs(r)
	if r.Target != nil && r.Target.Kind == nginx.TargetHost {
		// Host targets are either a declared upstream (an edge below)
		// or an external destination recorded as scope.
		if upstreamNamed(cfg, r.Target.Host) != nil {
			attrs["target_upstream"] = r.Target.Host
		} else {
			attrs["upstream_scope"] = "external"
		}
	}
	if err := sink.UpsertEntity(collector.Entity{
		Kind:        "nginx_route",
		Name:        r.Location,
		IdentityKey: key,
		Fingerprint: r.Fingerprint(),
		Attributes:  attrs,
	}); err != nil {
		return err
	}
	ref := "nginx-route:" + key
	evValue := map[string]string{
		"location":    r.Location,
		"file":        r.File,
		"line":        strconv.Itoa(r.Line),
		"listen":      strings.Join(r.Listen, ","),
		"server_name": strings.Join(r.ServerName, " "),
	}
	if r.Target != nil {
		evValue["target"] = r.Target.Raw
		evValue["target_kind"] = string(r.Target.Kind)
	}
	if err := emit(collector.Evidence{
		EntityIdentityKey: key,
		Polarity:          collector.PolarityNeutral,
		Channel:           "nginx",
		Strength:          collector.StrengthDeterministic,
		ObservedAt:        nowRFC3339(),
		RawRef:            r.RawRef(),
		Ref:               ref,
		Value:             evValue,
	}); err != nil {
		return err
	}
	if r.Target == nil {
		return nil // static location: entity only, no edge, no finding
	}

	t := r.Target
	switch t.Kind {
	case nginx.TargetUnresolved:
		// A variable (or map) decides the target: static analysis
		// does not guess, not even when the same block sets it.
		return sink.AddBlindSpot(collector.BlindSpot{
			EntityIdentityKey: key,
			Channel:           "nginx",
			Reason:            "nginx_target_unresolved",
			Detail: map[string]string{
				"target": t.Raw,
				"file":   r.File,
				"line":   strconv.Itoa(r.Line),
			},
		})

	case nginx.TargetUnix:
		if st, err := os.Stat(t.Socket); err != nil || st.IsDir() {
			return sink.AddFinding(collector.Finding{
				EntityIdentityKey: key,
				Kind:              "BROKEN_ROUTE",
				Severity:          "warn",
				Detail: map[string]string{
					"target": t.Raw,
					"socket": t.Socket,
					"file":   r.File,
					"line":   strconv.Itoa(r.Line),
					"reason": "unix socket missing at scan time",
				},
				EvidenceRef: ref,
			})
		}
		// Existing socket: no listener entity to link (the snapshot
		// only holds tcp/udp), so the attrs carry the fact.
		return nil

	case nginx.TargetLocal:
		if t.Port == 0 {
			// Without a static port there is nothing to match and
			// nothing to prove missing: report neither.
			return nil
		}
		keys := byPort[portKey{"tcp", t.Port}]
		if len(keys) == 0 {
			if c.index == nil {
				return nil // no snapshot: absence cannot be asserted
			}
			return sink.AddFinding(collector.Finding{
				EntityIdentityKey: key,
				Kind:              "BROKEN_ROUTE",
				Severity:          "warn",
				Detail: map[string]string{
					"target": t.Raw,
					"host":   t.Host,
					"port":   strconv.Itoa(t.Port),
					"file":   r.File,
					"line":   strconv.Itoa(r.Line),
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

	default: // nginx.TargetHost
		u := upstreamNamed(cfg, t.Host)
		if u == nil {
			// An external host is known truth, not a gap: attrs
			// record the scope, nothing else is claimed.
			return nil
		}
		return sink.UpsertEdge(collector.Edge{
			SrcIdentityKey: key,
			DstIdentityKey: u.Key(),
			Kind:           "proxies_to",
			Strength:       collector.StrengthDeterministic,
			EvidenceRef:    ref,
		})
	}
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

// routeAttrs renders the static shape of a location.
func routeAttrs(r *nginx.Route) map[string]string {
	attrs := map[string]string{
		"file":     r.File,
		"line":     strconv.Itoa(r.Line),
		"location": r.Location,
	}
	if len(r.Listen) > 0 {
		attrs["listen"] = strings.Join(r.Listen, ", ")
	}
	if len(r.ServerName) > 0 {
		attrs["server_name"] = strings.Join(r.ServerName, " ")
	}
	if len(r.SetVars) > 0 {
		attrs["set_directives"] = strings.Join(r.SetVars, "; ")
	}
	if r.Target == nil {
		return attrs
	}
	t := r.Target
	attrs["target"] = t.Raw
	attrs["target_kind"] = string(t.Kind)
	switch t.Kind {
	case nginx.TargetLocal, nginx.TargetHost:
		if t.Host != "" {
			attrs["target_host"] = t.Host
		}
		if t.Port > 0 {
			attrs["target_port"] = strconv.Itoa(t.Port)
		}
	case nginx.TargetUnix:
		attrs["target_socket"] = t.Socket
	}
	return attrs
}

// upstreamNamed finds a declared upstream by exact (case-sensitive,
// nginx treats names case-sensitively) name.
func upstreamNamed(cfg *nginx.Config, host string) *nginx.Upstream {
	if host == "" {
		return nil
	}
	for i := range cfg.Upstreams {
		if cfg.Upstreams[i].Name == host {
			return &cfg.Upstreams[i]
		}
	}
	return nil
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
