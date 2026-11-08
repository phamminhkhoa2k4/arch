// Package caddy collects the Caddy configuration inventory: route
// entities, proxies_to edges against the listener snapshot, broken-
// route findings and blind spots for targets static analysis refuses
// to guess.
package caddy

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"archaeologist/internal/caddy"
	"archaeologist/internal/collector"
	"archaeologist/internal/collector/listener"
)

// Index supplies the listener snapshot gathered by earlier collectors;
// nil skips the edges and the absence findings that depend on it.
type Index interface {
	ListenerRows() ([]collector.ListenerRow, error)
}

// Collector turns the Caddy configuration tree into entities, edges,
// findings and blind spots.
type Collector struct {
	loader *caddy.Loader
	index  Index
	root   string // chosen configuration entry point
}

// New creates a Caddy collector. loader may be nil (reads the first
// standard location that exists); index may be nil (no proxies_to
// edges, no BROKEN_ROUTE for tcp targets — absence cannot be asserted
// without the snapshot).
func New(loader *caddy.Loader, index Index) *Collector {
	if loader == nil {
		loader = caddy.NewLoader()
	}
	return &Collector{loader: loader, index: index}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return "caddy" }

// Version implements collector.Collector.
func (c *Collector) Version() string { return "1.0.0" }

// Collect parses the configuration once and writes entities, edges,
// findings and blind spots. A host without Caddy installed yields
// nothing: that is not a gap, merely an absent collector.
func (c *Collector) Collect(ctx context.Context, sink collector.Sink) error {
	if c.root == "" {
		c.root = c.pickRoot()
	}
	if c.root == "" {
		return nil // not installed: no blind spot
	}

	cfg, err := c.loader.Load(c.root)
	if err != nil {
		return sink.AddBlindSpot(collector.BlindSpot{
			Channel: "caddy",
			Reason:  "caddy_config_unreadable",
			Detail: map[string]string{
				"file":  c.root,
				"error": err.Error(),
			},
		})
	}

	// Syntax errors never crash the scan: each one becomes a blind
	// spot while the parts that parsed still yield routes.
	for _, fe := range cfg.Errors {
		if err := sink.AddBlindSpot(collector.BlindSpot{
			Channel: "caddy",
			Reason:  "caddy_config_parse_error",
			Detail: map[string]string{
				"file":  fe.File,
				"line":  strconv.Itoa(fe.Line),
				"error": fe.Err.Error(),
			},
		}); err != nil {
			return err
		}
	}

	// Unreadable imports are reported individually so the scan keeps
	// the routes from the files that did parse.
	for _, fe := range cfg.Unreadable {
		if err := sink.AddBlindSpot(collector.BlindSpot{
			Channel: "caddy",
			Reason:  "caddy_import_unreadable",
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

	for i := range cfg.Routes {
		if err := c.collectRoute(sink, &cfg.Routes[i], byPort, emit); err != nil {
			return err
		}
	}
	return nil
}

// pickRoot returns the first standard Caddyfile location that exists,
// or "" when Caddy is not installed.
func (c *Collector) pickRoot() string {
	roots := []string{caddy.DefaultRoot}
	roots = append(roots, caddy.AltRoots...)
	for _, r := range roots {
		if _, err := os.Stat(r); err == nil {
			return r
		}
	}
	return ""
}

// collectRoute writes one route: entity, evidence, then the blind
// spot, edges or finding its targets allow.
func (c *Collector) collectRoute(
	sink collector.Sink,
	r *caddy.Route,
	byPort map[portKey][]string,
	emit func(collector.Evidence) error,
) error {
	key := r.Key()
	attrs := routeAttrs(r)
	if err := sink.UpsertEntity(collector.Entity{
		Kind:        "caddy_route",
		Name:        r.Name(),
		IdentityKey: key,
		Fingerprint: r.Fingerprint(),
		Attributes:  attrs,
	}); err != nil {
		return err
	}

	ref := "caddy-route:" + key
	evValue := map[string]string{
		"site":     r.Site,
		"location": r.Location,
		"file":     r.File,
		"line":     strconv.Itoa(r.Line),
	}
	if len(r.Targets) > 0 {
		raws := make([]string, 0, len(r.Targets))
		for _, t := range r.Targets {
			raws = append(raws, t.Raw)
		}
		evValue["targets"] = strings.Join(raws, ", ")
	}

	strength := collector.StrengthDeterministic
	if err := emit(collector.Evidence{
		EntityIdentityKey: key,
		Polarity:          collector.PolarityNeutral,
		Channel:           "caddy",
		Strength:          strength,
		ObservedAt:        nowRFC3339(),
		RawRef:            r.RawRef(),
		Ref:               ref,
		Value:             evValue,
	}); err != nil {
		return err
	}

	for _, t := range r.Targets {
		if err := c.handleTarget(sink, key, ref, r, t, byPort); err != nil {
			return err
		}
	}
	return nil
}

// handleTarget classifies one upstream address of a route.
func (c *Collector) handleTarget(
	sink collector.Sink,
	key, ref string,
	r *caddy.Route,
	t caddy.Target,
	byPort map[portKey][]string,
) error {
	switch t.Kind {
	case caddy.TargetUnresolved:
		return sink.AddBlindSpot(collector.BlindSpot{
			EntityIdentityKey: key,
			Channel:           "caddy",
			Reason:            "caddy_target_unresolved",
			Detail: map[string]string{
				"target": t.Raw,
				"file":   r.File,
				"line":   strconv.Itoa(r.Line),
			},
		})
	case caddy.TargetUnix:
		if st, err := os.Stat(t.Socket); err != nil || st.IsDir() {
			return sink.AddFinding(collector.Finding{
				EntityIdentityKey: key,
				Kind:              "BROKEN_ROUTE",
				Severity:          "warn",
				Detail: map[string]string{
					"target": t.Raw,
					"socket": t.Socket,
					"reason": "unix socket missing at scan time",
				},
				EvidenceRef: ref,
			})
		}
		return nil
	case caddy.TargetLocal:
		if t.Port == 0 {
			return nil
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
					"target": t.Raw,
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
		// External or named host: recorded as scope in attrs, no edge.
		return nil
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

// routeAttrs renders the static shape of a route.
func routeAttrs(r *caddy.Route) map[string]string {
	attrs := map[string]string{
		"file":     r.File,
		"line":     strconv.Itoa(r.Line),
		"site":     r.Site,
		"location": r.Location,
	}
	if len(r.Targets) > 0 {
		raws := make([]string, 0, len(r.Targets))
		for _, t := range r.Targets {
			raws = append(raws, t.Raw)
		}
		attrs["targets"] = strings.Join(raws, ", ")
	}
	return attrs
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
