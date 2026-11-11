// Package apache collects the Apache httpd configuration inventory:
// route entities, proxies_to edges against the listener snapshot,
// broken-route findings and blind spots for targets static analysis
// refuses to guess.
package apache

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"archaeologist/internal/apache"
	"archaeologist/internal/collector"
	"archaeologist/internal/collector/listener"
	"archaeologist/internal/collector/netdep"
)

// Index supplies the listener snapshot gathered by earlier collectors;
// nil skips the edges and the absence findings that depend on it.
type Index interface {
	ListenerRows() ([]collector.ListenerRow, error)
}

// Collector turns one Apache configuration tree into entities,
// edges, findings and blind spots.
type Collector struct {
	index Index
	root  string // chosen main configuration entry point
}

// New creates an Apache collector. index may be nil (no proxies_to
// edges, no BROKEN_ROUTE for tcp targets — absence cannot be asserted
// without the snapshot).
func New(index Index) *Collector {
	return &Collector{index: index}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return "apache" }

// Version implements collector.Collector.
func (c *Collector) Version() string { return "1.0.0" }

// Collect parses the configuration once and writes entities, edges,
// findings and blind spots. A host without Apache installed yields
// nothing: that is not a gap, merely an absent collector.
func (c *Collector) Collect(ctx context.Context, sink collector.Sink) error {
	if c.root == "" {
		c.root = c.pickRoot()
	}
	if c.root == "" {
		return nil // not installed: no blind spot
	}

	cfg, err := apache.Load(c.root)
	if err != nil {
		return sink.AddBlindSpot(collector.BlindSpot{
			Channel: "apache",
			Reason:  "apache_config_unreadable",
			Detail: map[string]string{
				"file":  c.root,
				"error": err.Error(),
			},
		})
	}

	// Include targets that could not be read are reported
	// individually so the routes from the files that did parse stay.
	for _, fe := range cfg.Unreadable {
		if err := sink.AddBlindSpot(collector.BlindSpot{
			Channel: "apache",
			Reason:  "apache_include_unreadable",
			Detail: map[string]string{
				"file":  fe.File,
				"line":  strconv.Itoa(fe.Line),
				"error": fe.Err.Error(),
			},
		}); err != nil {
			return err
		}
	}

	// Syntax problems never crash the scan: each one becomes a
	// blind spot while the positions that parsed still yield routes.
	for _, fe := range cfg.Errors {
		if err := sink.AddBlindSpot(collector.BlindSpot{
			Channel: "apache",
			Reason:  "apache_config_parse_error",
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

// pickRoot returns the first standard Apache main configuration that
// exists, or "" when Apache is not installed.
func (c *Collector) pickRoot() string {
	roots := []string{apache.DefaultRoot}
	roots = append(roots, apache.AltRoots...)
	for _, r := range roots {
		if _, err := os.Stat(r); err == nil {
			return r
		}
	}
	return ""
}

// collectRoute writes one route: entity, evidence, then the blind
// spot, edges or finding its target allows.
func (c *Collector) collectRoute(
	sink collector.Sink,
	r *apache.Route,
	byPort map[portKey][]string,
	emit func(collector.Evidence) error,
) error {
	key := r.Key()
	attrs := routeAttrs(r)
	if err := sink.UpsertEntity(collector.Entity{
		Kind:        "apache_route",
		Name:        r.Path,
		IdentityKey: key,
		Fingerprint: r.Fingerprint(),
		Attributes:  attrs,
	}); err != nil {
		return err
	}

	ref := "apache-route:" + key
	if err := emit(collector.Evidence{
		EntityIdentityKey: key,
		Polarity:          collector.PolarityNeutral,
		Channel:           "apache",
		Strength:          collector.StrengthDeterministic,
		ObservedAt:        nowRFC3339(),
		RawRef:            r.RawRef(),
		Ref:               ref,
		Value:             attrs,
	}); err != nil {
		return err
	}

	t := apache.ParseTarget(r.Target)
	switch t.Kind {
	case apache.TargetUnresolved:
		return sink.AddBlindSpot(collector.BlindSpot{
			EntityIdentityKey: key,
			Channel:           "apache",
			Reason:            "apache_target_unresolved",
			Detail: map[string]string{
				"path":   r.Path,
				"target": r.Target,
				"file":   r.File,
				"line":   strconv.Itoa(r.Line),
			},
		})
	case apache.TargetUnix:
		if st, err := os.Stat(t.Socket); err != nil || st.IsDir() {
			return sink.AddFinding(collector.Finding{
				EntityIdentityKey: key,
				Kind:              "BROKEN_ROUTE",
				Severity:          "warn",
				Detail: map[string]string{
					"path":   r.Path,
					"target": r.Target,
					"socket": t.Socket,
					"reason": "unix socket missing at scan time",
				},
				EvidenceRef: ref,
			})
		}
		return nil
	case apache.TargetLocal:
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
					"path":   r.Path,
					"target": r.Target,
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
		// Off-host destination: a shared entity keeps the dependency
		// visible in the graph instead of a scope attribute.
		return netdep.Promote(sink, netdep.Link{
			FromKey:  key,
			Ref:      ref,
			Channel:  "apache",
			Strength: collector.StrengthDeterministic,
			RawRef:   r.RawRef(),
			Target: netdep.Target{
				Host: t.Host, Port: t.Port, Scheme: t.Scheme, Raw: t.Raw,
			},
		})
	}
}

// routeAttrs renders the static shape of a route.
func routeAttrs(r *apache.Route) map[string]string {
	attrs := map[string]string{
		"file":   r.File,
		"line":   strconv.Itoa(r.Line),
		"path":   r.Path,
		"target": r.Target,
	}
	if r.VHost != "" {
		attrs["vhost"] = r.VHost
	}
	if r.ServerName != "" {
		attrs["server_name"] = r.ServerName
	}
	return attrs
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
