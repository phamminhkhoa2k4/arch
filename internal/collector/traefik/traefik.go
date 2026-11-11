// Package traefik collects the Traefik configuration inventory:
// router and service entities, proxies_to edges against the listener
// snapshot, broken-route findings and blind spots for targets and
// providers static analysis refuses to guess.
package traefik

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"archaeologist/internal/collector"
	"archaeologist/internal/collector/listener"
	"archaeologist/internal/collector/netdep"
	"archaeologist/internal/traefik"
)

// Index supplies the listener snapshot gathered by earlier collectors;
// nil skips the edges and the absence findings that depend on it.
type Index interface {
	ListenerRows() ([]collector.ListenerRow, error)
}

// Collector turns one Traefik installation's configuration into
// entities, edges, findings and blind spots.
type Collector struct {
	index Index
	root  string // chosen static configuration entry point
}

// New creates a Traefik collector. index may be nil (no proxies_to
// edges, no BROKEN_ROUTE for tcp targets — absence cannot be asserted
// without the snapshot).
func New(index Index) *Collector {
	return &Collector{index: index}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return "traefik" }

// Version implements collector.Collector.
func (c *Collector) Version() string { return "1.0.0" }

// Collect parses the configuration once and writes entities, edges,
// findings and blind spots. A host without Traefik installed yields
// nothing: that is not a gap, merely an absent collector.
func (c *Collector) Collect(ctx context.Context, sink collector.Sink) error {
	if c.root == "" {
		c.root = c.pickRoot()
	}
	if c.root == "" {
		// A TOML-only install is present but unreadable: report the
		// gap instead of pretending Traefik is absent.
		if p := firstExisting(traefik.TOMLRoots); p != "" {
			return sink.AddBlindSpot(collector.BlindSpot{
				Channel: "traefik",
				Reason:  "traefik_config_unsupported",
				Detail: map[string]string{
					"file":  p,
					"error": "TOML static config is not parsed; convert it to traefik.yml",
				},
			})
		}
		return nil // not installed: no blind spot
	}

	cfg, err := traefik.Load(c.root)
	if err != nil {
		return sink.AddBlindSpot(collector.BlindSpot{
			Channel: "traefik",
			Reason:  "traefik_config_unreadable",
			Detail: map[string]string{
				"file":  c.root,
				"error": err.Error(),
			},
		})
	}

	// Every recorded problem becomes a blind spot while the sections
	// that parsed still yield inventory.
	for _, fe := range cfg.Unreadable {
		if err := sink.AddBlindSpot(collector.BlindSpot{
			Channel: "traefik",
			Reason:  "traefik_config_unreadable",
			Detail: map[string]string{
				"file":  fe.File,
				"error": fe.Err.Error(),
			},
		}); err != nil {
			return err
		}
	}
	for _, fe := range cfg.Unsupported {
		if err := sink.AddBlindSpot(collector.BlindSpot{
			Channel: "traefik",
			Reason:  "traefik_config_unsupported",
			Detail: map[string]string{
				"file":  fe.File,
				"error": fe.Err.Error(),
			},
		}); err != nil {
			return err
		}
	}
	for _, fe := range cfg.Errors {
		if err := sink.AddBlindSpot(collector.BlindSpot{
			Channel: "traefik",
			Reason:  "traefik_config_parse_error",
			Detail: map[string]string{
				"file":  fe.File,
				"line":  strconv.Itoa(fe.Line),
				"error": fe.Err.Error(),
			},
		}); err != nil {
			return err
		}
	}
	// Routing from docker/kubernetes/... providers lives outside the
	// files this collector reads: name each one so the gap is visible.
	for _, p := range cfg.Providers {
		if err := sink.AddBlindSpot(collector.BlindSpot{
			Channel: "traefik",
			Reason:  "traefik_provider_unsupported",
			Detail: map[string]string{
				"provider": p,
				"file":     c.root,
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

	serviceKeys := map[string]string{}
	for i := range cfg.Services {
		s := &cfg.Services[i]
		serviceKeys[s.Protocol+"#"+s.Name] = s.Key()
	}

	// Service entities first: routers and other services edge into
	// them, so the destinations must exist before those edges land.
	for i := range cfg.Services {
		s := &cfg.Services[i]
		if err := sink.UpsertEntity(collector.Entity{
			Kind:        "traefik_service",
			Name:        s.Name,
			IdentityKey: s.Key(),
			Fingerprint: s.Fingerprint(),
			Attributes:  serviceAttrs(s),
		}); err != nil {
			return err
		}
	}
	for i := range cfg.Services {
		if err := c.collectService(sink, &cfg.Services[i], serviceKeys, byPort, emit); err != nil {
			return err
		}
	}
	for i := range cfg.Routers {
		if err := c.collectRouter(sink, &cfg.Routers[i], serviceKeys, emit); err != nil {
			return err
		}
	}
	return nil
}

// pickRoot returns the first standard Traefik static configuration
// location that exists, or "" when Traefik is not installed.
func (c *Collector) pickRoot() string {
	return firstExisting(append([]string{traefik.DefaultRoot}, traefik.AltRoots...))
}

// firstExisting returns the first path that exists, or "".
func firstExisting(paths []string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// collectService writes one service's evidence, then the target
// handling its servers and references allow.
func (c *Collector) collectService(
	sink collector.Sink,
	s *traefik.Service,
	serviceKeys map[string]string,
	byPort map[portKey][]string,
	emit func(collector.Evidence) error,
) error {
	key := s.Key()
	ref := "traefik-service:" + key
	if err := emit(collector.Evidence{
		EntityIdentityKey: key,
		Polarity:          collector.PolarityNeutral,
		Channel:           "traefik",
		Strength:          collector.StrengthDeterministic,
		ObservedAt:        nowRFC3339(),
		RawRef:            s.RawRef(),
		Ref:               ref,
		Value:             serviceAttrs(s),
	}); err != nil {
		return err
	}

	// Weighted and mirroring services distribute to other services
	// declared in the same files; cross-provider references
	// (name@provider) stay visible as attributes only.
	for _, name := range s.Refs {
		if strings.Contains(name, "@") {
			continue
		}
		dst, ok := serviceKeys[s.Protocol+"#"+name]
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

	for _, srv := range s.Servers {
		t := targetFor(s, srv)
		if err := c.handleTarget(sink, key, ref, s, t, byPort); err != nil {
			return err
		}
	}
	return nil
}

// collectRouter writes one router: entity, evidence, then the routing
// edge to its service when that service is in the inventory.
func (c *Collector) collectRouter(
	sink collector.Sink,
	r *traefik.Router,
	serviceKeys map[string]string,
	emit func(collector.Evidence) error,
) error {
	key := r.Key()
	attrs := routerAttrs(r)
	if err := sink.UpsertEntity(collector.Entity{
		Kind:        "traefik_router",
		Name:        r.Name,
		IdentityKey: key,
		Fingerprint: r.Fingerprint(),
		Attributes:  attrs,
	}); err != nil {
		return err
	}

	ref := "traefik-router:" + key
	if err := emit(collector.Evidence{
		EntityIdentityKey: key,
		Polarity:          collector.PolarityNeutral,
		Channel:           "traefik",
		Strength:          collector.StrengthDeterministic,
		ObservedAt:        nowRFC3339(),
		RawRef:            r.RawRef(),
		Ref:               ref,
		Value:             attrs,
	}); err != nil {
		return err
	}

	if r.Service == "" || strings.Contains(r.Service, "@") {
		return nil // no service, or one owned by another provider
	}
	dst, ok := serviceKeys[r.Protocol+"#"+r.Service]
	if !ok {
		return nil // the service lives in a file this scan did not read
	}
	return sink.UpsertEdge(collector.Edge{
		SrcIdentityKey: key,
		DstIdentityKey: dst,
		Kind:           "proxies_to",
		Strength:       collector.StrengthDeterministic,
		EvidenceRef:    ref,
	})
}

// targetFor parses one server target in the way its protocol dictates:
// http services carry URLs, tcp services carry bare addresses.
func targetFor(s *traefik.Service, srv traefik.Server) traefik.Target {
	if s.Protocol == "tcp" {
		return traefik.ParseAddress(srv.Target)
	}
	return traefik.ParseURL(srv.Target)
}

// handleTarget classifies one server target of a service: a blind
// spot when static analysis refuses to guess, a broken-route finding
// when the target is provably missing, a proxies_to edge when a
// listener owns the port.
func (c *Collector) handleTarget(
	sink collector.Sink,
	key, ref string,
	s *traefik.Service,
	t traefik.Target,
	byPort map[portKey][]string,
) error {
	switch t.Kind {
	case traefik.TargetUnresolved:
		return sink.AddBlindSpot(collector.BlindSpot{
			EntityIdentityKey: key,
			Channel:           "traefik",
			Reason:            "traefik_target_unresolved",
			Detail: map[string]string{
				"service": s.Name,
				"target":  t.Raw,
				"file":    s.File,
				"line":    strconv.Itoa(s.Line),
			},
		})
	case traefik.TargetUnix:
		if st, err := os.Stat(t.Socket); err != nil || st.IsDir() {
			return sink.AddFinding(collector.Finding{
				EntityIdentityKey: key,
				Kind:              "BROKEN_ROUTE",
				Severity:          "warn",
				Detail: map[string]string{
					"service": s.Name,
					"target":  t.Raw,
					"socket":  t.Socket,
					"reason":  "unix socket missing at scan time",
				},
				EvidenceRef: ref,
			})
		}
		return nil
	case traefik.TargetLocal:
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
					"service": s.Name,
					"target":  t.Raw,
					"host":    t.Host,
					"port":    strconv.Itoa(t.Port),
					"reason":  fmt.Sprintf("no listener on tcp/%d at scan time", t.Port),
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
			Channel:  "traefik",
			Strength: collector.StrengthDeterministic,
			RawRef:   s.RawRef(),
			Target: netdep.Target{
				Host: t.Host, Port: t.Port, Scheme: t.Scheme, Raw: t.Raw,
			},
		})
	}
}

// routerAttrs renders the static shape of a router.
func routerAttrs(r *traefik.Router) map[string]string {
	attrs := map[string]string{
		"file":     r.File,
		"line":     strconv.Itoa(r.Line),
		"protocol": r.Protocol,
		"name":     r.Name,
		"service":  r.Service,
	}
	if r.Rule != "" {
		attrs["rule"] = r.Rule
	}
	if len(r.EntryPoints) > 0 {
		attrs["entrypoints"] = strings.Join(r.EntryPoints, ",")
	}
	if len(r.Middlewares) > 0 {
		attrs["middlewares"] = strings.Join(r.Middlewares, ",")
	}
	return attrs
}

// serviceAttrs renders the static shape of a service.
func serviceAttrs(s *traefik.Service) map[string]string {
	attrs := map[string]string{
		"file":     s.File,
		"line":     strconv.Itoa(s.Line),
		"protocol": s.Protocol,
		"name":     s.Name,
		"kind":     s.Kind,
	}
	if len(s.Servers) > 0 {
		targets := make([]string, 0, len(s.Servers))
		for _, srv := range s.Servers {
			targets = append(targets, srv.Target)
		}
		attrs["servers"] = strings.Join(targets, ";")
	}
	if len(s.Refs) > 0 {
		attrs["refs"] = strings.Join(s.Refs, ",")
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
