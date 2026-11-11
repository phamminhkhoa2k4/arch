// Package socketactivation collects systemd socket activation: which
// socket units exist, which addresses they declare, which service
// each one starts on demand, and the correlation between those
// declared addresses and the live listener snapshot. Unit files that
// cannot be read become blind spots on the socket unit — an
// activation target is never guessed.
package socketactivation

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"archaeologist/internal/collector"
	"archaeologist/internal/collector/listener"
	"archaeologist/internal/systemd"
)

// Index supplies snapshots gathered by earlier collectors; nil skips
// collection entirely (version-only registration).
type Index interface {
	UnitRows() ([]collector.UnitRow, error)
	ListenerRows() ([]collector.ListenerRow, error)
}

// Collector turns socket unit files into evidence, activation and
// live-listener edges, and blind spots.
type Collector struct {
	loader *systemd.Loader
	index  Index
}

// New creates the socket-activation collector. index may be nil
// (version-only use).
func New(loader *systemd.Loader, index Index) *Collector {
	return &Collector{loader: loader, index: index}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return "socket_activation" }

// Version implements collector.Collector.
func (c *Collector) Version() string { return "1.0.0" }

// listenKey is one listener's protocol and port in the /proc/net
// naming (family suffixes are folded before matching).
type listenKey struct {
	proto string
	port  int
}

// activation is the resolved Service= target of one socket unit.
type activation struct {
	service string // resolved service unit name, "" when unresolved
	raw     string // the Service= value as written, "" when defaulted
	ref     string // file:line of the Service= directive, "" when defaulted
	ok      bool   // false when an explicit Service= could not be expanded
}

// Collect reads every socket unit's file and writes its evidence,
// activation edges, live-listener correlations and blind spots.
func (c *Collector) Collect(ctx context.Context, sink collector.Sink) error {
	if c.index == nil || c.loader == nil {
		return nil
	}
	units, err := c.index.UnitRows()
	if err != nil {
		return fmt.Errorf("unit snapshot: %w", err)
	}
	listeners, err := c.index.ListenerRows()
	if err != nil {
		return fmt.Errorf("listener snapshot: %w", err)
	}
	sort.Slice(units, func(i, j int) bool { return units[i].Name < units[j].Name })

	keys := make(map[string]string, len(units))
	for _, u := range units {
		keys[u.Name] = u.IdentityKey
	}
	byPort := map[listenKey][]string{}
	for _, lr := range listeners {
		proto, _, port, _, perr := listener.ParseIdentityKey(lr.IdentityKey)
		if perr != nil {
			continue
		}
		lk := listenKey{normProto(proto), port}
		byPort[lk] = append(byPort[lk], lr.IdentityKey)
	}

	for _, u := range units {
		if !strings.HasSuffix(u.Name, ".socket") {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.collectSocket(sink, u, keys, byPort); err != nil {
			return err
		}
	}
	return nil
}

// collectSocket writes one socket unit's configuration evidence, its
// activates edge to the service it starts on demand, and the
// listens_on edges to every live listener its declared addresses
// match. An unreadable or missing file is a blind spot on the unit.
func (c *Collector) collectSocket(
	sink collector.Sink,
	u collector.UnitRow,
	keys map[string]string,
	byPort map[listenKey][]string,
) error {
	key := u.IdentityKey
	fragment := u.Attributes["fragment_path"]
	m, err := c.loader.Load(u.Name, fragment)
	if err != nil {
		reason := "socket_unit_unreadable"
		if systemd.IsNotFound(err) {
			reason = "socket_unit_missing"
		}
		return sink.AddBlindSpot(collector.BlindSpot{
			EntityIdentityKey: key,
			Channel:           "systemd_socket",
			Reason:            reason,
			Detail:            map[string]string{"unit": u.Name, "error": err.Error()},
		})
	}

	listens := socketListenDirectives(m)
	accept := "no"
	if ds := m.Get("Accept"); len(ds) > 0 {
		accept = ds[len(ds)-1].Value
	}
	act := serviceTarget(u.Name, m)

	// Configuration evidence: one row per socket unit, pointing at the
	// directive that proves its activation target when one is written,
	// otherwise at the listen set, the fragment, or the unit identity.
	rawRef := act.ref
	if rawRef == "" && len(listens) > 0 {
		rawRef = fmt.Sprintf("%s:%d", listens[0].File, listens[0].Line)
	}
	if rawRef == "" {
		rawRef = fragment
	}
	if rawRef == "" {
		rawRef = "unit-file:" + u.Name
	}
	polarity := collector.PolarityNeutral
	if u.Attributes["active_state"] == "active" {
		polarity = collector.PolarityInUse
	}
	listenValues := make([]string, 0, len(listens))
	for _, d := range listens {
		listenValues = append(listenValues, d.Value)
	}
	ref := "socket-activate:" + u.Name
	if err := sink.AddEvidence(collector.Evidence{
		EntityIdentityKey: key,
		Polarity:          polarity,
		Channel:           "systemd_socket",
		Strength:          collector.StrengthDeterministic,
		ObservedAt:        nowRFC3339(),
		RawRef:            rawRef,
		Ref:               ref,
		Value: map[string]string{
			"unit":    u.Name,
			"service": act.service,
			"accept":  accept,
			"listen":  strings.Join(listenValues, ", "),
		},
	}); err != nil {
		return err
	}

	if !act.ok {
		// An explicit Service= carries a reference this scan cannot
		// expand: report the gap and skip the edge, never guess.
		if err := sink.AddBlindSpot(collector.BlindSpot{
			EntityIdentityKey: key,
			Channel:           "systemd_socket",
			Reason:            "socket_service_unresolved",
			Detail: map[string]string{
				"unit":    u.Name,
				"service": act.raw,
			},
		}); err != nil {
			return err
		}
	} else if dst, present := keys[act.service]; present {
		if err := sink.UpsertEdge(collector.Edge{
			SrcIdentityKey: key,
			DstIdentityKey: dst,
			Kind:           "activates",
			Strength:       collector.StrengthDeterministic,
			EvidenceRef:    ref,
		}); err != nil {
			return err
		}
	}

	// Correlate declared addresses with the live listener snapshot.
	// Each matched directive proves one listener row, shared by every
	// listener that matches the declared protocol and port.
	for _, d := range listens {
		proto, port := parseListen(d.Key, d.Value)
		if port == 0 {
			continue // unix path, non-TCP family, or unparsable address
		}
		matches := byPort[listenKey{proto, port}]
		if len(matches) == 0 {
			continue // nothing is listening on the declared address
		}
		lref := fmt.Sprintf("socket-listen:%s:%s:%d", u.Name, d.File, d.Line)
		if err := sink.AddEvidence(collector.Evidence{
			EntityIdentityKey: key,
			Polarity:          collector.PolarityNeutral,
			Channel:           "systemd_socket",
			Strength:          collector.StrengthDeterministic,
			ObservedAt:        nowRFC3339(),
			RawRef:            fmt.Sprintf("%s:%d", d.File, d.Line),
			Ref:               lref,
			Value: map[string]string{
				"listen": d.Value,
				"proto":  proto,
				"port":   strconv.Itoa(port),
			},
		}); err != nil {
			return err
		}
		for _, lk := range matches {
			if err := sink.UpsertEdge(collector.Edge{
				SrcIdentityKey: lk,
				DstIdentityKey: key,
				Kind:           "listens_on",
				Strength:       collector.StrengthDeterministic,
				EvidenceRef:    lref,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// socketListenDirectives returns every Listen* directive of the unit
// in a fixed key order, so output stays deterministic.
func socketListenDirectives(m *systemd.Merged) []systemd.Directive {
	var out []systemd.Directive
	for _, k := range []string{
		"ListenStream", "ListenDatagram", "ListenSequentially",
		"ListenNetlink", "ListenMessageQueue", "ListenUSBFunction",
	} {
		out = append(out, m.All(k)...)
	}
	return out
}

// serviceTarget resolves the service unit a socket activates: an
// explicit Service= directive wins, otherwise systemd's documented
// default is the socket's own name with the .service suffix. ok=false
// means an explicit Service= carries a reference this scan cannot
// expand — the caller records a blind spot instead of guessing.
func serviceTarget(unit string, m *systemd.Merged) activation {
	if ds := m.Get("Service"); len(ds) > 0 {
		d := ds[len(ds)-1]
		ref := fmt.Sprintf("%s:%d", d.File, d.Line)
		expanded, ok := systemd.Expand(d.Value, map[string]string{}, systemd.Specifiers(unit))
		if !ok || expanded == "" {
			return activation{raw: d.Value, ref: ref, ok: false}
		}
		return activation{service: normalizeUnitName(expanded), raw: d.Value, ref: ref, ok: true}
	}
	return activation{service: strings.TrimSuffix(unit, ".socket") + ".service", ok: true}
}

// parseListen maps a Listen* directive onto the listener snapshot's
// protocol space: ListenStream→tcp, ListenDatagram→udp. Only a value
// carrying a port can match a /proc/net listener; unix paths and the
// other families (netlink, seqpacket, ...) return port 0.
func parseListen(key, value string) (string, int) {
	var proto string
	switch key {
	case "ListenStream":
		proto = "tcp"
	case "ListenDatagram":
		proto = "udp"
	default:
		return "", 0
	}
	v := strings.TrimSpace(value)
	if v == "" || strings.HasPrefix(v, "/") || strings.HasPrefix(v, "@") {
		return "", 0
	}
	var port string
	if strings.HasPrefix(v, "[") { // [addr]:port
		end := strings.Index(v, "]:")
		if end < 0 {
			return "", 0
		}
		port = v[end+2:]
	} else if i := strings.LastIndexByte(v, ':'); i >= 0 {
		port = v[i+1:]
	} else {
		port = v
	}
	p := portOf(port)
	if p == 0 {
		return "", 0
	}
	return proto, p
}

// portOf parses a bare port; 0 means "not a usable port".
func portOf(s string) int {
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0
	}
	return p
}

// normProto folds the /proc-style family names (tcp6/udp6) onto the
// declared-address names so a socket matches on both address families.
func normProto(p string) string {
	return strings.TrimSuffix(p, "6")
}

// normalizeUnitName applies systemd's default suffix: a unit name
// without a dot is a .service unit.
func normalizeUnitName(name string) string {
	if name == "" || strings.ContainsRune(name, '.') {
		return name
	}
	return name + ".service"
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// compile-time interface check
var _ collector.Collector = (*Collector)(nil)
