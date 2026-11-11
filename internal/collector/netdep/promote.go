package netdep

import (
	"net"
	"strconv"
	"strings"

	"archaeologist/internal/collector"
)

// ExternalKind is the entity kind shared by every proxy collector for
// a destination that lives outside this host.
const ExternalKind = "external_host"

// Target is one proxy destination that points off this host: the
// host (or address) the configuration names, plus whatever else static
// analysis could prove.
type Target struct {
	Host   string
	Port   int    // 0 when the configuration wrote no port
	Scheme string // empty when no scheme was written
	Raw    string // the address exactly as written
}

// Link is one referring configuration's claim about an off-host
// target.
type Link struct {
	FromKey  string // referring entity's identity key
	Ref      string // evidence ref already emitted for FromKey
	Channel  string // referring collector's channel (nginx, caddy, ...)
	Strength collector.Strength
	RawRef   string // file:line of the referring directive
	Target   Target
}

// ExternalKey is the shared identity of one off-host destination:
// the host alone when no port was provable, host:port otherwise.
// Every proxy collector uses it, so two configurations pointing at
// the same destination share one entity.
func ExternalKey(host string, port int) string {
	host = strings.Trim(host, "[]")
	if port > 0 {
		return ExternalKind + "|" + net.JoinHostPort(host, strconv.Itoa(port))
	}
	return ExternalKind + "|" + host
}

// Promote records an off-host proxy destination as an external_host
// entity (shared by every collector that points at it), attaches
// channel evidence naming the referring configuration line, and adds a
// proxies_to edge from the referring entity. l.Ref must be an evidence
// ref already emitted for l.FromKey; a target without a host is
// nothing to name and is ignored.
func Promote(sink collector.Sink, l Link) error {
	if strings.TrimSpace(l.Target.Host) == "" {
		return nil
	}
	host := strings.Trim(l.Target.Host, "[]")
	key := ExternalKey(host, l.Target.Port)
	attrs := map[string]string{"host": host}
	if l.Target.Port > 0 {
		attrs["port"] = strconv.Itoa(l.Target.Port)
	}
	if l.Target.Scheme != "" {
		attrs["scheme"] = l.Target.Scheme
	}
	if err := sink.UpsertEntity(collector.Entity{
		Kind:        ExternalKind,
		Name:        strings.TrimPrefix(key, ExternalKind+"|"),
		IdentityKey: key,
		Fingerprint: fingerprint(key),
		Attributes:  attrs,
	}); err != nil {
		return err
	}
	value := map[string]string{
		"host":    host,
		"target":  l.Target.Raw,
		"channel": l.Channel,
	}
	if l.Target.Port > 0 {
		value["port"] = strconv.Itoa(l.Target.Port)
	}
	if l.Target.Scheme != "" {
		value["scheme"] = l.Target.Scheme
	}
	// No evidence ref: the destination is cited by raw_ref, and the
	// edge points at the referring entity's own evidence.
	if err := sink.AddEvidence(collector.Evidence{
		EntityIdentityKey: key,
		Polarity:          collector.PolarityNeutral,
		Channel:           l.Channel,
		Strength:          l.Strength,
		ObservedAt:        nowRFC3339(),
		RawRef:            l.RawRef,
		Value:             value,
	}); err != nil {
		return err
	}
	return sink.UpsertEdge(collector.Edge{
		SrcIdentityKey: l.FromKey,
		DstIdentityKey: key,
		Kind:           "proxies_to",
		Strength:       l.Strength,
		EvidenceRef:    l.Ref,
	})
}
