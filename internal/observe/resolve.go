package observe

import "strings"

// pair is one distinct hit inside a single sample.
type pair struct {
	entity int64
	remote string
}

// index maps normalised proto+port onto the listeners bound there.
type index struct {
	byKey map[key][]Listener
}

type key struct {
	proto string
	port  int
}

// normProto collapses the IPv6 table spellings onto the family used
// for matching (a "tcp6" listener answers rows from either table).
func normProto(p string) string {
	switch {
	case strings.HasPrefix(p, "tcp"):
		return "tcp"
	case strings.HasPrefix(p, "udp"):
		return "udp"
	default:
		return p
	}
}

func isWildcard(addr string) bool {
	return addr == "0.0.0.0" || addr == "::" || addr == "*"
}

// wildcardFamily is the address family a wildcard listener accepts:
// "0.0.0.0" answers the IPv4 tables, "::" the IPv6 tables and "*"
// any (test fixtures). Cross-family wildcards must not both match,
// or one connection would be counted on two entities.
func wildcardFamily(addr string) string {
	switch addr {
	case "0.0.0.0":
		return "4"
	case "::":
		return "6"
	default:
		return "*"
	}
}

// sockFamily is the family of the table the row came from ("tcp6"
// rows are IPv6 even when a v4-mapped address renders as dotted
// quad).
func sockFamily(proto string) string {
	if strings.HasSuffix(proto, "6") {
		return "6"
	}
	return "4"
}

// newIndex builds the lookup for one sample round.
func newIndex(ls []Listener) *index {
	ix := &index{byKey: make(map[key][]Listener, len(ls))}
	for _, l := range ls {
		k := key{normProto(l.Proto), l.Port}
		ix.byKey[k] = append(ix.byKey[k], l)
	}
	return ix
}

// resolve returns the listener entities a connection whose local side
// is addr:port belongs to. An address-specific listener wins over a
// wildcard binding so the same port on 127.0.0.1 and 0.0.0.0 does not
// double-count; among wildcards only the one matching the socket's
// table family applies ("*").
func (ix *index) resolve(proto, addr string, port int) []int64 {
	cands := ix.byKey[key{normProto(proto), port}]
	if len(cands) == 0 {
		return nil
	}
	fam := sockFamily(proto)
	var exact, wild []int64
	for _, l := range cands {
		if l.Addr == addr {
			exact = append(exact, l.ID)
			continue
		}
		if !isWildcard(l.Addr) {
			continue
		}
		if wf := wildcardFamily(l.Addr); wf == fam || wf == "*" {
			wild = append(wild, l.ID)
		}
	}
	if len(exact) > 0 {
		return exact
	}
	return wild
}
