package observe

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"archaeologist/internal/procfs"
)

// tcpTables are the established-socket sources from proc (D1 scope).
var tcpTables = []struct{ proto, path string }{
	{"tcp", "/proc/net/tcp"},
	{"tcp6", "/proc/net/tcp6"},
}

// conntrackPath is read only when the kernel module is loaded (D7);
// a missing file silently narrows the sample.
const conntrackPath = "/proc/net/nf_conntrack"

// collect merges the proc tables and conntrack (when present) into a
// sorted, de-duplicated set of (listener entity, remote) pairs.
func (s *Sampler) collect() ([]pair, error) {
	listeners := s.listenerSnapshot()
	if len(listeners) == 0 {
		return nil, nil
	}
	ix := newIndex(listeners)
	seen := make(map[pair]struct{})

	for _, t := range tcpTables {
		data, err := s.reader.ReadFile(t.path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", t.path, err)
		}
		socks, err := procfs.ParseTCPTable(t.proto, data)
		if err != nil {
			return nil, err
		}
		for _, sock := range socks {
			if sock.State != "01" { // ESTABLISHED only
				continue
			}
			s.record(seen, ix, sock.Proto, sock.Addr, sock.Port, sock.RemoteAddr)
		}
	}

	// Conntrack supplements proc: entries linger briefly after a
	// connection closes and cover protocols proc matching misses.
	if data, err := s.reader.ReadFile(conntrackPath); err == nil {
		s.recordConntrack(seen, ix, data)
	}
	return sortedPairs(seen), nil
}

func (s *Sampler) record(seen map[pair]struct{}, ix *index, proto, localAddr string, localPort int, remote string) {
	for _, id := range ix.resolve(proto, localAddr, localPort) {
		if remote == "" || remote == "0.0.0.0" {
			continue
		}
		seen[pair{entity: id, remote: remote}] = struct{}{}
	}
}

// recordConntrack parses nf_conntrack lines. Row shape:
//
//	tcp  431999 ESTABLISHED src=1.2.3.4 dst=10.0.0.5 sport=44444 dport=80 src=...
//	udp  179    src=1.2.3.4 dst=10.0.0.5 sport=44444 dport=53 [UNREPLIED] src=...
//
// The first tuple is the initiator side: an inbound connection has
// dport on our listener and src as the remote address. Unreplied and
// non-established/non-assured rows are skipped.
func (s *Sampler) recordConntrack(seen map[pair]struct{}, ix *index, data []byte) {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "[UNREPLIED]") {
			continue
		}
		if !strings.Contains(line, "ESTABLISHED") && !strings.Contains(line, "ASSURED") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		proto := fields[0]
		var src, dst, dport string
		for _, f := range fields {
			switch {
			case strings.HasPrefix(f, "src="):
				if src == "" {
					src = strings.TrimPrefix(f, "src=")
				}
			case strings.HasPrefix(f, "dst="):
				if dst == "" {
					dst = strings.TrimPrefix(f, "dst=")
				}
			case strings.HasPrefix(f, "dport="):
				if dport == "" {
					dport = strings.TrimPrefix(f, "dport=")
				}
			}
		}
		if dst == "" || dport == "" || src == "" {
			continue
		}
		port, err := strconv.Atoi(dport)
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		s.record(seen, ix, proto, dst, port, src)
	}
}

// sortedPairs returns pairs in a stable order so tests and bucket
// counts never depend on map iteration.
func sortedPairs(m map[pair]struct{}) []pair {
	out := make([]pair, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].entity != out[j].entity {
			return out[i].entity < out[j].entity
		}
		return out[i].remote < out[j].remote
	})
	return out
}
