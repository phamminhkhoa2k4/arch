// Package listener implements the listener collector: map LISTEN sockets
// from /proc/net/tcp{,6} to owning processes through socket inodes.
//
// Inodes that cannot be mapped become blind spots
// (channel=listener_mapping) — a wrong PID is never guessed.
package listener

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"archaeologist/internal/collector"
	"archaeologist/internal/procfs"
)

// Collector reads the TCP tables and resolves inodes via /proc/*/fd.
type Collector struct {
	fs procfs.Reader
}

// New returns the listener collector reading through fs.
func New(fs procfs.Reader) *Collector { return &Collector{fs: fs} }

func (c *Collector) Name() string { return "listener" }

func (c *Collector) Version() string { return "1.0.0" }

// tcpTables are both TCP tables (IPv6 must not be missed).
var tcpTables = []struct{ proto, path string }{
	{"tcp", "/proc/net/tcp"},
	{"tcp6", "/proc/net/tcp6"},
}

func (c *Collector) Collect(ctx context.Context, sink collector.Sink) error {
	var socks []procfs.Sock
	for _, t := range tcpTables {
		if err := ctx.Err(); err != nil {
			return err
		}
		data, err := c.fs.ReadFile(t.path)
		if err != nil {
			return fmt.Errorf("read %s: %w", t.path, err)
		}
		rows, err := procfs.ParseTCPTable(t.proto, data)
		if err != nil {
			return fmt.Errorf("parse %s: %w", t.path, err)
		}
		for _, r := range rows {
			if r.IsLISTEN() {
				socks = append(socks, r)
			}
		}
	}
	if len(socks) == 0 {
		return nil
	}

	owners, denied := c.inodeOwners()
	ownerKeys := make(map[int]string) // pid → process identity key (cached)

	for _, s := range socks {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.emit(sink, s, owners, denied, ownerKeys); err != nil {
			return err
		}
	}
	return nil
}

func (c *Collector) emit(
	sink collector.Sink,
	s procfs.Sock,
	owners map[uint64]int,
	denied int,
	ownerKeys map[int]string,
) error {
	// The inode makes the key unique per socket: SO_REUSEPORT lets several
	// sockets share one addr:port (nginx workers, load balancers), and a
	// port-only key would collide — duplicate evidence refs would then
	// abort the collector. Fingerprint stays port-based so a service
	// restart keeps its diff identity (new incarnation, same service).
	lkey := fmt.Sprintf("listener|%s|%s|%d|%d", s.Proto, s.Addr, s.Port, s.Inode)
	detail := func(extra map[string]string) map[string]string {
		d := map[string]string{
			"proto": s.Proto,
			"addr":  s.Addr,
			"port":  strconv.Itoa(s.Port),
			"inode": strconv.FormatUint(s.Inode, 10),
		}
		for k, v := range extra {
			d[k] = v
		}
		return d
	}

	pid, mapped := owners[s.Inode]

	// The tcp table itself is solid evidence: the listener entity always
	// exists; only ownership may be a blind spot.
	attrs := map[string]string{
		"proto": s.Proto,
		"addr":  s.Addr,
		"port":  strconv.Itoa(s.Port),
		"inode": strconv.FormatUint(s.Inode, 10),
		"uid":   strconv.Itoa(s.UID),
	}
	evValue := map[string]string{
		"inode": strconv.FormatUint(s.Inode, 10),
		"state": s.State,
	}
	var ownerKey, ownerReason string
	if mapped {
		attrs["pid"] = strconv.Itoa(pid)
		evValue["pid"] = strconv.Itoa(pid)

		key, err := c.ownerKey(pid, ownerKeys)
		if err != nil {
			so, ok := err.(skipOwner)
			if !ok {
				return err
			}
			ownerReason = so.reason
		} else {
			ownerKey = key
		}
	}

	entity := collector.Entity{
		Kind:        "listener",
		Name:        fmt.Sprintf("%s:%d", s.Addr, s.Port),
		IdentityKey: lkey,
		Fingerprint: fingerprint(s.Proto, s.Addr, s.Port),
		Attributes:  attrs,
	}
	if err := sink.UpsertEntity(entity); err != nil {
		return err
	}

	ref := fmt.Sprintf("listen|%s|%s|%d|%d", s.Proto, s.Addr, s.Port, s.Inode)
	if err := sink.AddEvidence(collector.Evidence{
		EntityIdentityKey: lkey,
		Polarity:          collector.PolarityInUse,
		Channel:           "procfs_net",
		Strength:          collector.StrengthDeterministic,
		ObservedAt:        time.Now().UTC().Format(time.RFC3339),
		RawRef:            fmt.Sprintf("/proc/net/%s:sl=%d", s.Proto, s.Sl),
		Value:             evValue,
		Ref:               ref,
	}); err != nil {
		return err
	}

	if !mapped {
		// Unmapped inode → blind spot, never a guessed PID.
		return sink.AddBlindSpot(collector.BlindSpot{
			EntityIdentityKey: lkey,
			Channel:           "listener_mapping",
			Reason:            "inode_not_mapped",
			Detail:            detail(map[string]string{"unreadable_fd_dirs": strconv.Itoa(denied)}),
		})
	}
	if ownerKey == "" {
		if ownerReason == "" {
			ownerReason = "owner_unresolved"
		}
		return sink.AddBlindSpot(collector.BlindSpot{
			EntityIdentityKey: lkey,
			Channel:           "listener_mapping",
			Reason:            ownerReason,
			Detail:            detail(map[string]string{"pid": strconv.Itoa(pid)}),
		})
	}

	return sink.UpsertEdge(collector.Edge{
		SrcIdentityKey: lkey,
		DstIdentityKey: ownerKey,
		Kind:           "listens_on",
		Strength:       collector.StrengthDeterministic,
		EvidenceRef:    ref,
	})
}

// skipOwner marks an owner pid we cannot identify (vanished / denied /
// unparsable stat); recorded as a listener_mapping blind spot.
type skipOwner struct{ reason string }

func (skipOwner) Error() string { return "skip owner" }

// ownerKey reads the owner's /proc/<pid>/stat to build the same identity
// key the process collector uses, caching per pid.
func (c *Collector) ownerKey(pid int, cache map[int]string) (string, error) {
	if k, ok := cache[pid]; ok {
		return k, nil
	}
	path := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := c.fs.ReadFile(path)
	if err != nil {
		if procfs.IsNotExist(err) {
			return "", skipOwner{reason: "owner_vanished"}
		}
		reason := "owner_read_error"
		if procfs.IsPermission(err) {
			reason = "owner_permission_denied"
		}
		return "", skipOwner{reason: reason}
	}
	st, err := procfs.ParseStat(data)
	if err != nil {
		return "", skipOwner{reason: "owner_parse_error"}
	}
	key := procfs.IdentityKey(st.PID, st.StartTicks)
	cache[pid] = key
	return key, nil
}

// inodeOwners scans /proc/*/fd once and returns inode → pid plus the number
// of fd directories that could not be read (non-root: only own processes).
func (c *Collector) inodeOwners() (map[uint64]int, int) {
	owners := make(map[uint64]int)
	denied := 0

	names, err := c.fs.ReadDir("/proc")
	if err != nil {
		return owners, denied
	}
	for _, pid := range procfs.PIDNames(names) {
		fds, err := c.fs.ReadDir("/proc/" + pid + "/fd")
		if err != nil {
			if procfs.IsPermission(err) {
				denied++
			}
			continue // gone or unreadable — not a reason to abort
		}
		pidNum, convErr := strconv.Atoi(pid)
		if convErr != nil {
			continue
		}
		for _, fd := range fds {
			target, err := c.fs.Readlink("/proc/" + pid + "/fd/" + fd)
			if err != nil {
				continue // fd raced away
			}
			inode, ok := parseSocketInode(target)
			if !ok {
				continue
			}
			if _, exists := owners[inode]; !exists {
				owners[inode] = pidNum
			}
		}
	}
	return owners, denied
}

// parseSocketInode converts the readlink target "socket:[12345]" to 12345.
func parseSocketInode(target string) (uint64, bool) {
	if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]"), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// fingerprint: while the socket lives its (proto, addr, port) is stable —
// restarts keep the port but a new incarnation shows as new pid in attrs.
func fingerprint(proto, addr string, port int) string {
	h := sha256.New()
	_, _ = h.Write([]byte(proto))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(addr))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(strconv.Itoa(port)))
	return hex.EncodeToString(h.Sum(nil))
}
