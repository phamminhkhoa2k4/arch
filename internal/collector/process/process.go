// Package process implements the process collector: enumerate every
// pid from /proc, emit kind=process entities with stable fingerprints, and
// record permission gaps as blind spots instead of crashing.
package process

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/user"
	"strconv"
	"strings"
	"time"

	"archaeologist/internal/collector"
	"archaeologist/internal/procfs"
	"archaeologist/internal/redact"
)

// Collector walks /proc through a procfs.Reader (fake in tests).
type Collector struct {
	fs procfs.Reader
}

// New returns the process collector reading through fs.
func New(fs procfs.Reader) *Collector { return &Collector{fs: fs} }

func (c *Collector) Name() string { return "process" }

func (c *Collector) Version() string { return "1.0.0" }

// Collect emits one entity + evidence per readable pid. A pid that races
// away or is unreadable becomes a blind spot / skip, never an abort.
func (c *Collector) Collect(ctx context.Context, sink collector.Sink) error {
	names, err := c.fs.ReadDir("/proc")
	if err != nil {
		return fmt.Errorf("read /proc: %w", err)
	}

	for _, pid := range procfs.PIDNames(names) {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := c.emit(sink, pid)
		if _, skipped := err.(skipPID); skipped {
			continue // per-pid outcome already recorded as blind spot / gone
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// skipPID marks a pid we cannot or should not emit (raced away, denied,
// unparsable) — the blind spot, if any, has already been recorded.
type skipPID struct{ reason string }

func (skipPID) Error() string { return "skip pid" }

func (c *Collector) emit(sink collector.Sink, pid string) error {
	base := "/proc/" + pid

	statData, err := c.readOrBlind(sink, pid, base+"/stat")
	if err != nil {
		return err
	}
	st, err := procfs.ParseStat(statData)
	if err != nil {
		return sink.AddBlindSpot(collector.BlindSpot{
			Channel: "process",
			Reason:  "parse_error",
			Detail:  map[string]string{"pid": pid, "path": base + "/stat", "error": err.Error()},
		})
	}

	cmdData, err := c.readOrBlind(sink, pid, base+"/cmdline")
	if err != nil {
		return err
	}
	cmdline := decodeCmdline(cmdData)

	statusData, err := c.readOrBlind(sink, pid, base+"/status")
	if err != nil {
		return err
	}
	uid := procfs.ParseUID(statusData)

	cgData, err := c.readOrBlind(sink, pid, base+"/cgroup")
	if err != nil {
		return err
	}
	cg := procfs.ParseCgroup(cgData)

	key := procfs.IdentityKey(st.PID, st.StartTicks)
	attrs := map[string]string{
		"pid":        strconv.Itoa(st.PID),
		"ppid":       strconv.Itoa(st.PPID),
		"uid":        strconv.Itoa(uid),
		"user":       userName(uid),
		"cmdline":    cmdline,
		"start_time": strconv.FormatUint(st.StartTicks, 10),
		"cgroup":     cg.Path,
	}
	if cg.ContainerID != "" {
		attrs["container_id"] = cg.ContainerID
	}
	if cg.Unit != "" {
		attrs["unit"] = cg.Unit
	}

	entity := collector.Entity{
		Kind:        "process",
		Name:        st.Comm,
		IdentityKey: key,
		Fingerprint: fingerprint(cmdline, st.StartTicks, cg.Path),
		Attributes:  attrs,
	}
	if err := sink.UpsertEntity(entity); err != nil {
		return err
	}
	if err := sink.AddEvidence(collector.Evidence{
		EntityIdentityKey: key,
		Polarity:          collector.PolarityInUse,
		Channel:           "procfs",
		Strength:          collector.StrengthDeterministic,
		ObservedAt:        time.Now().UTC().Format(time.RFC3339),
		RawRef:            base + "/stat",
		Value: map[string]string{
			"pid":   strconv.Itoa(st.PID),
			"state": st.State,
		},
	}); err != nil {
		return err
	}
	return c.emitEnviron(sink, pid, key, base)
}

// emitEnviron reads /proc/<pid>/environ (NUL-separated NAME=VALUE),
// redacts credential-bearing names/values, and records the result as
// one evidence row. A denied or vanished file is skipped silently:
// cross-user environ is expected to be unreadable and the stat read
// already reported the pid-level permission blind spot.
func (c *Collector) emitEnviron(sink collector.Sink, pid, key, base string) error {
	data, err := c.fs.ReadFile(base + "/environ")
	if err != nil || len(data) == 0 {
		return nil
	}
	env := redact.RedactEnv(parseEnviron(data))
	if len(env) == 0 {
		return nil
	}
	return sink.AddEvidence(collector.Evidence{
		EntityIdentityKey: key,
		Polarity:          collector.PolarityNeutral,
		Channel:           "environ",
		Strength:          collector.StrengthDeterministic,
		ObservedAt:        time.Now().UTC().Format(time.RFC3339),
		RawRef:            base + "/environ",
		Value:             env,
	})
}

// parseEnviron splits the NUL-separated NAME=VALUE blob.
func parseEnviron(b []byte) map[string]string {
	out := map[string]string{}
	for _, entry := range strings.Split(strings.TrimRight(string(b), "\x00"), "\x00") {
		if entry == "" {
			continue
		}
		name, value, ok := strings.Cut(entry, "=")
		if !ok || name == "" {
			continue
		}
		out[name] = value
	}
	return out
}

// readOrBlind reads path and converts per-pid failures into blind spots:
// EACCES → channel=process/reason=permission_denied,
// ENOENT → pid vanished mid-scan (skip silently), other errors → read_error.
// The returned error is non-nil only for a sink failure or skipPID.
func (c *Collector) readOrBlind(sink collector.Sink, pid, path string) ([]byte, error) {
	data, err := c.fs.ReadFile(path)
	if err == nil {
		return data, nil
	}
	if procfs.IsNotExist(err) {
		return nil, skipPID{reason: "gone"}
	}
	reason := "read_error"
	if procfs.IsPermission(err) {
		reason = "permission_denied"
	}
	if sinkErr := sink.AddBlindSpot(collector.BlindSpot{
		Channel: "process",
		Reason:  reason,
		Detail:  map[string]string{"pid": pid, "path": path, "error": err.Error()},
	}); sinkErr != nil {
		return nil, sinkErr
	}
	return nil, skipPID{reason: reason}
}

func decodeCmdline(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	parts := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	return strings.Join(parts, " ")
}

// userName maps uid → login name, falling back to the numeric uid so the
// attribute is never a guess.
func userName(uid int) string {
	if uid < 0 {
		return ""
	}
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil && u.Username != "" {
		return u.Username
	}
	return strconv.Itoa(uid)
}

// fingerprint is stable across scans while the process lives: cmdline and
// cgroup identify behavior, start_time pins the incarnation.
func fingerprint(cmdline string, startTicks uint64, cgroupPath string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(cmdline))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(strconv.FormatUint(startTicks, 10)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(cgroupPath))
	return hex.EncodeToString(h.Sum(nil))
}
