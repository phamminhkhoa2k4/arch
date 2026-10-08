package cron

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// LastRun reports when scheduled work actually executed. The scan
// probes it once per run; a nil probe (tests, restricted
// environments) leaves the attribute off entirely instead of
// guessing.
type LastRun interface {
	// CronRuns maps a crontab command to the timestamp of its newest
	// journal line. An unreadable journal is an error: the caller
	// then records nothing.
	CronRuns(ctx context.Context) (map[string]time.Time, error)
	// TimerTrigger is the LastTriggerUSec of one timer unit; ok=false
	// means never fired or unparsable — never a guess.
	TimerTrigger(ctx context.Context, unit string) (time.Time, bool, error)
}

// execCommand is swapped in tests.
var execCommand = exec.CommandContext

// ExecLastRun probes the host through journalctl and systemctl.
type ExecLastRun struct{}

// NewExecLastRun returns the journalctl/systemd-backed probe.
func NewExecLastRun() *ExecLastRun { return &ExecLastRun{} }

// CronRuns reads the tail of the cron journal once per scan.
func (x *ExecLastRun) CronRuns(ctx context.Context) (map[string]time.Time, error) {
	out, err := execCommand(ctx, "journalctl", "-u", "cron", "-o", "short-iso",
		"-n", "5000", "--no-pager").Output()
	if err != nil {
		return nil, fmt.Errorf("journalctl -u cron: %w", err)
	}
	return parseCronRuns(out), nil
}

// TimerTrigger reads LastTriggerUSec of one timer unit. Failures and
// unparsable values report ok=false — absence is never invented into
// a timestamp.
func (x *ExecLastRun) TimerTrigger(ctx context.Context, unit string) (time.Time, bool, error) {
	if unit == "" || strings.HasPrefix(unit, "-") {
		return time.Time{}, false, fmt.Errorf("invalid timer unit %q", unit)
	}
	out, err := execCommand(ctx, "systemctl", "show", unit,
		"-p", "LastTriggerUSec", "--value").Output()
	if err != nil {
		return time.Time{}, false, nil
	}
	s := strings.TrimSpace(string(out))
	if s == "" || s == "n/a" {
		return time.Time{}, false, nil
	}
	// systemd prints e.g. `Wed 2026-10-07 02:00:00 UTC`.
	ts, err := time.Parse("Mon 2006-01-02 15:04:05 MST", s)
	if err != nil {
		return time.Time{}, false, nil
	}
	return ts, true, nil
}

// parseCronRuns reads `short-iso` journal output. Journal order is
// newest-first, so the first sighting of a command wins.
func parseCronRuns(out []byte) map[string]time.Time {
	runs := make(map[string]time.Time)
	for _, line := range strings.Split(string(out), "\n") {
		stamp, cmd, ok := parseCronCMDLine(line)
		if !ok {
			continue
		}
		if _, dup := runs[cmd]; dup {
			continue
		}
		runs[cmd] = stamp
	}
	return runs
}

// parseCronCMDLine splits one line of the shape
// `2026-10-08T18:25:01+07:00 host CRON[123]: (root) CMD (<command>)`.
func parseCronCMDLine(line string) (time.Time, string, bool) {
	const marker = " CMD ("
	i := strings.Index(line, marker)
	if i < 0 {
		return time.Time{}, "", false
	}
	rest := strings.TrimSpace(line[i+len(marker):])
	if !strings.HasSuffix(rest, ")") {
		return time.Time{}, "", false
	}
	cmd := strings.TrimSuffix(rest, ")")
	if cmd == "" {
		return time.Time{}, "", false
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return time.Time{}, "", false
	}
	stamp, err := time.Parse(time.RFC3339, fields[0])
	if err != nil {
		return time.Time{}, "", false
	}
	return stamp, cmd, true
}
