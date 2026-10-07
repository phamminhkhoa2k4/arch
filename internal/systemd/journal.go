package systemd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Journal reads the newest journal line of one unit. Implementations:
// the journalctl exec runner and fakes in tests. A non-nil error means
// the journal could not be read — the collector reports one blind spot
// instead of guessing.
type Journal interface {
	// LastLine returns the timestamp and cursor of the unit's most
	// recent journal entry. ok=false means the unit has no entries.
	LastLine(ctx context.Context, unit string) (time.Time, string, bool, error)
}

// unitNameRE restricts the -u argument to characters systemd accepts,
// and never lets the value look like another flag (no leading dash).
// The value never reaches a shell (fixed argv), but validating keeps
// the fixed argv free of surprises.
var unitNameRE = regexp.MustCompile(`^[A-Za-z0-9@_.:][A-Za-z0-9@_.:\-]*$`)

// ValidUnitName reports whether name passes the unit-name guard for
// journalctl -u. systemd itself hands out dash-prefixed names (the root
// mount is "-.mount"); callers skip such units instead of treating the
// rejection as a journal read failure.
func ValidUnitName(name string) bool {
	return unitNameRE.MatchString(name)
}

// ExecJournal reads entries by running journalctl once per unit.
type ExecJournal struct{}

// NewExecJournal returns the journalctl-backed reader.
func NewExecJournal() *ExecJournal { return &ExecJournal{} }

// LastLine runs `journalctl -u <unit> -n 1 -o json --no-pager` and
// parses its single JSON line. Empty output means the unit never
// logged (ok=false, no error).
func (j *ExecJournal) LastLine(ctx context.Context, unit string) (time.Time, string, bool, error) {
	if !unitNameRE.MatchString(unit) {
		return time.Time{}, "", false, fmt.Errorf("journalctl: invalid unit name %q", unit)
	}
	cmd := exec.CommandContext(ctx, "journalctl",
		"-u", unit, "-n", "1", "-o", "json", "--no-pager")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return time.Time{}, "", false, fmt.Errorf("journalctl -u %s: %w: %s", unit, err, msg)
		}
		return time.Time{}, "", false, fmt.Errorf("journalctl -u %s: %w", unit, err)
	}
	return parseJournalLine(stdout.String())
}

// journalEntry is the subset of one -o json line we read.
type journalEntry struct {
	RealTimeMicros string `json:"__REALTIME_TIMESTAMP"`
	Cursor         string `json:"__CURSOR"`
}

// parseJournalLine reads one journalctl json line. Empty output means
// no entries; an unparseable line is an error, never a guess.
func parseJournalLine(out string) (time.Time, string, bool, error) {
	out = strings.TrimSpace(out)
	if out == "" {
		return time.Time{}, "", false, nil
	}
	var e journalEntry
	if err := json.Unmarshal([]byte(out), &e); err != nil {
		return time.Time{}, "", false, fmt.Errorf("parse journal entry: %w", err)
	}
	if e.RealTimeMicros == "" {
		return time.Time{}, "", false, errors.New("journal entry has no __REALTIME_TIMESTAMP")
	}
	micros, err := strconv.ParseInt(e.RealTimeMicros, 10, 64)
	if err != nil {
		return time.Time{}, "", false, fmt.Errorf("parse journal timestamp: %w", err)
	}
	ts := time.Unix(micros/1_000_000, (micros%1_000_000)*1000).UTC()
	return ts, e.Cursor, true, nil
}
