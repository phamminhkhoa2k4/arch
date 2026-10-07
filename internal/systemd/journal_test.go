package systemd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseJournalLine(t *testing.T) {
	ts, cursor, ok, err := parseJournalLine(
		`{"__REALTIME_TIMESTAMP":"1760000000123456","__CURSOR":"s=abc;i=1"}` + "\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !ok {
		t.Fatal("ok = false, want true")
	}
	want := time.Unix(1760000000, 123456*1000).UTC()
	if !ts.Equal(want) {
		t.Errorf("ts = %v, want %v", ts, want)
	}
	if cursor != "s=abc;i=1" {
		t.Errorf("cursor = %q", cursor)
	}

	if _, _, ok, err := parseJournalLine("   \n"); err != nil || ok {
		t.Errorf("empty output = (ok=%v, err=%v), want (false, nil)", ok, err)
	}
	if _, _, _, err := parseJournalLine("{not json"); err == nil {
		t.Error("invalid json: want error")
	}
	if _, _, _, err := parseJournalLine(`{"__CURSOR":"c"}`); err == nil {
		t.Error("missing timestamp: want error")
	}
	if _, _, _, err := parseJournalLine(`{"__REALTIME_TIMESTAMP":"abc"}`); err == nil {
		t.Error("non-numeric timestamp: want error")
	}
}

// The -u value must match the unit-name charset before any exec.
func TestExecJournalRejectsInvalidUnitName(t *testing.T) {
	j := NewExecJournal()
	for _, unit := range []string{"x;rm -rf /", "a b", "-o", "$(reboot)", ""} {
		_, _, _, err := j.LastLine(context.Background(), unit)
		if err == nil || !strings.Contains(err.Error(), "invalid unit name") {
			t.Errorf("unit %q: err = %v, want invalid unit name", unit, err)
		}
	}
}

// ValidUnitName mirrors the -u guard for callers that skip such units
// instead of receiving an error. The root mount "-.mount" is a real
// systemd name but starts with a dash.
func TestValidUnitName(t *testing.T) {
	for _, unit := range []string{
		"lab-app.service", "session-2.scope", "dev-sda1.device", "user@1000.service",
	} {
		if !ValidUnitName(unit) {
			t.Errorf("%q: want valid", unit)
		}
	}
	for _, unit := range []string{"-.mount", "x;rm -rf /", "-o", ""} {
		if ValidUnitName(unit) {
			t.Errorf("%q: want invalid", unit)
		}
	}
}

// ExecJournal runs journalctl with the fixed argv and parses its json
// line. A stub journalctl on PATH records exactly what was executed.
func TestExecJournalRunsJournalctl(t *testing.T) {
	dir := t.TempDir()
	script := `#!/bin/sh
if [ "$*" != "-u lab-app.service -n 1 -o json --no-pager" ]; then
	echo "unexpected args: $*" >&2
	exit 2
fi
echo '{"__REALTIME_TIMESTAMP":"1760000000123456","__CURSOR":"c1"}'
`
	if err := os.WriteFile(filepath.Join(dir, "journalctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	j := NewExecJournal()
	ts, cursor, ok, err := j.LastLine(context.Background(), "lab-app.service")
	if err != nil {
		t.Fatalf("last line: %v", err)
	}
	if !ok || cursor != "c1" {
		t.Errorf("got (ok=%v, cursor=%q)", ok, cursor)
	}
	if ts.IsZero() {
		t.Error("timestamp must be set")
	}
}

// A failing journalctl surfaces stderr, never a silent zero time.
func TestExecJournalReportsCommandError(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\necho 'Permission denied' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "journalctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	j := NewExecJournal()
	_, _, _, err := j.LastLine(context.Background(), "lab-app.service")
	if err == nil {
		t.Fatal("want error from failing journalctl")
	}
	if !strings.Contains(err.Error(), "Permission denied") {
		t.Errorf("err = %v, want stderr included", err)
	}
}
