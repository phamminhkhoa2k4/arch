package cli

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"archaeologist/internal/store"
)

// fakeObserveProbe returns a fixed daemon state, standing in for the
// system bus in tests.
type fakeObserveProbe struct {
	state string
	err   error
}

func (f fakeObserveProbe) DaemonState(context.Context) (string, error) {
	return f.state, f.err
}

// observeStatusDB writes a database with one finished scan, optionally
// carrying one 30-day-old observation sample so the window is long
// enough to be sufficient.
func observeStatusDB(t *testing.T, withObservation bool) string {
	t.Helper()
	ctx := context.Background()
	db := filepath.Join(t.TempDir(), "observe.db")
	st, err := store.Open(ctx, db)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	host, err := st.InsertHost(ctx, "lab-host", "linux", "6.1")
	if err != nil {
		t.Fatalf("insert host: %v", err)
	}
	scan, err := st.InsertScan(ctx, host, "v0", "{}")
	if err != nil {
		t.Fatalf("insert scan: %v", err)
	}
	if withObservation {
		sink := store.NewScanSink(ctx, st, scan)
		mustEmitEntity(t, sink, "listener", "web", "listener|web")
		id := entityIDOf(t, st, scan, "listener|web")
		bucket := time.Now().UTC().AddDate(0, 0, -30).Format(time.RFC3339)
		latest := time.Now().UTC().Format(time.RFC3339)
		if err := st.UpsertObservation(ctx, id, "remote|1.2.3.4|443", bucket, latest); err != nil {
			t.Fatalf("insert observation: %v", err)
		}
	}
	if err := st.FinishScan(ctx, scan, "ok"); err != nil {
		t.Fatalf("finish scan: %v", err)
	}
	return db
}

// A fresh database cannot have a sufficient window: status reports how
// many days are still missing and that nothing was sampled yet.
func TestObserveStatusWindowProgress(t *testing.T) {
	db := observeStatusDB(t, false)
	probe := fakeObserveProbe{state: daemonActive}

	var sb strings.Builder
	if err := runObserveStatus(context.Background(), &sb, db, "", formatText, probe); err != nil {
		t.Fatalf("observe status: %v", err)
	}
	out := sb.String()
	want := []string{
		"Observation status",
		"daemon:       active (archaeologist-observe.service)",
		"scan:         #1",
		"window:       ",
		"required:     14 days",
		"window check: 14 days remaining — earliest sufficient date",
		"observations: none yet",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("status output missing %q:\n%s", w, out)
		}
	}
	if strings.Contains(out, "sufficient since") {
		t.Errorf("fresh database reported as sufficient:\n%s", out)
	}
}

// A long observation window is reported as sufficient, with the
// sample coverage summary.
func TestObserveStatusSufficientWindow(t *testing.T) {
	db := observeStatusDB(t, true)
	probe := fakeObserveProbe{state: daemonInactive}

	var sb strings.Builder
	if err := runObserveStatus(context.Background(), &sb, db, "", formatText, probe); err != nil {
		t.Fatalf("observe status: %v", err)
	}
	out := sb.String()
	if !strings.Contains(out, "daemon:       inactive") {
		t.Errorf("inactive daemon not reported:\n%s", out)
	}
	if !strings.Contains(out, "observe install-service") {
		t.Errorf("inactive daemon lacks a start hint:\n%s", out)
	}
	if !strings.Contains(out, "window check: sufficient since") {
		t.Errorf("sufficient window not reported:\n%s", out)
	}
	if strings.Contains(out, "days remaining") {
		t.Errorf("sufficient window still shows remaining days:\n%s", out)
	}
	if !strings.Contains(out, "observations: first") || !strings.Contains(out, "buckets") {
		t.Errorf("sample coverage missing:\n%s", out)
	}
}

// An unreachable systemd reports the unknown state with the reason,
// never failing the command.
func TestObserveStatusDaemonUnknown(t *testing.T) {
	db := observeStatusDB(t, false)
	probe := fakeObserveProbe{state: daemonUnknown, err: errFakeSystemd}

	var sb strings.Builder
	if err := runObserveStatus(context.Background(), &sb, db, "", formatText, probe); err != nil {
		t.Fatalf("observe status: %v", err)
	}
	out := sb.String()
	if !strings.Contains(out, "daemon:       unknown") {
		t.Errorf("unknown daemon not reported:\n%s", out)
	}
	if !strings.Contains(out, "systemd unreachable") || !strings.Contains(out, errFakeSystemd.Error()) {
		t.Errorf("unknown daemon lacks the reason:\n%s", out)
	}
}

// errFakeSystemd stands in for a system bus that is not there.
var errFakeSystemd = errors.New("connect system bus: no such socket")

// JSON output carries the window, the remaining days, and null sample
// times while nothing was sampled.
func TestObserveStatusJSON(t *testing.T) {
	db := observeStatusDB(t, false)
	probe := fakeObserveProbe{state: daemonActive}

	var sb strings.Builder
	if err := runObserveStatus(context.Background(), &sb, db, "", formatJSON, probe); err != nil {
		t.Fatalf("observe status: %v", err)
	}
	var doc observeStatusJSON
	if err := json.Unmarshal([]byte(sb.String()), &doc); err != nil {
		t.Fatalf("json parse: %v\noutput:\n%s", err, sb.String())
	}
	if doc.Daemon != daemonActive || doc.DaemonDetail != "" {
		t.Errorf("daemon = %q (%q), want active with empty detail", doc.Daemon, doc.DaemonDetail)
	}
	if doc.Unit != "archaeologist-observe.service" {
		t.Errorf("unit = %q", doc.Unit)
	}
	if doc.ScanID != 1 {
		t.Errorf("scan_id = %d, want 1", doc.ScanID)
	}
	if doc.WindowReady || doc.DaysRemaining != 14 || doc.RequiredDays != 14 {
		t.Errorf("window ready=%v remaining=%d required=%d, want false/14/14",
			doc.WindowReady, doc.DaysRemaining, doc.RequiredDays)
	}
	if doc.ReadyAt == nil {
		t.Error("ready_at is null; want the earliest sufficient date")
	}
	if doc.Observations.First != nil || doc.Observations.Latest != nil || doc.Observations.Buckets != 0 {
		t.Errorf("observations = %+v, want null/null/0", doc.Observations)
	}
}

// JSON output reports a sufficient window and the sample coverage
// when observations exist.
func TestObserveStatusJSONSufficient(t *testing.T) {
	db := observeStatusDB(t, true)
	probe := fakeObserveProbe{state: daemonInactive, err: nil}

	var sb strings.Builder
	if err := runObserveStatus(context.Background(), &sb, db, "", formatJSON, probe); err != nil {
		t.Fatalf("observe status: %v", err)
	}
	var doc observeStatusJSON
	if err := json.Unmarshal([]byte(sb.String()), &doc); err != nil {
		t.Fatalf("json parse: %v\noutput:\n%s", err, sb.String())
	}
	if !doc.WindowReady || doc.DaysRemaining != 0 {
		t.Errorf("window ready=%v remaining=%d, want true/0", doc.WindowReady, doc.DaysRemaining)
	}
	if doc.Observations.First == nil || doc.Observations.Latest == nil {
		t.Errorf("observations times = %v/%v, want both set", doc.Observations.First, doc.Observations.Latest)
	}
	if doc.Observations.Buckets != 1 {
		t.Errorf("buckets = %d, want 1", doc.Observations.Buckets)
	}
}

// A database without scans is an actionable error, not a crash.
func TestObserveStatusNoScans(t *testing.T) {
	db := filepath.Join(t.TempDir(), "fresh.db")
	probe := fakeObserveProbe{state: daemonInactive}
	var sb strings.Builder
	err := runObserveStatus(context.Background(), &sb, db, "", formatText, probe)
	if err == nil {
		t.Fatalf("expected an error, got:\n%s", sb.String())
	}
	if !strings.Contains(err.Error(), "no scans recorded") ||
		!strings.Contains(err.Error(), "scan") {
		t.Errorf("error not actionable: %v", err)
	}
}

// The observe command gains the status subcommand.
func TestObserveHelpListsStatus(t *testing.T) {
	out, err := runCLI(t, "observe", "--help")
	if err != nil {
		t.Fatalf("observe --help: %v", err)
	}
	for _, name := range []string{"status", "install-service", "uninstall-service"} {
		if !strings.Contains(out, name) {
			t.Errorf("observe --help missing %q:\n%s", name, out)
		}
	}
}
