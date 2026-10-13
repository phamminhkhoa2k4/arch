package cli

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"archaeologist/internal/collector"
	"archaeologist/internal/store"
	"archaeologist/internal/verdict"
)

// `scan` runs the real collectors against this host's /proc
// (read-only) and records a scan row with entities — no stub anymore.
func TestScanRunsAgainstHostProc(t *testing.T) {
	root := rootCmd()
	addCommands(root)
	db := filepath.Join(t.TempDir(), "scan.db")
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"scan", "--db", db})

	if err := root.Execute(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "status=") || !strings.Contains(out, "blind spots:") ||
		!strings.Contains(out, "findings:") {
		t.Errorf("summary missing fields:\n%s", out)
	}

	st, err := store.Open(context.Background(), db)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer func() { _ = st.Close() }()

	var scans, entities int
	var status string
	ctx := context.Background()
	if err := st.DB().QueryRowContext(ctx,
		`SELECT count(*), min(status) FROM scans`).Scan(&scans, &status); err != nil {
		t.Fatalf("query scans: %v", err)
	}
	if scans != 1 || (status != "ok" && status != "partial") {
		t.Errorf("scans=%d status=%q, want 1 scan with ok/partial", scans, status)
	}
	if err := st.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM entities`).Scan(&entities); err != nil {
		t.Fatalf("query entities: %v", err)
	}
	if entities == 0 {
		t.Error("scan emitted no process entities — /proc walk failed")
	}
}

// All probes available → the exact success line is printed.
func TestDoctorAllSourcesAvailable(t *testing.T) {
	buf := new(bytes.Buffer)
	ok := runDoctor(buf, []doctorCheck{
		{pass: "A", run: func() error { return nil }},
		{pass: "B", run: func() error { return nil }},
	})
	if !ok {
		t.Error("runDoctor must report available")
	}
	if !strings.Contains(buf.String(), "✅ All sources available") {
		t.Errorf("missing success line:\n%s", buf.String())
	}
}

// Non-root output lists each gap with a remediation hint.
func TestDoctorListsGapsWithHints(t *testing.T) {
	buf := new(bytes.Buffer)
	ok := runDoctor(buf, []doctorCheck{
		{
			fail: "Cannot read other users' processes",
			hint: "run with sudo/root",
			run:  func() error { return errDenied },
		},
		{
			fail: "Cannot access the Docker socket",
			hint: "sudo usermod -aG docker $USER",
			run:  func() error { return errDenied },
		},
		{
			pass: "Log paths (/var/log)",
			run:  func() error { return nil },
		},
	})
	if ok {
		t.Error("runDoctor must report gaps")
	}
	out := buf.String()
	for _, want := range []string{
		"Cannot read other users' processes",
		"Cannot access the Docker socket",
		"Hint: run with sudo/root",
		"Hint: sudo usermod -aG docker $USER",
		"✓ Log paths",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "✅ All sources available") {
		t.Errorf("success line must not appear when gaps exist:\n%s", out)
	}
}

// errDenied simulates a permission failure without touching the system.
var errDenied = errors.New("permission denied")

// Scan-time verdict rollup persists one verdict per entity and the
// counts add up; spot-checks match delete-check semantics under the
// embedded rules: deterministic in-use evidence → ACTIVE, no evidence
// at all → UNKNOWN (no blockers, coverage LOW).
func TestComputeAndSaveVerdicts(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rollup.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = st.Close() }()
	host, err := st.InsertHost(ctx, "h", "linux", "k")
	if err != nil {
		t.Fatal(err)
	}
	scanID, err := st.InsertScan(ctx, host, "v", "{}")
	if err != nil {
		t.Fatal(err)
	}
	k := store.NewScanSink(ctx, st, scanID)
	if err := k.UpsertEntity(collector.Entity{
		Kind: "container", Name: "used", IdentityKey: "container|used",
		Fingerprint: "f1",
		Attributes:  map[string]string{"state": "running"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := k.UpsertEntity(collector.Entity{
		Kind: "container", Name: "quiet", IdentityKey: "container|quiet",
		Fingerprint: "f2",
		Attributes:  map[string]string{"state": "exited"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := k.AddEvidence(collector.Evidence{
		EntityIdentityKey: "container|used", Polarity: "in_use",
		Channel: "docker", Strength: "deterministic",
		ObservedAt: time.Now().UTC().Format(time.RFC3339),
		RawRef:     "docker inspect used",
		Value:      map[string]string{"container_id": "abc"},
	}); err != nil {
		t.Fatalf("evidence: %v", err)
	}
	// An inbound connection inside the window is a hard blocker (B2),
	// which is what flips the verdict to ACTIVE.
	usedEnt, err := st.FindEntities(ctx, scanID, "container|used")
	if err != nil || len(usedEnt) != 1 {
		t.Fatalf("find used: %v %v", usedEnt, err)
	}
	if err := st.UpsertObservation(ctx, usedEnt[0].ID, "10.0.0.9:443",
		time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("observation: %v", err)
	}

	rollup, err := computeAndSaveVerdicts(ctx, st, scanID)
	if err != nil {
		t.Fatalf("rollup: %v", err)
	}
	total := 0
	for _, n := range rollup {
		total += n
	}
	if total != 2 {
		t.Errorf("rollup total = %d, want 2 (%v)", total, rollup)
	}
	checks := map[string]string{
		"container|used":  verdict.StateActive,
		"container|quiet": verdict.StateUnknown,
	}
	for key, want := range checks {
		found, err := st.FindEntities(ctx, scanID, key)
		if err != nil || len(found) != 1 {
			t.Fatalf("find %s: %v %v", key, found, err)
		}
		rec, err := st.VerdictFor(ctx, found[0].ID, scanID)
		if err != nil {
			t.Fatalf("verdict %s: %v", key, err)
		}
		if rec.State != want {
			t.Errorf("%s state = %s, want %s", key, rec.State, want)
		}
	}
}

// The summary verdict line lists all four states with counts.
func TestFormatVerdictRollup(t *testing.T) {
	line := formatVerdictRollup(map[string]int{
		verdict.StateActive: 14, verdict.StateUnknown: 5,
		verdict.StateLikelyOrphaned: 1, verdict.StateOrphaned: 3,
	})
	for _, want := range []string{
		"active 14", "unknown 5", "likely-orphaned 1", "orphaned 3",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("rollup line %q missing %q", line, want)
		}
	}
}
