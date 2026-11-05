package cli

import (
	"context"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"archaeologist/internal/collector"
	"archaeologist/internal/store"
	"archaeologist/internal/verdict"
)

// mustEmitEntity writes one entity through the scan sink.
func mustEmitEntity(t *testing.T, sink *store.ScanSink, kind, name, key string) {
	t.Helper()
	err := sink.UpsertEntity(collector.Entity{
		Kind:        kind,
		Name:        name,
		IdentityKey: key,
		Fingerprint: "fp-" + key,
	})
	if err != nil {
		t.Fatalf("emit entity %s: %v", key, err)
	}
}

// entityIDOf resolves one identity key inside a scan.
func entityIDOf(t *testing.T, st *store.Store, scanID int64, key string) int64 {
	t.Helper()
	ents, err := st.EntitiesInScan(context.Background(), scanID)
	if err != nil {
		t.Fatalf("entities of scan %d: %v", scanID, err)
	}
	for _, e := range ents {
		if e.IdentityKey == key {
			return e.ID
		}
	}
	t.Fatalf("entity %q not in scan %d", key, scanID)
	return 0
}

// scanHistoryFixture writes two scans that differ the way a real
// re-scan would: two entities added, one gone, a blocker swap on a
// shared unit, a coverage/verdict flip on a shared process, and a blind
// spot only the second scan recorded.
func scanHistoryFixture(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	db := filepath.Join(t.TempDir(), "scan.db")
	st, err := store.Open(ctx, db)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	host, err := st.InsertHost(ctx, "lab-host", "linux", "6.1")
	if err != nil {
		t.Fatalf("insert host: %v", err)
	}
	from, err := st.InsertScan(ctx, host, "v0", "{}")
	if err != nil {
		t.Fatalf("insert scan 1: %v", err)
	}
	sinkFrom := store.NewScanSink(ctx, st, from)
	mustEmitEntity(t, sinkFrom, "process", "keep-me", "process:keep-me")
	mustEmitEntity(t, sinkFrom, "systemd_unit", "web", "systemd_unit:web")
	mustEmitEntity(t, sinkFrom, "container", "old-worker", "container:old-worker")
	if err := sinkFrom.AddBlindSpot(collector.BlindSpot{
		Channel: "docker", Reason: "daemon_unreachable",
	}); err != nil {
		t.Fatalf("blind spot: %v", err)
	}
	if err := st.FinishScan(ctx, from, "ok"); err != nil {
		t.Fatalf("finish scan 1: %v", err)
	}

	to, err := st.InsertScan(ctx, host, "v0", "{}")
	if err != nil {
		t.Fatalf("insert scan 2: %v", err)
	}
	sinkTo := store.NewScanSink(ctx, st, to)
	mustEmitEntity(t, sinkTo, "process", "keep-me", "process:keep-me")
	mustEmitEntity(t, sinkTo, "systemd_unit", "web", "systemd_unit:web")
	mustEmitEntity(t, sinkTo, "script", "new-job-a", "script:new-job-a")
	mustEmitEntity(t, sinkTo, "script", "new-job-b", "script:new-job-b")
	if err := sinkTo.AddBlindSpot(collector.BlindSpot{
		Channel: "docker", Reason: "daemon_unreachable",
	}); err != nil {
		t.Fatalf("blind spot docker: %v", err)
	}
	if err := sinkTo.AddBlindSpot(collector.BlindSpot{
		Channel: "cron", Reason: "crontab_unreadable",
	}); err != nil {
		t.Fatalf("blind spot cron: %v", err)
	}
	if err := st.FinishScan(ctx, to, "ok"); err != nil {
		t.Fatalf("finish scan 2: %v", err)
	}

	// Shared entities change the way an operator would expect: the
	// process loses its blocker and flips to orphaned, the unit swaps
	// one blocker for another and its coverage drops.
	saveVerdict(t, st, from, "process:keep-me", store.VerdictRecord{
		State:     verdict.StateUnknown,
		Coverage:  "LOW",
		Blockers:  []verdict.Item{{Code: "B1", Text: "referenced by cron job"}},
		RulesHash: "rules-1",
	})
	saveVerdict(t, st, from, "systemd_unit:web", store.VerdictRecord{
		State:     verdict.StateActive,
		Coverage:  "HIGH",
		Blockers:  []verdict.Item{{Code: "B2", Text: "systemd unit in use"}},
		RulesHash: "rules-1",
	})
	saveVerdict(t, st, to, "process:keep-me", store.VerdictRecord{
		State:     verdict.StateOrphaned,
		Coverage:  "HIGH",
		RulesHash: "rules-1",
	})
	saveVerdict(t, st, to, "systemd_unit:web", store.VerdictRecord{
		State:     verdict.StateActive,
		Coverage:  "LOW",
		Blockers:  []verdict.Item{{Code: "B6", Text: "listens on :8080"}},
		RulesHash: "rules-1",
	})
	return db
}

// saveVerdict stores a verdict row for one entity of one scan.
func saveVerdict(t *testing.T, st *store.Store, scanID int64, key string, rec store.VerdictRecord) {
	t.Helper()
	rec.EntityID = entityIDOf(t, st, scanID, key)
	rec.ScanID = scanID
	rec.ComputedAt = "2026-10-07T20:00:00Z"
	if err := st.UpsertVerdict(context.Background(), rec); err != nil {
		t.Fatalf("upsert verdict %s: %v", key, err)
	}
}

// scan list prints one table row per recorded scan; a database without
// verdicts shows "-" in the verdict column instead of a rollup.
func TestScanListFixtureDB(t *testing.T) {
	db := copyFixtureDB(t)
	out, err := runCLI(t, "scan", "list", "--db", db)
	if err != nil {
		t.Fatalf("scan list: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Entities") || !strings.Contains(out, "Findings") ||
		!strings.Contains(out, "Verdict") {
		t.Errorf("table header missing:\n%s", out)
	}
	rows := []*regexp.Regexp{
		regexp.MustCompile(`(?m)^  2\s+2026-10-07T20:50:21Z\s+ok\s+1025\s+\d+\s+\d+\s+-$`),
		regexp.MustCompile(`(?m)^  1\s+2026-10-07T20:48:47Z\s+ok\s+1025\s+\d+\s+\d+\s+-$`),
	}
	for _, re := range rows {
		if !re.MatchString(out) {
			t.Errorf("row %s missing:\n%s", re, out)
		}
	}
	if strings.Contains(out, "active 0") {
		t.Errorf("empty verdict rollup printed instead of '-':\n%s", out)
	}
}

// scan list shows each scan's verdict rollup when verdicts exist.
func TestScanListShowsVerdictRollup(t *testing.T) {
	db := scanHistoryFixture(t)
	out, err := runCLI(t, "scan", "list", "--db", db)
	if err != nil {
		t.Fatalf("scan list: %v\n%s", err, out)
	}
	if !regexp.MustCompile(`(?m)^  2\s+\S+\s+ok\s+4\s+2\s+0\s+active 1`).MatchString(out) {
		t.Errorf("scan 2 row with rollup missing:\n%s", out)
	}
	if !regexp.MustCompile(`(?m)^  1\s+\S+\s+ok\s+3\s+1\s+0\s+active 1 · unknown 1`).MatchString(out) {
		t.Errorf("scan 1 row with rollup missing:\n%s", out)
	}
}

// An empty database lists nothing and points at the scan command.
func TestScanListEmpty(t *testing.T) {
	db := filepath.Join(t.TempDir(), "empty.db")
	out, err := runCLI(t, "scan", "list", "--db", db)
	if err != nil {
		t.Fatalf("scan list: %v\n%s", err, out)
	}
	if !strings.Contains(out, "no scans recorded") {
		t.Errorf("empty-database message missing:\n%s", out)
	}
}

// unfinishedScanDB writes a database whose only scan row never reached
// FinishScan, so it carries the status default with a null finish time.
func unfinishedScanDB(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	db := filepath.Join(t.TempDir(), "scan.db")
	st, err := store.Open(ctx, db)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	host, err := st.InsertHost(ctx, "lab-host", "linux", "6.1")
	if err != nil {
		t.Fatalf("insert host: %v", err)
	}
	if _, err := st.InsertScan(ctx, host, "v0", "{}"); err != nil {
		t.Fatalf("insert scan: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	return db
}

// A scan row that never finished is reported as incomplete instead of
// the status default it carries in the database.
func TestScanListIncompleteScan(t *testing.T) {
	db := unfinishedScanDB(t)
	out, err := runCLI(t, "scan", "list", "--db", db)
	if err != nil {
		t.Fatalf("scan list: %v\n%s", err, out)
	}
	re := regexp.MustCompile(`(?m)^  1\s+\S+\s+incomplete\s+0\s+0\s+0\s+-$`)
	if !re.MatchString(out) {
		t.Errorf("incomplete row missing:\n%s", out)
	}
}

// scan diff reports every roadmap section: entities, blockers, blind
// spots, coverage and verdict changes.
func TestScanDiffSections(t *testing.T) {
	db := scanHistoryFixture(t)
	out, err := runCLI(t, "scan", "diff", "1", "2", "--db", db)
	if err != nil {
		t.Fatalf("scan diff: %v\n%s", err, out)
	}
	want := []string{
		"Scan #1 → #2",
		"entities: 3 → 4 (+1)",
		"container: 1 → 0 (-1)",
		"script: 0 → 2 (+2)",
		"added (2):",
		"+ [script] new-job-a",
		"+ [script] new-job-b",
		"removed (1):",
		"- [container] old-worker",
		"blockers: 2 → 1 (-1)",
		"new blockers (1):",
		"+ [systemd_unit] web: B6 — listens on :8080",
		"gone blockers (2):",
		"- [process] keep-me: B1 — referenced by cron job",
		"- [systemd_unit] web: B2 — systemd unit in use",
		"blind spots: 1 → 2 (+1)",
		"new blind spots (1):",
		"+ cron/crontab_unreadable (host)",
		"coverage: HIGH 1 → 1 · MEDIUM 0 → 0 · LOW 1 → 1",
		"coverage changes (2):",
		"[process] keep-me: LOW → HIGH",
		"[systemd_unit] web: HIGH → LOW",
		"verdict: active 1 → 1 · unknown 1 → 0 · likely-orphaned 0 → 0 · orphaned 0 → 1",
		"verdict changes (1):",
		"[process] keep-me: UNKNOWN → ORPHANED",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("diff output missing %q:\n%s", w, out)
		}
	}
	if strings.Contains(out, "gone blind spots") {
		t.Errorf("section with nothing to report printed:\n%s", out)
	}
	header := regexp.MustCompile(`(?m)^  from: \S+ status=ok host=lab-host$`)
	if !header.MatchString(out) {
		t.Errorf("from header missing:\n%s", out)
	}
}

// --limit truncates each change list and says how much is hidden;
// zero shows everything.
func TestScanDiffLimit(t *testing.T) {
	db := scanHistoryFixture(t)

	out, err := runCLI(t, "scan", "diff", "1", "2", "--db", db, "--limit", "1")
	if err != nil {
		t.Fatalf("scan diff --limit 1: %v\n%s", err, out)
	}
	if !strings.Contains(out, "+ [script] new-job-a") ||
		strings.Contains(out, "+ [script] new-job-b") {
		t.Errorf("limit 1 did not cut the added list:\n%s", out)
	}
	if !strings.Contains(out, "… and 1 more (raise --limit to see them)") {
		t.Errorf("truncation note missing:\n%s", out)
	}

	full, err := runCLI(t, "scan", "diff", "1", "2", "--db", db, "--limit", "0")
	if err != nil {
		t.Fatalf("scan diff --limit 0: %v\n%s", err, full)
	}
	if !strings.Contains(full, "+ [script] new-job-b") {
		t.Errorf("limit 0 hid a change:\n%s", full)
	}
	if strings.Contains(full, "more (raise --limit") {
		t.Errorf("limit 0 still truncated:\n%s", full)
	}
}

// An unknown scan id is an execution error that points at scan list.
func TestScanDiffUnknownScan(t *testing.T) {
	db := scanHistoryFixture(t)
	out, err := runCLI(t, "scan", "diff", "1", "99", "--db", db)
	if err == nil {
		t.Fatalf("expected an error, got:\n%s", out)
	}
	if exitCodeOf(err) != ExitError {
		t.Errorf("exit = %d, want %d", exitCodeOf(err), ExitError)
	}
	if !strings.Contains(err.Error(), "not recorded") ||
		!strings.Contains(err.Error(), "scan list") {
		t.Errorf("error not actionable: %v", err)
	}
}

// Malformed scan ids and a negative limit are rejected before any
// database work.
func TestScanDiffBadArguments(t *testing.T) {
	db := scanHistoryFixture(t)
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"scan", "diff", "abc", "2", "--db", db}, `scan id "abc": want a positive number`},
		{[]string{"scan", "diff", "1", "2", "--db", db, "--limit", "-1"}, "--limit must be >= 0"},
	}
	for _, tc := range cases {
		out, err := runCLI(t, tc.args...)
		if err == nil {
			t.Errorf("%v: expected an error, got:\n%s", tc.args, out)
			continue
		}
		if exitCodeOf(err) != ExitError {
			t.Errorf("%v: exit = %d, want %d", tc.args, exitCodeOf(err), ExitError)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: error = %v, want %q", tc.args, err, tc.want)
		}
	}
}

// The scan command keeps its own run behaviour and gains the two
// history subcommands.
func TestScanHelpListsHistorySubcommands(t *testing.T) {
	out, err := runCLI(t, "scan", "--help")
	if err != nil {
		t.Fatalf("scan --help: %v", err)
	}
	for _, name := range []string{"list", "diff"} {
		if !strings.Contains(out, name) {
			t.Errorf("scan --help missing %q:\n%s", name, out)
		}
	}
}

// decodeScanList parses `scan list --format json` into its payload.
func decodeScanList(t *testing.T, out string) scanListJSON {
	t.Helper()
	var doc scanListJSON
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("json parse: %v\noutput:\n%s", err, out)
	}
	return doc
}

// JSON output reports an unfinished scan with a null finish time and
// the incomplete status, not the status default it carries in the row.
func TestScanListJSONIncompleteScan(t *testing.T) {
	db := unfinishedScanDB(t)
	out, err := runCLI(t, "scan", "list", "--db", db, "--format", "json")
	if err != nil {
		t.Fatalf("scan list: %v\n%s", err, out)
	}
	doc := decodeScanList(t, out)
	if len(doc.Scans) != 1 {
		t.Fatalf("scans = %d, want 1:\n%s", len(doc.Scans), out)
	}
	row := doc.Scans[0]
	if row.FinishedAt != nil {
		t.Errorf("finished_at = %q, want null", *row.FinishedAt)
	}
	if row.Status != "incomplete" {
		t.Errorf("status = %q, want incomplete", row.Status)
	}
	if row.Verdict != nil {
		t.Errorf("verdict = %v, want null when no verdicts exist", row.Verdict)
	}
}

// JSON output carries the full verdict rollup with every state key
// when verdicts were computed.
func TestScanListJSONVerdictRollup(t *testing.T) {
	db := scanHistoryFixture(t)
	out, err := runCLI(t, "scan", "list", "--db", db, "--format", "json")
	if err != nil {
		t.Fatalf("scan list: %v\n%s", err, out)
	}
	doc := decodeScanList(t, out)
	if len(doc.Scans) != 2 {
		t.Fatalf("scans = %d, want 2:\n%s", len(doc.Scans), out)
	}
	// Newest first: scan 2 has one ACTIVE and one ORPHANED verdict.
	for _, key := range rollupKeys {
		if _, ok := doc.Scans[0].Verdict[key]; !ok {
			t.Errorf("verdict object missing key %q: %v", key, doc.Scans[0].Verdict)
		}
	}
	if doc.Scans[0].Verdict[verdict.StateOrphaned] != 1 {
		t.Errorf("orphaned = %d, want 1: %v",
			doc.Scans[0].Verdict[verdict.StateOrphaned], doc.Scans[0].Verdict)
	}
}

// JSON output is never capped by --limit, which only shapes the text
// view.
func TestScanDiffJSONNotCappedByLimit(t *testing.T) {
	db := scanHistoryFixture(t)
	out, err := runCLI(t, "scan", "diff", "1", "2", "--db", db,
		"--limit", "1", "--format", "json")
	if err != nil {
		t.Fatalf("scan diff: %v\n%s", err, out)
	}
	var doc diffJSON
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("json parse: %v\noutput:\n%s", err, out)
	}
	if len(doc.Entities.Added) != 2 {
		t.Errorf("added = %d, want 2 (the text limit must not apply):\n%s",
			len(doc.Entities.Added), out)
	}
	if strings.Contains(out, "raise --limit") {
		t.Errorf("JSON output carries a text truncation note:\n%s", out)
	}
	if len(doc.Verdict.Changes) != 1 {
		t.Errorf("verdict changes = %d, want 1:\n%s", len(doc.Verdict.Changes), out)
	}
}
