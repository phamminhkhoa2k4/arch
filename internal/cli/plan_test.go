package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"archaeologist/internal/cleanup"
	"archaeologist/internal/store"
)

// copyFixtureDB copies the committed lab fixture (plus any WAL files)
// into a temp dir so plan mutations never touch the tracked db.
func copyFixtureDB(t *testing.T) string {
	t.Helper()
	src := filepath.Join("..", "..", "lab", "fixtures", "scan.db")
	dst := filepath.Join(t.TempDir(), "scan.db")
	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.Create(dst)
	if err != nil {
		t.Fatalf("create copy: %v", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		t.Fatalf("copy fixture: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close copy: %v", err)
	}
	return dst
}

// runPlanRoot executes the plan command tree against a fixture db.
// labRules points at the lab rules file shipped with the fixture
// (observation window zero days matches the fixture's zero-day scan).
func labRules() string {
	return filepath.Join("..", "..", "lab", "rules.lab.yaml")
}

func runPlanRoot(t *testing.T, db string, out io.Writer, args ...string) error {
	t.Helper()
	root := &cobra.Command{Use: "archaeologist", SilenceUsage: true, SilenceErrors: true}
	root.SetOut(out)
	root.SetErr(out)
	root.AddCommand(newPlanCmd())
	root.SetArgs(append([]string{"plan"}, args...))
	return root.ExecuteContext(context.Background())
}

// A known-ORPHANED lab component gets a full six-stage plan: markdown plan document
// plus six numbered scripts, and nothing is executed.
func TestPlanGenerateOrphaned(t *testing.T) {
	db := copyFixtureDB(t)
	outDir := t.TempDir()
	var buf strings.Builder
	err := runPlanRoot(t, db, &buf, "lab-worker",
		"--db", db, "--out", outDir, "--rules-file", labRules())
	if err != nil {
		t.Fatalf("generate: %v\n%s", err, buf.String())
	}
	dir := filepath.Join(outDir, "container-lab-worker")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read plan dir: %v", err)
	}
	if len(entries) != 8 {
		t.Errorf("plan files = %d, want 8", len(entries))
	}
	for _, want := range []string{
		"plan.md", "plan.json", "01-candidate.sh", "02-quarantined.sh", "03-observed.sh",
		"04-archived.sh", "05-removed.sh", "06-verified.sh",
	} {
		if _, err := os.Stat(filepath.Join(dir, want)); err != nil {
			t.Errorf("missing %s: %v", want, err)
		}
	}
	body, err := os.ReadFile(filepath.Join(dir, "02-quarantined.sh"))
	if err != nil {
		t.Fatalf("read quarantine: %v", err)
	}
	if !strings.Contains(string(body), "# rollback:") {
		t.Error("quarantine script missing rollback marker")
	}
	if !strings.Contains(buf.String(), "no command is auto-executed") {
		t.Errorf("missing no-exec notice:\n%s", buf.String())
	}
}

// An ACTIVE component is refused with blocker-based guidance and the
// attention exit code.
func TestPlanRefuseActive(t *testing.T) {
	db := copyFixtureDB(t)
	var buf strings.Builder
	err := runPlanRoot(t, db, &buf, "lab-web", "--db", db, "--out", t.TempDir())
	if err == nil {
		t.Fatal("active refusal must return the attention error")
	}
	if got := exitCodeOf(err); got != ExitAttention {
		t.Errorf("exit code = %d, want %d", got, ExitAttention)
	}
	out := buf.String()
	if !strings.Contains(out, "No cleanup plan generated") || !strings.Contains(out, "ACTIVE") {
		t.Errorf("refusal message missing:\n%s", out)
	}
	if !strings.Contains(out, "remove the blockers") {
		t.Errorf("ACTIVE refusal must suggest removing blockers:\n%s", out)
	}
}

// status and confirm round-trip: out-of-order confirm fails, ordered
// confirms persist, and status reports the current stage.
func TestPlanStatusAndConfirm(t *testing.T) {
	db := copyFixtureDB(t)
	var buf strings.Builder
	if err := runPlanRoot(t, db, &buf, "lab-worker",
		"--db", db, "--out", t.TempDir(), "--rules-file", labRules()); err != nil {
		t.Fatalf("generate: %v", err)
	}

	buf.Reset()
	err := runPlanRoot(t, db, &buf, "confirm", "lab-worker", "Observed", "--db", db)
	if err == nil || err.Error() != "cannot confirm Observed: Candidate must be completed first" {
		t.Errorf("out-of-order confirm err = %v, want Candidate as the blocker", err)
	}

	buf.Reset()
	if err := runPlanRoot(t, db, &buf, "confirm", "lab-worker", "candidate",
		"--db", db); err != nil {
		t.Fatalf("confirm candidate: %v", err)
	}
	buf.Reset()
	if err := runPlanRoot(t, db, &buf, "confirm", "lab-worker", "quarantined", "--db", db); err != nil {
		t.Fatalf("confirm quarantined: %v", err)
	}

	buf.Reset()
	if err := runPlanRoot(t, db, &buf, "status", "lab-worker", "--db", db); err != nil {
		t.Fatalf("status: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "[✓] Candidate") || !strings.Contains(out, "[✓] Quarantined") {
		t.Errorf("status missing confirmed marks:\n%s", out)
	}
	if !strings.Contains(out, "Current stage: Observed") {
		t.Errorf("status current stage wrong:\n%s", out)
	}
}

// confirm before any plan exists fails with a generate hint.
func TestPlanConfirmWithoutPlan(t *testing.T) {
	db := copyFixtureDB(t)
	var buf strings.Builder
	err := runPlanRoot(t, db, &buf, "confirm", "lab-old-app", "Candidate", "--db", db)
	if err == nil || !strings.Contains(err.Error(), "plan") {
		t.Errorf("confirm without plan err = %v", err)
	}
}

// The generated Verified script greps for cleanup.GoneSignal to tell
// "the component is gone" (a pass) from "the command could not run"
// (a failure), because both exit with the execution-error code. The
// not-found error resolveComponent produces must keep carrying that
// exact substring, or the script would report a successful removal
// when the check actually failed.
func TestGoneSignalMatchesResolveError(t *testing.T) {
	db := copyFixtureDB(t)
	ctx := context.Background()
	st, err := store.Open(ctx, db)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	scanID, err := st.LatestScanID(ctx)
	if err != nil {
		t.Fatalf("latest scan: %v", err)
	}
	_, err = resolveComponent(ctx, st, scanID, "definitely-not-a-real-component")
	if err == nil {
		t.Fatal("resolveComponent must fail for an unknown component")
	}
	if !strings.Contains(err.Error(), cleanup.GoneSignal) {
		t.Errorf("resolveComponent error %q must contain cleanup.GoneSignal %q",
			err.Error(), cleanup.GoneSignal)
	}
}

// An untouched plan passes `plan check`.
func TestPlanCheckPasses(t *testing.T) {
	db := copyFixtureDB(t)
	outDir := t.TempDir()
	var buf strings.Builder
	if err := runPlanRoot(t, db, &buf, "lab-worker",
		"--db", db, "--out", outDir, "--rules-file", labRules()); err != nil {
		t.Fatalf("generate: %v", err)
	}

	buf.Reset()
	err := runPlanRoot(t, db, &buf, "check", "lab-worker",
		"--db", db, "--out", outDir, "--rules-file", labRules())
	if err != nil {
		t.Fatalf("check must pass on an untouched plan: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "match the manifest") {
		t.Errorf("check output missing the pass summary:\n%s", buf.String())
	}
}

// Editing a stage script after generation makes `plan check` fail with
// the attention exit code.
func TestPlanCheckDetectsTamperedScript(t *testing.T) {
	db := copyFixtureDB(t)
	outDir := t.TempDir()
	var buf strings.Builder
	if err := runPlanRoot(t, db, &buf, "lab-worker",
		"--db", db, "--out", outDir, "--rules-file", labRules()); err != nil {
		t.Fatalf("generate: %v", err)
	}

	path := filepath.Join(outDir, "container-lab-worker", "05-removed.sh")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}
	if err := os.WriteFile(path,
		append(body, []byte("\nrm -rf /important\n")...), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	buf.Reset()
	err = runPlanRoot(t, db, &buf, "check", "lab-worker",
		"--db", db, "--out", outDir, "--rules-file", labRules())
	if err == nil {
		t.Fatal("check must fail after a script is tampered with")
	}
	if got := exitCodeOf(err); got != ExitAttention {
		t.Errorf("exit code = %d, want %d", got, ExitAttention)
	}
	out := buf.String()
	if !strings.Contains(out, "NOT safe to run") || !strings.Contains(out, "05-removed.sh was modified") {
		t.Errorf("check output missing the tamper diagnostic:\n%s", out)
	}
}

// A plan generated under one rule set is refused by `plan check` when
// the rules no longer match, even though every script hash is intact.
func TestPlanCheckDetectsRulesChange(t *testing.T) {
	db := copyFixtureDB(t)
	outDir := t.TempDir()
	var buf strings.Builder
	if err := runPlanRoot(t, db, &buf, "lab-worker",
		"--db", db, "--out", outDir, "--rules-file", labRules()); err != nil {
		t.Fatalf("generate: %v", err)
	}

	buf.Reset()
	// Check with the embedded defaults instead of the lab override.
	err := runPlanRoot(t, db, &buf, "check", "lab-worker",
		"--db", db, "--out", outDir)
	if err == nil {
		t.Fatal("check must fail when the rules no longer match the manifest")
	}
	if !strings.Contains(buf.String(), "rules changed since generation") {
		t.Errorf("check output missing the rules diagnostic:\n%s", buf.String())
	}
}

// A component whose fingerprint changed since the plan was generated
// is flagged so the operator reviews the plan before acting. It is a
// warning rather than a hard failure: a rescan naturally refreshes some
// attributes, and the script hashes still pin the plan itself.
func TestPlanCheckWarnsOnFingerprintChange(t *testing.T) {
	db := copyFixtureDB(t)
	outDir := t.TempDir()
	var buf strings.Builder
	if err := runPlanRoot(t, db, &buf, "lab-worker",
		"--db", db, "--out", outDir, "--rules-file", labRules()); err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Rewrite the fingerprint recorded for the plan's component so the
	// latest scan no longer matches the manifest.
	ctx := context.Background()
	st, err := store.Open(ctx, db)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE entities SET fingerprint = 'changed-since-plan'
		 WHERE identity_key = (SELECT identity_key FROM entities
		                       WHERE scan_id = (SELECT max(id) FROM scans)
		                         AND name = 'lab-worker')`); err != nil {
		_ = st.Close()
		t.Fatalf("update fingerprint: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	buf.Reset()
	if err := runPlanRoot(t, db, &buf, "check", "lab-worker",
		"--db", db, "--out", outDir, "--rules-file", labRules()); err != nil {
		t.Fatalf("fingerprint drift must warn, not fail: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "changed since the plan was generated") {
		t.Errorf("check output missing the fingerprint warning:\n%s", buf.String())
	}
}

// A plan directory that was never generated reports a clear problem
// instead of a stack trace.
func TestPlanCheckWithoutGeneratedPlan(t *testing.T) {
	db := copyFixtureDB(t)
	var buf strings.Builder
	// Generate into one directory, then check against a different one
	// that was never written to.
	if err := runPlanRoot(t, db, &buf, "lab-worker",
		"--db", db, "--out", t.TempDir(), "--rules-file", labRules()); err != nil {
		t.Fatalf("generate: %v", err)
	}

	buf.Reset()
	err := runPlanRoot(t, db, &buf, "check", "lab-worker",
		"--db", db, "--out", t.TempDir(), "--rules-file", labRules())
	if err == nil {
		t.Fatal("check must fail when no plan directory exists")
	}
	if !strings.Contains(buf.String(), cleanup.ManifestFile) {
		t.Errorf("check output must name the missing manifest:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "NOT safe to run") {
		t.Errorf("check output must mark the plan unsafe:\n%s", buf.String())
	}
}
