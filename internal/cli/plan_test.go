package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
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
	if len(entries) != 7 {
		t.Errorf("plan files = %d, want 7", len(entries))
	}
	for _, want := range []string{
		"plan.md", "01-candidate.sh", "02-quarantined.sh", "03-observed.sh",
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
