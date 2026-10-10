package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// delete-check --format json emits the published schema shape and the
// attention exit code for an orphan verdict.
func TestDeleteCheckJSONOutput(t *testing.T) {
	db := copyFixtureDB(t)
	root := rootCmd()
	addCommands(root)
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"delete-check", "lab-worker",
		"--db", db, "--rules-file", labRules(), "--format", "json"})
	execErr := root.ExecuteContext(context.Background())

	var out struct {
		State    string `json:"state"`
		Coverage string `json:"coverage"`
		ExitCode int    `json:"exit_code"`
		ScanID   int64  `json:"scan_id"`
		Kind     string `json:"kind"`
		Identity string `json:"identity"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("json parse: %v\n%s", err, buf.String())
	}
	if out.State != "ORPHANED" || out.ExitCode != 1 || out.Kind != "container" {
		t.Errorf("json = %+v", out)
	}
	if out.ScanID <= 0 || !strings.HasPrefix(out.Identity, "container|") {
		t.Errorf("json identity/scan = %+v", out)
	}
	if execErr == nil || exitCodeOf(execErr) != ExitAttention {
		t.Errorf("exit = %v, want attention", execErr)
	}
}

// An ACTIVE component exits 0 with exit_code 0 in JSON.
func TestDeleteCheckJSONActiveExitZero(t *testing.T) {
	db := copyFixtureDB(t)
	root := rootCmd()
	addCommands(root)
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"delete-check", "lab-web",
		"--db", db, "--rules-file", labRules(), "--format", "json"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("active delete-check: %v", err)
	}
	var out struct {
		State    string `json:"state"`
		ExitCode int    `json:"exit_code"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out.State != "ACTIVE" || out.ExitCode != 0 {
		t.Errorf("json = %+v, want ACTIVE/0", out)
	}
}

// explain --format json parses and carries the entity identity.
func TestExplainJSONOutput(t *testing.T) {
	db := copyFixtureDB(t)
	root := rootCmd()
	addCommands(root)
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"explain", "lab-worker", "--db", db, "--format", "json"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("explain: %v", err)
	}
	var out struct {
		Kind     string           `json:"kind"`
		Name     string           `json:"name"`
		Identity string           `json:"identity"`
		Evidence []map[string]any `json:"evidence"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("parse: %v\n%s", err, buf.String())
	}
	if out.Kind != "container" || out.Name != "lab-worker" || !strings.HasPrefix(out.Identity, "container|") {
		t.Errorf("explain json = %+v", out)
	}
}

// scan --format json on a synthetic small db: schema shape + verdict
// rollup keys present.
func TestScanJSONOutput(t *testing.T) {
	db := filepath.Join(t.TempDir(), "scan.db")
	root := rootCmd()
	addCommands(root)
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"scan", "--db", db, "--format", "json"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("scan: %v\n%s", err, buf.String())
	}
	var out struct {
		ScanID         int64          `json:"scan_id"`
		Status         string         `json:"status"`
		EntitiesByKind map[string]int `json:"entities_by_kind"`
		Verdict        map[string]int `json:"verdict"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("parse: %v\n%s", err, buf.String())
	}
	if out.ScanID <= 0 || len(out.EntitiesByKind) == 0 {
		t.Errorf("scan json = %+v", out)
	}
	if _, ok := out.Verdict["UNKNOWN"]; !ok && len(out.EntitiesByKind) > 0 {
		t.Errorf("verdict rollup missing: %v", out.Verdict)
	}
}

// Unknown --format values are rejected as execution errors.
func TestFormatFlagRejectsBogus(t *testing.T) {
	db := copyFixtureDB(t)
	root := rootCmd()
	addCommands(root)
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"delete-check", "lab-web", "--db", db, "--format", "xml"})
	err := root.ExecuteContext(context.Background())
	if err == nil || exitCodeOf(err) != ExitError {
		t.Errorf("bogus format err = %v, want exit 2", err)
	}
}

// Exit codes: ACTIVE → 0, orphan/unknown → 1, execution error → 2.
func TestDeleteCheckExitCodes(t *testing.T) {
	db := copyFixtureDB(t)
	run := func(args ...string) int {
		root := rootCmd()
		addCommands(root)
		var buf bytes.Buffer
		root.SetOut(&buf)
		root.SetErr(&buf)
		root.SetArgs(args)
		return exitCodeOf(root.ExecuteContext(context.Background()))
	}
	if got := run("delete-check", "lab-web", "--db", db, "--rules-file", labRules()); got != ExitOK {
		t.Errorf("ACTIVE exit = %d, want 0", got)
	}
	if got := run("delete-check", "lab-worker", "--db", db, "--rules-file", labRules()); got != ExitAttention {
		t.Errorf("ORPHANED exit = %d, want 1", got)
	}
	if got := run("delete-check", "khong-ton-tai", "--db", db, "--rules-file", labRules()); got != ExitError {
		t.Errorf("missing component exit = %d, want 2", got)
	}
}
