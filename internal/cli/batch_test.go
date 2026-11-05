package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// componentsFixture is the shipped lab database (copied), whose latest
// scan has 1025 components and no stored verdicts.
func componentsFixture(t *testing.T) string {
	t.Helper()
	return copyFixtureDB(t)
}

// components --kind narrows the list to one kind and shows every
// matching row without a truncation note.
func TestComponentsFilterKind(t *testing.T) {
	db := componentsFixture(t)
	out, err := runCLI(t, "components", "--db", db, "--kind", "nginx_route")
	if err != nil {
		t.Fatalf("components: %v\n%s", err, out)
	}
	for _, want := range []string{"/web/", "/dead/", "/pool/", "nginx_route"} {
		if !strings.Contains(out, want) {
			t.Errorf("components output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "more (raise --limit") {
		t.Errorf("six routes should not be truncated:\n%s", out)
	}
}

// components --state filters on the stored verdict state; a fixture
// without verdicts has no ACTIVE component.
func TestComponentsFilterState(t *testing.T) {
	db := componentsFixture(t)
	out, err := runCLI(t, "components", "--db", db, "--state", "ACTIVE")
	if err != nil {
		t.Fatalf("components: %v\n%s", err, out)
	}
	if !strings.Contains(out, "no components in scan") {
		t.Errorf("ACTIVE filter should match nothing in the fixture:\n%s", out)
	}
}

// components caps the text list at --limit and says how much is hidden.
func TestComponentsLimit(t *testing.T) {
	db := componentsFixture(t)
	out, err := runCLI(t, "components", "--db", db, "--limit", "1")
	if err != nil {
		t.Fatalf("components: %v\n%s", err, out)
	}
	if !strings.Contains(out, "… and 1024 more (raise --limit to see them)") {
		t.Errorf("truncation note missing or wrong:\n%s", out)
	}
}

// components --format json carries every component, including those
// without a stored verdict (reported as UNKNOWN with empty coverage).
func TestComponentsJSON(t *testing.T) {
	db := componentsFixture(t)
	out, err := runCLI(t, "components", "--db", db, "--format", "json")
	if err != nil {
		t.Fatalf("components: %v\n%s", err, out)
	}
	var doc struct {
		ScanID     int64 `json:"scan_id"`
		Components []struct {
			Kind         string `json:"kind"`
			VerdictState string `json:"verdict_state"`
			Coverage     string `json:"coverage"`
		} `json:"components"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("json parse: %v\n%s", err, out)
	}
	if doc.ScanID != 2 {
		t.Errorf("scan_id = %d, want 2", doc.ScanID)
	}
	if len(doc.Components) != 1025 {
		t.Errorf("components = %d, want 1025", len(doc.Components))
	}
	for _, c := range doc.Components {
		if c.VerdictState != "UNKNOWN" || c.Coverage != "" {
			t.Errorf("component = %+v, want UNKNOWN/empty (no stored verdicts)", c)
			break
		}
	}
}

// delete-check --all returns an aggregate exit code of 1 when any
// component needs attention, and never aborts the batch.
func TestDeleteCheckAllAggregateExitCode(t *testing.T) {
	db := componentsFixture(t)
	out, err := runCLI(t, "delete-check", "--all", "--db", db)
	if err == nil {
		t.Fatalf("expected attention error, got:\n%s", out)
	}
	if exitCodeOf(err) != ExitAttention {
		t.Errorf("exit = %d, want %d (ExitAttention)", exitCodeOf(err), ExitAttention)
	}
	if !strings.Contains(out, "summary:") || !strings.Contains(out, "errors (exit 1)") {
		t.Errorf("summary line missing:\n%s", out)
	}
}

// delete-check --all --kind scopes the batch and --format json reports
// the per-component results and the aggregate summary.
func TestDeleteCheckAllJSON(t *testing.T) {
	db := componentsFixture(t)
	out, _ := runCLI(t, "delete-check", "--all", "--kind", "nginx_route", "--db", db, "--format", "json")
	var doc struct {
		ScanID  int64 `json:"scan_id"`
		Summary struct {
			Total     int `json:"total"`
			Attention int `json:"attention"`
			Errors    int `json:"errors"`
			ExitCode  int `json:"exit_code"`
		} `json:"summary"`
		Results []struct {
			Kind     string `json:"kind"`
			ExitCode int    `json:"exit_code"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("json parse: %v\noutput:\n%s", err, out)
	}
	if doc.Summary.Total != 6 || doc.Summary.Errors != 0 {
		t.Errorf("summary = %+v, want total 6 errors 0", doc.Summary)
	}
	if doc.Summary.ExitCode != 1 {
		t.Errorf("exit_code = %d, want 1", doc.Summary.ExitCode)
	}
	if len(doc.Results) != 6 {
		t.Errorf("results = %d, want 6", len(doc.Results))
	}
	for _, r := range doc.Results {
		if r.Kind != "nginx_route" {
			t.Errorf("result kind = %q, want nginx_route", r.Kind)
		}
	}
}

// An empty filter set is clean: no attention, exit 0.
func TestDeleteCheckAllEmptyFilter(t *testing.T) {
	db := componentsFixture(t)
	out, err := runCLI(t, "delete-check", "--all", "--kind", "no_such_kind", "--db", db)
	if err != nil {
		t.Fatalf("expected clean exit, got %v:\n%s", err, out)
	}
	if !strings.Contains(out, "no components in scan") {
		t.Errorf("empty-set message missing:\n%s", out)
	}
}

// Both new commands appear in the help.
func TestComponentsAndBatchInHelp(t *testing.T) {
	out, err := runCLI(t, "--help")
	if err != nil {
		t.Fatalf("--help: %v", err)
	}
	for _, name := range []string{"components", "delete-check"} {
		if !strings.Contains(out, name) {
			t.Errorf("root help missing %q:\n%s", name, out)
		}
	}
	help, err := runCLI(t, "delete-check", "--help")
	if err != nil {
		t.Fatalf("delete-check --help: %v", err)
	}
	if !strings.Contains(help, "--all") {
		t.Errorf("delete-check --help missing --all:\n%s", help)
	}
}
