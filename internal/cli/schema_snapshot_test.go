package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func loadSchema(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	path := filepath.Join("..", "..", "schema", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read schema %s: %v", path, err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse schema %s: %v", path, err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(path, doc); err != nil {
		t.Fatalf("add resource %s: %v", path, err)
	}
	sch, err := c.Compile(path)
	if err != nil {
		t.Fatalf("compile %s: %v", path, err)
	}
	return sch
}

func decodeCLI(t *testing.T, args ...string) map[string]any {
	t.Helper()
	out, _ := runCLI(t, args...)
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("json parse: %v\noutput:\n%s", err, out)
	}
	return m
}

func marshalDoc(t *testing.T, v any) string {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func TestSchemaConformance_Scan(t *testing.T) {
	db := copyFixtureDB(t)
	doc := decodeCLI(t, "scan", "--db", db, "--format", "json")
	if err := loadSchema(t, "scan.schema.json").Validate(doc); err != nil {
		t.Errorf("scan output violates schema: %v\ndoc:\n%s", err, marshalDoc(t, doc))
	}
}

func TestSchemaConformance_DeleteCheck(t *testing.T) {
	db := copyFixtureDB(t)
	doc := decodeCLI(t,
		"delete-check", "lab-worker",
		"--db", db, "--rules-file", labRules(), "--format", "json")
	if err := loadSchema(t, "delete-check.schema.json").Validate(doc); err != nil {
		t.Errorf("delete-check output violates schema: %v\ndoc:\n%s", err, marshalDoc(t, doc))
	}
}

func TestSchemaConformance_Explain(t *testing.T) {
	db := copyFixtureDB(t)
	doc := decodeCLI(t, "explain", "lab-worker", "--db", db, "--format", "json")
	if err := loadSchema(t, "explain.schema.json").Validate(doc); err != nil {
		t.Errorf("explain output violates schema: %v\ndoc:\n%s", err, marshalDoc(t, doc))
	}
}

func TestSchemaConformance_Report(t *testing.T) {
	db := copyFixtureDB(t)
	doc := decodeCLI(t, "report", "--db", db, "--format", "json")
	if err := loadSchema(t, "report.schema.json").Validate(doc); err != nil {
		t.Errorf("report output violates schema: %v\ndoc:\n%s", err, marshalDoc(t, doc))
	}
}

func TestSchemaConformance_ScanList(t *testing.T) {
	db := copyFixtureDB(t)
	doc := decodeCLI(t, "scan", "list", "--db", db, "--format", "json")
	if err := loadSchema(t, "scan-list.schema.json").Validate(doc); err != nil {
		t.Errorf("scan list output violates schema: %v\ndoc:\n%s", err, marshalDoc(t, doc))
	}
}

func TestSchemaConformance_ScanListWithVerdicts(t *testing.T) {
	db := scanHistoryFixture(t)
	doc := decodeCLI(t, "scan", "list", "--db", db, "--format", "json")
	if err := loadSchema(t, "scan-list.schema.json").Validate(doc); err != nil {
		t.Errorf("scan list (with verdicts) violates schema: %v\ndoc:\n%s", err, marshalDoc(t, doc))
	}
}

func TestSchemaConformance_ScanDiff(t *testing.T) {
	db := copyFixtureDB(t)
	doc := decodeCLI(t, "scan", "diff", "1", "2", "--db", db, "--format", "json")
	if err := loadSchema(t, "scan-diff.schema.json").Validate(doc); err != nil {
		t.Errorf("scan diff output violates schema: %v\ndoc:\n%s", err, marshalDoc(t, doc))
	}
}

func TestSchemaConformance_ScanDiffWithChanges(t *testing.T) {
	db := scanHistoryFixture(t)
	doc := decodeCLI(t, "scan", "diff", "1", "2", "--db", db, "--format", "json")
	if err := loadSchema(t, "scan-diff.schema.json").Validate(doc); err != nil {
		t.Errorf("scan diff (with changes) violates schema: %v\ndoc:\n%s", err, marshalDoc(t, doc))
	}
}

func TestSchemaConformance_ExplainNext(t *testing.T) {
	db := copyFixtureDB(t)
	doc := decodeCLI(t,
		"explain", "lab-worker",
		"--db", db, "--next", "--format", "json")
	if err := loadSchema(t, "explain.schema.json").Validate(doc); err != nil {
		t.Errorf("explain --next output violates schema: %v\ndoc:\n%s", err, marshalDoc(t, doc))
	}
	if _, ok := doc["next"]; !ok {
		t.Errorf("next object missing from explain --next output:\n%s", marshalDoc(t, doc))
	}
}

func TestSchemaConformance_ObserveStatus(t *testing.T) {
	db := copyFixtureDB(t)
	doc := decodeCLI(t, "observe", "status", "--db", db, "--format", "json")
	if err := loadSchema(t, "observe-status.schema.json").Validate(doc); err != nil {
		t.Errorf("observe status output violates schema: %v\ndoc:\n%s", err, marshalDoc(t, doc))
	}
}

func TestSchemaConformance_Impact(t *testing.T) {
	db := copyFixtureDB(t)
	doc := decodeCLI(t, "impact", "lab-worker", "--db", db, "--format", "json")
	if err := loadSchema(t, "impact.schema.json").Validate(doc); err != nil {
		t.Errorf("impact output violates schema: %v\ndoc:\n%s", err, marshalDoc(t, doc))
	}
	if doc["verdict"] != nil {
		t.Errorf("verdict = %v, want null for the fixture's empty verdict table", doc["verdict"])
	}
}

func TestSchemaConformance_ImpactWithRisks(t *testing.T) {
	db := impactFixture(t)
	doc := decodeCLI(t, "impact", "app.service", "--db", db, "--format", "json")
	if err := loadSchema(t, "impact.schema.json").Validate(doc); err != nil {
		t.Errorf("impact (with verdict and risk) violates schema: %v\ndoc:\n%s", err, marshalDoc(t, doc))
	}
}

// Negative proof: removing a required field must cause validation to
// fail. Guards against a vacuous test (e.g. a schema that accepts
// everything).
func TestSchemaConformance_NegativeProof(t *testing.T) {
	db := copyFixtureDB(t)
	doc := decodeCLI(t,
		"delete-check", "lab-worker",
		"--db", db, "--rules-file", labRules(), "--format", "json")
	delete(doc, "state")
	err := loadSchema(t, "delete-check.schema.json").Validate(doc)
	if err == nil {
		t.Fatalf("expected validation error after dropping required 'state'; got nil\ndoc:\n%s",
			marshalDoc(t, doc))
	}
	if !strings.Contains(err.Error(), "state") {
		t.Errorf("expected error to mention 'state'; got: %v", err)
	}
}

// Negative proof for the scan history documents: dropping a required
// top-level key must make each schema reject its own output.
func TestSchemaConformance_ScanHistoryNegativeProof(t *testing.T) {
	db := copyFixtureDB(t)

	list := decodeCLI(t, "scan", "list", "--db", db, "--format", "json")
	delete(list, "scans")
	err := loadSchema(t, "scan-list.schema.json").Validate(list)
	if err == nil {
		t.Fatalf("expected validation error after dropping required 'scans'\ndoc:\n%s",
			marshalDoc(t, list))
	}
	if !strings.Contains(err.Error(), "scans") {
		t.Errorf("expected error to mention 'scans'; got: %v", err)
	}

	diff := decodeCLI(t, "scan", "diff", "1", "2", "--db", db, "--format", "json")
	delete(diff, "verdict")
	err = loadSchema(t, "scan-diff.schema.json").Validate(diff)
	if err == nil {
		t.Fatalf("expected validation error after dropping required 'verdict'\ndoc:\n%s",
			marshalDoc(t, diff))
	}
	if !strings.Contains(err.Error(), "verdict") {
		t.Errorf("expected error to mention 'verdict'; got: %v", err)
	}
}

// Negative proof for the remediation documents: the nested required
// keys must be enforced, so the new definitions are not vacuous.
func TestSchemaConformance_RemediationNegativeProof(t *testing.T) {
	db := copyFixtureDB(t)

	next := decodeCLI(t, "explain", "lab-worker", "--db", db, "--next", "--format", "json")
	inner, ok := next["next"].(map[string]any)
	if !ok {
		t.Fatalf("next object missing:\n%s", marshalDoc(t, next))
	}
	delete(inner, "window")
	err := loadSchema(t, "explain.schema.json").Validate(next)
	if err == nil {
		t.Fatalf("expected validation error after dropping required next.window\ndoc:\n%s",
			marshalDoc(t, next))
	}
	if !strings.Contains(err.Error(), "window") {
		t.Errorf("expected error to mention 'window'; got: %v", err)
	}

	status := decodeCLI(t, "observe", "status", "--db", db, "--format", "json")
	delete(status, "days_remaining")
	err = loadSchema(t, "observe-status.schema.json").Validate(status)
	if err == nil {
		t.Fatalf("expected validation error after dropping required 'days_remaining'\ndoc:\n%s",
			marshalDoc(t, status))
	}
	if !strings.Contains(err.Error(), "days_remaining") {
		t.Errorf("expected error to mention 'days_remaining'; got: %v", err)
	}

	impact := decodeCLI(t, "impact", "lab-worker", "--db", db, "--format", "json")
	delete(impact, "inbound")
	err = loadSchema(t, "impact.schema.json").Validate(impact)
	if err == nil {
		t.Fatalf("expected validation error after dropping required 'inbound'\ndoc:\n%s",
			marshalDoc(t, impact))
	}
	if !strings.Contains(err.Error(), "inbound") {
		t.Errorf("expected error to mention 'inbound'; got: %v", err)
	}
}
