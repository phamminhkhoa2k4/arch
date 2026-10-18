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
