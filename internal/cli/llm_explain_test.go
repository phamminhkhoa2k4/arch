package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"archaeologist/internal/llm"
	"archaeologist/internal/store"
)

// fakeLLM stands up an OpenAI-compatible stub that records the last
// request body and replies with a fixed explanation.
func fakeLLM(t *testing.T) (*httptest.Server, *string) {
	t.Helper()
	var lastBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r.Body)
		lastBody = buf.String()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"role": "assistant", "content": "canned explanation"}},
			},
		})
	}))
	t.Cleanup(srv.Close)
	return srv, &lastBody
}

// runCLI executes the root command with args and returns stdout+stderr.
func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := rootCmd()
	addCommands(root)
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

// Only redacted data reaches the provider: a secret planted straight
// into the database (bypassing the sink's redaction) must not appear
// in the captured request body.
func TestExplainPayloadRedacted(t *testing.T) {
	srv, lastBody := fakeLLM(t)
	t.Setenv(llm.EnvBaseURL, srv.URL)
	t.Setenv(llm.EnvAPIKey, "test-key")

	db := copyFixtureDB(t)
	secret := "hunter2-super-secret-value"
	st, err := store.Open(context.Background(), db)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := st.DB().Exec(
		`UPDATE entities SET attributes_json = json_set(attributes_json, '$.DB_PASSWORD', ?)
		 WHERE kind = 'script' AND identity_key LIKE 'script|/%'`, secret); err != nil {
		t.Fatalf("plant secret: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	out, err := runCLI(t, "explain", "--db", db, "--explain", "script|/usr/bin/cloud-init")
	if err != nil {
		t.Fatalf("explain: %v\n%s", err, out)
	}
	if strings.Contains(*lastBody, secret) {
		t.Errorf("secret leaked into the LLM payload:\n%s", *lastBody)
	}
	if !strings.Contains(out, "canned explanation") {
		t.Errorf("missing explanation text:\n%s", out)
	}
}

// Without the flag nothing touches the network: a dead-port base URL
// produces no dial error and no provider output.
func TestExplainFlagOffNoNetwork(t *testing.T) {
	t.Setenv(llm.EnvBaseURL, "http://127.0.0.1:9")
	t.Setenv(llm.EnvAPIKey, "test-key")

	db := copyFixtureDB(t)
	out, err := runCLI(t, "delete-check", "--db", db, "nginx.service")
	if strings.Contains(out, "dial") || (err != nil && strings.Contains(err.Error(), "dial")) {
		t.Fatalf("network dial without --explain: %v\n%s", err, out)
	}
	if strings.Contains(out, labelExplanation) {
		t.Errorf("explanation printed without --explain:\n%s", out)
	}
}

// With --explain the output carries the automation label before the
// model text.
func TestExplainLabelPresent(t *testing.T) {
	srv, _ := fakeLLM(t)
	t.Setenv(llm.EnvBaseURL, srv.URL)
	t.Setenv(llm.EnvAPIKey, "test-key")

	db := copyFixtureDB(t)
	out, _ := runCLI(t, "delete-check", "--db", db, "--explain", "nginx.service")
	iLabel := strings.Index(out, labelExplanation)
	if iLabel < 0 {
		t.Fatalf("label missing:\n%s", out)
	}
	if !strings.Contains(out[iLabel:], "canned explanation") {
		t.Errorf("text missing after label:\n%s", out)
	}
}

// --explain never mutates the evidence graph.
func TestExplainDoesNotWriteDB(t *testing.T) {
	srv, _ := fakeLLM(t)
	t.Setenv(llm.EnvBaseURL, srv.URL)
	t.Setenv(llm.EnvAPIKey, "test-key")

	db := copyFixtureDB(t)
	before := countRows(t, db)
	out, err := runCLI(t, "explain", "--db", db, "--explain", "script|/usr/bin/cloud-init")
	if err != nil {
		t.Fatalf("explain: %v\n%s", err, out)
	}
	after := countRows(t, db)
	for table, n := range before {
		if after[table] != n {
			t.Errorf("table %s changed: %d → %d", table, n, after[table])
		}
	}
}

// --explain without an API key is a hard error and sends no request
// (D2/D8).
func TestExplainMissingKey(t *testing.T) {
	requested := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = true
	}))
	defer srv.Close()
	t.Setenv(llm.EnvBaseURL, srv.URL)
	t.Setenv(llm.EnvAPIKey, "")

	db := copyFixtureDB(t)
	out, err := runCLI(t, "delete-check", "--db", db, "--explain", "nginx.service")
	if err == nil {
		t.Fatalf("missing key must error:\n%s", out)
	}
	if !strings.Contains(err.Error(), llm.EnvAPIKey) {
		t.Errorf("error should name the env var: %v", err)
	}
	if requested {
		t.Error("request reached the server without an API key")
	}
}

// A script with no references gets the hypothesis label.
func TestExplainScriptHypothesisLabel(t *testing.T) {
	srv, _ := fakeLLM(t)
	t.Setenv(llm.EnvBaseURL, srv.URL)
	t.Setenv(llm.EnvAPIKey, "test-key")

	db := copyFixtureDB(t)
	// Strip this script's edges so it matches the "no reference"
	// hypothesis trigger.
	st, err := store.Open(context.Background(), db)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := st.DB().Exec(
		`DELETE FROM edges WHERE src_id IN (SELECT id FROM entities WHERE identity_key = 'script|/usr/bin/cloud-init')
		   OR dst_id IN (SELECT id FROM entities WHERE identity_key = 'script|/usr/bin/cloud-init')`); err != nil {
		t.Fatalf("strip edges: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	out, err := runCLI(t, "explain", "--db", db, "--explain", "script|/usr/bin/cloud-init")
	if err != nil {
		t.Fatalf("explain: %v\n%s", err, out)
	}
	if !strings.Contains(out, labelHypothesis) {
		t.Errorf("hypothesis label missing:\n%s", out)
	}
}

// countRows snapshots the row counts of the mutation-sensitive tables.
func countRows(t *testing.T, db string) map[string]int {
	t.Helper()
	st, err := store.Open(context.Background(), db)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = st.Close() }()
	out := map[string]int{}
	for _, table := range []string{"evidence", "edges", "verdicts", "entities"} {
		var n int
		if err := st.DB().QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		out[table] = n
	}
	return out
}
