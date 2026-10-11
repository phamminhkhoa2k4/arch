package bench

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"archaeologist/internal/rules"
)

// The gate fails on any false orphan, any unresolvable component or a
// measured precision below threshold, and passes on a vacuous run.
func TestCheckpointGateLogic(t *testing.T) {
	cases := []struct {
		name string
		cp   CheckpointReport
		want bool
	}{
		{"clean", CheckpointReport{}, false},
		{"false orphan", CheckpointReport{
			FalseOrphans: []componentVerdict{{ID: "x"}},
		}, true},
		{"resolve error", CheckpointReport{
			Errors: []string{"x: no match"},
		}, true},
		{"precision miss", CheckpointReport{
			LikelyTP: 1, LikelyFP: 1, Predictions: 2,
		}, true},
		{"precision ok", CheckpointReport{
			LikelyTP: 19, LikelyFP: 1, Predictions: 20,
		}, false},
		{"vacuous precision", CheckpointReport{
			LikelyTP: 0, LikelyFP: 0, Predictions: 0,
		}, false},
	}
	for _, tc := range cases {
		if got := tc.cp.GateFailed(); got != tc.want {
			t.Errorf("%s: GateFailed() = %v, want %v", tc.name, got, tc.want)
		}
	}
	if got := (&CheckpointReport{Predictions: 0}).Precision(); got != 100.0 {
		t.Errorf("vacuous precision = %.1f, want 100", got)
	}
	if got := (&CheckpointReport{LikelyTP: 19, Predictions: 20}).Precision(); got != 95.0 {
		t.Errorf("precision 19/20 = %.1f, want 95", got)
	}
}

// The committed lab fixture must clear Checkpoint #2: zero false
// orphans against the full ground truth. The db is copied first so
// the WAL header flip never dirties the tracked fixture file.
func TestCheckpointOnLabFixture(t *testing.T) {
	gt, err := LoadGT(filepath.Join("..", "..", "lab", "ground-truth.yaml"))
	if err != nil {
		t.Fatalf("load gt: %v", err)
	}
	working, cleanup, err := copyDB(filepath.Join("..", "..", "lab", "fixtures", "scan.db"))
	if err != nil {
		t.Fatalf("copy fixture: %v", err)
	}
	defer cleanup()
	r, _, err := rules.Load(filepath.Join("..", "..", "lab", "rules.lab.yaml"))
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	cp, err := MeasureCheckpoint(working, gt, r)
	if err != nil {
		t.Fatalf("measure checkpoint: %v", err)
	}
	if len(cp.Errors) > 0 {
		t.Errorf("component errors: %v", cp.Errors)
	}
	if len(cp.FalseOrphans) > 0 {
		t.Errorf("false orphans on fixture: %+v", cp.FalseOrphans)
	}
	if cp.NonOrphanExpected != 19 {
		t.Errorf("denominator = %d, want 19 (23 components − 4 expected ORPHANED)", cp.NonOrphanExpected)
	}
	if len(cp.TrapResults) != 4 {
		t.Errorf("trap results = %d, want 4 (3 traps, nginx_variable covers 2 components)", len(cp.TrapResults))
	}
	if cp.GateFailed() {
		t.Errorf("fixture must pass Checkpoint #2: %+v", cp)
	}
	var out bytes.Buffer
	if err := cp.Write(&out); err != nil {
		t.Fatalf("write: %v", err)
	}
	if strings.Contains(out.String(), "::error") {
		t.Errorf("pass report must not error:\n%s", out.String())
	}
}

// A ground-truth component whose ref matches nothing is a gate miss,
// never a silent pass.
func TestCheckpointUnresolvedComponentFailsGate(t *testing.T) {
	gt := &GroundTruth{Components: []GTComponent{{
		ID: "ghost", Kind: "container", Ref: "no-such-thing", Expected: "ACTIVE",
	}}}
	working, cleanup, err := copyDB(filepath.Join("..", "..", "lab", "fixtures", "scan.db"))
	if err != nil {
		t.Fatalf("copy fixture: %v", err)
	}
	defer cleanup()
	cp, err := MeasureCheckpoint(working, gt, rules.Rules{})
	if err != nil {
		t.Fatalf("measure checkpoint: %v", err)
	}
	if !cp.GateFailed() {
		t.Fatal("unresolved component must fail the gate")
	}
	if len(cp.Errors) != 1 || !strings.Contains(cp.Errors[0], "ghost") {
		t.Errorf("errors = %v, want one ghost error", cp.Errors)
	}
}

// LoadGT rejects a component without a ref: the benchmark and
// deletecheck both resolve through that field.
func TestLoadGTRejectsMissingRef(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gt.yaml")
	yaml := `
listeners:
  - id: l1
    proto: tcp
    addr: "0.0.0.0"
    port: 8081
    expected_owner: {kind: container, name: lab-web}
route_chains:
  - id: c1
    location: /web/
    file: lab.conf
    simple: true
    expected: [{proto: tcp, port: 8081, owner: {kind: container, name: lab-web}}]
components:
  - id: ghost
    kind: container
    expected: ACTIVE
`
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadGT(path); err == nil || !strings.Contains(err.Error(), "no ref") {
		t.Errorf("err = %v, want no-ref complaint", err)
	}
}

// Recall counts every expected-ORPHANED component and every orphan
// verdict on them; the fixture's four true orphans are all found.
func TestCheckpointRecallOnLabFixture(t *testing.T) {
	working, cleanup, err := copyDB(filepath.Join("..", "..", "lab", "fixtures", "scan.db"))
	if err != nil {
		t.Fatalf("copy fixture: %v", err)
	}
	defer cleanup()
	gtPath := filepath.Join("..", "..", "lab", "ground-truth.yaml")
	rulesPath := filepath.Join("..", "..", "lab", "rules.lab.yaml")
	gt, err := LoadGT(gtPath)
	if err != nil {
		t.Fatalf("gt: %v", err)
	}
	r, _, err := rules.Load(rulesPath)
	if err != nil {
		t.Fatalf("rules: %v", err)
	}
	cp, err := MeasureCheckpoint(working, gt, r)
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if cp.OrphanExpected != 4 {
		t.Errorf("OrphanExpected = %d, want 4", cp.OrphanExpected)
	}
	if cp.OrphanHits != 4 || cp.Recall() != 100.0 {
		t.Errorf("Recall = %d/%d = %.1f%%, want 4/4 = 100%%",
			cp.OrphanHits, cp.OrphanExpected, cp.Recall())
	}
	var buf bytes.Buffer
	if err := cp.Write(&buf); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !strings.Contains(buf.String(), "Recall ORPHANED: 4/4 = 100.0%") {
		t.Errorf("recall line missing:\n%s", buf.String())
	}
}
