package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"archaeologist/internal/collector"
)

// seedPlan inserts one entity into the latest scan and returns its id.
func seedPlan(t *testing.T, st *Store, scanID int64, kind, name, key string) int64 {
	t.Helper()
	ctx := context.Background()
	k := NewScanSink(ctx, st, scanID)
	if err := k.UpsertEntity(collector.Entity{
		Kind: kind, Name: name, IdentityKey: key, Fingerprint: "f",
	}); err != nil {
		t.Fatalf("upsert entity: %v", err)
	}
	ents, err := st.FindEntities(ctx, scanID, key)
	if err != nil || len(ents) != 1 {
		t.Fatalf("find entity: %v %v", ents, err)
	}
	return ents[0].ID
}

// EnsurePlan is idempotent: the same entity keeps one plan row so
// stage progress survives regeneration.
func TestEnsurePlanIdempotent(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "plans.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = st.Close() }()
	host, err := st.InsertHost(ctx, "h", "linux", "k")
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	scan, err := st.InsertScan(ctx, host, "v", "{}")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	eid := seedPlan(t, st, scan, "container", "old", "container|old")

	p1, err := st.EnsurePlan(ctx, eid)
	if err != nil {
		t.Fatalf("ensure 1: %v", err)
	}
	p2, err := st.EnsurePlan(ctx, eid)
	if err != nil {
		t.Fatalf("ensure 2: %v", err)
	}
	if p1 != p2 {
		t.Errorf("plan ids %d != %d, must reuse", p1, p2)
	}
}

// Confirmation follows machine order and persists across reopen.
func TestConfirmPlanStageOrderAndPersist(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "plans.db")
	st, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	host, _ := st.InsertHost(ctx, "h", "linux", "k")
	scan, _ := st.InsertScan(ctx, host, "v", "{}")
	eid := seedPlan(t, st, scan, "container", "old", "container|old")
	planID, err := st.EnsurePlan(ctx, eid)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}

	if err := st.ConfirmPlanStage(ctx, planID, "Observed"); err == nil ||
		!strings.Contains(err.Error(), "Candidate") {
		t.Fatalf("out-of-order confirm err = %v, want Candidate complaint", err)
	}
	if err := st.ConfirmPlanStage(ctx, planID, "Nope"); err == nil ||
		!strings.Contains(err.Error(), "invalid stage") {
		t.Fatalf("bad stage err = %v", err)
	}
	if err := st.ConfirmPlanStage(ctx, planID, "Candidate"); err != nil {
		t.Fatalf("confirm candidate: %v", err)
	}
	if err := st.ConfirmPlanStage(ctx, planID, "Quarantined"); err != nil {
		t.Fatalf("confirm quarantined: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	st2, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = st2.Close() }()
	states, err := st2.PlanStageStates(ctx, planID)
	if err != nil {
		t.Fatalf("states: %v", err)
	}
	if states[0].Status != "done" || states[1].Status != "done" {
		t.Errorf("states after reopen = %+v, want first two done", states)
	}
	if states[2].Status != "pending" || states[2].ConfirmedAt != "" {
		t.Errorf("stage 3 = %+v, want pending", states[2])
	}
}
