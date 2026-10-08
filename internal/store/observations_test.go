package store

import (
	"context"
	"testing"
)

func TestUpsertObservationCountsAndMovesLastSeen(t *testing.T) {
	s := newVerdictStore(t)
	ctx := context.Background()
	_, scanID := seedVerdictScan(t, s, ctx)
	eid := seedVerdictEntity(t, s, ctx, scanID, "listener", "web", nil)

	bucket := "2026-10-08T15:00:00Z"
	for _, seen := range []string{"2026-10-08T15:00:10Z", "2026-10-08T15:04:00Z"} {
		if err := s.UpsertObservation(ctx, eid, "10.0.0.5", bucket, seen); err != nil {
			t.Fatalf("UpsertObservation: %v", err)
		}
	}
	if err := s.UpsertObservation(ctx, eid, "10.0.0.6", bucket, "2026-10-08T15:05:00Z"); err != nil {
		t.Fatalf("UpsertObservation: %v", err)
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT remote_key, bucket_start, count, last_seen_at FROM observations
		 WHERE entity_id = ? ORDER BY remote_key`, eid)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	type row struct {
		remote, bucket, lastSeen string
		count                    int
	}
	var got []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.remote, &r.bucket, &r.count, &r.lastSeen); err != nil {
			t.Fatal(err)
		}
		got = append(got, r)
	}
	if len(got) != 2 {
		t.Fatalf("rows = %d, want 2 (distinct remotes)", len(got))
	}
	if got[0].count != 2 || got[0].lastSeen != "2026-10-08T15:04:00Z" {
		t.Errorf("first row = %+v, want count=2 last_seen moved", got[0])
	}
	if got[1].count != 1 {
		t.Errorf("second row = %+v, want count=1", got[1])
	}
}

func TestPruneObservationsDropsExpiredBuckets(t *testing.T) {
	s := newVerdictStore(t)
	ctx := context.Background()
	_, scanID := seedVerdictScan(t, s, ctx)
	eid := seedVerdictEntity(t, s, ctx, scanID, "listener", "web", nil)

	for _, bucket := range []string{"2026-08-01T00:00:00Z", "2026-08-02T00:00:00Z", "2026-10-08T00:00:00Z"} {
		if err := s.UpsertObservation(ctx, eid, "10.0.0.5", bucket, bucket); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	n, err := s.PruneObservations(ctx, "2026-09-01T00:00:00Z")
	if err != nil {
		t.Fatalf("PruneObservations: %v", err)
	}
	if n != 2 {
		t.Errorf("pruned = %d, want 2", n)
	}
	var left int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM observations`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 1 {
		t.Errorf("remaining = %d, want 1", left)
	}
}

func TestLatestListenersUsesNewestScan(t *testing.T) {
	s := newVerdictStore(t)
	ctx := context.Background()
	hostID, scan1 := seedVerdictScan(t, s, ctx)
	old := seedVerdictEntity(t, s, ctx, scan1, "listener", "old", nil)
	scan2, err := s.InsertScan(ctx, hostID, "v0.1-test", "{}")
	if err != nil {
		t.Fatal(err)
	}
	cur := seedVerdictEntity(t, s, ctx, scan2, "listener", "current", nil)
	seedVerdictEntity(t, s, ctx, scan2, "container", "not-a-listener", nil)

	got, err := s.LatestListeners(ctx)
	if err != nil {
		t.Fatalf("LatestListeners: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("listeners = %+v, want only the newest scan's", got)
	}
	if got[0].ID != cur {
		t.Errorf("id = %d, want %d (old listener %d must not appear)", got[0].ID, cur, old)
	}
	if got[0].IdentityKey != "listener|current" {
		t.Errorf("identity_key = %q", got[0].IdentityKey)
	}
}

// The daemon's buckets stay attached to the entity row that was
// current when they were written; a rescan must not lose them (D3).
func TestWindowAndObservationsSurviveRescan(t *testing.T) {
	s := newVerdictStore(t)
	ctx := context.Background()
	hostID, scan1 := seedVerdictScan(t, s, ctx)
	entOld := seedVerdictEntity(t, s, ctx, scan1, "listener", "web", nil)
	if err := s.UpsertObservation(ctx, entOld, "10.0.0.5",
		"2026-09-01T00:00:00Z", "2026-09-01T06:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertObservation(ctx, entOld, "10.0.0.5",
		"2026-10-07T13:00:00Z", "2026-10-07T13:45:00Z"); err != nil {
		t.Fatal(err)
	}

	scan2, err := s.InsertScan(ctx, hostID, "v0.1-test", "{}")
	if err != nil {
		t.Fatal(err)
	}
	entNew := seedVerdictEntity(t, s, ctx, scan2, "listener", "web", nil)
	seedVerdictEvidence(t, s, ctx, entNew, "procfs_net", "in_use", "deterministic",
		"2026-10-01T00:00:00Z", "/proc/net/tcp:sl=1", `{}`)

	in, err := s.BuildInput(ctx, scan2, entNew)
	if err != nil {
		t.Fatalf("BuildInput: %v", err)
	}
	if in.Window.Source != "observations" || in.Window.Start != "2026-09-01T00:00:00Z" {
		t.Errorf("window = %+v, want observations start from scan1 rows", in.Window)
	}
	if len(in.Observations) != 2 {
		t.Errorf("observations = %+v, want both rows via identity key", in.Observations)
	}
	// End follows the latest observation (2026-10-07T13:45) over the
	// older evidence (2026-10-01).
	if in.Window.End != "2026-10-07T13:45:00Z" {
		t.Errorf("window end = %q, want 2026-10-07T13:45:00Z", in.Window.End)
	}
	if in.Window.Days < 36 {
		t.Errorf("window days = %d, want ≥36", in.Window.Days)
	}
}
