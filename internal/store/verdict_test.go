package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"archaeologist/internal/rules"
	"archaeologist/internal/verdict"
)

var verdictNow = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func newVerdictStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "verdict.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// seedVerdictScan creates a host (first seen 2026-08-01) and a scan,
// returning both ids.
func seedVerdictScan(t *testing.T, s *Store, ctx context.Context) (hostID, scanID int64) {
	t.Helper()
	hostID, err := s.InsertHost(ctx, "lab-vm", "linux", "6.8")
	if err != nil {
		t.Fatal(err)
	}
	scanID, err = s.InsertScan(ctx, hostID, "v0.1-test", "{}")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE hosts SET first_seen_at = '2026-08-01T00:00:00Z' WHERE id = ?`,
		hostID); err != nil {
		t.Fatal(err)
	}
	return hostID, scanID
}

func seedVerdictEntity(t *testing.T, s *Store, ctx context.Context, scanID int64, kind, name string, attrs map[string]string) int64 {
	t.Helper()
	attrsJSON, err := json.Marshal(attrs)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO entities (scan_id, kind, name, identity_key, fingerprint,
		                       attributes_json, created_at, updated_at)
		 VALUES (?, ?, ?, ?, 'fp', ?, '2026-10-08T00:00:00Z', '2026-10-08T00:00:00Z')`,
		scanID, kind, name, kind+"|"+name, string(attrsJSON))
	if err != nil {
		t.Fatal(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func seedVerdictEvidence(t *testing.T, s *Store, ctx context.Context, entityID int64, channel, polarity, strength, observedAt, rawRef, valueJSON string) int64 {
	t.Helper()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO evidence (entity_id, polarity, channel, strength,
		                       observed_at, raw_ref, value_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		entityID, polarity, channel, strength, observedAt, rawRef, valueJSON)
	if err != nil {
		t.Fatal(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func seedVerdictObservation(t *testing.T, s *Store, ctx context.Context, entityID, count int64, bucket, lastSeen string) {
	t.Helper()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO observations (entity_id, remote_key, bucket_start, count, last_seen_at)
		 VALUES (?, '10.0.0.9:443', ?, ?, ?)`,
		entityID, bucket, count, lastSeen); err != nil {
		t.Fatal(err)
	}
}

func defaultVerdictRules(t *testing.T) rules.Rules {
	t.Helper()
	r, _, err := rules.Default()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestBuildInputCarriesEveryEngineFact(t *testing.T) {
	s := newVerdictStore(t)
	ctx := context.Background()
	_, scanID := seedVerdictScan(t, s, ctx)
	cid := seedVerdictEntity(t, s, ctx, scanID, "container", "lab-web",
		map[string]string{"state": "running", "created_at": "2026-10-01T00:00:00Z"})
	seedVerdictEvidence(t, s, ctx, cid, "docker", "in_use", "deterministic",
		"2026-10-08T00:00:00Z", "docker:inspect:lab-web", `{"state":"running"}`)
	seedVerdictEvidence(t, s, ctx, cid, "docker_created", "neutral", "deterministic",
		"2026-10-08T00:00:01Z", "docker:created:lab-web", `{"created_at":"2026-10-01T00:00:00Z"}`)
	seedVerdictObservation(t, s, ctx, cid, 12, "2026-09-01T00:00:00Z", "2026-10-07T10:00:00Z")
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO blind_spots (scan_id, entity_id, channel, reason, detail_json, created_at)
		 VALUES (?, ?, 'docker', 'docker_socket_unreadable', '{"errno":"13"}', '2026-10-08T00:00:00Z')`,
		scanID, cid); err != nil {
		t.Fatal(err)
	}

	in, err := s.BuildInput(ctx, scanID, cid)
	if err != nil {
		t.Fatalf("BuildInput: %v", err)
	}
	if in.Kind != "container" || in.Name != "lab-web" {
		t.Errorf("entity = %s/%s", in.Kind, in.Name)
	}
	if in.Attributes["state"] != "running" {
		t.Errorf("attributes = %v", in.Attributes)
	}
	if len(in.Evidence) != 2 {
		t.Errorf("evidence = %d, want 2", len(in.Evidence))
	}
	if in.Evidence[0].Value["state"] != "running" {
		t.Errorf("evidence value not parsed: %+v", in.Evidence[0])
	}
	if len(in.Blinds) != 1 || in.Blinds[0].Channel != "docker" || in.Blinds[0].Detail["errno"] != "13" {
		t.Errorf("blinds = %+v", in.Blinds)
	}
	if len(in.Observations) != 1 || in.Observations[0].Count != 12 {
		t.Errorf("observations = %+v", in.Observations)
	}
	if in.Window.Source != "observations" || in.Window.Start != "2026-09-01T00:00:00Z" {
		t.Errorf("window = %+v", in.Window)
	}
	if in.Window.Days < 30 {
		t.Errorf("window days = %d, want ≥30", in.Window.Days)
	}
}

func TestVerdictLifecycleActiveOnObservation(t *testing.T) {
	s := newVerdictStore(t)
	ctx := context.Background()
	_, scanID := seedVerdictScan(t, s, ctx)
	cid := seedVerdictEntity(t, s, ctx, scanID, "container", "lab-web",
		map[string]string{"state": "running", "created_at": "2026-10-01T00:00:00Z"})
	seedVerdictEvidence(t, s, ctx, cid, "docker", "in_use", "deterministic",
		"2026-10-08T00:00:00Z", "docker:inspect:lab-web", `{"state":"running"}`)
	seedVerdictEvidence(t, s, ctx, cid, "docker_created", "neutral", "deterministic",
		"2026-10-08T00:00:01Z", "docker:created:lab-web", `{"created_at":"2026-10-01T00:00:00Z"}`)
	seedVerdictObservation(t, s, ctx, cid, 4, "2026-10-07T00:00:00Z", "2026-10-07T23:00:00Z")

	in, err := s.BuildInput(ctx, scanID, cid)
	if err != nil {
		t.Fatalf("BuildInput: %v", err)
	}
	res := verdict.Compute(in, defaultVerdictRules(t), verdictNow)
	if res.State != verdict.StateActive {
		t.Fatalf("state = %s, want ACTIVE (recent observation blocks)", res.State)
	}

	if err := s.SaveVerdict(ctx, cid, scanID, res, "hash-test"); err != nil {
		t.Fatalf("SaveVerdict: %v", err)
	}
	rec, err := s.VerdictFor(ctx, cid, scanID)
	if err != nil {
		t.Fatalf("VerdictFor: %v", err)
	}
	if rec.State != verdict.StateActive || rec.RulesHash != "hash-test" {
		t.Errorf("record = %+v", rec)
	}
	if len(rec.Blockers) == 0 || rec.Blockers[0].Code != "B2" {
		t.Errorf("blockers = %+v, want B2", rec.Blockers)
	}
	if rec.Window.Source != "observations" || rec.Coverage == "" {
		t.Errorf("window/coverage missing: %+v", rec)
	}

	// Re-save replaces instead of duplicating.
	if err := s.SaveVerdict(ctx, cid, scanID, res, "hash-test-2"); err != nil {
		t.Fatalf("second SaveVerdict: %v", err)
	}
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM verdicts WHERE entity_id = ?`, cid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("verdict rows = %d, want 1 (latest wins)", n)
	}
}

func TestOldAPISyntheticEndToEnd(t *testing.T) {
	s := newVerdictStore(t)
	ctx := context.Background()
	_, scanID := seedVerdictScan(t, s, ctx)
	cid := seedVerdictEntity(t, s, ctx, scanID, "container", "old-api",
		map[string]string{
			"state":          "exited",
			"created_at":     "2026-04-01T00:00:00Z",
			"last_deploy_at": "2026-04-01T00:00:00Z",
		})
	seedVerdictEvidence(t, s, ctx, cid, "docker", "neutral", "deterministic",
		"2026-10-08T00:00:00Z", "docker:inspect:old-api", `{"state":"exited"}`)
	seedVerdictEvidence(t, s, ctx, cid, "docker_created", "neutral", "deterministic",
		"2026-10-08T00:00:01Z", "docker:created:old-api",
		`{"created_at":"2026-04-01T00:00:00Z","last_deploy_at":"2026-04-01T00:00:00Z"}`)
	seedVerdictEvidence(t, s, ctx, cid, "mtime", "neutral", "deterministic",
		"2026-10-08T00:00:02Z", "fs:/srv/old-api/app.py", `{"age_days":"210"}`)

	in, err := s.BuildInput(ctx, scanID, cid)
	if err != nil {
		t.Fatalf("BuildInput: %v", err)
	}
	res := verdict.Compute(in, defaultVerdictRules(t), verdictNow)
	if res.State != verdict.StateOrphaned {
		t.Fatalf("state = %s, want ORPHANED (no inbound, 2/2 HIGH, window ok)", res.State)
	}
	if len(res.Signals) < 3 {
		t.Errorf("signals = %+v, want mtime+deploy+state", res.Signals)
	}
	for _, s := range res.Signals {
		switch s.Code {
		case "S1", "S2", "S4":
		default:
			t.Errorf("unexpected signal %q", s.Code)
		}
	}
	// No percentages anywhere in the reasons.
	for _, r := range res.Reasons {
		if strings.Contains(r, "%") || strings.Contains(strings.ToLower(r), "confidence") {
			t.Errorf("reason leaks a percentage/confidence: %q", r)
		}
	}
}

func TestWindowWithoutObservationsUsesFirstSeen(t *testing.T) {
	s := newVerdictStore(t)
	ctx := context.Background()
	_, scanID := seedVerdictScan(t, s, ctx)
	cid := seedVerdictEntity(t, s, ctx, scanID, "process", "orphan-proc", map[string]string{})
	seedVerdictEvidence(t, s, ctx, cid, "procfs", "in_use", "deterministic",
		"2026-10-08T00:00:00Z", "proc:1234", `{}`)

	in, err := s.BuildInput(ctx, scanID, cid)
	if err != nil {
		t.Fatalf("BuildInput: %v", err)
	}
	if in.Window.Source != "first_seen" {
		t.Errorf("window source = %s, want first_seen", in.Window.Source)
	}
	if in.Window.Start != "2026-08-01T00:00:00Z" {
		t.Errorf("window start = %s", in.Window.Start)
	}
	if in.Window.Days < 60 {
		t.Errorf("window days = %d, want ≥60 (2026-08-01 → 2026-10-08)", in.Window.Days)
	}
}

func TestBuildInputsMatchesSingleEntity(t *testing.T) {
	s := newVerdictStore(t)
	ctx := context.Background()
	_, scanID := seedVerdictScan(t, s, ctx)

	unit := seedVerdictEntity(t, s, ctx, scanID, "systemd_unit", "svc.service",
		map[string]string{"active_state": "active"})
	proc := seedVerdictEntity(t, s, ctx, scanID, "process", "nginx",
		map[string]string{"pid": "1"})
	lis := seedVerdictEntity(t, s, ctx, scanID, "listener", ":::80",
		map[string]string{"proto": "tcp"})
	lonely := seedVerdictEntity(t, s, ctx, scanID, "script", "/srv/idle.sh", nil)

	seedVerdictEvidence(t, s, ctx, unit, "systemd", "in_use", "deterministic",
		"2026-10-08T00:00:00Z", "dbus:ListUnits", `{"active_state":"active"}`)
	seedVerdictEvidence(t, s, ctx, proc, "procfs", "in_use", "deterministic",
		"2026-10-08T00:00:01Z", "proc:1", `{}`)
	seedVerdictEvidence(t, s, ctx, lis, "procfs", "in_use", "deterministic",
		"2026-10-08T00:00:02Z", "proc/net/tcp", `{}`)
	seedVerdictObservation(t, s, ctx, unit, 3, "2026-10-01T00:00:00Z", "2026-10-07T00:00:00Z")
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO blind_spots (scan_id, entity_id, channel, reason, detail_json, created_at)
		 VALUES (?, ?, 'procfs', 'proc_unreadable', '{"pid":"1"}', '2026-10-08T00:00:00Z')`,
		scanID, proc); err != nil {
		t.Fatal(err)
	}

	addEdge := func(src, dst int64, kind, ref string) {
		t.Helper()
		ev := seedVerdictEvidence(t, s, ctx, src, "test", "neutral", "deterministic",
			"2026-10-08T00:00:00Z", ref, `{}`)
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO edges (scan_id, src_id, dst_id, kind, strength, evidence_id)
			 VALUES (?, ?, ?, ?, 'deterministic', ?)`,
			scanID, src, dst, kind, ev); err != nil {
			t.Fatal(err)
		}
	}
	addEdge(unit, proc, "manages", "unit:manages")
	addEdge(proc, lis, "listens_on", "proc:listens")

	bulk, err := s.BuildInputs(ctx, scanID)
	if err != nil {
		t.Fatalf("BuildInputs: %v", err)
	}
	if len(bulk) != 4 {
		t.Fatalf("inputs = %d entities, want 4", len(bulk))
	}
	for _, id := range []int64{unit, proc, lis, lonely} {
		one, err := s.BuildInput(ctx, scanID, id)
		if err != nil {
			t.Fatalf("BuildInput(%d): %v", id, err)
		}
		if !reflect.DeepEqual(bulk[id], one) {
			t.Errorf("entity %d: bulk input differs\n bulk: %+v\n  one: %+v", id, bulk[id], one)
		}
	}
}

func TestVerdictForReturnsNoRows(t *testing.T) {
	s := newVerdictStore(t)
	_, err := s.VerdictFor(context.Background(), 999, 999)
	if err != sql.ErrNoRows {
		t.Errorf("err = %v, want sql.ErrNoRows", err)
	}
}

// VerdictRollup counts stored verdicts by state for one scan only.
func TestVerdictRollup(t *testing.T) {
	s := newVerdictStore(t)
	ctx := context.Background()
	_, scanID := seedVerdictScan(t, s, ctx)
	usedEnt := seedVerdictEntity(t, s, ctx, scanID, "container", "a", map[string]string{})
	quietEnt := seedVerdictEntity(t, s, ctx, scanID, "container", "b", map[string]string{})
	procEnt := seedVerdictEntity(t, s, ctx, scanID, "process", "c", map[string]string{})
	for _, c := range []struct {
		id    int64
		state string
	}{{usedEnt, verdict.StateActive}, {quietEnt, verdict.StateOrphaned}, {procEnt, verdict.StateOrphaned}} {
		if err := s.SaveVerdict(ctx, c.id, scanID, verdict.Result{State: c.state, Coverage: "HIGH"}, "h"); err != nil {
			t.Fatalf("save: %v", err)
		}
	}
	got, err := s.VerdictRollup(ctx, scanID)
	if err != nil {
		t.Fatalf("rollup: %v", err)
	}
	if got[verdict.StateActive] != 1 || got[verdict.StateOrphaned] != 2 {
		t.Errorf("rollup = %v, want active:1 orphaned:2", got)
	}
	if _, err := s.VerdictRollup(ctx, 999); err != nil {
		t.Errorf("empty scan rollup err: %v", err)
	}
}

// HasBrokenRoute is true only for BROKEN_ROUTE findings of that entity.
func TestHasBrokenRoute(t *testing.T) {
	s := newVerdictStore(t)
	ctx := context.Background()
	_, scanID := seedVerdictScan(t, s, ctx)
	eid := seedVerdictEntity(t, s, ctx, scanID, "nginx_route", "/dead/", map[string]string{})
	other := seedVerdictEntity(t, s, ctx, scanID, "container", "x", map[string]string{})

	if ok, err := s.HasBrokenRoute(ctx, scanID, eid); err != nil || ok {
		t.Fatalf("before finding: ok=%v err=%v, want false/nil", ok, err)
	}
	insertFindingRaw(t, s, ctx, scanID, eid, "BROKEN_ROUTE", "warn")
	if ok, err := s.HasBrokenRoute(ctx, scanID, eid); err != nil || !ok {
		t.Fatalf("after BROKEN_ROUTE: ok=%v err=%v", ok, err)
	}
	insertFindingRaw(t, s, ctx, scanID, other, "UNUSED_IMAGE", "info")
	if ok, err := s.HasBrokenRoute(ctx, scanID, other); err != nil || ok {
		t.Fatalf("UNUSED_IMAGE must not count: ok=%v err=%v", ok, err)
	}
}

// EntitiesInScan lists every entity of the scan ordered by identity key.
func TestEntitiesInScan(t *testing.T) {
	s := newVerdictStore(t)
	ctx := context.Background()
	_, scanID := seedVerdictScan(t, s, ctx)
	seedVerdictEntity(t, s, ctx, scanID, "container", "b", map[string]string{})
	seedVerdictEntity(t, s, ctx, scanID, "container", "a", map[string]string{})
	ents, err := s.EntitiesInScan(ctx, scanID)
	if err != nil {
		t.Fatalf("entities: %v", err)
	}
	if len(ents) != 2 || ents[0].Name != "a" || ents[1].Name != "b" {
		t.Errorf("ents = %+v, want a then b", ents)
	}
}
