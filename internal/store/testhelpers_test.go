package store

import (
	"context"
	"testing"
	"time"
)

// seedEvidence inserts a full valid chain (host→scan→entity→evidence) and
// returns the evidence id. Used by positive-path tests.
func seedEvidence(t *testing.T, s *Store, ctx context.Context, polarity, rawRef string) int64 {
	t.Helper()
	id, err := insertEvidenceRaw(t, s, ctx, polarity, "nginx_access_log", "deterministic", rawRef)
	if err != nil {
		t.Fatalf("insert evidence: %v", err)
	}
	return id
}

// insertEvidenceRaw builds the minimal host/scan/entity chain (reusing ids
// when present is unnecessary in tests) and inserts evidence with the exact
// values under test, so CHECK violations surface from the database.
func insertEvidenceRaw(t *testing.T, s *Store, ctx context.Context, polarity, channel, strength, rawRef string) (int64, error) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)

	hostID, err := s.InsertHost(ctx, "lab-host", "linux", "test-kernel")
	if err != nil {
		return 0, err
	}
	scanID, err := s.InsertScan(ctx, hostID, "v0.1-test", "{}")
	if err != nil {
		return 0, err
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO entities (scan_id, kind, name, identity_key, fingerprint, created_at, updated_at)
		 VALUES (?, 'process', 'test', ?, ?, ?, ?)`,
		scanID, "proc:"+now+randSuffix(), "fp", now, now)
	if err != nil {
		return 0, err
	}
	entityID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	res, err = s.db.ExecContext(ctx,
		`INSERT INTO evidence (entity_id, polarity, channel, strength, observed_at, raw_ref)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		entityID, polarity, channel, strength, now, rawRef)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// insertEdgeRaw inserts an edge with the given strength to exercise the
// strength CHECK constraint.
func insertEdgeRaw(t *testing.T, s *Store, ctx context.Context, strength string) (int64, error) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)

	hostID, err := s.InsertHost(ctx, "lab-host", "linux", "test-kernel")
	if err != nil {
		return 0, err
	}
	scanID, err := s.InsertScan(ctx, hostID, "v0.1-test", "{}")
	if err != nil {
		return 0, err
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO entities (scan_id, kind, name, identity_key, fingerprint, created_at, updated_at)
		 VALUES (?, 'process', ?, ?, 'fp', ?, ?)`,
		scanID, "e-"+randSuffix(), "key:"+randSuffix(), now, now)
	if err != nil {
		return 0, err
	}
	srcID, _ := res.LastInsertId()
	res, err = s.db.ExecContext(ctx,
		`INSERT INTO entities (scan_id, kind, name, identity_key, fingerprint, created_at, updated_at)
		 VALUES (?, 'systemd_unit', ?, ?, 'fp', ?, ?)`,
		scanID, "u-"+randSuffix(), "key2:"+randSuffix(), now, now)
	if err != nil {
		return 0, err
	}
	dstID, _ := res.LastInsertId()
	res, err = s.db.ExecContext(ctx,
		`INSERT INTO evidence (entity_id, polarity, channel, strength, observed_at, raw_ref)
		 VALUES (?, 'neutral', 'test', ?, ?, '/x:1')`,
		srcID, strengthOfInsert(strength), now)
	if err != nil {
		return 0, err
	}
	evID, _ := res.LastInsertId()
	res, err = s.db.ExecContext(ctx,
		`INSERT INTO edges (scan_id, src_id, dst_id, kind, strength, evidence_id)
		 VALUES (?, ?, ?, 'runs_as', ?, ?)`,
		scanID, srcID, dstID, strength, evID)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// strengthOfInsert keeps the evidence strength valid so the edge constraint
// is the one under test, not the evidence one.
func strengthOfInsert(requested string) string {
	switch requested {
	case "deterministic", "strong_heuristic", "weak_heuristic":
		return requested
	default:
		return "deterministic"
	}
}

var counter int

func randSuffix() string {
	counter++
	return time.Now().UTC().Format("150405.000000000") + "-" + itoa(counter)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// insertFindingRaw inserts one finding row directly.
func insertFindingRaw(t *testing.T, s *Store, ctx context.Context, scanID, entityID int64, kind, severity string) int64 {
	t.Helper()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO findings (scan_id, entity_id, kind, severity, detail_json)
		 VALUES (?, ?, ?, ?, '{}')`, scanID, entityID, kind, severity)
	if err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
