package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"archaeologist/internal/collector"
)

// newScan creates host+scan rows and returns a sink bound to them.
func newScan(t *testing.T, s *Store) *ScanSink {
	t.Helper()
	ctx := context.Background()
	hostID, err := s.InsertHost(ctx, "lab", "linux", "test")
	if err != nil {
		t.Fatalf("insert host: %v", err)
	}
	scanID, err := s.InsertScan(ctx, hostID, "v0.1-test", "{}")
	if err != nil {
		t.Fatalf("insert scan: %v", err)
	}
	return NewScanSink(ctx, s, scanID)
}

func procEntity(key string) collector.Entity {
	return collector.Entity{
		Kind: "process", Name: "nginx", IdentityKey: key, Fingerprint: "fp1",
		Attributes: map[string]string{"pid": "1"},
	}
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// Positive path: entity → evidence → edge → blind spot land in the schema.
func TestSinkFullChain(t *testing.T) {
	s := openTemp(t)
	k := newScan(t, s)
	ctx := context.Background()

	if err := k.UpsertEntity(procEntity("process|1|100")); err != nil {
		t.Fatalf("upsert entity: %v", err)
	}
	listener := collector.Entity{
		Kind: "listener", Name: ":8080", IdentityKey: "listener|tcp|0.0.0.0|8080",
		Fingerprint: "fp2", Attributes: map[string]string{"port": "8080"},
	}
	if err := k.UpsertEntity(listener); err != nil {
		t.Fatalf("upsert listener: %v", err)
	}
	if err := k.AddEvidence(collector.Evidence{
		EntityIdentityKey: listener.IdentityKey, Polarity: collector.PolarityInUse,
		Channel: "procfs_net", Strength: collector.StrengthDeterministic,
		ObservedAt: now(), RawRef: "/proc/net/tcp:0", Ref: "listen-8080",
	}); err != nil {
		t.Fatalf("add evidence: %v", err)
	}
	if err := k.UpsertEdge(collector.Edge{
		SrcIdentityKey: listener.IdentityKey, DstIdentityKey: "process|1|100",
		Kind: "listens_on", Strength: collector.StrengthDeterministic,
		EvidenceRef: "listen-8080",
	}); err != nil {
		t.Fatalf("upsert edge: %v", err)
	}
	if err := k.AddBlindSpot(collector.BlindSpot{
		EntityIdentityKey: listener.IdentityKey, Channel: "listener_mapping",
		Reason: "permission_denied", Detail: map[string]string{"port": "8080"},
	}); err != nil {
		t.Fatalf("add blind spot: %v", err)
	}
	if err := k.AddBlindSpot(collector.BlindSpot{
		Channel: "process", Reason: "permission_denied",
	}); err != nil {
		t.Fatalf("add host-wide blind spot: %v", err)
	}

	var entities, edges, evidence, blind int
	for _, q := range []struct {
		sql string
		dst *int
	}{
		{`SELECT count(*) FROM entities`, &entities},
		{`SELECT count(*) FROM edges`, &edges},
		{`SELECT count(*) FROM evidence`, &evidence},
		{`SELECT count(*) FROM blind_spots`, &blind},
	} {
		if err := s.db.QueryRowContext(ctx, q.sql).Scan(q.dst); err != nil {
			t.Fatalf("count %s: %v", q.sql, err)
		}
	}
	if entities != 2 || edges != 1 || evidence != 1 || blind != 2 {
		t.Errorf("got entities=%d edges=%d evidence=%d blind=%d, want 2/1/1/2",
			entities, edges, evidence, blind)
	}

	// Entity-scoped blind spot must link to the entity; host-wide one must not.
	var scoped, hostWide int
	_ = s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM blind_spots WHERE entity_id IS NOT NULL`).Scan(&scoped)
	_ = s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM blind_spots WHERE entity_id IS NULL`).Scan(&hostWide)
	if scoped != 1 || hostWide != 1 {
		t.Errorf("blind spot scoping: scoped=%d hostWide=%d, want 1/1", scoped, hostWide)
	}
}

// Same identity key twice in one scan keeps one row with a stable id.
func TestSinkUpsertEntityIsIdempotentWithinScan(t *testing.T) {
	s := openTemp(t)
	k := newScan(t, s)
	ctx := context.Background()

	if err := k.UpsertEntity(procEntity("process|1|100")); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	updated := procEntity("process|1|100")
	updated.Fingerprint = "fp2"
	if err := k.UpsertEntity(updated); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	var n int
	var fp string
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*), max(fingerprint) FROM entities
		 WHERE identity_key = 'process|1|100'`).Scan(&n, &fp); err != nil {
		t.Fatalf("query: %v", err)
	}
	if n != 1 || fp != "fp2" {
		t.Errorf("rows=%d fingerprint=%q, want 1 row with fp2", n, fp)
	}
}

// Negative proof: the sink rejects malformed chains instead of guessing.
func TestSinkRejectsBrokenChains(t *testing.T) {
	s := openTemp(t)

	t.Run("evidence for unknown entity", func(t *testing.T) {
		k := newScan(t, s)
		err := k.AddEvidence(collector.Evidence{
			EntityIdentityKey: "ghost", Polarity: collector.PolarityInUse,
			Channel: "x", Strength: collector.StrengthDeterministic,
			ObservedAt: now(), RawRef: "/proc/1/stat",
		})
		if err == nil || !strings.Contains(err.Error(), "unknown entity") {
			t.Errorf("got %v, want unknown entity error", err)
		}
	})

	t.Run("empty raw_ref rejected", func(t *testing.T) {
		k := newScan(t, s)
		if err := k.UpsertEntity(procEntity("p1")); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		err := k.AddEvidence(collector.Evidence{
			EntityIdentityKey: "p1", Polarity: collector.PolarityInUse,
			Channel: "x", Strength: collector.StrengthDeterministic,
			ObservedAt: now(), RawRef: "",
		})
		if err == nil || !strings.Contains(err.Error(), "raw_ref") {
			t.Errorf("got %v, want raw_ref error", err)
		}
	})

	t.Run("edge with unresolved evidence ref", func(t *testing.T) {
		k := newScan(t, s)
		if err := k.UpsertEntity(procEntity("p1")); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		if err := k.UpsertEntity(procEntity("p2")); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		err := k.UpsertEdge(collector.Edge{
			SrcIdentityKey: "p1", DstIdentityKey: "p2", Kind: "listens_on",
			Strength: collector.StrengthDeterministic, EvidenceRef: "missing",
		})
		if err == nil || !strings.Contains(err.Error(), "evidence ref") {
			t.Errorf("got %v, want evidence ref error", err)
		}
	})

	t.Run("duplicate evidence ref", func(t *testing.T) {
		k := newScan(t, s)
		if err := k.UpsertEntity(procEntity("p1")); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		ev := collector.Evidence{
			EntityIdentityKey: "p1", Polarity: collector.PolarityInUse,
			Channel: "x", Strength: collector.StrengthDeterministic,
			ObservedAt: now(), RawRef: "/proc/1/stat", Ref: "r1",
		}
		if err := k.AddEvidence(ev); err != nil {
			t.Fatalf("first evidence: %v", err)
		}
		if err := k.AddEvidence(ev); err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Errorf("got %v, want duplicate ref error", err)
		}
	})

	t.Run("blind spot for unknown entity", func(t *testing.T) {
		k := newScan(t, s)
		err := k.AddBlindSpot(collector.BlindSpot{
			EntityIdentityKey: "ghost", Channel: "process", Reason: "permission_denied",
		})
		if err == nil || !strings.Contains(err.Error(), "unknown entity") {
			t.Errorf("got %v, want unknown entity error", err)
		}
	})
}

// Nil attribute/value/detail maps serialize as "{}", never JSON "null",
// so downstream readers (report, UI) always see an object.
func TestSinkNilMapsMarshalAsEmptyObject(t *testing.T) {
	s := openTemp(t)
	k := newScan(t, s)
	ctx := context.Background()

	if err := k.UpsertEntity(collector.Entity{
		Kind: "process", Name: "p", IdentityKey: "process|9|1", Fingerprint: "fp",
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := k.AddEvidence(collector.Evidence{
		EntityIdentityKey: "process|9|1", Polarity: collector.PolarityInUse,
		Channel: "procfs", Strength: collector.StrengthDeterministic,
		ObservedAt: now(), RawRef: "/proc/9/stat", Ref: "r1",
	}); err != nil {
		t.Fatalf("evidence: %v", err)
	}
	if err := k.AddBlindSpot(collector.BlindSpot{
		EntityIdentityKey: "process|9|1", Channel: "process", Reason: "read_error",
	}); err != nil {
		t.Fatalf("blind spot: %v", err)
	}

	var attrs, val, detail string
	if err := s.db.QueryRowContext(ctx,
		`SELECT attributes_json FROM entities WHERE identity_key='process|9|1'`).Scan(&attrs); err != nil {
		t.Fatalf("query attrs: %v", err)
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT value_json FROM evidence`).Scan(&val); err != nil {
		t.Fatalf("query value: %v", err)
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT detail_json FROM blind_spots`).Scan(&detail); err != nil {
		t.Fatalf("query detail: %v", err)
	}
	for name, got := range map[string]string{"attributes": attrs, "value": val, "detail": detail} {
		if got != "{}" {
			t.Errorf("%s = %q, want {}", name, got)
		}
	}
}
