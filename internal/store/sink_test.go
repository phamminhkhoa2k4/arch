package store

import (
	"context"
	"database/sql"
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

// Findings persist with entity + optional evidence link; unknown refs and
// schema-incompatible kinds/severities are rejected at the boundary.
func TestSinkAddFinding(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	t.Run("full chain", func(t *testing.T) {
		k := newScan(t, s)
		if err := k.UpsertEntity(procEntity("p1")); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		if err := k.AddEvidence(collector.Evidence{
			EntityIdentityKey: "p1", Polarity: collector.PolarityNeutral,
			Channel: "unit_file", Strength: collector.StrengthDeterministic,
			ObservedAt: now(), RawRef: "/lib/systemd/system/a.service:12", Ref: "ev1",
		}); err != nil {
			t.Fatalf("evidence: %v", err)
		}
		if err := k.AddFinding(collector.Finding{
			EntityIdentityKey: "p1", Kind: "DANGLING_DEPENDS", Severity: "warn",
			EvidenceRef: "ev1", Detail: map[string]string{"missing": "ghost.service"},
		}); err != nil {
			t.Fatalf("add finding: %v", err)
		}

		var kind, sev, detail string
		var ev sql.NullInt64
		if err := s.db.QueryRowContext(ctx,
			`SELECT kind, severity, detail_json, evidence_id FROM findings`).Scan(
			&kind, &sev, &detail, &ev); err != nil {
			t.Fatalf("query: %v", err)
		}
		if kind != "DANGLING_DEPENDS" || sev != "warn" {
			t.Errorf("kind/sev = %q/%q", kind, sev)
		}
		if detail != `{"missing":"ghost.service"}` {
			t.Errorf("detail = %s", detail)
		}
		if !ev.Valid {
			t.Error("evidence_id must link the finding")
		}
	})

	t.Run("evidence link is optional", func(t *testing.T) {
		k := newScan(t, s)
		if err := k.UpsertEntity(procEntity("p2")); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		if err := k.AddFinding(collector.Finding{
			EntityIdentityKey: "p2", Kind: "DANGLING_DEPENDS", Severity: "info",
		}); err != nil {
			t.Fatalf("add finding without evidence: %v", err)
		}
	})

	t.Run("unknown entity rejected", func(t *testing.T) {
		k := newScan(t, s)
		err := k.AddFinding(collector.Finding{
			EntityIdentityKey: "ghost", Kind: "DANGLING_DEPENDS", Severity: "warn",
		})
		if err == nil || !strings.Contains(err.Error(), "unknown entity") {
			t.Errorf("got %v, want unknown entity error", err)
		}
	})

	t.Run("unknown evidence ref rejected", func(t *testing.T) {
		k := newScan(t, s)
		if err := k.UpsertEntity(procEntity("p3")); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		err := k.AddFinding(collector.Finding{
			EntityIdentityKey: "p3", Kind: "DANGLING_DEPENDS", Severity: "warn",
			EvidenceRef: "missing",
		})
		if err == nil || !strings.Contains(err.Error(), "evidence ref") {
			t.Errorf("got %v, want evidence ref error", err)
		}
	})

	t.Run("kind outside schema check rejected", func(t *testing.T) {
		k := newScan(t, s)
		if err := k.UpsertEntity(procEntity("p4")); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		err := k.AddFinding(collector.Finding{
			EntityIdentityKey: "p4", Kind: "NOT_A_KIND", Severity: "warn",
		})
		if err == nil || !strings.Contains(err.Error(), "CHECK") {
			t.Errorf("got %v, want CHECK constraint error", err)
		}
	})

	t.Run("severity outside schema check rejected", func(t *testing.T) {
		k := newScan(t, s)
		if err := k.UpsertEntity(procEntity("p5")); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		err := k.AddFinding(collector.Finding{
			EntityIdentityKey: "p5", Kind: "DANGLING_DEPENDS", Severity: "critical",
		})
		if err == nil || !strings.Contains(err.Error(), "CHECK") {
			t.Errorf("got %v, want CHECK constraint error", err)
		}
	})
}

// Processes group by their cgroup unit attribute; rows outside systemd
// (no unit) are omitted so no process ever gains a guessed owner.
func TestProcessRowsByUnit(t *testing.T) {
	s := openTemp(t)
	k := newScan(t, s)

	procs := []collector.Entity{
		{Kind: "process", Name: "app", IdentityKey: "process|100|1", Fingerprint: "f",
			Attributes: map[string]string{"unit": "app.service"}},
		{Kind: "process", Name: "app2", IdentityKey: "process|101|1", Fingerprint: "f",
			Attributes: map[string]string{"unit": "app.service"}},
		{Kind: "process", Name: "bare", IdentityKey: "process|102|1", Fingerprint: "f",
			Attributes: map[string]string{"pid": "102"}},
		{Kind: "listener", Name: ":80", IdentityKey: "listener|tcp|0.0.0.0|80",
			Fingerprint: "f", Attributes: map[string]string{"unit": "app.service"}},
	}
	for _, p := range procs {
		if err := k.UpsertEntity(p); err != nil {
			t.Fatalf("upsert %s: %v", p.IdentityKey, err)
		}
	}

	got, err := k.ProcessRowsByUnit()
	if err != nil {
		t.Fatalf("rows by unit: %v", err)
	}
	rows := got["app.service"]
	if len(rows) != 2 {
		t.Fatalf("app.service rows = %+v, want 2 processes", rows)
	}
	if rows[0].IdentityKey == "" || rows[0].Owner != "app.service" {
		t.Errorf("row = %+v", rows[0])
	}
	if _, ok := got[""]; ok {
		t.Error("unitless process must be omitted, not grouped under empty key")
	}
	if len(got) != 1 {
		t.Errorf("got %d unit groups, want only app.service", len(got))
	}
}

// Processes group by cgroup container id; processes outside any
// container are omitted so nothing gains a guessed owner.
func TestProcessRowsByContainer(t *testing.T) {
	s := openTemp(t)
	k := newScan(t, s)

	procs := []collector.Entity{
		{Kind: "process", Name: "in-a", IdentityKey: "process|200|1", Fingerprint: "f",
			Attributes: map[string]string{"container_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
		{Kind: "process", Name: "in-a-2", IdentityKey: "process|201|1", Fingerprint: "f",
			Attributes: map[string]string{"container_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
		{Kind: "process", Name: "bare", IdentityKey: "process|202|1", Fingerprint: "f",
			Attributes: map[string]string{"pid": "202"}},
		{Kind: "process", Name: "in-b", IdentityKey: "process|203|1", Fingerprint: "f",
			Attributes: map[string]string{"container_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},
	}
	for _, p := range procs {
		if err := k.UpsertEntity(p); err != nil {
			t.Fatalf("upsert %s: %v", p.IdentityKey, err)
		}
	}

	got, err := k.ProcessRowsByContainer()
	if err != nil {
		t.Fatalf("rows by container: %v", err)
	}
	a := got["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
	if len(a) != 2 {
		t.Fatalf("container a rows = %+v, want 2", a)
	}
	if a[0].Owner != a[0].IdentityKey && a[0].Owner == "" {
		t.Errorf("owner = %q, want container id", a[0].Owner)
	}
	if _, ok := got[""]; ok {
		t.Error("containerless process must be omitted")
	}
	if len(got) != 2 {
		t.Errorf("got %d groups, want 2", len(got))
	}
}

// ListenerRows exposes identity keys for published-port matching.
func TestListenerRows(t *testing.T) {
	s := openTemp(t)
	k := newScan(t, s)

	for _, e := range []collector.Entity{
		{Kind: "listener", Name: "0.0.0.0:8081",
			IdentityKey: "listener|tcp|0.0.0.0|8081|11", Fingerprint: "f"},
		{Kind: "listener", Name: "127.0.0.1:6379",
			IdentityKey: "listener|tcp|127.0.0.1|6379|22", Fingerprint: "f"},
		{Kind: "process", Name: "p", IdentityKey: "process|1|1", Fingerprint: "f"},
	} {
		if err := k.UpsertEntity(e); err != nil {
			t.Fatalf("upsert %s: %v", e.IdentityKey, err)
		}
	}

	rows, err := k.ListenerRows()
	if err != nil {
		t.Fatalf("listener rows: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d listener rows, want 2", len(rows))
	}
	if rows[0].IdentityKey != "listener|tcp|0.0.0.0|8081|11" || rows[0].Name != "0.0.0.0:8081" {
		t.Errorf("row[0] = %+v", rows[0])
	}
}

// UnitRows exposes identity keys for systemctl-reference matching.
func TestUnitRows(t *testing.T) {
	s := openTemp(t)
	k := newScan(t, s)

	for _, e := range []collector.Entity{
		{Kind: "systemd_unit", Name: "lab-batch.service",
			IdentityKey: "systemd_unit|lab-batch.service", Fingerprint: "f"},
		{Kind: "systemd_unit", Name: "ssh.service",
			IdentityKey: "systemd_unit|ssh.service", Fingerprint: "f"},
		{Kind: "process", Name: "p", IdentityKey: "process|1|1", Fingerprint: "f"},
	} {
		if err := k.UpsertEntity(e); err != nil {
			t.Fatalf("upsert %s: %v", e.IdentityKey, err)
		}
	}

	rows, err := k.UnitRows()
	if err != nil {
		t.Fatalf("unit rows: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d unit rows, want 2", len(rows))
	}
	if rows[0].IdentityKey != "systemd_unit|lab-batch.service" || rows[0].Name != "lab-batch.service" {
		t.Errorf("row[0] = %+v", rows[0])
	}
}

// ContainerRows exposes identity, name and image for command matching.
func TestContainerRows(t *testing.T) {
	s := openTemp(t)
	k := newScan(t, s)

	for _, e := range []collector.Entity{
		{Kind: "container", Name: "lab-cache",
			IdentityKey: "container|abc123", Fingerprint: "f",
			Attributes: map[string]string{"image": "redis:7-alpine"}},
		{Kind: "container", Name: "lab-web",
			IdentityKey: "container|def456", Fingerprint: "f",
			Attributes: map[string]string{"image": "nginx:alpine"}},
		{Kind: "listener", Name: "l", IdentityKey: "listener|tcp|0.0.0.0|80|1", Fingerprint: "f"},
	} {
		if err := k.UpsertEntity(e); err != nil {
			t.Fatalf("upsert %s: %v", e.IdentityKey, err)
		}
	}

	rows, err := k.ContainerRows()
	if err != nil {
		t.Fatalf("container rows: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d container rows, want 2", len(rows))
	}
	if rows[0].IdentityKey != "container|abc123" || rows[0].Name != "lab-cache" || rows[0].Image != "redis:7-alpine" {
		t.Errorf("row[0] = %+v", rows[0])
	}
}
