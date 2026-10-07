package store

import (
	"context"
	"testing"

	"archaeologist/internal/collector"
)

// LatestScanID returns the most recently inserted scan.
func TestLatestScanID(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	if _, err := s.LatestScanID(ctx); err == nil {
		t.Fatal("latest scan on empty db: want error, got nil")
	}

	hostID, err := s.InsertHost(ctx, "lab", "linux", "test")
	if err != nil {
		t.Fatalf("insert host: %v", err)
	}
	first, err := s.InsertScan(ctx, hostID, "v0.1", "{}")
	if err != nil {
		t.Fatalf("insert scan: %v", err)
	}
	second, err := s.InsertScan(ctx, hostID, "v0.1", "{}")
	if err != nil {
		t.Fatalf("insert scan: %v", err)
	}

	got, err := s.LatestScanID(ctx)
	if err != nil {
		t.Fatalf("latest scan: %v", err)
	}
	if got != second || got == first {
		t.Errorf("latest scan = %d, want %d (second insert)", got, second)
	}
}

// FindEntities: exact identity_key wins, name is the fallback, no match
// yields an empty slice.
func TestFindEntities(t *testing.T) {
	s := openTemp(t)
	k := newScan(t, s)
	ctx := context.Background()

	for _, e := range []collector.Entity{
		{Kind: "nginx_route", Name: "shared", IdentityKey: "nginx_route|/web/", Fingerprint: "f"},
		{Kind: "container", Name: "shared", IdentityKey: "container|abc", Fingerprint: "f"},
		{Kind: "process", Name: "nginx", IdentityKey: "process|1|2", Fingerprint: "f"},
	} {
		if err := k.UpsertEntity(e); err != nil {
			t.Fatalf("upsert %s: %v", e.IdentityKey, err)
		}
	}

	rows, err := s.FindEntities(ctx, k.scanID, "nginx_route|/web/")
	if err != nil {
		t.Fatalf("find by key: %v", err)
	}
	if len(rows) != 1 || rows[0].IdentityKey != "nginx_route|/web/" {
		t.Fatalf("find by key = %+v, want single identity match", rows)
	}

	rows, err = s.FindEntities(ctx, k.scanID, "shared")
	if err != nil {
		t.Fatalf("find by name: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("find by name = %d rows, want 2", len(rows))
	}

	rows, err = s.FindEntities(ctx, k.scanID, "missing")
	if err != nil {
		t.Fatalf("find missing: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("find missing = %+v, want empty", rows)
	}
}

// EvidenceFor lists an entity's evidence in insertion order; BlindSpotsFor
// lists only entity-scoped gaps (host-wide excluded).
func TestEvidenceAndBlindSpotsFor(t *testing.T) {
	s := openTemp(t)
	k := newScan(t, s)
	ctx := context.Background()

	key := "nginx_route|/web/"
	if err := k.UpsertEntity(collector.Entity{
		Kind: "nginx_route", Name: "/web/", IdentityKey: key, Fingerprint: "f",
		Attributes: map[string]string{"location": "/web/"},
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := k.AddEvidence(collector.Evidence{
		EntityIdentityKey: key,
		Polarity:          collector.PolarityInUse,
		Channel:           "nginx_access_log",
		Strength:          collector.StrengthDeterministic,
		ObservedAt:        now(),
		RawRef:            "/var/log/nginx/lab_access.log:3",
		Value:             map[string]string{"count": "2"},
	}); err != nil {
		t.Fatalf("add evidence: %v", err)
	}
	if err := k.AddEvidence(collector.Evidence{
		EntityIdentityKey: key,
		Polarity:          collector.PolarityNeutral,
		Channel:           "nginx",
		Strength:          collector.StrengthDeterministic,
		ObservedAt:        now(),
		RawRef:            "/etc/nginx/conf.d/lab.conf:14",
	}); err != nil {
		t.Fatalf("add evidence 2: %v", err)
	}
	if err := k.AddBlindSpot(collector.BlindSpot{
		EntityIdentityKey: key,
		Channel:           "log",
		Reason:            "log_retention_short",
		Detail:            map[string]string{"retention_days": "7"},
	}); err != nil {
		t.Fatalf("add blind: %v", err)
	}
	if err := k.AddBlindSpot(collector.BlindSpot{
		Channel: "docker",
		Reason:  "api_unreachable",
	}); err != nil {
		t.Fatalf("add host-wide blind: %v", err)
	}

	entities, err := s.FindEntities(ctx, k.scanID, key)
	if err != nil || len(entities) != 1 {
		t.Fatalf("resolve entity: %v, rows=%d", err, len(entities))
	}
	evid, err := s.EvidenceFor(ctx, entities[0].ID)
	if err != nil {
		t.Fatalf("evidence for: %v", err)
	}
	if len(evid) != 2 {
		t.Fatalf("got %d evidence rows, want 2", len(evid))
	}
	if evid[0].Channel != "nginx_access_log" || evid[0].RawRef != "/var/log/nginx/lab_access.log:3" {
		t.Errorf("evidence[0] = %+v", evid[0])
	}
	if evid[0].Value["count"] != "2" {
		t.Errorf("evidence[0].Value = %+v", evid[0].Value)
	}
	if evid[1].Channel != "nginx" || evid[1].Value == nil {
		t.Errorf("evidence[1] = %+v", evid[1])
	}

	blinds, err := s.BlindSpotsFor(ctx, entities[0].ID)
	if err != nil {
		t.Fatalf("blind spots for: %v", err)
	}
	if len(blinds) != 1 {
		t.Fatalf("got %d blind rows, want 1 (host-wide excluded)", len(blinds))
	}
	if blinds[0].Reason != "log_retention_short" || blinds[0].Detail["retention_days"] != "7" {
		t.Errorf("blind[0] = %+v", blinds[0])
	}
}
