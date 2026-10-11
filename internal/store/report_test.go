package store

import (
	"context"
	"testing"

	"archaeologist/internal/collector"
)

// Findings join their entity; host-wide and entity-scoped blind spots
// both appear; the scan header carries hostname and status.
func TestReportQueries(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	k := newScan(t, s)

	e := procEntity("process|1|1")
	if err := k.UpsertEntity(e); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	entityID := k.entities[e.IdentityKey]
	insertFindingRaw(t, s, ctx, k.scanID, entityID, "BROKEN_ROUTE", "warn")
	insertFindingRaw(t, s, ctx, k.scanID, entityID, "ORPHAN_CRON", "info")

	if err := k.AddBlindSpot(collector.BlindSpot{
		EntityIdentityKey: e.IdentityKey, Channel: "process",
		Reason: "permission_denied", Detail: map[string]string{"pid": "1"},
	}); err != nil {
		t.Fatalf("entity blind: %v", err)
	}
	if err := k.AddBlindSpot(collector.BlindSpot{
		Channel: "systemd", Reason: "dbus_unavailable",
		Detail: map[string]string{"error": "connection refused"},
	}); err != nil {
		t.Fatalf("host blind: %v", err)
	}

	findings, err := s.FindingsInScan(ctx, k.scanID)
	if err != nil {
		t.Fatalf("findings: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	// ORDER BY severity DESC: "warn" > "info".
	if findings[0].Kind != "BROKEN_ROUTE" || findings[0].Severity != "warn" {
		t.Errorf("first finding = %s/%s, want BROKEN_ROUTE/warn", findings[0].Kind, findings[0].Severity)
	}
	if findings[0].EntityKind != "process" || findings[0].EntityName != "nginx" {
		t.Errorf("finding entity = %s/%s, want process/nginx", findings[0].EntityKind, findings[0].EntityName)
	}
	if findings[0].Identity != e.IdentityKey {
		t.Errorf("finding identity = %q, want %q", findings[0].Identity, e.IdentityKey)
	}

	blinds, err := s.BlindSpotsInScan(ctx, k.scanID)
	if err != nil {
		t.Fatalf("blind spots: %v", err)
	}
	if len(blinds) != 2 {
		t.Fatalf("got %d blind spots, want 2", len(blinds))
	}
	var hostWide, scoped bool
	for _, b := range blinds {
		if b.Channel == "systemd" && b.EntityName == "" {
			hostWide = true
			if b.Detail["error"] != "connection refused" {
				t.Errorf("host-wide detail lost: %+v", b.Detail)
			}
		}
		if b.Channel == "process" && b.EntityName == "nginx" {
			scoped = true
		}
	}
	if !hostWide || !scoped {
		t.Errorf("blind spots wrong: hostWide=%v scoped=%v %+v", hostWide, scoped, blinds)
	}

	host, status, err := s.ScanHostStatus(ctx, k.scanID)
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	if host != "lab" || (status != "ok" && status != "partial") {
		t.Errorf("header = %s/%s, want lab + ok/partial", host, status)
	}
}

// Empty scan yields empty slices, not nil-crash.
func TestReportQueriesEmptyScan(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	k := newScan(t, s)

	findings, err := s.FindingsInScan(ctx, k.scanID)
	if err != nil || len(findings) != 0 {
		t.Errorf("findings = %v err=%v, want empty", findings, err)
	}
	blinds, err := s.BlindSpotsInScan(ctx, k.scanID)
	if err != nil || len(blinds) != 0 {
		t.Errorf("blinds = %v err=%v, want empty", blinds, err)
	}
	if _, _, err := s.ScanHostStatus(ctx, 99999); err == nil {
		t.Error("missing scan must error")
	}
}
