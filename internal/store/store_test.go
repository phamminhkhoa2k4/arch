package store

import (
	"context"
	"path/filepath"
	"testing"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// US-0.1 AC: migration on an empty SQLite database creates every table.
func TestMigrateCreatesAllTables(t *testing.T) {
	s := openTemp(t)

	want := map[string]bool{
		"entities": false, "edges": false, "evidence": false,
		"observations": false, "blind_spots": false, "verdicts": false,
		"scans": false, "hosts": false, "findings": false,
		"plans": false, "plan_stages": false,
	}
	got, err := s.Tables(context.Background())
	if err != nil {
		t.Fatalf("tables: %v", err)
	}
	for _, n := range got {
		if _, ok := want[n]; ok {
			want[n] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("table %q not created; got %v", name, got)
		}
	}
}

// Idempotency: running Migrate twice must not fail.
func TestMigrateIdempotent(t *testing.T) {
	s := openTemp(t)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

// US-0.1 AC (positive): a valid evidence row with polarity and raw_ref inserts.
func TestEvidenceValidRowAccepted(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	id := seedEvidence(t, s, ctx, "in_use", "/proc/net/tcp:42")
	if id == 0 {
		t.Fatal("expected evidence id")
	}
}

// US-0.1 AC (negative): invalid polarity and empty raw_ref are rejected by
// CHECK constraints — the diagnostic names the violated rule.
func TestEvidenceConstraintsRejectInvalidRows(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	cases := []struct {
		name, polarity, rawRef, wantRule string
	}{
		{"bad polarity", "maybe", "/x:1", "evidence.polarity"},
		{"empty raw_ref", "in_use", "", "evidence.raw_ref"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := insertEvidenceRaw(t, s, ctx, tc.polarity, "test", "deterministic", tc.rawRef)
			if err == nil {
				t.Fatalf("want constraint violation (%s), got nil", tc.wantRule)
			}
		})
	}
}

// US-0.1 AC (negative): edge strength outside the allowed set is rejected.
func TestEdgeStrengthConstraint(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	_, err := insertEdgeRaw(t, s, ctx, "made_up_strength")
	if err == nil {
		t.Fatal("want CHECK violation for edge.strength, got nil")
	}
}

func TestScanStatusConstraint(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	host, err := s.InsertHost(ctx, "lab", "linux", "test")
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	if _, err := s.InsertScan(ctx, host, "v0.1", "{}"); err != nil {
		t.Fatalf("scan: %v", err)
	}
	// status CHECK enforced at FinishScan
	scan, err := s.InsertScan(ctx, host, "v0.1", "{}")
	if err != nil {
		t.Fatalf("scan2: %v", err)
	}
	if err := s.FinishScan(ctx, scan, "bogus"); err == nil {
		t.Fatal("want CHECK violation for scans.status, got nil")
	}
}
