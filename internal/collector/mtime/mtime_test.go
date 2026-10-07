package mtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"archaeologist/internal/collector"
)

// recSink records everything the collector emits.
type recSink struct {
	entities map[string]collector.Entity
	evidence []collector.Evidence
	blinds   []collector.BlindSpot
}

func newRecSink() *recSink { return &recSink{entities: map[string]collector.Entity{}} }

func (r *recSink) UpsertEntity(e collector.Entity) error {
	r.entities[e.IdentityKey] = e
	return nil
}
func (r *recSink) UpsertEdge(e collector.Edge) error { return nil }
func (r *recSink) AddEvidence(e collector.Evidence) error {
	r.evidence = append(r.evidence, e)
	return nil
}
func (r *recSink) AddBlindSpot(b collector.BlindSpot) error {
	r.blinds = append(r.blinds, b)
	return nil
}
func (r *recSink) AddFinding(f collector.Finding) error { return nil }

// fakeIndex serves fixed path rows.
type fakeIndex struct {
	rows []collector.PathRow
	err  error
}

func (f *fakeIndex) PathRows() ([]collector.PathRow, error) { return f.rows, f.err }

// US-6.3 AC2: mtime becomes a neutral signal with the exact mtime and
// age; the entity is never re-upserted (evidence only).
func TestCollectMtimeEvidence(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "backup.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Date(2025, 1, 5, 12, 0, 0, 0, time.UTC)
	if err := os.Chtimes(script, old, old); err != nil {
		t.Fatal(err)
	}

	c := New(&fakeIndex{rows: []collector.PathRow{
		{IdentityKey: "script|" + script, Path: script},
		{IdentityKey: "script|" + filepath.Join(dir, "gone.sh"),
			Path: filepath.Join(dir, "gone.sh")},
	}})
	sink := newRecSink()
	if err := c.Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}

	if len(sink.evidence) != 1 {
		t.Fatalf("evidence = %+v, want 1 (missing file adds none)", sink.evidence)
	}
	e := sink.evidence[0]
	if e.EntityIdentityKey != "script|"+script || e.Channel != "mtime" ||
		e.Polarity != collector.PolarityNeutral ||
		e.Strength != collector.StrengthDeterministic {
		t.Errorf("evidence = %+v", e)
	}
	if e.RawRef != script {
		t.Errorf("raw_ref = %q, want the file path", e.RawRef)
	}
	if e.Value["mtime"] != old.Format(time.RFC3339) {
		t.Errorf("mtime = %q, want %q", e.Value["mtime"], old.Format(time.RFC3339))
	}
	if e.Value["age_days"] == "" || e.Value["path"] != script {
		t.Errorf("value = %+v", e.Value)
	}
	if e.ObservedAt == "" {
		t.Error("observed_at must be set")
	}
	if len(sink.blinds) != 0 {
		t.Errorf("missing file must stay silent (orphan findings cover it): %+v", sink.blinds)
	}
}

// An unstatable path is reported, not guessed over.
func TestCollectUnreadableBlind(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "locked.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o755) }()

	c := New(&fakeIndex{rows: []collector.PathRow{
		{IdentityKey: "script|" + script, Path: script},
	}})
	sink := newRecSink()
	if err := c.Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(sink.evidence) != 0 {
		t.Errorf("evidence = %+v, want none", sink.evidence)
	}
	if len(sink.blinds) != 1 || sink.blinds[0].Reason != "mtime_unreadable" ||
		sink.blinds[0].Channel != "mtime" ||
		sink.blinds[0].EntityIdentityKey != "script|"+script {
		t.Errorf("blinds = %+v, want one mtime_unreadable", sink.blinds)
	}
}

// A failing index surfaces instead of producing half a scan.
func TestCollectIndexError(t *testing.T) {
	c := New(&fakeIndex{err: os.ErrPermission})
	if err := c.Collect(context.Background(), newRecSink()); err == nil {
		t.Fatal("want error from failing index")
	}
}

// Without an index the collector refuses to run.
func TestCollectNilIndex(t *testing.T) {
	if err := New(nil).Collect(context.Background(), newRecSink()); err == nil {
		t.Fatal("want error for nil index")
	}
}
