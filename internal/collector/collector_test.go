package collector

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// mockSink captures everything collectors emit.
type mockSink struct {
	entities   []Entity
	edges      []Edge
	evidence   []Evidence
	blindSpots []BlindSpot
	failOnAdd  bool
}

func (m *mockSink) UpsertEntity(e Entity) error {
	if m.failOnAdd {
		return errors.New("sink unavailable")
	}
	m.entities = append(m.entities, e)
	return nil
}

func (m *mockSink) UpsertEdge(e Edge) error {
	m.edges = append(m.edges, e)
	return nil
}

func (m *mockSink) AddEvidence(e Evidence) error {
	m.evidence = append(m.evidence, e)
	return nil
}

func (m *mockSink) AddBlindSpot(b BlindSpot) error {
	m.blindSpots = append(m.blindSpots, b)
	return nil
}

// mockCollector is a minimal implementation of the Collector interface.
type mockCollector struct{}

func (mockCollector) Name() string    { return "mock" }
func (mockCollector) Version() string { return "0.0.1" }
func (mockCollector) Collect(_ context.Context, sink Sink) error {
	if err := sink.UpsertEntity(Entity{
		Kind: "process", Name: "init", IdentityKey: "pid:1", Fingerprint: "fp:init",
	}); err != nil {
		return err
	}
	return sink.AddEvidence(Evidence{
		EntityIdentityKey: "pid:1",
		Polarity:          PolarityInUse,
		Channel:           "test",
		Strength:          StrengthDeterministic,
		ObservedAt:        "2026-10-03T00:00:00Z",
		RawRef:            "/proc/1/stat:1",
		Ref:               "ev:1",
	})
}

// failingCollector simulates a permission error (US-0.2 AC).
type failingCollector struct{}

func (failingCollector) Name() string    { return "denied" }
func (failingCollector) Version() string { return "0.0.1" }
func (failingCollector) Collect(context.Context, Sink) error {
	return errors.New("permission denied reading /proc/999")
}

// US-0.2 AC 1: core runs any collector through the shared interface.
func TestRunCallsCollectorThroughInterface(t *testing.T) {
	cs := []Collector{mockCollector{}}
	sink := &mockSink{}

	res, err := Run(context.Background(), cs, sink)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Partial() {
		t.Fatalf("unexpected failure: %v", res.Failed)
	}
	if len(sink.entities) != 1 || sink.entities[0].Name != "init" {
		t.Fatalf("entities = %+v", sink.entities)
	}
	if len(sink.evidence) != 1 || sink.evidence[0].RawRef == "" {
		t.Fatalf("evidence missing or untraceable: %+v", sink.evidence)
	}
}

// US-0.2 AC 2: a failing collector becomes a blind spot, not a crash.
func TestRunRecordsFailureAsBlindSpot(t *testing.T) {
	sink := &mockSink{}
	res, err := Run(context.Background(), []Collector{failingCollector{}}, sink)
	if err != nil {
		t.Fatalf("run must not fail: %v", err)
	}
	if !res.Partial() {
		t.Fatal("result should be partial")
	}
	if len(sink.blindSpots) != 1 {
		t.Fatalf("want 1 blind spot, got %d", len(sink.blindSpots))
	}
	bs := sink.blindSpots[0]
	if bs.Channel != "denied" || bs.Reason != "collector_error" {
		t.Fatalf("blind spot = %+v", bs)
	}
	if !strings.Contains(bs.Detail["error"], "permission denied") {
		t.Fatalf("error detail lost: %+v", bs.Detail)
	}
}

// US-0.2 AC 3: every collector's Version feeds collector_versions_json.
func TestVersionsPayload(t *testing.T) {
	got := Versions([]Collector{mockCollector{}, failingCollector{}})
	if !strings.Contains(got, `"mock":"0.0.1"`) || !strings.Contains(got, `"denied":"0.0.1"`) {
		t.Fatalf("versions = %s", got)
	}
}
