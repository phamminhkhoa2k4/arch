package bench

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The release-notes fragment carries the heading, the lab description,
// and one table row per published metric with the run's numbers.
func TestRenderReleaseNotes(t *testing.T) {
	rec := HistoryRecord{Metrics: HistoryMetrics{
		OwnedPct:          96.5,
		RoutesPct:         100.0,
		FalseOrphanRate:   0.0,
		LikelyPrecision:   100.0,
		LikelyPredictions: 3,
		OrphanRecall:      100.0,
		OrphanExpected:    4,
		RawRefPct:         100.0,
	}}
	var buf bytes.Buffer
	if err := renderReleaseNotes(&buf, rec); err != nil {
		t.Fatalf("render: %v", err)
	}
	got := buf.String()
	wantParts := []string{
		"## Benchmark",
		"make bench",
		"| Listeners with owner | 96.5% |",
		"| Correct route chains | 100.0% |",
		"| False-orphan rate | 0.0% |",
		"| LIKELY_ORPHANED precision | 100.0% (3 predictions) |",
		"| ORPHANED recall | 100.0% (4 expected) |",
		"| Evidence with raw_ref | 100.0% |",
	}
	for _, w := range wantParts {
		if !strings.Contains(got, w) {
			t.Errorf("notes missing %q:\n%s", w, got)
		}
	}
}

// WriteReleaseNotes creates the parent directory and the file; an
// empty path is a no-op.
func TestWriteReleaseNotes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "notes.md")
	rec := HistoryRecord{Metrics: HistoryMetrics{OwnedPct: 100.0}}
	if err := WriteReleaseNotes(path, rec); err != nil {
		t.Fatalf("write: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.Contains(string(data), "| Listeners with owner | 100.0% |") {
		t.Errorf("written notes missing metric row:\n%s", data)
	}
	if err := WriteReleaseNotes("", rec); err != nil {
		t.Errorf("empty path no-op: %v", err)
	}
}
