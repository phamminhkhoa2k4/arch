package bench

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// HistoryRecord is one JSONL line appended per benchmark run so runs
// can be compared over time.
type HistoryRecord struct {
	GeneratedAt string         `json:"generated_at"`
	GitSHA      string         `json:"git_sha"`
	Metrics     HistoryMetrics `json:"metrics"`
	Gates       HistoryGates   `json:"gates"`
}

// HistoryMetrics are the published numbers of one run. Nullable fields
// stay pointers so "unknown" is distinguishable from zero.
type HistoryMetrics struct {
	OwnedPct          float64 `json:"owned_pct"`
	RoutesPct         float64 `json:"routes_pct"`
	FalseOrphanRate   float64 `json:"false_orphan_rate"`
	LikelyPrecision   float64 `json:"likely_precision"`
	LikelyPredictions int     `json:"likely_predictions"`
	OrphanRecall      float64 `json:"orphan_recall"`
	OrphanExpected    int     `json:"orphan_expected"`
	RawRefPct         float64 `json:"raw_ref_pct"`
	ScanSeconds       *int    `json:"scan_seconds"`
	Observe           string  `json:"observe"`
}

// HistoryGates records whether the blocking gate passed.
type HistoryGates struct {
	CheckpointFailed bool `json:"checkpoint_failed"`
}

// gitSHA resolves the current commit for the history line: the CI
// environment variable wins, then a local rev-parse, then "unknown".
func gitSHA() string {
	if sha := os.Getenv("GITHUB_SHA"); sha != "" {
		return sha
	}
	out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// newHistoryRecord assembles the JSONL line for one completed run.
// The reports are always non-nil when called from Run.
func newHistoryRecord(rep *Report, cp *CheckpointReport, integ *IntegrityReport) HistoryRecord {
	return HistoryRecord{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		GitSHA:      gitSHA(),
		Metrics: HistoryMetrics{
			OwnedPct:          rep.OwnedPct,
			RoutesPct:         rep.RoutesPct,
			FalseOrphanRate:   falseOrphanRate(cp),
			LikelyPrecision:   cp.Precision(),
			LikelyPredictions: cp.Predictions,
			OrphanRecall:      cp.Recall(),
			OrphanExpected:    cp.OrphanExpected,
			RawRefPct:         integ.RawRefPct,
			ScanSeconds:       integ.ScanSeconds,
			Observe:           integ.Observe,
		},
		Gates: HistoryGates{CheckpointFailed: cp.GateFailed()},
	}
}

// falseOrphanRate recomputes the printed rate for the JSON line.
func falseOrphanRate(cp *CheckpointReport) float64 {
	if cp.NonOrphanExpected == 0 {
		return 0.0
	}
	return float64(len(cp.FalseOrphans)) / float64(cp.NonOrphanExpected) * 100.0
}

// AppendHistory appends one JSON line to path, creating parent
// directories as needed. An empty path is a no-op.
func AppendHistory(path string, rec HistoryRecord) error {
	if path == "" {
		return nil
	}
	if dir := parentDir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("history dir: %w", err)
		}
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("history marshal: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("history open: %w", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("history write: %w", err)
	}
	return nil
}

func parentDir(path string) string {
	i := strings.LastIndexAny(path, `/\`)
	if i < 0 {
		return ""
	}
	return path[:i]
}
