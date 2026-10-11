package bench

import (
	"context"
	"fmt"
	"io"
	"time"

	"archaeologist/internal/rules"
	"archaeologist/internal/store"
	"archaeologist/internal/verdict"
)

// False-orphan gate thresholds (go/no-go before the cleanup builder).
const (
	// MinLikelyPrecision is the required precision of
	// LIKELY_ORPHANED predictions on the lab ground truth.
	MinLikelyPrecision = 95.0
)

// componentVerdict is one computed verdict next to its expectation.
type componentVerdict struct {
	ID       string
	Trap     string
	Expected string
	Got      string
}

// CheckpointReport holds the false-orphan and precision metrics.
type CheckpointReport struct {
	// NonOrphanExpected is the false-orphan denominator: components
	// whose real state is not an orphan verdict (D2).
	NonOrphanExpected int
	// FalseOrphans lists every in-use component that received an
	// orphan verdict.
	FalseOrphans []componentVerdict
	// LikelyTP/LikelyFP split the LIKELY_ORPHANED predictions (D1):
	// a hit on expected ORPHANED counts as true, anything else false.
	LikelyTP     int
	LikelyFP     int
	LikelyFPList []componentVerdict
	// Predictions is LikelyTP+LikelyFP; zero means the precision is
	// vacuous and passes (D1).
	Predictions int
	// OrphanExpected/OrphanHits are the true-orphan recall: every
	// ground-truth component expected ORPHANED is a denominator slot;
	// an orphan verdict (LIKELY_ORPHANED or ORPHANED) on it is a hit.
	// Published, never gated.
	OrphanExpected int
	OrphanHits     int
	// TrapResults lists every trap component with its verdict so a
	// reader can see the three known traps did not flip.
	TrapResults []componentVerdict
	// Errors lists components that failed to resolve or compute.
	Errors []string
}

// MeasureCheckpoint computes the false-orphan rate and the
// LIKELY_ORPHANED precision against the ground truth components.
func MeasureCheckpoint(dbPath string, gt *GroundTruth, r rules.Rules) (*CheckpointReport, error) {
	ctx := context.Background()
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	defer func() { _ = st.Close() }()
	scanID, err := st.LatestScanID(ctx)
	if err != nil {
		return nil, fmt.Errorf("db: %w", err)
	}

	cp := &CheckpointReport{}
	now := time.Now().UTC()
	for _, comp := range gt.Components {
		ents, err := st.FindEntities(ctx, scanID, comp.Ref)
		if err != nil {
			cp.Errors = append(cp.Errors, fmt.Sprintf("%s: %v", comp.ID, err))
			continue
		}
		if len(ents) != 1 {
			cp.Errors = append(cp.Errors,
				fmt.Sprintf("%s: ref %q khớp %d entity", comp.ID, comp.Ref, len(ents)))
			continue
		}
		in, err := st.BuildInput(ctx, scanID, ents[0].ID)
		if err != nil {
			cp.Errors = append(cp.Errors, fmt.Sprintf("%s: %v", comp.ID, err))
			continue
		}
		got := string(verdict.Compute(in, r, now).State)
		cv := componentVerdict{ID: comp.ID, Trap: comp.Trap, Expected: comp.Expected, Got: got}

		if comp.Trap != "" {
			cp.TrapResults = append(cp.TrapResults, cv)
		}
		if comp.Expected == string(verdict.StateOrphaned) {
			continue // orphan-expected components sit outside D2/D1 sweeps
		}
		cp.NonOrphanExpected++
		if isOrphanVerdict(got) {
			cp.FalseOrphans = append(cp.FalseOrphans, cv)
		}
		if got == string(verdict.StateLikelyOrphaned) {
			// D1: LIKELY_ORPHANED on a non-orphan-expected component
			// is by definition a false positive.
			cp.LikelyFP++
			cp.LikelyFPList = append(cp.LikelyFPList, cv)
		}
	}
	// True positives + recall: pass over the orphan-expected
	// components once. LIKELY_ORPHANED is the precision true-positive;
	// any orphan claim counts toward recall. One pass keeps the first
	// loop single-exit and only touches the (few) orphan-expected
	// components.
	for _, comp := range gt.Components {
		if comp.Expected != string(verdict.StateOrphaned) {
			continue
		}
		cp.OrphanExpected++
		ents, err := st.FindEntities(ctx, scanID, comp.Ref)
		if err != nil || len(ents) != 1 {
			continue // recorded in Errors by the first pass when applicable
		}
		in, err := st.BuildInput(ctx, scanID, ents[0].ID)
		if err != nil {
			continue
		}
		got := verdict.Compute(in, r, now).State
		if got == string(verdict.StateLikelyOrphaned) {
			cp.LikelyTP++
		}
		if isOrphanVerdict(string(got)) {
			cp.OrphanHits++
		}
	}
	cp.Predictions = cp.LikelyTP + cp.LikelyFP
	return cp, nil
}

// Recall is the true-orphan recall in percent; an empty denominator is
// a vacuous 100%.
func (c *CheckpointReport) Recall() float64 {
	return percent(c.OrphanHits, c.OrphanExpected)
}

// Precision is the LIKELY_ORPHANED precision in percent; an empty
// prediction set is a vacuous 100% (D1).
func (c *CheckpointReport) Precision() float64 {
	if c.Predictions == 0 {
		return 100.0
	}
	return float64(c.LikelyTP) / float64(c.Predictions) * 100.0
}

// GateFailed reports a Checkpoint #2 miss: any false orphan, any
// unresolvable component, or a measured precision below threshold (D3).
func (c *CheckpointReport) GateFailed() bool {
	if len(c.FalseOrphans) > 0 || len(c.Errors) > 0 {
		return true
	}
	return c.Predictions > 0 && c.Precision() < MinLikelyPrecision
}

// isOrphanVerdict reports whether a state counts as an orphan claim.
func isOrphanVerdict(state string) bool {
	return state == string(verdict.StateLikelyOrphaned) || state == string(verdict.StateOrphaned)
}

// Write prints the checkpoint section; a miss adds a hard ::error
// annotation that fails the CI job (D3).
func (c *CheckpointReport) Write(out io.Writer) error {
	rate := 0.0
	if c.NonOrphanExpected > 0 {
		rate = float64(len(c.FalseOrphans)) / float64(c.NonOrphanExpected) * 100.0
	}
	if _, err := fmt.Fprintf(out, "False-orphan: %d/%d = %.1f%% (mục tiêu 0)\n",
		len(c.FalseOrphans), c.NonOrphanExpected, rate); err != nil {
		return err
	}
	for _, fo := range c.FalseOrphans {
		if _, err := fmt.Fprintf(out, "  false-orphan: %s (expected=%s got=%s)%s\n",
			fo.ID, fo.Expected, fo.Got, trapNote(fo)); err != nil {
			return err
		}
	}
	if c.Predictions == 0 {
		if _, err := fmt.Fprintln(out,
			"Precision LIKELY_ORPHANED: không có dự đoán (vacuous — đạt)"); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(out, "Precision LIKELY_ORPHANED: %d/%d = %.1f%% (mục tiêu ≥%.0f%%)\n",
			c.LikelyTP, c.Predictions, c.Precision(), MinLikelyPrecision); err != nil {
			return err
		}
		for _, fp := range c.LikelyFPList {
			if _, err := fmt.Fprintf(out, "  false-positive: %s (expected=%s)\n", fp.ID, fp.Expected); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprintf(out, "Recall ORPHANED: %d/%d = %.1f%% (informational)\n",
		c.OrphanHits, c.OrphanExpected, c.Recall()); err != nil {
		return err
	}
	if len(c.TrapResults) > 0 {
		if _, err := fmt.Fprintln(out, "Bẫy:"); err != nil {
			return err
		}
		for _, tr := range c.TrapResults {
			mark := "✓"
			if isOrphanVerdict(tr.Got) {
				mark = "✗"
			}
			if _, err := fmt.Fprintf(out, "  %s %s (%s) → %s (expected=%s)\n",
				mark, tr.ID, tr.Trap, tr.Got, tr.Expected); err != nil {
				return err
			}
		}
	}
	for _, e := range c.Errors {
		if _, err := fmt.Fprintf(out, "  lỗi component: %s\n", e); err != nil {
			return err
		}
	}
	if c.GateFailed() {
		if _, err := fmt.Fprintln(out,
			"::error title=checkpoint2::False-orphan hoặc precision LIKELY_ORPHANED dưới ngưỡng — chặn merge feature"); err != nil {
			return err
		}
	}
	return nil
}

// trapNote renders the optional trap tag for a listing line.
func trapNote(cv componentVerdict) string {
	if cv.Trap == "" {
		return ""
	}
	return " [bẫy: " + cv.Trap + "]"
}
