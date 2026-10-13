package bench

import (
	"fmt"
	"io"
	"os"
)

// WriteReleaseNotes renders one release-notes markdown fragment from a
// completed run and writes it to path (creating parent directories).
// The fragment carries the lab description plus the published metric
// table; an empty path is a no-op.
func WriteReleaseNotes(path string, rec HistoryRecord) error {
	if path == "" {
		return nil
	}
	if dir := parentDir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("notes dir: %w", err)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("notes create: %w", err)
	}
	defer func() { _ = f.Close() }()
	return renderReleaseNotes(f, rec)
}

// renderReleaseNotes writes the markdown fragment: a heading, one line
// describing the lab that produced the numbers, and a metric table.
func renderReleaseNotes(out io.Writer, rec HistoryRecord) error {
	m := rec.Metrics
	if _, err := fmt.Fprintln(out, "## Benchmark"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out,
		"Measured on the lab golden fixture: a docker-compose scan database checked against the ground-truth YAML (reproduce with `make bench`)."); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, "| Metric | Value |"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, "| --- | --- |"); err != nil {
		return err
	}
	rows := []struct {
		name  string
		value string
	}{
		{"Listeners with owner", fmt.Sprintf("%.1f%%", m.OwnedPct)},
		{"Correct route chains", fmt.Sprintf("%.1f%%", m.RoutesPct)},
		{"False-orphan rate", fmt.Sprintf("%.1f%%", m.FalseOrphanRate)},
		{"LIKELY_ORPHANED precision", fmt.Sprintf("%.1f%% (%d predictions)",
			m.LikelyPrecision, m.LikelyPredictions)},
		{"ORPHANED recall", fmt.Sprintf("%.1f%% (%d expected)",
			m.OrphanRecall, m.OrphanExpected)},
		{"Evidence with raw_ref", fmt.Sprintf("%.1f%%", m.RawRefPct)},
	}
	for _, r := range rows {
		if _, err := fmt.Fprintf(out, "| %s | %s |\n", r.name, r.value); err != nil {
			return err
		}
	}
	return nil
}
