// Package mtime collects filesystem modification times for the
// file-backed entities recorded earlier in the scan (scripts,
// binaries) as neutral activity signals for later rules (US-6.3).
//
// Evidence only: attributes belong to the collectors that own the
// entities, so this collector never upserts.
package mtime

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"time"

	"archaeologist/internal/collector"
)

// Index supplies the paths of file-backed entities recorded earlier
// in the scan. Implemented by the scan's sink.
type Index interface {
	PathRows() ([]collector.PathRow, error)
}

// Collector stats one path per file-backed entity.
type Collector struct {
	index Index
}

// New returns the mtime collector. index may be nil only when the
// collector is used for name/version registration, not Collect.
func New(index Index) *Collector { return &Collector{index: index} }

// Name implements collector.Collector.
func (c *Collector) Name() string { return "mtime" }

// Version implements collector.Collector.
func (c *Collector) Version() string { return "1.0.0" }

// Collect stats every recorded path. A vanished file is already
// covered by the orphan findings of earlier epics; an unreadable path
// becomes a blind spot.
func (c *Collector) Collect(ctx context.Context, sink collector.Sink) error {
	if c.index == nil {
		return errors.New("mtime collector: no path index")
	}
	rows, err := c.index.PathRows()
	if err != nil {
		return fmt.Errorf("path rows: %w", err)
	}
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		fi, err := os.Stat(row.Path)
		switch {
		case err == nil:
		case errors.Is(err, fs.ErrNotExist):
			continue
		default:
			if bErr := sink.AddBlindSpot(collector.BlindSpot{
				EntityIdentityKey: row.IdentityKey,
				Channel:           "mtime",
				Reason:            "mtime_unreadable",
				Detail:            map[string]string{"path": row.Path, "error": err.Error()},
			}); bErr != nil {
				return bErr
			}
			continue
		}
		mt := fi.ModTime().UTC()
		age := int(time.Now().UTC().Sub(mt).Hours() / 24)
		if age < 0 {
			age = 0
		}
		if err := sink.AddEvidence(collector.Evidence{
			EntityIdentityKey: row.IdentityKey,
			Polarity:          collector.PolarityNeutral,
			Channel:           "mtime",
			Strength:          collector.StrengthDeterministic,
			ObservedAt:        time.Now().UTC().Format(time.RFC3339),
			RawRef:            row.Path,
			Ref:               "mtime:" + row.IdentityKey,
			Value: map[string]string{
				"mtime":    mt.Format(time.RFC3339),
				"age_days": strconv.Itoa(age),
				"path":     row.Path,
			},
		}); err != nil {
			return err
		}
	}
	return nil
}
