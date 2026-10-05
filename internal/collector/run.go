package collector

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// RunResult summarizes one collect pass.
type RunResult struct {
	// Failed lists collectors that returned an error; each failure is also
	// recorded as a blind spot so the scan continues.
	Failed []string
}

// Partial reports whether any collector failed — scan status becomes "partial".
func (r RunResult) Partial() bool { return len(r.Failed) > 0 }

// Versions returns the collector_versions_json payload: name → version.
func Versions(cs []Collector) string {
	names := make([]string, 0, len(cs))
	byName := make(map[string]string, len(cs))
	for _, c := range cs {
		names = append(names, c.Name())
		byName[c.Name()] = c.Version()
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%q:%q", n, byName[n]))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// Run executes every collector against the sink.
//
// A collector error is converted into a blind spot (channel = collector name,
// reason = error) and recorded in the result instead of aborting the scan,
// so one broken source never crashes the whole run.
func Run(ctx context.Context, cs []Collector, sink Sink) (RunResult, error) {
	var res RunResult
	for _, c := range cs {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if err := c.Collect(ctx, sink); err != nil {
			res.Failed = append(res.Failed, c.Name())
			bs := BlindSpot{
				Channel: c.Name(),
				Reason:  "collector_error",
				Detail:  map[string]string{"error": err.Error()},
			}
			if sinkErr := sink.AddBlindSpot(bs); sinkErr != nil {
				return res, fmt.Errorf("record blind spot for %s: %w", c.Name(), sinkErr)
			}
		}
	}
	return res, nil
}
