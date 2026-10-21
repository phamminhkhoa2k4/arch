package collector

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Prefetcher optionally warms read-only data before Collect runs.
// Run drives prefetchers in the background, one at a time, while the
// collect loop runs serially. External reads (journals, container APIs,
// unit files) therefore overlap collection without competing with each
// other, and every sink write stays ordered. Implementations must not
// touch the sink and must store their own errors for Collect.
type Prefetcher interface {
	Prefetch(ctx context.Context)
}

// RunResult summarizes one collect pass.
type RunResult struct {
	// Failed lists collectors that returned an error; each failure is also
	// recorded as a blind spot so the scan continues. Run keeps it non-nil
	// so serialized results emit an empty array when every collector works.
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
	res := RunResult{Failed: []string{}}
	pctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	// Prefetchers run one at a time but overlap the collect loop: two
	// heavy external scans (the systemd and cron journals both walk the
	// same journal) compete for the same disk when started together,
	// while serial prefetch lets each one use the full device during
	// the collector that follows it.
	go func() {
		defer wg.Done()
		for _, c := range cs {
			p, ok := c.(Prefetcher)
			if !ok {
				continue
			}
			if pctx.Err() != nil {
				return
			}
			p.Prefetch(pctx)
		}
	}()
	// Prefetchers only read; once any Collect path is done (including
	// a fatal error) cancel the rest and wait so no goroutine outlives
	// the scan.
	defer func() {
		cancel()
		wg.Wait()
	}()

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
