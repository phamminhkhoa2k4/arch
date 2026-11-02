package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"archaeologist/internal/collector"
)

// progressMode selects how scan progress reaches the user.
type progressMode int

const (
	// progressOff stays silent: machine consumers get a clean stream.
	progressOff progressMode = iota
	// progressPlain writes one line per phase for non-terminal writers.
	progressPlain
	// progressLive redraws a single animated line on a terminal.
	progressLive
)

// progressModeFor picks the mode for a scan's stderr writer. A
// terminal always gets the animated line (progress never touches
// stdout, so JSON output stays parseable); other writers get plain
// lines only for text output so redirected JSON pairs stay clean.
func progressModeFor(w io.Writer, format string) progressMode {
	if writerIsTerminal(w) && os.Getenv("TERM") != "dumb" {
		return progressLive
	}
	if format == formatText {
		return progressPlain
	}
	return progressOff
}

// writerIsTerminal reports whether w is a character device, i.e. an
// interactive terminal where in-place line updates render correctly.
func writerIsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// spinnerFrames rotate while a collector runs so a slow source still
// looks alive.
var spinnerFrames = [...]string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// scanProgress reports scan phases on stderr while the collectors run,
// so the command never looks frozen. stdout stays reserved for the
// command result: the summary and the --format json payload remain the
// only stdout content.
type scanProgress struct {
	w     io.Writer
	total int
	mode  progressMode

	mu       sync.Mutex
	stopped  bool
	rendered bool
	started  int
	label    string
	frame    int

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// newScanProgress builds a reporter for total collectors. A nil writer
// or progressOff mode yields a reporter that never writes.
func newScanProgress(w io.Writer, total int, mode progressMode) *scanProgress {
	if w == nil {
		mode = progressOff
	}
	p := &scanProgress{
		w:      w,
		total:  total,
		mode:   mode,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	if mode == progressLive {
		go p.tick()
	}
	return p
}

// tick redraws the animated line until stop ends the report.
func (p *scanProgress) tick() {
	defer close(p.doneCh)
	t := time.NewTicker(120 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-p.stopCh:
			return
		case <-t.C:
			p.mu.Lock()
			if !p.stopped {
				p.renderLocked()
			}
			p.mu.Unlock()
		}
	}
}

// start reports that the collector name just began running.
func (p *scanProgress) start(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped || p.mode == progressOff {
		return
	}
	p.started++
	p.reportLocked(fmt.Sprintf("collecting %s (%d/%d)", name, p.started, p.total))
}

// phase reports a named step that is not a collector, such as the
// verdict pass after collection finishes.
func (p *scanProgress) phase(label string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped || p.mode == progressOff {
		return
	}
	p.reportLocked(label)
}

// reportLocked publishes label in the active mode; callers hold p.mu.
func (p *scanProgress) reportLocked(label string) {
	p.label = label
	if p.mode == progressLive {
		p.renderLocked()
		return
	}
	_, _ = fmt.Fprintf(p.w, "scan: %s\n", label)
}

// renderLocked redraws the single in-place line; callers hold p.mu.
func (p *scanProgress) renderLocked() {
	p.frame++
	_, _ = fmt.Fprintf(p.w, "\r\033[K%s %s", spinnerFrames[p.frame%len(spinnerFrames)], p.label)
	p.rendered = true
}

// stop ends the report and clears the in-place line; later calls are
// no-ops, so it is safe to defer and also call before printing output.
func (p *scanProgress) stop() {
	p.stopOnce.Do(func() {
		p.mu.Lock()
		p.stopped = true
		live := p.mode == progressLive
		p.mu.Unlock()
		if !live {
			return
		}
		close(p.stopCh)
		<-p.doneCh
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.rendered {
			_, _ = fmt.Fprint(p.w, "\r\033[K")
		}
	})
}

// progressCollector announces each wrapped collector to the reporter so
// the progress line advances through the pipeline. Prefetch is
// forwarded to the inner collector when it warms data in the
// background, so wrapping never disables that optimization.
type progressCollector struct {
	inner collector.Collector
	prog  *scanProgress
}

func (c progressCollector) Name() string    { return c.inner.Name() }
func (c progressCollector) Version() string { return c.inner.Version() }

func (c progressCollector) Prefetch(ctx context.Context) {
	if pf, ok := c.inner.(collector.Prefetcher); ok {
		pf.Prefetch(ctx)
	}
}

func (c progressCollector) Collect(ctx context.Context, sink collector.Sink) error {
	c.prog.start(c.inner.Name())
	return c.inner.Collect(ctx, sink)
}
