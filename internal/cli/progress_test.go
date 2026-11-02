package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"archaeologist/internal/collector"
)

// Text scan streams collector progress on stderr; stdout keeps only
// the summary so pipes and scripts stay clean.
func TestScanProgressStreamsOnStderr(t *testing.T) {
	db := filepath.Join(t.TempDir(), "scan.db")
	root := rootCmd()
	addCommands(root)
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	root.SetArgs([]string{"scan", "--db", db})

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("scan: %v\nstderr:\n%s", err, errBuf.String())
	}

	progOut := errBuf.String()
	first := regexp.MustCompile(`scan: collecting process \(1/\d+\)`)
	last := regexp.MustCompile(`scan: collecting git \(\d+/\d+\)`)
	if !first.MatchString(progOut) {
		t.Errorf("first collector progress missing on stderr:\n%s", progOut)
	}
	if !last.MatchString(progOut) {
		t.Errorf("last collector progress missing on stderr:\n%s", progOut)
	}
	if !strings.Contains(progOut, "scan: computing verdicts") {
		t.Errorf("verdict phase missing on stderr:\n%s", progOut)
	}
	if strings.Contains(out.String(), "scan: collecting") {
		t.Errorf("progress leaked to stdout:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "status=") {
		t.Errorf("summary missing on stdout:\n%s", out.String())
	}
}

// JSON scan keeps stderr silent for non-terminal writers so redirected
// output pairs stay machine-clean.
func TestScanProgressSilentForJSON(t *testing.T) {
	db := filepath.Join(t.TempDir(), "scan.db")
	root := rootCmd()
	addCommands(root)
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	root.SetArgs([]string{"scan", "--db", db, "--format", "json"})

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("scan: %v\n%s", err, errBuf.String())
	}
	if errBuf.Len() != 0 {
		t.Errorf("stderr not clean under --format json:\n%s", errBuf.String())
	}
	var payload struct {
		ScanID int64 `json:"scan_id"`
	}
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("json parse: %v\n%s", err, out.String())
	}
	if payload.ScanID <= 0 {
		t.Errorf("scan_id = %d, want > 0", payload.ScanID)
	}
}

// Plain mode writes one line per phase and stays idempotent on stop.
func TestScanProgressPlainMode(t *testing.T) {
	var buf bytes.Buffer
	prog := newScanProgress(&buf, 2, progressPlain)
	prog.start("alpha")
	prog.start("beta")
	prog.phase("computing verdicts")
	prog.stop()
	prog.stop() // second stop must not double-report or panic
	want := "scan: collecting alpha (1/2)\n" +
		"scan: collecting beta (2/2)\n" +
		"scan: computing verdicts\n"
	if buf.String() != want {
		t.Errorf("progress output = %q, want %q", buf.String(), want)
	}
}

// Live mode redraws one in-place line and clears it on stop so the
// summary prints from column zero.
func TestScanProgressLiveModeRedrawsInPlace(t *testing.T) {
	var buf bytes.Buffer
	prog := newScanProgress(&buf, 2, progressLive)
	prog.start("alpha")
	prog.phase("computing verdicts")
	prog.stop()
	prog.stop()
	out := buf.String()
	if !strings.Contains(out, "\r") || !strings.Contains(out, "\033[K") {
		t.Errorf("no in-place redraw: %q", out)
	}
	if !strings.Contains(out, "collecting alpha (1/2)") {
		t.Errorf("collector label missing: %q", out)
	}
	if !strings.Contains(out, "computing verdicts") {
		t.Errorf("phase label missing: %q", out)
	}
	if !strings.HasSuffix(out, "\r\033[K") {
		t.Errorf("line not cleared on stop: %q", out)
	}
}

// A nil writer disables progress instead of panicking.
func TestScanProgressNilWriterIsSilent(t *testing.T) {
	prog := newScanProgress(nil, 1, progressPlain)
	prog.start("alpha")
	prog.phase("computing verdicts")
	prog.stop()
}

// Mode selection: terminals animate, other writers get plain lines
// only for text output, regular files are never treated as terminals.
func TestProgressModeFor(t *testing.T) {
	var buf bytes.Buffer
	if got := progressModeFor(&buf, formatText); got != progressPlain {
		t.Errorf("buffer + text = %v, want plain", got)
	}
	if got := progressModeFor(&buf, formatJSON); got != progressOff {
		t.Errorf("buffer + json = %v, want off", got)
	}
	f, err := os.CreateTemp(t.TempDir(), "not-a-terminal")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	t.Cleanup(func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	})
	if got := progressModeFor(f, formatText); got != progressPlain {
		t.Errorf("regular file + text = %v, want plain", got)
	}
	if got := progressModeFor(f, formatJSON); got != progressOff {
		t.Errorf("regular file + json = %v, want off", got)
	}
}

// stubCollector records collect calls for the wrapper tests.
type stubCollector struct {
	name          string
	collected     int
	beforeCollect func()
}

func (s *stubCollector) Name() string    { return s.name }
func (s *stubCollector) Version() string { return "stub" }
func (s *stubCollector) Collect(context.Context, collector.Sink) error {
	if s.beforeCollect != nil {
		s.beforeCollect()
	}
	s.collected++
	return nil
}

// warmStubCollector also warms data before collection, like the
// sources that prefetch journals and container lists. warmed is atomic
// because the run loop's prefetch pass writes it from its own
// goroutine.
type warmStubCollector struct {
	stubCollector
	warmed atomic.Bool
}

func (s *warmStubCollector) Prefetch(context.Context) { s.warmed.Store(true) }

// noopSink satisfies the collector sink without recording anything.
type noopSink struct{}

func (noopSink) UpsertEntity(collector.Entity) error    { return nil }
func (noopSink) UpsertEdge(collector.Edge) error        { return nil }
func (noopSink) AddEvidence(collector.Evidence) error   { return nil }
func (noopSink) AddBlindSpot(collector.BlindSpot) error { return nil }
func (noopSink) AddFinding(collector.Finding) error     { return nil }

// The wrapper forwards identity and background prefetch to the inner
// collector while reporting each collect start.
func TestProgressCollectorForwardsHooks(t *testing.T) {
	var buf bytes.Buffer
	prog := newScanProgress(&buf, 2, progressPlain)

	warm := &warmStubCollector{stubCollector: stubCollector{name: "warm"}}
	wrappedWarm := progressCollector{inner: warm, prog: prog}
	wrappedWarm.Prefetch(context.Background())
	if !warm.warmed.Load() {
		t.Error("prefetch not forwarded to the inner collector")
	}
	if wrappedWarm.Name() != "warm" || wrappedWarm.Version() != "stub" {
		t.Errorf("identity not forwarded: %s/%s", wrappedWarm.Name(), wrappedWarm.Version())
	}
	if err := wrappedWarm.Collect(context.Background(), noopSink{}); err != nil {
		t.Fatalf("collect warm: %v", err)
	}

	plain := &stubCollector{name: "plain"}
	wrappedPlain := progressCollector{inner: plain, prog: prog}
	wrappedPlain.Prefetch(context.Background()) // no prefetch support: must be a no-op
	if err := wrappedPlain.Collect(context.Background(), noopSink{}); err != nil {
		t.Fatalf("collect plain: %v", err)
	}
	if warm.collected != 1 || plain.collected != 1 {
		t.Errorf("inner collect calls = warm %d, plain %d, want 1 each", warm.collected, plain.collected)
	}

	out := buf.String()
	if !strings.Contains(out, "scan: collecting warm (1/2)") ||
		!strings.Contains(out, "scan: collecting plain (2/2)") {
		t.Errorf("progress lines missing:\n%s", out)
	}
}

// The wrapper stays compatible with the core run loop, including its
// background prefetch pass.
func TestProgressCollectorInsideRun(t *testing.T) {
	var buf bytes.Buffer
	prog := newScanProgress(&buf, 2, progressPlain)
	warm := &warmStubCollector{stubCollector: stubCollector{name: "beta"}}
	// The first collector blocks until the background prefetch pass has
	// warmed the second, so the assertion proves the run loop drives
	// Prefetch through the wrapper instead of racing past it.
	alpha := &stubCollector{name: "alpha", beforeCollect: func() {
		deadline := time.Now().Add(2 * time.Second)
		for !warm.warmed.Load() && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	}}
	cs := []collector.Collector{
		progressCollector{inner: alpha, prog: prog},
		progressCollector{inner: warm, prog: prog},
	}

	res, err := collector.Run(context.Background(), cs, noopSink{})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Partial() {
		t.Errorf("failed collectors = %v, want none", res.Failed)
	}
	if !warm.warmed.Load() {
		t.Error("background prefetch disabled by the wrapper")
	}
	out := buf.String()
	if !strings.Contains(out, "scan: collecting alpha (1/2)") ||
		!strings.Contains(out, "scan: collecting beta (2/2)") {
		t.Errorf("progress lines missing:\n%s", out)
	}
}
