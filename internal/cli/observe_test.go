package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"archaeologist/internal/observe"
)

// fakeObserver counts samples and optionally fires a signal per call.
type fakeObserver struct {
	samples atomic.Int64
	ch      chan struct{}
	err     error
	sets    atomic.Int64
}

func (f *fakeObserver) SampleOnce(ctx context.Context) (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	f.samples.Add(1)
	if f.ch != nil {
		select {
		case f.ch <- struct{}{}:
		default:
		}
	}
	return 3, nil
}

func (f *fakeObserver) SetListeners([]observe.Listener) { f.sets.Add(1) }

func TestObserveLoopPrintsSamplesAndStops(t *testing.T) {
	f := &fakeObserver{ch: make(chan struct{}, 8)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var buf bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- observeLoop(ctx, &buf, f, time.Millisecond, false, func() error { return nil })
	}()
	// Wait for at least two samples, then stop.
	for i := 0; i < 2; i++ {
		select {
		case <-f.ch:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for samples")
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("observeLoop: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "lần mẫu") {
		t.Errorf("output missing per-sample line: %q", out)
	}
	if !strings.Contains(out, "observe: dừng sau") {
		t.Errorf("output missing stop line: %q", out)
	}
	if n := f.samples.Load(); n < 2 {
		t.Errorf("samples = %d, want ≥2", n)
	}
}

func TestObserveLoopDaemonIsQuiet(t *testing.T) {
	f := &fakeObserver{ch: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- observeLoop(ctx, &bufNull{}, f, time.Millisecond, true, func() error { return nil })
	}()
	select {
	case <-f.ch:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a sample")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("observeLoop: %v", err)
	}
}

// bufNull swallows output (daemon mode must print nothing).
type bufNull struct{}

func (*bufNull) Write(p []byte) (int, error) { return len(p), nil }

func TestObserveLoopLoadErrorFailsFast(t *testing.T) {
	f := &fakeObserver{}
	err := observeLoop(context.Background(), &bufNull{}, f, time.Millisecond, false,
		func() error { return errors.New("chưa có scan nào") })
	if err == nil || !strings.Contains(err.Error(), "chưa có scan") {
		t.Fatalf("err = %v, want load failure", err)
	}
	if f.samples.Load() != 0 {
		t.Errorf("samples = %d, want 0", f.samples.Load())
	}
}

func TestObserveLoopRejectsBadInterval(t *testing.T) {
	err := observeLoop(context.Background(), &bufNull{}, &fakeObserver{}, 0, false,
		func() error { return nil })
	if err == nil || !strings.Contains(err.Error(), "--interval") {
		t.Fatalf("err = %v, want interval rejection", err)
	}
}

// A failing sample costs one round, not the daemon: the loop keeps
// ticking and surfaces the error on its output instead of exiting.
func TestObserveLoopSurvivesSampleError(t *testing.T) {
	f := &fakeObserver{err: errors.New("proc hỏng")}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var buf bytes.Buffer
	var loads atomic.Int64
	done := make(chan error, 1)
	go func() {
		done <- observeLoop(ctx, &buf, f, time.Millisecond, false,
			func() error {
				if loads.Add(1) >= 3 {
					cancel()
				}
				return nil
			})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("observeLoop must survive sample errors, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not survive sample errors")
	}
	if !strings.Contains(buf.String(), "Error: lấy mẫu") {
		t.Errorf("output missing sample error line: %q", buf.String())
	}
	if loads.Load() < 3 {
		t.Errorf("load called %d times, want ≥3", loads.Load())
	}
}

// A transient listener-load failure mid-run is logged and retried on
// the next tick (a concurrent scan may hold the database).
func TestObserveLoopSurvivesLoadError(t *testing.T) {
	f := &fakeObserver{ch: make(chan struct{}, 8)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var buf bytes.Buffer
	var loads atomic.Int64
	done := make(chan error, 1)
	go func() {
		done <- observeLoop(ctx, &buf, f, time.Millisecond, false,
			func() error {
				n := loads.Add(1)
				if n == 2 || n == 3 { // initial load succeeds; next two rounds fail
					return errors.New("database is locked")
				}
				return nil
			})
	}()
	select {
	case <-f.ch: // reached only after a successful load
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a sample after load errors")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("observeLoop must survive load errors, got %v", err)
	}
	if !strings.Contains(buf.String(), "Error: tải listener") {
		t.Errorf("output missing load error line: %q", buf.String())
	}
}

func TestObserveCmdFlags(t *testing.T) {
	cmd := newObserveCmd()
	for _, name := range []string{"db", "interval", "daemon"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("missing flag %q", name)
		}
	}
}

func TestObserveServiceSubcommands(t *testing.T) {
	cmd := newObserveCmd()
	names := map[string]bool{}
	for _, c := range cmd.Commands() {
		names[c.Name()] = true
	}
	for _, want := range []string{"install-service", "uninstall-service"} {
		if !names[want] {
			t.Errorf("observe missing subcommand %q", want)
		}
	}
}
