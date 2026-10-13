package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"archaeologist/internal/collector/listener"
	"archaeologist/internal/observe"
	"archaeologist/internal/procfs"
	"archaeologist/internal/store"
	"archaeologist/internal/systemd"
)

// observer is the sampler surface the loop drives (faked in tests).
type observer interface {
	SampleOnce(ctx context.Context) (int, error)
	SetListeners(ls []observe.Listener)
}

// newObserveCmd wires the sampling daemon: a foreground loop (D1) —
// --daemon only silences the per-sample output, systemd or nohup owns
// the backgrounding, never a double fork.
func newObserveCmd() *cobra.Command {
	var (
		dbPath   string
		interval time.Duration
		daemon   bool
	)
	cmd := &cobra.Command{
		Use:   "observe",
		Short: "Sample network activity to measure real usage over time",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runObserve(cmd.Context(), cmd.OutOrStdout(), dbPath, interval, daemon)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "archaeologist.db",
		"path to the SQLite evidence database")
	cmd.Flags().DurationVar(&interval, "interval", 5*time.Second,
		"how often to sample the socket tables")
	cmd.Flags().BoolVar(&daemon, "daemon", false,
		"quiet long-running mode (backgrounding is done by systemd or nohup)")
	cmd.AddCommand(newObserveInstallCmd(), newObserveUninstallCmd())
	return cmd
}

// newObserveInstallCmd installs and enables the systemd service that
// keeps the daemon running. Writing that unit file is the one place
// this tool modifies the system outside its own database.
func newObserveInstallCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "install-service",
		Short: "Install and enable the systemd observation service",
		RunE: func(cmd *cobra.Command, _ []string) error {
			bin, err := os.Executable()
			if err != nil {
				return fmt.Errorf("cannot find binary: %w", err)
			}
			if resolved, rerr := filepath.EvalSymlinks(bin); rerr == nil {
				bin = resolved
			}
			abs, err := filepath.Abs(dbPath)
			if err != nil {
				return fmt.Errorf("db path: %w", err)
			}
			inst := systemd.NewInstall(systemd.NewOSUnitWriter(), systemd.NewExecRunner())
			return inst.InstallService(cmd.Context(),
				systemd.ServiceSpec{Binary: bin, DBPath: abs})
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "archaeologist.db",
		"path to the SQLite evidence database the daemon writes")
	return cmd
}

// newObserveUninstallCmd stops, disables and removes the service.
func newObserveUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall-service",
		Short: "Stop, disable and remove the systemd observation service",
		RunE: func(cmd *cobra.Command, _ []string) error {
			inst := systemd.NewInstall(systemd.NewOSUnitWriter(), systemd.NewExecRunner())
			return inst.UninstallService(cmd.Context())
		},
	}
}

func runObserve(ctx context.Context, w io.Writer, dbPath string, interval time.Duration, daemon bool) error {
	if interval <= 0 {
		return fmt.Errorf("--interval must be greater than 0")
	}
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer func() { _ = st.Close() }()

	sampler := observe.New(procfs.OSReader{}, st, nil)
	load := func() error {
		rows, err := st.LatestListeners(ctx)
		if err != nil {
			return err
		}
		ls := make([]observe.Listener, 0, len(rows))
		for _, r := range rows {
			proto, addr, port, _, err := listener.ParseIdentityKey(r.IdentityKey)
			if err != nil {
				continue // one malformed key must not stop the daemon
			}
			ls = append(ls, observe.Listener{ID: r.ID, Proto: proto, Addr: addr, Port: port})
		}
		sampler.SetListeners(ls)
		return nil
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	return observeLoop(ctx, w, sampler, interval, daemon, load)
}

// observeLoop samples on a ticker until the context is cancelled. The
// listener set reloads every round so a rescan mid-run re-points the
// daemon at the newest entity ids (D3).
func observeLoop(ctx context.Context, w io.Writer, s observer, interval time.Duration, daemon bool, load func() error) error {
	if interval <= 0 {
		return fmt.Errorf("--interval must be greater than 0")
	}
	if err := load(); err != nil {
		return err
	}
	// One start banner even in daemon mode: the journal then always
	// shows when the sampler came up.
	_, _ = fmt.Fprintf(w, "observe: interval %v — starting\n", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	rounds := 0
	for {
		select {
		case <-ctx.Done():
			if !daemon {
				_, _ = fmt.Fprintf(w, "observe: stopped after %d sample rounds\n", rounds)
			}
			return nil
		case <-ticker.C:
			rounds++
			// A transient failure (a concurrent scan holding the
			// database lock, a reader error) must cost one round,
			// never the whole daemon: log and try again next tick.
			if err := load(); err != nil {
				_, _ = fmt.Fprintf(w, "Error: loading listeners: %v\n", err)
				continue
			}
			n, err := s.SampleOnce(ctx)
			if err != nil {
				_, _ = fmt.Fprintf(w, "Error: sampling: %v\n", err)
				continue
			}
			if !daemon {
				_, _ = fmt.Fprintf(w, "sample round %d: %d pairs\n", rounds, n)
			}
		}
	}
}
