package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"archaeologist/internal/collector"
	dcoll "archaeologist/internal/collector/docker"
	"archaeologist/internal/collector/listener"
	ncoll "archaeologist/internal/collector/nginx"
	"archaeologist/internal/collector/process"
	sysd "archaeologist/internal/collector/systemd"
	"archaeologist/internal/compose"
	dengine "archaeologist/internal/docker"
	"archaeologist/internal/nginx"
	"archaeologist/internal/procfs"
	"archaeologist/internal/store"
	"archaeologist/internal/systemd"
)

// newScanCmd wires the real scan pipeline: open the database, run the
// collectors through the shared framework, print a summary.
func newScanCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan the host and print an infrastructure summary",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScan(cmd.Context(), cmd.OutOrStdout(), dbPath, Version)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "archaeologist.db",
		"path to the SQLite evidence database")
	return cmd
}

func runScan(ctx context.Context, w io.Writer, dbPath, toolVersion string) error {
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer func() { _ = st.Close() }()

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	hostID, err := st.InsertHost(ctx, hostname, "linux", kernelRelease())
	if err != nil {
		return err
	}

	fs := procfs.OSReader{}
	bus := systemd.NewDBusBus()
	loader := systemd.NewLoader(systemd.OSFS{})
	// Order matters: the listener collector emits edges to process
	// entities and the systemd collector reads the process snapshot, so
	// both run after the process collector. The docker collector matches
	// published ports against listeners and cgroup container ids, so it
	// runs before nginx, which matches proxy targets against the same
	// listener snapshot. The systemd, docker and nginx collectors need
	// the sink as their index, but the sink only exists after the scan
	// row is created — build the list twice (Versions needs only
	// names/versions).
	type scanIndex interface {
		sysd.ProcessIndex
		dcoll.Index
		ncoll.Index
	}
	newCollectors := func(index scanIndex) []collector.Collector {
		var sIdx sysd.ProcessIndex
		var dIdx dcoll.Index
		var nIdx ncoll.Index
		if index != nil {
			sIdx = index
			dIdx = index
			nIdx = index
		}
		return []collector.Collector{
			process.New(fs),
			listener.New(fs),
			sysd.New(bus, loader, sIdx),
			dcoll.New(dengine.NewClient(dengine.DefaultSocket), compose.NewLoader(), dIdx),
			ncoll.New(nginx.NewLoader(), nIdx),
		}
	}
	cs := newCollectors(nil)
	scanID, err := st.InsertScan(ctx, hostID, toolVersion, collector.Versions(cs))
	if err != nil {
		return err
	}

	sink := store.NewScanSink(ctx, st, scanID)
	cs = newCollectors(sink)
	res, err := collector.Run(ctx, cs, sink)
	if err != nil {
		_ = st.FinishScan(ctx, scanID, "failed")
		return fmt.Errorf("scan: %w", err)
	}
	status := "ok"
	if res.Partial() {
		status = "partial"
	}
	if err := st.FinishScan(ctx, scanID, status); err != nil {
		return err
	}

	sum, err := st.ScanSummary(ctx, scanID)
	if err != nil {
		return err
	}
	return printScanSummary(w, scanID, hostname, status, res.Failed, sum)
}

func printScanSummary(
	w io.Writer,
	scanID int64,
	hostname, status string,
	failed []string,
	sum store.Summary,
) error {
	if _, err := fmt.Fprintf(w, "Scan #%d — host=%s status=%s\n", scanID, hostname, status); err != nil {
		return err
	}
	kinds := make([]string, 0, len(sum.Entities))
	for k := range sum.Entities {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		if _, err := fmt.Fprintf(w, "  %-10s %d\n", k+":", sum.Entities[k]); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "  %-10s %d\n", "blind spots:", sum.BlindSpots); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  %-10s %d\n", "findings:", sum.Findings); err != nil {
		return err
	}
	if len(failed) > 0 {
		// Every failure is already recorded as a blind spot.
		if _, err := fmt.Fprintf(w, "  failed collectors: %s\n", strings.Join(failed, ", ")); err != nil {
			return err
		}
	}
	return nil
}

// kernelRelease reads /proc/sys/kernel/osrelease (read-only).
func kernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
