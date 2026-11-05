package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"archaeologist/internal/rules"
	"archaeologist/internal/store"
	"archaeologist/internal/systemd"
)

// Observation daemon states reported by `observe status`.
const (
	daemonActive   = "active"
	daemonInactive = "inactive"
	daemonUnknown  = "unknown"
)

// observeDaemonProbe reports whether the observation systemd service
// is running. An error means systemd itself is unreachable, which the
// caller reports as the unknown state instead of failing the command.
type observeDaemonProbe interface {
	DaemonState(ctx context.Context) (string, error)
}

// systemdDaemonProbe reads the unit's runtime state from the system
// bus. A unit that is not loaded this boot has never run here, so it
// reports inactive rather than unknown.
type systemdDaemonProbe struct{}

func (systemdDaemonProbe) DaemonState(_ context.Context) (string, error) {
	loaded, err := systemd.NewDBusBus().LoadedUnits()
	if err != nil {
		return daemonUnknown, err
	}
	for _, u := range loaded {
		if u.Name != systemd.UnitName {
			continue
		}
		if u.ActiveState == "active" {
			return daemonActive, nil
		}
		return daemonInactive, nil
	}
	return daemonInactive, nil
}

// newObserveStatusCmd wires the observation summary: daemon state,
// window progress, and observation coverage — read only.
func newObserveStatusCmd() *cobra.Command {
	var dbPath, rulesPath string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show daemon state, observation window progress, and sample coverage",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, _ := cmd.Flags().GetString("format")
			return runObserveStatus(cmd.Context(), cmd.OutOrStdout(),
				dbPath, rulesPath, format, systemdDaemonProbe{})
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "archaeologist.db",
		"path to the SQLite evidence database")
	cmd.Flags().StringVar(&rulesPath, "rules-file", "",
		"path to a rules.yaml override (default: embedded rules)")
	addFormatFlag(cmd)
	return cmd
}

// windowStatusJSON is the observation window of the latest scan.
type windowStatusJSON struct {
	Start  string `json:"start"`
	End    string `json:"end"`
	Days   int    `json:"days"`
	Source string `json:"source"`
}

// observationStatusJSON is the observation-table coverage summary.
type observationStatusJSON struct {
	First   *string `json:"first"`   // earliest bucket; null when none
	Latest  *string `json:"latest"`  // newest sample; null when none
	Buckets int     `json:"buckets"` // distinct hour buckets
}

// observeStatusJSON is the whole `observe status --format json`
// document.
type observeStatusJSON struct {
	Daemon        string                `json:"daemon"`
	DaemonDetail  string                `json:"daemon_detail"` // why the state is unknown
	Unit          string                `json:"unit"`
	ScanID        int64                 `json:"scan_id"`
	Window        windowStatusJSON      `json:"window"`
	RequiredDays  int                   `json:"required_days"`
	WindowReady   bool                  `json:"window_ready"`
	DaysRemaining int                   `json:"days_remaining"`
	ReadyAt       *string               `json:"ready_at"` // earliest sufficient date
	Observations  observationStatusJSON `json:"observations"`
}

// runObserveStatus summarizes how far the observation has progressed.
// A failed daemon probe degrades to state "unknown" — the window and
// sample facts come from the database and must still be reported.
func runObserveStatus(ctx context.Context, w io.Writer, dbPath, rulesPath, format string, probe observeDaemonProbe) error {
	if err := validateFormat(format); err != nil {
		return err
	}
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer func() { _ = st.Close() }()

	scanID, err := st.LatestScanID(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("no scans recorded in %s — run `scan --db %s` first", dbPath, dbPath)
	}
	if err != nil {
		return err
	}
	win, err := st.Window(ctx, scanID)
	if err != nil {
		return err
	}
	r, _, err := rules.Load(rulesPath)
	if err != nil {
		return err
	}
	required := r.Thresholds.ObservationWindowDays
	stats, err := st.ObservationStats(ctx)
	if err != nil {
		return err
	}

	daemon, detail := daemonUnknown, ""
	if state, perr := probe.DaemonState(ctx); perr == nil {
		daemon = state
	} else {
		detail = perr.Error()
	}

	remaining := required - win.Days
	if remaining < 0 {
		remaining = 0
	}
	doc := observeStatusJSON{
		Daemon:        daemon,
		DaemonDetail:  detail,
		Unit:          systemd.UnitName,
		ScanID:        scanID,
		Window:        windowStatusJSON{Start: win.Start, End: win.End, Days: win.Days, Source: win.Source},
		RequiredDays:  required,
		WindowReady:   win.Days >= required,
		DaysRemaining: remaining,
		ReadyAt:       windowReadyAt(win.Start, required),
		Observations: observationStatusJSON{
			First:   nullIfEmpty(stats.FirstBucket),
			Latest:  nullIfEmpty(stats.LatestSeen),
			Buckets: stats.Buckets,
		},
	}

	if format == formatJSON {
		return writeJSON(w, doc)
	}
	return printObserveStatus(w, doc)
}

// nullIfEmpty exposes an absent timestamp as a JSON null.
func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// printObserveStatus renders the fixed status layout from the same
// document the JSON format emits.
func printObserveStatus(w io.Writer, doc observeStatusJSON) error {
	daemon := fmt.Sprintf("daemon:       %s (%s)", doc.Daemon, doc.Unit)
	switch doc.Daemon {
	case daemonUnknown:
		if doc.DaemonDetail != "" {
			daemon += " — systemd unreachable: " + doc.DaemonDetail
		}
	case daemonInactive:
		daemon += " — start it with `observe install-service` or `systemctl start " + doc.Unit + "`"
	}
	if _, err := fmt.Fprintln(w, "Observation status"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "  "+daemon); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  scan:         #%d\n", doc.ScanID); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  window:       %s → %s (%d days, source=%s)\n",
		doc.Window.Start, doc.Window.End, doc.Window.Days, doc.Window.Source); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  required:     %d days\n", doc.RequiredDays); err != nil {
		return err
	}
	check, err := windowCheckLine(doc)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "  "+check); err != nil {
		return err
	}
	obs := "  observations: none yet"
	if doc.Observations.First != nil {
		obs = fmt.Sprintf("  observations: first %s · latest %s · %d buckets",
			*doc.Observations.First, orEmptyStr(doc.Observations.Latest), doc.Observations.Buckets)
	}
	_, err = fmt.Fprintln(w, obs)
	return err
}

// windowCheckLine renders the acceptance line: how many days are
// still missing, and the earliest date the window can qualify.
func windowCheckLine(doc observeStatusJSON) (string, error) {
	if doc.WindowReady {
		if doc.ReadyAt != nil {
			return fmt.Sprintf("window check: sufficient since %s (%d of %d required days)",
				*doc.ReadyAt, doc.Window.Days, doc.RequiredDays), nil
		}
		return fmt.Sprintf("window check: sufficient (%d of %d required days)",
			doc.Window.Days, doc.RequiredDays), nil
	}
	if doc.ReadyAt != nil {
		return fmt.Sprintf("window check: %d days remaining — earliest sufficient date %s",
			doc.DaysRemaining, *doc.ReadyAt), nil
	}
	return fmt.Sprintf("window check: %d days remaining", doc.DaysRemaining), nil
}

// orEmptyStr dereferences a nullable stamp, treating null as "-".
func orEmptyStr(p *string) string {
	if p == nil {
		return "-"
	}
	return *p
}

// parseStampLoose accepts the timestamp layouts the database stores
// (RFC3339 from the tool itself, the legacy SQL layout from older
// rows).
func parseStampLoose(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unparsable timestamp %q", s)
}
