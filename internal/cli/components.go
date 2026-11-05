package cli

import (
	"context"
	"fmt"
	"io"
	"sort"

	"github.com/spf13/cobra"

	"archaeologist/internal/store"
)

// newComponentsCmd lists every component of the latest scan so an
// operator can find targets without knowing an identity key first.
func newComponentsCmd() *cobra.Command {
	var (
		dbPath string
		kind   string
		state  string
		limit  int
	)
	cmd := &cobra.Command{
		Use:   "components",
		Short: "List components recorded in the latest scan",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, _ := cmd.Flags().GetString("format")
			return runComponents(cmd.Context(), cmd.OutOrStdout(),
				dbPath, kind, state, limit, format)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "archaeologist.db",
		"path to the SQLite evidence database")
	cmd.Flags().StringVar(&kind, "kind", "",
		"keep only components of this kind (e.g. systemd_unit)")
	cmd.Flags().StringVar(&state, "state", "",
		"keep only components whose stored verdict state is this (UNKNOWN includes components without a verdict)")
	cmd.Flags().IntVar(&limit, "limit", defaultComponentLimit,
		"cap the text list (0 shows every component; JSON is always complete)")
	addFormatFlag(cmd)
	return cmd
}

// defaultComponentLimit keeps the text listing readable on large hosts.
const defaultComponentLimit = 20

// componentJSON is one row of `components --format json`.
type componentJSON struct {
	Kind         string `json:"kind"`
	Name         string `json:"name"`
	Identity     string `json:"identity"`
	VerdictState string `json:"verdict_state"` // UNKNOWN when no verdict was stored
	Coverage     string `json:"coverage"`      // empty when no verdict was stored
}

// componentsJSON is the whole `components --format json` document.
type componentsJSON struct {
	ScanID     int64           `json:"scan_id"`
	Components []componentJSON `json:"components"`
}

// runComponents lists the components of the latest scan, optionally
// filtered, and caps only the text view.
func runComponents(ctx context.Context, w io.Writer, dbPath, kind, state string, limit int, format string) error {
	if err := validateFormat(format); err != nil {
		return err
	}
	if limit < 0 {
		return fmt.Errorf("--limit must be >= 0, got %d", limit)
	}
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer func() { _ = st.Close() }()

	scanID, err := st.LatestScanID(ctx)
	if err != nil {
		return err
	}
	ents, err := st.EntitiesInScan(ctx, scanID)
	if err != nil {
		return err
	}
	verdicts, err := st.VerdictsInScan(ctx, scanID)
	if err != nil {
		return err
	}

	type row struct {
		Kind         string
		Name         string
		Identity     string
		VerdictState string
		Coverage     string
	}
	var rows []row
	for _, e := range ents {
		vs, ok := verdicts[e.IdentityKey]
		stt := "UNKNOWN"
		cov := ""
		if ok {
			stt = vs.State
			cov = vs.Coverage
		}
		if kind != "" && e.Kind != kind {
			continue
		}
		if state != "" && stt != state {
			continue
		}
		rows = append(rows, row{
			Kind: e.Kind, Name: e.Name, Identity: e.IdentityKey,
			VerdictState: stt, Coverage: cov,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Kind != rows[j].Kind {
			return rows[i].Kind < rows[j].Kind
		}
		if rows[i].Name != rows[j].Name {
			return rows[i].Name < rows[j].Name
		}
		return rows[i].Identity < rows[j].Identity
	})

	doc := componentsJSON{ScanID: scanID, Components: []componentJSON{}}
	for _, r := range rows {
		doc.Components = append(doc.Components, componentJSON(r))
	}

	if format == formatJSON {
		return writeJSON(w, doc)
	}

	if len(rows) == 0 {
		_, _ = fmt.Fprintf(w, "no components in scan #%d match the filters\n", scanID)
		return nil
	}
	if _, err := fmt.Fprintf(w, "  %-16s %-26s %-11s %-9s  %s\n",
		"Kind", "Name", "State", "Coverage", "Identity"); err != nil {
		return err
	}
	shown := rows
	if limit > 0 && len(rows) > limit {
		shown = rows[:limit]
	}
	for _, r := range shown {
		if _, err := fmt.Fprintf(w, "  %-16s %-26s %-11s %-9s  %s\n",
			r.Kind, r.Name, r.VerdictState, r.Coverage, r.Identity); err != nil {
			return err
		}
	}
	if len(shown) < len(rows) {
		_, _ = fmt.Fprintf(w, "  … and %d more (raise --limit to see them)\n", len(rows)-len(shown))
	}
	return nil
}
