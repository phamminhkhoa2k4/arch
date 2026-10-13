package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"archaeologist/internal/store"
)

// newExplainCmd shows one component's dependencies, evidence, and
// blind spots from the latest scan.
func newExplainCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "explain <component>",
		Short: "Show dependencies, evidence, and blind spots for a component",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, _ := cmd.Flags().GetString("format")
			return runExplain(cmd.Context(), cmd.OutOrStdout(), dbPath, args[0], format)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "archaeologist.db",
		"path to the SQLite evidence database")
	addFormatFlag(cmd)
	return cmd
}

func runExplain(ctx context.Context, w io.Writer, dbPath, ref, format string) error {
	if err := validateFormat(format); err != nil {
		return err
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
	ent, err := resolveComponent(ctx, st, scanID, ref)
	if err != nil {
		return err
	}
	evid, err := st.EvidenceFor(ctx, ent.ID)
	if err != nil {
		return err
	}
	neighbors, err := st.NeighborRows(ctx, scanID, ent.ID)
	if err != nil {
		return err
	}
	blinds, err := st.BlindSpotsFor(ctx, ent.ID)
	if err != nil {
		return err
	}
	if format == formatJSON {
		return writeJSON(w, explainJSON(scanID, ent, evid, neighbors, blinds))
	}
	return printExplain(w, scanID, ent, evid, neighbors, blinds)
}

// explainJSON is the --format json shape for explain.
func explainJSON(scanID int64, ent store.EntityRow, evid []store.EvidenceRow,
	neighbors []store.NeighborRow, blinds []store.BlindRow,
) map[string]any {
	type evidenceJSON struct {
		ID         int64             `json:"id"`
		Polarity   string            `json:"polarity"`
		Channel    string            `json:"channel"`
		Strength   string            `json:"strength"`
		ObservedAt string            `json:"observed_at"`
		RawRef     string            `json:"raw_ref"`
		Value      map[string]string `json:"value"`
	}
	type neighborJSON struct {
		EdgeKind     string `json:"edge_kind"`
		Strength     string `json:"strength"`
		NeighborKind string `json:"neighbor_kind"`
		NeighborName string `json:"neighbor_name"`
		Channel      string `json:"channel"`
		RawRef       string `json:"raw_ref"`
	}
	type blindJSON struct {
		Channel string            `json:"channel"`
		Reason  string            `json:"reason"`
		Detail  map[string]string `json:"detail"`
	}
	ev := make([]evidenceJSON, 0, len(evid))
	for _, e := range evid {
		ev = append(ev, evidenceJSON{
			ID: e.ID, Polarity: e.Polarity, Channel: e.Channel,
			Strength: e.Strength, ObservedAt: e.ObservedAt,
			RawRef: e.RawRef, Value: e.Value,
		})
	}
	nb := make([]neighborJSON, 0, len(neighbors))
	for _, n := range neighbors {
		nb = append(nb, neighborJSON{
			EdgeKind: n.EdgeKind, Strength: n.Strength,
			NeighborKind: n.NeighborKind, NeighborName: n.NeighborName,
			Channel: n.Channel, RawRef: n.RawRef,
		})
	}
	bl := make([]blindJSON, 0, len(blinds))
	for _, b := range blinds {
		bl = append(bl, blindJSON{Channel: b.Channel, Reason: b.Reason, Detail: b.Detail})
	}
	return map[string]any{
		"scan_id":     scanID,
		"kind":        ent.Kind,
		"name":        ent.Name,
		"identity":    ent.IdentityKey,
		"attributes":  ent.Attributes,
		"evidence":    ev,
		"neighbors":   nb,
		"blind_spots": bl,
	}
}

func printExplain(
	w io.Writer,
	scanID int64,
	ent store.EntityRow,
	evid []store.EvidenceRow,
	neighbors []store.NeighborRow,
	blinds []store.BlindRow,
) error {
	if _, err := fmt.Fprintf(w, "Component: %s — %s (scan #%d)\n", ent.Kind, ent.Name, scanID); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Identity:  %s\n", ent.IdentityKey); err != nil {
		return err
	}
	if len(ent.Attributes) > 0 {
		if _, err := fmt.Fprintln(w, "Attributes:"); err != nil {
			return err
		}
		for _, k := range sortedKeys(ent.Attributes) {
			if _, err := fmt.Fprintf(w, "  %s = %s\n", k, ent.Attributes[k]); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintf(w, "Evidence (%d):\n", len(evid)); err != nil {
		return err
	}
	if len(evid) == 0 {
		if _, err := fmt.Fprintln(w, "  (no evidence)"); err != nil {
			return err
		}
	}
	for _, e := range evid {
		if _, err := fmt.Fprintf(w, "  [%s] %s %s %s\n",
			e.Polarity, e.Channel, e.Strength, e.ObservedAt); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "    value: %s\n", joinKV(e.Value)); err != nil {
			return err
		}
		// One copyable line per source so a reader can jump straight
		// to the file, API call or command behind the fact.
		if _, err := fmt.Fprintf(w, "    source: %s\n", e.RawRef); err != nil {
			return err
		}
	}

	if err := printDependencies(w, neighbors); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(w, "Blind spots (%d):\n", len(blinds)); err != nil {
		return err
	}
	if len(blinds) == 0 {
		if _, err := fmt.Fprintln(w, "  (no blind spots)"); err != nil {
			return err
		}
	}
	for _, b := range blinds {
		if _, err := fmt.Fprintf(w, "  [%s] %s: %s\n", b.Channel, b.Reason, joinKV(b.Detail)); err != nil {
			return err
		}
	}
	return nil
}

// printDependencies renders the four explain groups:
// one line per edge with strength, kind and neighbor, the evidence
// source underneath. An isolated component gets a single line instead
// of four empty groups.
func printDependencies(w io.Writer, neighbors []store.NeighborRow) error {
	if len(neighbors) == 0 {
		_, err := fmt.Fprintln(w, "Dependencies: (none discovered)")
		return err
	}
	if _, err := fmt.Fprintf(w, "Dependencies (%d):\n", len(neighbors)); err != nil {
		return err
	}
	for _, group := range []string{
		store.GroupIncoming, store.GroupOutgoing,
		store.GroupDeployedBy, store.GroupScheduledBy,
	} {
		var rows []store.NeighborRow
		for _, n := range neighbors {
			if n.Group == group {
				rows = append(rows, n)
			}
		}
		if _, err := fmt.Fprintf(w, "  %s (%d):\n", group, len(rows)); err != nil {
			return err
		}
		if len(rows) == 0 {
			if _, err := fmt.Fprintln(w, "    (none)"); err != nil {
				return err
			}
			continue
		}
		for _, r := range rows {
			if _, err := fmt.Fprintf(w, "    [%s] %s — %s %s\n",
				r.Strength, r.EdgeKind, r.NeighborKind, r.NeighborName); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "      source: %s %s\n", r.Channel, r.RawRef); err != nil {
				return err
			}
		}
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// joinKV renders a string map as deterministic "k=v k=v" pairs.
func joinKV(m map[string]string) string {
	parts := make([]string, 0, len(m))
	for _, k := range sortedKeys(m) {
		parts = append(parts, fmt.Sprintf("%s=%s", k, m[k]))
	}
	return strings.Join(parts, " ")
}
