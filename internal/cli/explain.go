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
			return runExplain(cmd.Context(), cmd.OutOrStdout(), dbPath, args[0])
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "archaeologist.db",
		"path to the SQLite evidence database")
	return cmd
}

func runExplain(ctx context.Context, w io.Writer, dbPath, ref string) error {
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
	return printExplain(w, scanID, ent, evid, neighbors, blinds)
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
		if _, err := fmt.Fprintln(w, "  (không có evidence)"); err != nil {
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
		if _, err := fmt.Fprintf(w, "    nguồn: %s\n", e.RawRef); err != nil {
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
		if _, err := fmt.Fprintln(w, "  (không có blind spot)"); err != nil {
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
		_, err := fmt.Fprintln(w, "Phụ thuộc: (không có phụ thuộc nào được phát hiện)")
		return err
	}
	if _, err := fmt.Fprintf(w, "Phụ thuộc (%d):\n", len(neighbors)); err != nil {
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
			if _, err := fmt.Fprintln(w, "    (không có)"); err != nil {
				return err
			}
			continue
		}
		for _, r := range rows {
			if _, err := fmt.Fprintf(w, "    [%s] %s — %s %s\n",
				r.Strength, r.EdgeKind, r.NeighborKind, r.NeighborName); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "      nguồn: %s %s\n", r.Channel, r.RawRef); err != nil {
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
