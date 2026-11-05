package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"archaeologist/internal/store"
)

// newImpactCmd wires the cleanup impact view: what depends on the
// component, what it touches, and which risks surround it. Read only —
// never a rescan.
func newImpactCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "impact <component>",
		Short: "Show what depends on a component and what a cleanup would touch",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, _ := cmd.Flags().GetString("format")
			return runImpact(cmd.Context(), cmd.OutOrStdout(), dbPath, args[0], format)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "archaeologist.db",
		"path to the SQLite evidence database")
	addFormatFlag(cmd)
	return cmd
}

// impactVerdictJSON is the stored verdict of the component, or null
// when verdicts were never computed for it.
type impactVerdictJSON struct {
	State    string `json:"state"`
	Coverage string `json:"coverage"`
	Blockers int    `json:"blockers"`
}

// impactEdgeJSON is one incident edge with its evidence source.
type impactEdgeJSON struct {
	EdgeKind         string `json:"edge_kind"`
	Strength         string `json:"strength"`
	NeighborKind     string `json:"neighbor_kind"`
	NeighborName     string `json:"neighbor_name"`
	NeighborIdentity string `json:"neighbor_identity"`
	Channel          string `json:"channel"`
	RawRef           string `json:"raw_ref"`
}

// impactKindJSON groups every related component of one entity kind.
type impactKindJSON struct {
	Kind       string   `json:"kind"`
	Components []string `json:"components"`
}

// impactFindingJSON is one broken-route finding in the component's
// neighbourhood.
type impactFindingJSON struct {
	ID         int64             `json:"id"`
	Severity   string            `json:"severity"`
	EntityKind string            `json:"entity_kind"`
	EntityName string            `json:"entity_name"`
	Detail     map[string]string `json:"detail"`
}

// impactBlindJSON is one blind spot affecting the component's
// conclusion.
type impactBlindJSON struct {
	Channel string            `json:"channel"`
	Reason  string            `json:"reason"`
	Detail  map[string]string `json:"detail"`
}

// impactJSON is the whole `impact --format json` document.
type impactJSON struct {
	ScanID          int64               `json:"scan_id"`
	Kind            string              `json:"kind"`
	Name            string              `json:"name"`
	Identity        string              `json:"identity"`
	Verdict         *impactVerdictJSON  `json:"verdict"`
	Inbound         []impactEdgeJSON    `json:"inbound"`
	Outbound        []impactEdgeJSON    `json:"outbound"`
	DeployedBy      []impactEdgeJSON    `json:"deployed_by"`
	ScheduledBy     []impactEdgeJSON    `json:"scheduled_by"`
	RelatedByKind   []impactKindJSON    `json:"related_by_kind"`
	BrokenRouteRisk []impactFindingJSON `json:"broken_route_risk"`
	BlindSpots      []impactBlindJSON   `json:"blind_spots"`
}

// runImpact builds the impact view for one component of the latest
// scan. Every read is scoped to that scan; nothing is written.
func runImpact(ctx context.Context, w io.Writer, dbPath, ref, format string) error {
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
	neighbors, err := st.NeighborRows(ctx, scanID, ent.ID)
	if err != nil {
		return err
	}

	doc := impactJSON{
		ScanID:          scanID,
		Kind:            ent.Kind,
		Name:            ent.Name,
		Identity:        ent.IdentityKey,
		Inbound:         []impactEdgeJSON{},
		Outbound:        []impactEdgeJSON{},
		DeployedBy:      []impactEdgeJSON{},
		ScheduledBy:     []impactEdgeJSON{},
		BrokenRouteRisk: []impactFindingJSON{},
		BlindSpots:      []impactBlindJSON{},
	}

	// The component itself plus every incident neighbour form the
	// neighbourhood a cleanup touches: broken routes anywhere in it
	// are risk the operator must see.
	neighborIDs := []int64{ent.ID}
	seen := map[int64]bool{ent.ID: true}
	for _, n := range neighbors {
		edge := impactEdgeJSON{
			EdgeKind: n.EdgeKind, Strength: n.Strength,
			NeighborKind: n.NeighborKind, NeighborName: n.NeighborName,
			NeighborIdentity: n.NeighborKey, Channel: n.Channel, RawRef: n.RawRef,
		}
		switch n.Group {
		case store.GroupIncoming:
			doc.Inbound = append(doc.Inbound, edge)
		case store.GroupOutgoing:
			doc.Outbound = append(doc.Outbound, edge)
		case store.GroupDeployedBy:
			doc.DeployedBy = append(doc.DeployedBy, edge)
		case store.GroupScheduledBy:
			doc.ScheduledBy = append(doc.ScheduledBy, edge)
		}
		if !seen[n.NeighborID] {
			seen[n.NeighborID] = true
			neighborIDs = append(neighborIDs, n.NeighborID)
		}
	}
	doc.RelatedByKind = relatedByKind(neighbors)

	rec, err := st.VerdictFor(ctx, ent.ID, scanID)
	switch {
	case err == nil:
		doc.Verdict = &impactVerdictJSON{
			State: rec.State, Coverage: rec.Coverage, Blockers: len(rec.Blockers),
		}
	case errors.Is(err, sql.ErrNoRows):
		// No verdict stored: the JSON field stays null.
	default:
		return fmt.Errorf("verdict for %s: %w", ent.IdentityKey, err)
	}

	findings, err := st.FindingsForEntities(ctx, "BROKEN_ROUTE", neighborIDs)
	if err != nil {
		return err
	}
	for _, f := range findings {
		doc.BrokenRouteRisk = append(doc.BrokenRouteRisk, impactFindingJSON{
			ID: f.ID, Severity: f.Severity,
			EntityKind: f.EntityKind, EntityName: f.EntityName, Detail: f.Detail,
		})
	}

	blinds, err := st.BlindSpotsFor(ctx, ent.ID)
	if err != nil {
		return err
	}
	for _, b := range blinds {
		doc.BlindSpots = append(doc.BlindSpots, impactBlindJSON{
			Channel: b.Channel, Reason: b.Reason, Detail: b.Detail,
		})
	}

	if format == formatJSON {
		return writeJSON(w, doc)
	}
	return printImpact(w, doc)
}

// relatedByKind groups every incident neighbour by entity kind so the
// routes, units, jobs, listeners, volumes, and images a cleanup would
// touch are visible at a glance.
func relatedByKind(neighbors []store.NeighborRow) []impactKindJSON {
	byKind := map[string][]string{}
	for _, n := range neighbors {
		byKind[n.NeighborKind] = append(byKind[n.NeighborKind], n.NeighborName)
	}
	kinds := make([]string, 0, len(byKind))
	for k := range byKind {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	out := make([]impactKindJSON, 0, len(kinds))
	for _, k := range kinds {
		names := byKind[k]
		sort.Strings(names)
		// One neighbour can arrive over several edges; list it once.
		out = append(out, impactKindJSON{Kind: k, Components: uniqueStrings(names)})
	}
	return out
}

// uniqueStrings drops duplicates from a sorted list.
func uniqueStrings(in []string) []string {
	out := in[:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

// printImpact renders the fixed impact section order: identity,
// verdict, the four edge groups, related components by kind, broken
// routes, and blind spots.
func printImpact(w io.Writer, doc impactJSON) error {
	if _, err := fmt.Fprintf(w, "Impact: %s %s (scan #%d)\n", doc.Kind, doc.Name, doc.ScanID); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  identity:     %s\n", doc.Identity); err != nil {
		return err
	}
	verdict := "no verdict stored"
	if doc.Verdict != nil {
		verdict = fmt.Sprintf("%s (coverage %s, %d blockers)",
			doc.Verdict.State, doc.Verdict.Coverage, doc.Verdict.Blockers)
	}
	if _, err := fmt.Fprintf(w, "  verdict:      %s\n", verdict); err != nil {
		return err
	}

	sections := []struct {
		title string
		edges []impactEdgeJSON
	}{
		{"inbound dependents", doc.Inbound},
		{"outbound dependencies", doc.Outbound},
		{"deployed by", doc.DeployedBy},
		{"scheduled by", doc.ScheduledBy},
	}
	for _, s := range sections {
		if err := impactEdgeSection(w, s.title, s.edges); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintf(w, "  related components by kind (%d kinds):\n", len(doc.RelatedByKind)); err != nil {
		return err
	}
	if len(doc.RelatedByKind) == 0 {
		if _, err := fmt.Fprintln(w, "    (none)"); err != nil {
			return err
		}
	}
	for _, k := range doc.RelatedByKind {
		if _, err := fmt.Fprintf(w, "    %s: %s\n", k.Kind, strings.Join(k.Components, ", ")); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintf(w, "  broken-route risk (%d):\n", len(doc.BrokenRouteRisk)); err != nil {
		return err
	}
	if len(doc.BrokenRouteRisk) == 0 {
		if _, err := fmt.Fprintln(w, "    (none)"); err != nil {
			return err
		}
	}
	for _, f := range doc.BrokenRouteRisk {
		reason := f.Detail["reason"]
		if reason == "" {
			reason = joinKV(f.Detail)
		}
		if _, err := fmt.Fprintf(w, "    [%s] %s (%s): %s\n",
			f.Severity, f.EntityName, f.EntityKind, reason); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintf(w, "  blind spots (%d):\n", len(doc.BlindSpots)); err != nil {
		return err
	}
	if len(doc.BlindSpots) == 0 {
		if _, err := fmt.Fprintln(w, "    (none)"); err != nil {
			return err
		}
	}
	for _, b := range doc.BlindSpots {
		if _, err := fmt.Fprintf(w, "    [%s] %s: %s\n", b.Channel, b.Reason, joinKV(b.Detail)); err != nil {
			return err
		}
	}
	return nil
}

// impactEdgeSection prints one edge group with its count, or a single
// (none) marker.
func impactEdgeSection(w io.Writer, title string, edges []impactEdgeJSON) error {
	if _, err := fmt.Fprintf(w, "  %s (%d):\n", title, len(edges)); err != nil {
		return err
	}
	if len(edges) == 0 {
		_, err := fmt.Fprintln(w, "    (none)")
		return err
	}
	for _, e := range edges {
		if _, err := fmt.Fprintf(w, "    [%s] %s — %s %s\n",
			e.Strength, e.EdgeKind, e.NeighborKind, e.NeighborName); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "      source: %s %s\n", e.Channel, e.RawRef); err != nil {
			return err
		}
	}
	return nil
}
