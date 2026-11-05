package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"archaeologist/internal/store"
	"archaeologist/internal/verdict"
)

// defaultDiffLimit caps every change list `scan diff` prints; zero
// means no cap.
const defaultDiffLimit = 20

// newScanListCmd wires the scan history listing.
func newScanListCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List recorded scans with counts and verdict rollup",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScanList(cmd.Context(), cmd.OutOrStdout(), dbPath)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "archaeologist.db",
		"path to the SQLite evidence database")
	return cmd
}

// newScanDiffCmd wires the two-scan comparison.
func newScanDiffCmd() *cobra.Command {
	var (
		dbPath string
		limit  int
	)
	cmd := &cobra.Command{
		Use:   "diff <scan-a> <scan-b>",
		Short: "Compare two scans: entities, blockers, blind spots, coverage, verdicts",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			fromID, err := parseScanID(args[0])
			if err != nil {
				return err
			}
			toID, err := parseScanID(args[1])
			if err != nil {
				return err
			}
			return runScanDiff(cmd.Context(), cmd.OutOrStdout(), dbPath, fromID, toID, limit)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "archaeologist.db",
		"path to the SQLite evidence database")
	cmd.Flags().IntVar(&limit, "limit", defaultDiffLimit,
		"maximum lines per change list (0 shows every change)")
	return cmd
}

// parseScanID turns a positional scan reference into an id.
func parseScanID(s string) (int64, error) {
	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("scan id %q: want a positive number", s)
	}
	return id, nil
}

// runScanList prints the recorded scans, newest first, one row each
// with its rollup counts and verdict rollup when verdicts exist.
func runScanList(ctx context.Context, w io.Writer, dbPath string) error {
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	scans, err := st.ListScans(ctx)
	if err != nil {
		return err
	}
	if len(scans) == 0 {
		_, _ = fmt.Fprintf(w, "no scans recorded in %s — run `scan --db %s` first\n", dbPath, dbPath)
		return nil
	}

	if _, err := fmt.Fprintf(w, "  %-4s %-21s %-11s %8s %6s %8s  %s\n",
		"ID", "Started", "Status", "Entities", "Blind", "Findings", "Verdict"); err != nil {
		return err
	}
	for _, sc := range scans {
		rollup, err := st.VerdictRollup(ctx, sc.ID)
		if err != nil {
			return err
		}
		cell := "-"
		if len(rollup) > 0 {
			cell = verdictRollupLine(rollup)
		}
		if _, err := fmt.Fprintf(w, "  %-4d %-21s %-11s %8d %6d %8d  %s\n",
			sc.ID, sc.StartedAt, scanStatus(sc), sc.Entities, sc.BlindSpots, sc.Findings, cell); err != nil {
			return err
		}
	}
	return nil
}

// scanStatus renders a scan's status. A row that never finished keeps
// the table's default status value, so it is reported as incomplete
// instead of trusting that default.
func scanStatus(sc store.ScanRow) string {
	if sc.FinishedAt == "" {
		return "incomplete"
	}
	return sc.Status
}

// scanLookupError turns a missing scan id into an actionable message.
func scanLookupError(err error, dbPath string) error {
	if errors.Is(err, store.ErrNoScan) {
		return fmt.Errorf("%w — run `scan list --db %s` to see recorded scans", err, dbPath)
	}
	return err
}

// runScanDiff compares two recorded scans and prints what changed
// between them. It only reads the database.
func runScanDiff(ctx context.Context, w io.Writer, dbPath string, fromID, toID int64, limit int) error {
	if limit < 0 {
		return fmt.Errorf("--limit must be >= 0, got %d", limit)
	}
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	from, err := st.ScanInfo(ctx, fromID)
	if err != nil {
		return scanLookupError(err, dbPath)
	}
	to, err := st.ScanInfo(ctx, toID)
	if err != nil {
		return scanLookupError(err, dbPath)
	}
	sumFrom, err := st.ScanSummary(ctx, fromID)
	if err != nil {
		return err
	}
	sumTo, err := st.ScanSummary(ctx, toID)
	if err != nil {
		return err
	}
	entsFrom, err := st.EntitiesInScan(ctx, fromID)
	if err != nil {
		return err
	}
	entsTo, err := st.EntitiesInScan(ctx, toID)
	if err != nil {
		return err
	}
	blindsFrom, err := st.BlindSpotsInScan(ctx, fromID)
	if err != nil {
		return err
	}
	blindsTo, err := st.BlindSpotsInScan(ctx, toID)
	if err != nil {
		return err
	}
	verdFrom, err := st.VerdictsInScan(ctx, fromID)
	if err != nil {
		return err
	}
	verdTo, err := st.VerdictsInScan(ctx, toID)
	if err != nil {
		return err
	}
	rollFrom, err := st.VerdictRollup(ctx, fromID)
	if err != nil {
		return err
	}
	rollTo, err := st.VerdictRollup(ctx, toID)
	if err != nil {
		return err
	}

	var b strings.Builder
	scanDiff{
		from: from, to: to,
		sumFrom: sumFrom, sumTo: sumTo,
		entsFrom: entsFrom, entsTo: entsTo,
		blindsFrom: blindsFrom, blindsTo: blindsTo,
		verdFrom: verdFrom, verdTo: verdTo,
		rollFrom: rollFrom, rollTo: rollTo,
		limit: limit,
	}.render(&b)
	_, err = io.WriteString(w, b.String())
	return err
}

// scanDiff holds every row one comparison needs so the renderer is a
// pure function of loaded data.
type scanDiff struct {
	from, to             store.ScanRow
	sumFrom, sumTo       store.Summary
	entsFrom, entsTo     []store.EntityRow
	blindsFrom, blindsTo []store.BlindRowScan
	verdFrom, verdTo     map[string]store.VerdictSnapshot
	rollFrom, rollTo     map[string]int
	limit                int
}

func (d scanDiff) render(b *strings.Builder) {
	_, _ = fmt.Fprintf(b, "Scan #%d → #%d\n", d.from.ID, d.to.ID)
	_, _ = fmt.Fprintf(b, "  from: %s status=%s host=%s\n", d.from.StartedAt, scanStatus(d.from), d.from.Host)
	_, _ = fmt.Fprintf(b, "  to:   %s status=%s host=%s\n", d.to.StartedAt, scanStatus(d.to), d.to.Host)
	d.renderEntities(b)
	d.renderBlockers(b)
	d.renderBlindSpots(b)
	d.renderCoverage(b)
	d.renderVerdicts(b)
}

// renderEntities prints the count delta per kind plus the entities
// only one of the two scans has.
func (d scanDiff) renderEntities(b *strings.Builder) {
	fromTotal := entityTotal(d.sumFrom.Entities)
	toTotal := entityTotal(d.sumTo.Entities)
	_, _ = fmt.Fprintf(b, "  entities: %d → %d (%s)\n",
		fromTotal, toTotal, signedDelta(toTotal-fromTotal))

	for _, kind := range unionKinds(d.sumFrom.Entities, d.sumTo.Entities) {
		a, c := d.sumFrom.Entities[kind], d.sumTo.Entities[kind]
		if a == c {
			continue
		}
		_, _ = fmt.Fprintf(b, "    %s: %d → %d (%s)\n", kind, a, c, signedDelta(c-a))
	}

	added, removed := splitEntities(d.entsFrom, d.entsTo)
	if len(added) > 0 {
		_, _ = fmt.Fprintf(b, "  added (%d):\n", len(added))
		printList(b, d.limit, added, func(e store.EntityRow) string {
			return "    + [" + e.Kind + "] " + e.Name
		})
	}
	if len(removed) > 0 {
		_, _ = fmt.Fprintf(b, "  removed (%d):\n", len(removed))
		printList(b, d.limit, removed, func(e store.EntityRow) string {
			return "    - [" + e.Kind + "] " + e.Name
		})
	}
}

// blockerChange is one hard blocker that appeared or disappeared on an
// entity present in both scans.
type blockerChange struct {
	entity store.VerdictSnapshot
	item   verdict.Item
}

// renderBlockers prints the blocker count delta plus the blockers that
// appeared or disappeared on shared entities.
func (d scanDiff) renderBlockers(b *strings.Builder) {
	fromTotal, toTotal := blockerTotal(d.verdFrom), blockerTotal(d.verdTo)
	_, _ = fmt.Fprintf(b, "  blockers: %d → %d (%s)\n",
		fromTotal, toTotal, signedDelta(toTotal-fromTotal))

	var appeared, disappeared []blockerChange
	for _, key := range sharedKeys(d.verdFrom, d.verdTo) {
		fromV, toV := d.verdFrom[key], d.verdTo[key]
		fromCodes := blockerCodes(fromV)
		toCodes := blockerCodes(toV)
		for _, item := range toV.Blockers {
			if !fromCodes[item.Code] {
				appeared = append(appeared, blockerChange{entity: toV, item: item})
			}
		}
		for _, item := range fromV.Blockers {
			if !toCodes[item.Code] {
				disappeared = append(disappeared, blockerChange{entity: fromV, item: item})
			}
		}
	}
	if len(appeared) > 0 {
		_, _ = fmt.Fprintf(b, "  new blockers (%d):\n", len(appeared))
		printList(b, d.limit, appeared, func(c blockerChange) string {
			return fmt.Sprintf("    + [%s] %s: %s — %s", c.entity.Kind, c.entity.Name, c.item.Code, c.item.Text)
		})
	}
	if len(disappeared) > 0 {
		_, _ = fmt.Fprintf(b, "  gone blockers (%d):\n", len(disappeared))
		printList(b, d.limit, disappeared, func(c blockerChange) string {
			return fmt.Sprintf("    - [%s] %s: %s — %s", c.entity.Kind, c.entity.Name, c.item.Code, c.item.Text)
		})
	}
}

// renderBlindSpots prints the blind spot count delta plus the gaps
// that only one scan recorded.
func (d scanDiff) renderBlindSpots(b *strings.Builder) {
	_, _ = fmt.Fprintf(b, "  blind spots: %d → %d (%s)\n",
		d.sumFrom.BlindSpots, d.sumTo.BlindSpots,
		signedDelta(d.sumTo.BlindSpots-d.sumFrom.BlindSpots))

	fromCounts := blindCounts(d.blindsFrom)
	toCounts := blindCounts(d.blindsTo)
	var appeared, disappeared []string
	for _, key := range blindUnion(fromCounts, toCounts) {
		switch {
		case fromCounts[key] == 0 && toCounts[key] > 0:
			appeared = append(appeared, key)
		case fromCounts[key] > 0 && toCounts[key] == 0:
			disappeared = append(disappeared, key)
		}
	}
	if len(appeared) > 0 {
		_, _ = fmt.Fprintf(b, "  new blind spots (%d):\n", len(appeared))
		printList(b, d.limit, appeared, func(k string) string { return "    + " + k })
	}
	if len(disappeared) > 0 {
		_, _ = fmt.Fprintf(b, "  gone blind spots (%d):\n", len(disappeared))
		printList(b, d.limit, disappeared, func(k string) string { return "    - " + k })
	}
}

// renderCoverage prints the coverage band counts and the entities whose
// evidence coverage moved between bands.
func (d scanDiff) renderCoverage(b *strings.Builder) {
	fromCounts := coverageCounts(d.verdFrom)
	toCounts := coverageCounts(d.verdTo)
	parts := make([]string, 0, 3)
	for _, level := range []string{"HIGH", "MEDIUM", "LOW"} {
		parts = append(parts, fmt.Sprintf("%s %d → %d", level, fromCounts[level], toCounts[level]))
	}
	_, _ = fmt.Fprintf(b, "  coverage: %s\n", strings.Join(parts, " · "))

	var changed []string
	for _, key := range sharedKeys(d.verdFrom, d.verdTo) {
		fromV, toV := d.verdFrom[key], d.verdTo[key]
		if fromV.Coverage == toV.Coverage {
			continue
		}
		changed = append(changed,
			fmt.Sprintf("    [%s] %s: %s → %s", toV.Kind, toV.Name, fromV.Coverage, toV.Coverage))
	}
	if len(changed) > 0 {
		_, _ = fmt.Fprintf(b, "  coverage changes (%d):\n", len(changed))
		printList(b, d.limit, changed, func(s string) string { return s })
	}
}

// renderVerdicts prints the state rollup of both scans and the shared
// entities whose verdict state moved.
func (d scanDiff) renderVerdicts(b *strings.Builder) {
	_, _ = fmt.Fprintf(b, "  verdict: %s\n", rollupDeltaLine(d.rollFrom, d.rollTo))

	var changed []string
	for _, key := range sharedKeys(d.verdFrom, d.verdTo) {
		fromV, toV := d.verdFrom[key], d.verdTo[key]
		if fromV.State == toV.State {
			continue
		}
		changed = append(changed,
			fmt.Sprintf("    [%s] %s: %s → %s", toV.Kind, toV.Name, fromV.State, toV.State))
	}
	if len(changed) > 0 {
		_, _ = fmt.Fprintf(b, "  verdict changes (%d):\n", len(changed))
		printList(b, d.limit, changed, func(s string) string { return s })
	}
}

// printList writes up to limit items (all of them when limit is 0)
// followed by a note when anything is left out.
func printList[T any](b *strings.Builder, limit int, items []T, line func(T) string) {
	show := items
	if limit > 0 && len(items) > limit {
		show = items[:limit]
	}
	for _, item := range show {
		_, _ = fmt.Fprintln(b, line(item))
	}
	if len(show) < len(items) {
		_, _ = fmt.Fprintf(b, "    … and %d more (raise --limit to see them)\n", len(items)-len(show))
	}
}

// entityTotal sums the per-kind entity counts.
func entityTotal(m map[string]int) int {
	total := 0
	for _, n := range m {
		total += n
	}
	return total
}

// signedDelta renders a change with an explicit sign: +3, -2, 0.
func signedDelta(n int) string {
	if n > 0 {
		return fmt.Sprintf("+%d", n)
	}
	return strconv.Itoa(n)
}

// unionKinds returns every entity kind seen in either scan, sorted.
func unionKinds(from, to map[string]int) []string {
	seen := map[string]bool{}
	for k := range from {
		seen[k] = true
	}
	for k := range to {
		seen[k] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// splitEntities splits two entity lists into the rows only the second
// scan has (added) and only the first has (removed), each ordered by
// kind then name.
func splitEntities(from, to []store.EntityRow) (added, removed []store.EntityRow) {
	fromKeys := map[string]bool{}
	for _, e := range from {
		fromKeys[e.IdentityKey] = true
	}
	toKeys := map[string]bool{}
	for _, e := range to {
		toKeys[e.IdentityKey] = true
	}
	for _, e := range to {
		if !fromKeys[e.IdentityKey] {
			added = append(added, e)
		}
	}
	for _, e := range from {
		if !toKeys[e.IdentityKey] {
			removed = append(removed, e)
		}
	}
	sortEntityRows(added)
	sortEntityRows(removed)
	return added, removed
}

func sortEntityRows(rows []store.EntityRow) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Kind != rows[j].Kind {
			return rows[i].Kind < rows[j].Kind
		}
		if rows[i].Name != rows[j].Name {
			return rows[i].Name < rows[j].Name
		}
		return rows[i].IdentityKey < rows[j].IdentityKey
	})
}

// sharedKeys returns the sorted identity keys present in both maps.
func sharedKeys[V any](from, to map[string]V) []string {
	out := []string{}
	for k := range from {
		if _, ok := to[k]; ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// blockerTotal sums the stored blocker items of one scan.
func blockerTotal(verdicts map[string]store.VerdictSnapshot) int {
	total := 0
	for _, v := range verdicts {
		total += len(v.Blockers)
	}
	return total
}

// blockerCodes indexes one snapshot's blockers by code; codes are the
// stable identifier of a blocker rule.
func blockerCodes(v store.VerdictSnapshot) map[string]bool {
	codes := map[string]bool{}
	for _, item := range v.Blockers {
		codes[item.Code] = true
	}
	return codes
}

// blindCounts counts blind spots by their display key per scan.
func blindCounts(rows []store.BlindRowScan) map[string]int {
	counts := map[string]int{}
	for _, r := range rows {
		counts[blindKey(r)]++
	}
	return counts
}

// blindKey renders one blind spot for humans: host-wide gaps carry no
// entity, attached ones name it.
func blindKey(r store.BlindRowScan) string {
	if r.EntityName == "" {
		return fmt.Sprintf("%s/%s (host)", r.Channel, r.Reason)
	}
	return fmt.Sprintf("%s/%s [%s %s]", r.Channel, r.Reason, r.EntityKind, r.EntityName)
}

// blindUnion returns the sorted display keys seen in either scan.
func blindUnion(from, to map[string]int) []string {
	seen := map[string]bool{}
	for k := range from {
		seen[k] = true
	}
	for k := range to {
		seen[k] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// coverageCounts counts stored verdicts per coverage band.
func coverageCounts(verdicts map[string]store.VerdictSnapshot) map[string]int {
	counts := map[string]int{}
	for _, v := range verdicts {
		counts[v.Coverage]++
	}
	return counts
}
