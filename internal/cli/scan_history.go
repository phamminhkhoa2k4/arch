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

// defaultDiffLimit caps every change list in the text view of
// `scan diff`; zero means no cap. JSON output is never capped.
const defaultDiffLimit = 20

// newScanListCmd wires the scan history listing.
func newScanListCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List recorded scans with counts and verdict rollup",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, _ := cmd.Flags().GetString("format")
			return runScanList(cmd.Context(), cmd.OutOrStdout(), dbPath, format)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "archaeologist.db",
		"path to the SQLite evidence database")
	addFormatFlag(cmd)
	return cmd
}

// newScanDiffCmd wires the two-scan comparison.
func newScanDiffCmd() *cobra.Command {
	var (
		dbPath string
		format string
		limit  int
	)
	cmd := &cobra.Command{
		Use:   "diff <scan-a> <scan-b>",
		Short: "Compare two scans: entities, blockers, blind spots, coverage, verdicts",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, _ = cmd.Flags().GetString("format")
			fromID, err := parseScanID(args[0])
			if err != nil {
				return err
			}
			toID, err := parseScanID(args[1])
			if err != nil {
				return err
			}
			return runScanDiff(cmd.Context(), cmd.OutOrStdout(), dbPath, fromID, toID, limit, format)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "archaeologist.db",
		"path to the SQLite evidence database")
	cmd.Flags().IntVar(&limit, "limit", defaultDiffLimit,
		"cap each change list in text output (0 = no cap; JSON is always complete)")
	addFormatFlag(cmd)
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
func runScanList(ctx context.Context, w io.Writer, dbPath, format string) error {
	if err := validateFormat(format); err != nil {
		return err
	}
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	scans, err := st.ListScans(ctx)
	if err != nil {
		return err
	}
	if format == formatJSON {
		payload := scanListJSON{Scans: make([]scanListEntryJSON, 0, len(scans))}
		for _, sc := range scans {
			rollup, err := st.VerdictRollup(ctx, sc.ID)
			if err != nil {
				return err
			}
			payload.Scans = append(payload.Scans, scanListEntry(sc, rollup))
		}
		return writeJSON(w, payload)
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

// finishedAtPtr exposes the finish time as null while the scan never
// finished.
func finishedAtPtr(sc store.ScanRow) *string {
	if sc.FinishedAt == "" {
		return nil
	}
	s := sc.FinishedAt
	return &s
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
func runScanDiff(ctx context.Context, w io.Writer, dbPath string, fromID, toID int64, limit int, format string) error {
	if err := validateFormat(format); err != nil {
		return err
	}
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

	d := scanDiff{
		from: from, to: to,
		sumFrom: sumFrom, sumTo: sumTo,
		entsFrom: entsFrom, entsTo: entsTo,
		blindsFrom: blindsFrom, blindsTo: blindsTo,
		verdFrom: verdFrom, verdTo: verdTo,
		rollFrom: rollFrom, rollTo: rollTo,
	}
	changes := d.computeChanges()

	if format == formatJSON {
		return writeJSON(w, d.json(changes))
	}
	var b strings.Builder
	d.renderText(&b, changes, limit)
	_, err = io.WriteString(w, b.String())
	return err
}

// scanDiff holds every row one comparison needs so the computation is
// a pure function of loaded data.
type scanDiff struct {
	from, to             store.ScanRow
	sumFrom, sumTo       store.Summary
	entsFrom, entsTo     []store.EntityRow
	blindsFrom, blindsTo []store.BlindRowScan
	verdFrom, verdTo     map[string]store.VerdictSnapshot
	rollFrom, rollTo     map[string]int
}

// kindCount is one entity kind's count in both scans.
type kindCount struct {
	Kind string
	From int
	To   int
}

// blockerChange is one hard blocker that appeared or disappeared on an
// entity present in both scans.
type blockerChange struct {
	entity store.VerdictSnapshot
	item   verdict.Item
}

// snapshotChange is one shared entity whose coverage or verdict state
// moved between the scans.
type snapshotChange struct {
	from, to store.VerdictSnapshot
}

// diffChanges is the computed comparison shared by the text and JSON
// renderers.
type diffChanges struct {
	kinds           []kindCount
	added, removed  []store.EntityRow
	blockersNew     []blockerChange
	blockersGone    []blockerChange
	blindsNew       []store.BlindRowScan
	blindsGone      []store.BlindRowScan
	coverageChanges []snapshotChange
	verdictChanges  []snapshotChange
}

// computeChanges derives every list both renderers show.
func (d scanDiff) computeChanges() diffChanges {
	c := diffChanges{}

	for _, kind := range unionKinds(d.sumFrom.Entities, d.sumTo.Entities) {
		c.kinds = append(c.kinds, kindCount{
			Kind: kind,
			From: d.sumFrom.Entities[kind],
			To:   d.sumTo.Entities[kind],
		})
	}
	c.added, c.removed = splitEntities(d.entsFrom, d.entsTo)

	for _, key := range sharedKeys(d.verdFrom, d.verdTo) {
		fromV, toV := d.verdFrom[key], d.verdTo[key]
		fromCodes := blockerCodes(fromV)
		toCodes := blockerCodes(toV)
		for _, item := range toV.Blockers {
			if !fromCodes[item.Code] {
				c.blockersNew = append(c.blockersNew, blockerChange{entity: toV, item: item})
			}
		}
		for _, item := range fromV.Blockers {
			if !toCodes[item.Code] {
				c.blockersGone = append(c.blockersGone, blockerChange{entity: fromV, item: item})
			}
		}
		if fromV.Coverage != toV.Coverage {
			c.coverageChanges = append(c.coverageChanges, snapshotChange{from: fromV, to: toV})
		}
		if fromV.State != toV.State {
			c.verdictChanges = append(c.verdictChanges, snapshotChange{from: fromV, to: toV})
		}
	}

	fromBlinds := blindRows(d.blindsFrom)
	toBlinds := blindRows(d.blindsTo)
	for _, key := range blindUnion(countKeys(fromBlinds), countKeys(toBlinds)) {
		fromRow, fromOK := fromBlinds[key]
		toRow, toOK := toBlinds[key]
		switch {
		case !fromOK && toOK:
			c.blindsNew = append(c.blindsNew, toRow)
		case fromOK && !toOK:
			c.blindsGone = append(c.blindsGone, fromRow)
		}
	}
	sortBlindRows(c.blindsNew)
	sortBlindRows(c.blindsGone)
	return c
}

// renderText writes the human view: header, count lines and the
// change lists capped at limit.
func (d scanDiff) renderText(b *strings.Builder, c diffChanges, limit int) {
	_, _ = fmt.Fprintf(b, "Scan #%d → #%d\n", d.from.ID, d.to.ID)
	_, _ = fmt.Fprintf(b, "  from: %s status=%s host=%s\n", d.from.StartedAt, scanStatus(d.from), d.from.Host)
	_, _ = fmt.Fprintf(b, "  to:   %s status=%s host=%s\n", d.to.StartedAt, scanStatus(d.to), d.to.Host)

	d.renderEntities(b, c, limit)
	d.renderBlockers(b, c, limit)
	d.renderBlindSpots(b, c, limit)
	d.renderCoverage(b, c, limit)
	d.renderVerdicts(b, c, limit)
}

// renderEntities prints the count delta per kind plus the entities
// only one of the two scans has.
func (d scanDiff) renderEntities(b *strings.Builder, c diffChanges, limit int) {
	fromTotal := entityTotal(d.sumFrom.Entities)
	toTotal := entityTotal(d.sumTo.Entities)
	_, _ = fmt.Fprintf(b, "  entities: %d → %d (%s)\n",
		fromTotal, toTotal, signedDelta(toTotal-fromTotal))

	for _, kc := range c.kinds {
		if kc.From == kc.To {
			continue
		}
		_, _ = fmt.Fprintf(b, "    %s: %d → %d (%s)\n", kc.Kind, kc.From, kc.To, signedDelta(kc.To-kc.From))
	}
	if len(c.added) > 0 {
		_, _ = fmt.Fprintf(b, "  added (%d):\n", len(c.added))
		printList(b, limit, c.added, func(e store.EntityRow) string {
			return "    + [" + e.Kind + "] " + e.Name
		})
	}
	if len(c.removed) > 0 {
		_, _ = fmt.Fprintf(b, "  removed (%d):\n", len(c.removed))
		printList(b, limit, c.removed, func(e store.EntityRow) string {
			return "    - [" + e.Kind + "] " + e.Name
		})
	}
}

// renderBlockers prints the blocker count delta plus the blockers that
// appeared or disappeared on shared entities.
func (d scanDiff) renderBlockers(b *strings.Builder, c diffChanges, limit int) {
	fromTotal, toTotal := blockerTotal(d.verdFrom), blockerTotal(d.verdTo)
	_, _ = fmt.Fprintf(b, "  blockers: %d → %d (%s)\n",
		fromTotal, toTotal, signedDelta(toTotal-fromTotal))

	if len(c.blockersNew) > 0 {
		_, _ = fmt.Fprintf(b, "  new blockers (%d):\n", len(c.blockersNew))
		printList(b, limit, c.blockersNew, func(ch blockerChange) string {
			return fmt.Sprintf("    + [%s] %s: %s — %s", ch.entity.Kind, ch.entity.Name, ch.item.Code, ch.item.Text)
		})
	}
	if len(c.blockersGone) > 0 {
		_, _ = fmt.Fprintf(b, "  gone blockers (%d):\n", len(c.blockersGone))
		printList(b, limit, c.blockersGone, func(ch blockerChange) string {
			return fmt.Sprintf("    - [%s] %s: %s — %s", ch.entity.Kind, ch.entity.Name, ch.item.Code, ch.item.Text)
		})
	}
}

// renderBlindSpots prints the blind spot count delta plus the gaps
// that only one scan recorded.
func (d scanDiff) renderBlindSpots(b *strings.Builder, c diffChanges, limit int) {
	_, _ = fmt.Fprintf(b, "  blind spots: %d → %d (%s)\n",
		d.sumFrom.BlindSpots, d.sumTo.BlindSpots,
		signedDelta(d.sumTo.BlindSpots-d.sumFrom.BlindSpots))

	if len(c.blindsNew) > 0 {
		_, _ = fmt.Fprintf(b, "  new blind spots (%d):\n", len(c.blindsNew))
		printList(b, limit, c.blindsNew, func(r store.BlindRowScan) string {
			return "    + " + blindKey(r)
		})
	}
	if len(c.blindsGone) > 0 {
		_, _ = fmt.Fprintf(b, "  gone blind spots (%d):\n", len(c.blindsGone))
		printList(b, limit, c.blindsGone, func(r store.BlindRowScan) string {
			return "    - " + blindKey(r)
		})
	}
}

// renderCoverage prints the coverage band counts and the entities whose
// evidence coverage moved between bands.
func (d scanDiff) renderCoverage(b *strings.Builder, c diffChanges, limit int) {
	fromCounts := coverageCounts(d.verdFrom)
	toCounts := coverageCounts(d.verdTo)
	parts := make([]string, 0, 3)
	for _, level := range coverageLevels {
		parts = append(parts, fmt.Sprintf("%s %d → %d", level, fromCounts[level], toCounts[level]))
	}
	_, _ = fmt.Fprintf(b, "  coverage: %s\n", strings.Join(parts, " · "))

	if len(c.coverageChanges) > 0 {
		_, _ = fmt.Fprintf(b, "  coverage changes (%d):\n", len(c.coverageChanges))
		printList(b, limit, c.coverageChanges, func(ch snapshotChange) string {
			return fmt.Sprintf("    [%s] %s: %s → %s", ch.to.Kind, ch.to.Name, ch.from.Coverage, ch.to.Coverage)
		})
	}
}

// renderVerdicts prints the state rollup of both scans and the shared
// entities whose verdict state moved.
func (d scanDiff) renderVerdicts(b *strings.Builder, c diffChanges, limit int) {
	_, _ = fmt.Fprintf(b, "  verdict: %s\n", rollupDeltaLine(d.rollFrom, d.rollTo))

	if len(c.verdictChanges) > 0 {
		_, _ = fmt.Fprintf(b, "  verdict changes (%d):\n", len(c.verdictChanges))
		printList(b, limit, c.verdictChanges, func(ch snapshotChange) string {
			return fmt.Sprintf("    [%s] %s: %s → %s", ch.to.Kind, ch.to.Name, ch.from.State, ch.to.State)
		})
	}
}

// coverageLevels are the evidence coverage bands, best first.
var coverageLevels = []string{"HIGH", "MEDIUM", "LOW"}

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

// blindRows indexes blind spots by display key; the first row wins for
// a repeated key, which only happens for identical gaps.
func blindRows(rows []store.BlindRowScan) map[string]store.BlindRowScan {
	byKey := map[string]store.BlindRowScan{}
	for _, r := range rows {
		key := blindKey(r)
		if _, ok := byKey[key]; !ok {
			byKey[key] = r
		}
	}
	return byKey
}

// countKeys returns the display keys of a blind spot index, sorted.
func countKeys(rows map[string]store.BlindRowScan) map[string]bool {
	keys := make(map[string]bool, len(rows))
	for k := range rows {
		keys[k] = true
	}
	return keys
}

// blindKey renders one blind spot for humans: host-wide gaps carry no
// entity, attached ones name it.
func blindKey(r store.BlindRowScan) string {
	if r.EntityName == "" {
		return fmt.Sprintf("%s/%s (host)", r.Channel, r.Reason)
	}
	return fmt.Sprintf("%s/%s [%s %s]", r.Channel, r.Reason, r.EntityKind, r.EntityName)
}

// blindUnion returns the sorted display keys seen in either set.
func blindUnion(from, to map[string]bool) []string {
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

// sortBlindRows orders blind spot rows for stable output.
func sortBlindRows(rows []store.BlindRowScan) {
	sort.Slice(rows, func(i, j int) bool {
		return blindKey(rows[i]) < blindKey(rows[j])
	})
}

// coverageCounts counts stored verdicts per coverage band.
func coverageCounts(verdicts map[string]store.VerdictSnapshot) map[string]int {
	counts := map[string]int{}
	for _, v := range verdicts {
		counts[v.Coverage]++
	}
	return counts
}

//
// JSON payloads (schema/scan-list.schema.json, schema/scan-diff.schema.json)
//

// scanRefJSON identifies one scan in the JSON view of either command.
type scanRefJSON struct {
	ID         int64   `json:"id"`
	StartedAt  string  `json:"started_at"`
	FinishedAt *string `json:"finished_at"` // null while the scan never finished
	Host       string  `json:"host"`
	Status     string  `json:"status"` // ok | partial | failed | incomplete
}

// scanListEntryJSON is one row of `scan list --format json`.
type scanListEntryJSON struct {
	scanRefJSON
	Entities   int            `json:"entities"`
	BlindSpots int            `json:"blind_spots"`
	Findings   int            `json:"findings"`
	Verdict    map[string]int `json:"verdict"` // null when no verdicts exist
}

// rollupKeys are the verdict states carried by every rollup object,
// always all present so consumers never probe for a key. The keys
// match `scan --format json`'s verdict object.
var rollupKeys = []string{
	verdict.StateActive, verdict.StateUnknown,
	verdict.StateLikelyOrphaned, verdict.StateOrphaned,
}

// scanListJSON is the whole `scan list --format json` document.
type scanListJSON struct {
	Scans []scanListEntryJSON `json:"scans"`
}

// scanRef renders the shared identification fields of one scan row.
func scanRef(sc store.ScanRow) scanRefJSON {
	return scanRefJSON{
		ID:         sc.ID,
		StartedAt:  sc.StartedAt,
		FinishedAt: finishedAtPtr(sc),
		Host:       sc.Host,
		Status:     scanStatus(sc),
	}
}

// rollupObject converts a stored rollup into the fixed four-state
// object.
func rollupObject(rollup map[string]int) map[string]int {
	out := make(map[string]int, len(rollupKeys))
	for _, k := range rollupKeys {
		out[k] = rollup[k]
	}
	return out
}

// scanListEntry renders one scan row for the JSON document; the
// verdict object is null when no verdicts were computed.
func scanListEntry(sc store.ScanRow, rollup map[string]int) scanListEntryJSON {
	var verdicts map[string]int
	if len(rollup) > 0 {
		verdicts = rollupObject(rollup)
	}
	return scanListEntryJSON{
		scanRefJSON: scanRef(sc),
		Entities:    sc.Entities,
		BlindSpots:  sc.BlindSpots,
		Findings:    sc.Findings,
		Verdict:     verdicts,
	}
}

// entityRefJSON is one entity line of a diff list.
type entityRefJSON struct {
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	IdentityKey string `json:"identity_key"`
}

// kindDeltaJSON is one entity kind's count move between the scans.
type kindDeltaJSON struct {
	Kind  string `json:"kind"`
	From  int    `json:"from"`
	To    int    `json:"to"`
	Delta int    `json:"delta"`
}

// entitiesDiffJSON is the `entities` section of the diff document.
type entitiesDiffJSON struct {
	From    int             `json:"from"`
	To      int             `json:"to"`
	Delta   int             `json:"delta"`
	Kinds   []kindDeltaJSON `json:"kinds"`
	Added   []entityRefJSON `json:"added"`
	Removed []entityRefJSON `json:"removed"`
}

// blockerLineJSON is one hard blocker that appeared or disappeared.
type blockerLineJSON struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	Code string `json:"code"`
	Text string `json:"text"`
}

// blockersDiffJSON is the `blockers` section of the diff document.
type blockersDiffJSON struct {
	From  int               `json:"from"`
	To    int               `json:"to"`
	Delta int               `json:"delta"`
	New   []blockerLineJSON `json:"new"`
	Gone  []blockerLineJSON `json:"gone"`
}

// blindLineJSON is one blind spot that appeared or disappeared; the
// entity fields are empty for host-wide gaps.
type blindLineJSON struct {
	Channel    string `json:"channel"`
	Reason     string `json:"reason"`
	EntityKind string `json:"entity_kind"`
	EntityName string `json:"entity_name"`
}

// blindSpotsDiffJSON is the `blind_spots` section of the diff document.
type blindSpotsDiffJSON struct {
	From  int             `json:"from"`
	To    int             `json:"to"`
	Delta int             `json:"delta"`
	New   []blindLineJSON `json:"new"`
	Gone  []blindLineJSON `json:"gone"`
}

// snapshotLineJSON is one shared entity whose coverage band or verdict
// state moved between the scans.
type snapshotLineJSON struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	From string `json:"from"`
	To   string `json:"to"`
}

// coverageDiffJSON is the `coverage` section of the diff document; the
// band counts always carry every band.
type coverageDiffJSON struct {
	From    map[string]int     `json:"from"`
	To      map[string]int     `json:"to"`
	Changes []snapshotLineJSON `json:"changes"`
}

// verdictDiffJSON is the `verdict` section of the diff document.
type verdictDiffJSON struct {
	From    map[string]int     `json:"from"`
	To      map[string]int     `json:"to"`
	Changes []snapshotLineJSON `json:"changes"`
}

// diffJSON is the whole `scan diff --format json` document. Unlike the
// text view it is never capped by --limit.
type diffJSON struct {
	From       scanRefJSON        `json:"from"`
	To         scanRefJSON        `json:"to"`
	Entities   entitiesDiffJSON   `json:"entities"`
	Blockers   blockersDiffJSON   `json:"blockers"`
	BlindSpots blindSpotsDiffJSON `json:"blind_spots"`
	Coverage   coverageDiffJSON   `json:"coverage"`
	Verdict    verdictDiffJSON    `json:"verdict"`
}

// bandCounts seeds every coverage band so the counts are stable even
// when a band is unused.
func bandCounts(counts map[string]int) map[string]int {
	out := make(map[string]int, len(coverageLevels))
	for _, level := range coverageLevels {
		out[level] = counts[level]
	}
	return out
}

// json builds the machine-readable diff document from the computed
// changes.
func (d scanDiff) json(c diffChanges) diffJSON {
	added := make([]entityRefJSON, 0, len(c.added))
	for _, e := range c.added {
		added = append(added, entityRefJSON{Kind: e.Kind, Name: e.Name, IdentityKey: e.IdentityKey})
	}
	removed := make([]entityRefJSON, 0, len(c.removed))
	for _, e := range c.removed {
		removed = append(removed, entityRefJSON{Kind: e.Kind, Name: e.Name, IdentityKey: e.IdentityKey})
	}
	kinds := make([]kindDeltaJSON, 0, len(c.kinds))
	for _, kc := range c.kinds {
		kinds = append(kinds, kindDeltaJSON{
			Kind: kc.Kind, From: kc.From, To: kc.To, Delta: kc.To - kc.From,
		})
	}

	blockersNew := make([]blockerLineJSON, 0, len(c.blockersNew))
	for _, ch := range c.blockersNew {
		blockersNew = append(blockersNew, blockerLineJSON{
			Kind: ch.entity.Kind, Name: ch.entity.Name,
			Code: ch.item.Code, Text: ch.item.Text,
		})
	}
	blockersGone := make([]blockerLineJSON, 0, len(c.blockersGone))
	for _, ch := range c.blockersGone {
		blockersGone = append(blockersGone, blockerLineJSON{
			Kind: ch.entity.Kind, Name: ch.entity.Name,
			Code: ch.item.Code, Text: ch.item.Text,
		})
	}

	blindsNew := make([]blindLineJSON, 0, len(c.blindsNew))
	for _, r := range c.blindsNew {
		blindsNew = append(blindsNew, blindLineJSON{
			Channel: r.Channel, Reason: r.Reason,
			EntityKind: r.EntityKind, EntityName: r.EntityName,
		})
	}
	blindsGone := make([]blindLineJSON, 0, len(c.blindsGone))
	for _, r := range c.blindsGone {
		blindsGone = append(blindsGone, blindLineJSON{
			Channel: r.Channel, Reason: r.Reason,
			EntityKind: r.EntityKind, EntityName: r.EntityName,
		})
	}

	coverageChanges := make([]snapshotLineJSON, 0, len(c.coverageChanges))
	for _, ch := range c.coverageChanges {
		coverageChanges = append(coverageChanges, snapshotLineJSON{
			Kind: ch.to.Kind, Name: ch.to.Name,
			From: ch.from.Coverage, To: ch.to.Coverage,
		})
	}
	verdictChanges := make([]snapshotLineJSON, 0, len(c.verdictChanges))
	for _, ch := range c.verdictChanges {
		verdictChanges = append(verdictChanges, snapshotLineJSON{
			Kind: ch.to.Kind, Name: ch.to.Name,
			From: ch.from.State, To: ch.to.State,
		})
	}

	fromTotal := entityTotal(d.sumFrom.Entities)
	toTotal := entityTotal(d.sumTo.Entities)
	return diffJSON{
		From: scanRef(d.from),
		To:   scanRef(d.to),
		Entities: entitiesDiffJSON{
			From: fromTotal, To: toTotal, Delta: toTotal - fromTotal,
			Kinds: kinds, Added: added, Removed: removed,
		},
		Blockers: blockersDiffJSON{
			From: blockerTotal(d.verdFrom), To: blockerTotal(d.verdTo),
			Delta: blockerTotal(d.verdTo) - blockerTotal(d.verdFrom),
			New:   blockersNew, Gone: blockersGone,
		},
		BlindSpots: blindSpotsDiffJSON{
			From: d.sumFrom.BlindSpots, To: d.sumTo.BlindSpots,
			Delta: d.sumTo.BlindSpots - d.sumFrom.BlindSpots,
			New:   blindsNew, Gone: blindsGone,
		},
		Coverage: coverageDiffJSON{
			From:    bandCounts(coverageCounts(d.verdFrom)),
			To:      bandCounts(coverageCounts(d.verdTo)),
			Changes: coverageChanges,
		},
		Verdict: verdictDiffJSON{
			From: rollupObject(d.rollFrom), To: rollupObject(d.rollTo),
			Changes: verdictChanges,
		},
	}
}
