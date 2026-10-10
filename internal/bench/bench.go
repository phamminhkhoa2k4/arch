// Package bench computes the correlation quality metrics against a
// scan database and the ground truth file.
package bench

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"archaeologist/internal/rules"
	"archaeologist/internal/store"
)

// Go/no-go thresholds.
const (
	// MinOwnedPercent is the share of listeners whose deterministic
	// owner chain (≤2 hops) reaches a container or systemd unit.
	MinOwnedPercent = 95.0
	// MinRoutePercent is the share of simple ground-truth route chains
	// fully resolved to the expected listeners and owners.
	MinRoutePercent = 100.0
)

// routeWalkDepth caps route walks at the graph query's 5-hop depth.
const routeWalkDepth = 5

// ownerWalkDepth is the deterministic ≤2-hop owner rule from the
// benchmark definition.
const ownerWalkDepth = 2

// Report holds both benchmark metrics for one run.
type Report struct {
	OwnedTotal   int
	OwnedOK      int
	OwnedPct     float64
	Unowned      []string // listener identity keys without a valid owner
	RoutesTotal  int
	RoutesOK     int
	RoutesPct    float64
	BrokenRoutes []string // ground-truth chain ids that failed
}

// Run loads the ground truth and the scan database, computes the
// correlation metrics plus the checkpoint metrics, and writes the
// human-readable report to out. Correlation misses add GitHub Actions
// warning annotations and still return nil (exit 0); a checkpoint
// miss returns an error so the CI job fails (D3). The database is
// copied to a temp file first: the store flips the WAL header and the
// verdict cache writes rows — neither may dirty the committed fixture.
func Run(dbPath, gtPath, rulesPath string, out io.Writer) error {
	gt, err := LoadGT(gtPath)
	if err != nil {
		return fmt.Errorf("ground truth: %w", err)
	}
	working, cleanup, err := copyDB(dbPath)
	if err != nil {
		return err
	}
	defer cleanup()

	rep, err := Measure(working, gt)
	if err != nil {
		return err
	}
	r, _, err := rules.Load(rulesPath)
	if err != nil {
		return fmt.Errorf("rules: %w", err)
	}
	cp, err := MeasureCheckpoint(working, gt, r)
	if err != nil {
		return err
	}
	if err := rep.Write(out); err != nil {
		return err
	}
	if err := cp.Write(out); err != nil {
		return err
	}
	if cp.GateFailed() {
		return fmt.Errorf("checkpoint #2: false-orphan hoặc precision LIKELY_ORPHANED dưới ngưỡng")
	}
	return nil
}

// copyDB copies the database file into a fresh temp directory and
// returns the copy plus a cleanup that removes it.
func copyDB(src string) (string, func(), error) {
	data, err := os.ReadFile(src)
	if err != nil {
		return "", func() {}, fmt.Errorf("read db: %w", err)
	}
	dir, err := os.MkdirTemp("", "bench-db-")
	if err != nil {
		return "", func() {}, err
	}
	dst := filepath.Join(dir, "scan.db")
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", func() {}, fmt.Errorf("copy db: %w", err)
	}
	return dst, func() { _ = os.RemoveAll(dir) }, nil
}

// Measure evaluates both metrics. dbPath errors and missing scans are
// tool errors; metric misses only show up in the Report.
func Measure(dbPath string, gt *GroundTruth) (*Report, error) {
	st, err := store.Open(context.Background(), dbPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	defer func() { _ = st.Close() }()
	scanID, err := st.LatestScanID(context.Background())
	if err != nil {
		return nil, fmt.Errorf("db: %w", err)
	}
	rep := &Report{}
	if err := rep.measureOwned(st, scanID, gt); err != nil {
		return nil, err
	}
	if err := rep.measureRoutes(st, scanID, gt); err != nil {
		return nil, err
	}
	return rep, nil
}

// measureOwned counts every listener entity: listeners listed in the
// ground truth must reach their expected owner, any other listener
// accepts any container/unit owner. A ground-truth listener missing
// from the scan counts against the denominator — a silent lab drift is
// not a pass.
func (r *Report) measureOwned(st *store.Store, scanID int64, gt *GroundTruth) error {
	listeners, err := listenerEntities(st, scanID)
	if err != nil {
		return err
	}
	byKey := map[string]listenerEntity{}
	for _, l := range listeners {
		byKey[l.attrs["proto"]+"|"+l.attrs["addr"]+"|"+l.attrs["port"]] = l
	}

	r.OwnedTotal = len(listeners)
	for _, want := range gt.Listeners {
		if _, ok := byKey[want.key()]; !ok {
			r.OwnedTotal++
			r.Unowned = append(r.Unowned, "gt:"+want.ID+" (không có trong scan)")
		}
	}
	for _, l := range listeners {
		want := gt.findListener(l.attrs["proto"], l.attrs["addr"], l.attrs["port"])
		owned, err := l.hasOwner(st, scanID, want)
		if err != nil {
			return err
		}
		if owned {
			r.OwnedOK++
		} else {
			r.Unowned = append(r.Unowned, l.identity)
		}
	}
	r.OwnedPct = percent(r.OwnedOK, r.OwnedTotal)
	return nil
}

// measureRoutes checks every simple ground-truth chain: from the route
// entity a proxies_to-only deterministic walk must reach a listener
// with the expected proto/port, and that listener must reach the
// expected owner within ownerWalkDepth deterministic hops.
func (r *Report) measureRoutes(st *store.Store, scanID int64, gt *GroundTruth) error {
	simple := 0
	for _, chain := range gt.RouteChains {
		if !chain.Simple {
			continue
		}
		simple++
		ok, err := chain.satisfied(st, scanID)
		if err != nil {
			return err
		}
		if ok {
			r.RoutesOK++
		} else {
			r.BrokenRoutes = append(r.BrokenRoutes, chain.ID)
		}
	}
	r.RoutesTotal = simple
	r.RoutesPct = percent(r.RoutesOK, r.RoutesTotal)
	return nil
}

// Write prints the report; misses add GitHub Actions warning
// annotations that keep the job green (exit 0) while surfacing the gap.
func (r *Report) Write(out io.Writer) error {
	if _, err := fmt.Fprintf(out, "Listener có chủ: %d/%d = %.1f%% (mục tiêu ≥%.0f%%)\n",
		r.OwnedOK, r.OwnedTotal, r.OwnedPct, MinOwnedPercent); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Chuỗi route đúng: %d/%d = %.1f%% (mục tiêu %.0f%%)\n",
		r.RoutesOK, r.RoutesTotal, r.RoutesPct, MinRoutePercent); err != nil {
		return err
	}
	if r.OwnedPct < MinOwnedPercent {
		for _, id := range r.Unowned {
			if _, err := fmt.Fprintf(out, "  không có chủ: %s\n", id); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(out,
			"::warning title=benchmark::Listener có chủ %.1f%% dưới ngưỡng %.0f%%\n",
			r.OwnedPct, MinOwnedPercent); err != nil {
			return err
		}
	}
	if r.RoutesPct < MinRoutePercent {
		for _, id := range r.BrokenRoutes {
			if _, err := fmt.Fprintf(out, "  chuỗi sai: %s\n", id); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(out,
			"::warning title=benchmark::Chuỗi route đúng %.1f%% dưới ngưỡng %.0f%%\n",
			r.RoutesPct, MinRoutePercent); err != nil {
			return err
		}
	}
	return nil
}

// percent returns the share as 0–100, treating an empty denominator as
// a vacuous pass so a fixture without listeners cannot fake a failure.
func percent(ok, total int) float64 {
	if total == 0 {
		return 100.0
	}
	return float64(ok) / float64(total) * 100.0
}

// listenerEntity is one listener row plus its parsed attributes.
type listenerEntity struct {
	id       int64
	identity string
	attrs    map[string]string
}

// hasOwner answers the benchmark owner rule: a deterministic walk of at
// most ownerWalkDepth hops reaching a container/systemd_unit — or the
// ground-truth expected owner when this listener is listed there.
func (l listenerEntity) hasOwner(st *store.Store, scanID int64, want *GTListener) (bool, error) {
	walks, err := st.Chain(context.Background(), scanID, l.id, ownerWalkDepth)
	if err != nil {
		return false, err
	}
	for _, w := range walks {
		if !allDeterministic(w) {
			continue
		}
		end := w.Nodes[len(w.Nodes)-1]
		if want == nil {
			if end.Kind == "container" || end.Kind == "systemd_unit" {
				return true, nil
			}
			continue
		}
		if end.Kind == want.ExpectedOwner.Kind && end.Name == want.ExpectedOwner.Name {
			return true, nil
		}
	}
	return false, nil
}

// satisfied walks one ground-truth chain as described in measureRoutes.
func (c GTRouteChain) satisfied(st *store.Store, scanID int64) (bool, error) {
	route, err := findRoute(st, scanID, c.Location, c.File)
	if err != nil {
		return false, err
	}
	if route == 0 {
		return false, nil
	}
	walks, err := st.Chain(context.Background(), scanID, route, routeWalkDepth)
	if err != nil {
		return false, err
	}
	for _, want := range c.Expected {
		ok, err := reachesListener(walks, st, scanID, want)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

// reachesListener reports whether some proxies_to-only deterministic
// prefix of a walk lands on a listener with the expected proto/port
// whose own owner walk ends at the expected owner.
func reachesListener(walks []store.ChainRow, st *store.Store, scanID int64, want ExpectedRoute) (bool, error) {
	for _, w := range walks {
		for i := range w.Nodes {
			if !prefixIsProxiesTo(w, i) {
				continue
			}
			node := w.Nodes[i]
			if node.Kind != "listener" || !matchProtoPort(node.IdentityKey, want.Proto, want.Port) {
				continue
			}
			owned, err := ownerReaches(st, scanID, node.ID, want.Owner)
			if err != nil {
				return false, err
			}
			if owned {
				return true, nil
			}
		}
	}
	return false, nil
}

// prefixIsProxiesTo checks hops [0, i) of one walk: every hop must be
// a deterministic proxies_to edge (the route chain itself).
func prefixIsProxiesTo(w store.ChainRow, i int) bool {
	for j := 0; j < i; j++ {
		if w.EdgeKinds[j] != "proxies_to" || w.Strengths[j] != "deterministic" {
			return false
		}
	}
	return true
}

// ownerReaches mirrors listener.hasOwner for an expected owner pair.
func ownerReaches(st *store.Store, scanID, listenerID int64, want Owner) (bool, error) {
	walks, err := st.Chain(context.Background(), scanID, listenerID, ownerWalkDepth)
	if err != nil {
		return false, err
	}
	for _, w := range walks {
		if !allDeterministic(w) {
			continue
		}
		end := w.Nodes[len(w.Nodes)-1]
		if end.Kind == want.Kind && end.Name == want.Name {
			return true, nil
		}
	}
	return false, nil
}

func allDeterministic(w store.ChainRow) bool {
	for _, s := range w.Strengths {
		if s != "deterministic" {
			return false
		}
	}
	return true
}

// matchProtoPort compares "listener|proto|addr|port|inode" against the
// expected proto and port; the inode suffix changes every scan and the
// address may differ between the proxy target and the bind.
func matchProtoPort(identity, proto string, port int) bool {
	parts := strings.Split(identity, "|")
	if len(parts) < 4 || parts[0] != "listener" {
		return false
	}
	return parts[1] == proto && parts[3] == fmt.Sprintf("%d", port)
}

// listenerEntities lists every listener of the scan with attributes.
func listenerEntities(st *store.Store, scanID int64) ([]listenerEntity, error) {
	rows, err := st.DB().QueryContext(context.Background(),
		`SELECT id, identity_key, attributes_json FROM entities
		 WHERE scan_id = ? AND kind = 'listener' ORDER BY identity_key`, scanID)
	if err != nil {
		return nil, fmt.Errorf("listener entities: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []listenerEntity
	for rows.Next() {
		var l listenerEntity
		var attrsJSON string
		if err := rows.Scan(&l.id, &l.identity, &attrsJSON); err != nil {
			return nil, fmt.Errorf("listener entities: %w", err)
		}
		l.attrs = map[string]string{}
		if err := json.Unmarshal([]byte(attrsJSON), &l.attrs); err != nil {
			return nil, fmt.Errorf("listener %s: parse attrs: %w", l.identity, err)
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// findRoute resolves one ground-truth route by location attribute plus
// the config file suffix; ties break on identity_key so the pick stays
// deterministic.
func findRoute(st *store.Store, scanID int64, location, file string) (int64, error) {
	rows, err := st.DB().QueryContext(context.Background(),
		`SELECT id, identity_key, attributes_json FROM entities
		 WHERE scan_id = ? AND kind = 'nginx_route'
		 ORDER BY identity_key`, scanID)
	if err != nil {
		return 0, fmt.Errorf("route %s: %w", location, err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var id int64
		var identity, attrsJSON string
		if err := rows.Scan(&id, &identity, &attrsJSON); err != nil {
			return 0, fmt.Errorf("route %s: %w", location, err)
		}
		attrs := map[string]string{}
		if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
			continue
		}
		if attrs["location"] == location && strings.HasSuffix(attrs["file"], file) {
			return id, nil
		}
	}
	return 0, rows.Err()
}
