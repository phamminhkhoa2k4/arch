package store

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Graph groups for the explain command. Every incident
// edge lands in exactly one group: the scheduling/deployment axis kinds
// first (either direction — a timer sees its incoming scheduled_by the
// same way a unit sees its outgoing one), then generic incoming and
// outgoing.
const (
	GroupIncoming    = "incoming"
	GroupOutgoing    = "outgoing"
	GroupDeployedBy  = "deployed_by"
	GroupScheduledBy = "scheduled_by"
)

// NeighborRow is one incident edge with the entity on its other end,
// the evidence behind the link, and the explain group it belongs to.
type NeighborRow struct {
	Group        string
	EdgeKind     string
	Strength     string
	NeighborID   int64
	NeighborKind string
	NeighborName string
	NeighborKey  string
	Channel      string
	RawRef       string
}

// NeighborRows lists every edge incident to entityID within scanID,
// grouped for explain. The order is fully determined:
// group order (incoming, outgoing, deployed_by, scheduled_by), then
// edge kind, neighbor identity_key, edge id.
func (s *Store) NeighborRows(ctx context.Context, scanID, entityID int64) ([]NeighborRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT
		   CASE
		     WHEN e.kind IN ('deployed_by', 'built_from') THEN 3
		     WHEN e.kind = 'scheduled_by' THEN 4
		     WHEN e.dst_id = ? THEN 1
		     ELSE 2
		   END AS grp_rank,
		   e.kind, e.strength,
		   n.id, n.kind, n.name, n.identity_key,
		   ev.channel, ev.raw_ref
		 FROM edges e
		 JOIN entities n
		   ON n.id = CASE WHEN e.src_id = ? THEN e.dst_id ELSE e.src_id END
		 JOIN evidence ev ON ev.id = e.evidence_id
		 WHERE e.scan_id = ? AND (e.src_id = ? OR e.dst_id = ?)
		 ORDER BY grp_rank, e.kind, n.identity_key, e.id`,
		entityID, entityID, scanID, entityID, entityID)
	if err != nil {
		return nil, fmt.Errorf("neighbor rows: %w", err)
	}
	defer func() { _ = rows.Close() }()

	groups := []string{
		1: GroupIncoming,
		2: GroupOutgoing,
		3: GroupDeployedBy,
		4: GroupScheduledBy,
	}
	var out []NeighborRow
	for rows.Next() {
		var r NeighborRow
		var rank int
		if err := rows.Scan(&rank, &r.EdgeKind, &r.Strength,
			&r.NeighborID, &r.NeighborKind, &r.NeighborName, &r.NeighborKey,
			&r.Channel, &r.RawRef); err != nil {
			return nil, fmt.Errorf("neighbor rows: %w", err)
		}
		r.Group = groups[rank]
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("neighbor rows: %w", err)
	}
	return out, nil
}

// ChainNode is one node on a chain walk.
type ChainNode struct {
	ID          int64
	Kind        string
	Name        string
	IdentityKey string
}

// ChainRow is one walk from the start entity: Depth edges leading
// through Nodes (start first, end last), one entry per hop in
// EdgeKinds/Strengths/Reversed. Reversed marks a hop taken against the
// stored src→dst direction — ownership often walks manages backwards
// (process → unit).
type ChainRow struct {
	Depth     int
	Nodes     []ChainNode
	EdgeKinds []string
	Strengths []string
	Reversed  []bool
}

// placeholders returns n comma-separated SQL bind placeholders.
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// Chain walks undirected paths from startID for up to maxDepth hops
// using one recursive CTE. A node is never visited
// twice on the same path, so cycles terminate. Every path is returned
// (no dedup): callers with sparse start nodes stay small, and callers
// that need a specific intermediate node — the benchmark matching a
// listener on the way — must not lose it to a merged end node.
// Results are ordered by depth then path, fully deterministic.
func (s *Store) Chain(ctx context.Context, scanID, startID int64, maxDepth int) ([]ChainRow, error) {
	return s.chain(ctx, scanID, startID, maxDepth, nil)
}

// ChainKinds is Chain restricted to edges of the given kinds. Callers
// that only pattern-match a small set of edge kinds use it to keep the
// walk from exploding over unrelated dense edges (depends_on graphs).
func (s *Store) ChainKinds(ctx context.Context, scanID, startID int64, maxDepth int, kinds []string) ([]ChainRow, error) {
	return s.chain(ctx, scanID, startID, maxDepth, kinds)
}

func (s *Store) chain(ctx context.Context, scanID, startID int64, maxDepth int, kinds []string) ([]ChainRow, error) {
	if maxDepth < 1 {
		return nil, nil
	}
	kindFilter := ""
	kindArgs := make([]any, 0, len(kinds))
	if len(kinds) > 0 {
		kindFilter = " AND e.kind IN (" + placeholders(len(kinds)) + ")"
		for _, k := range kinds {
			kindArgs = append(kindArgs, k)
		}
	}
	args := []any{startID, startID, startID, startID, scanID, startID, startID}
	args = append(args, kindArgs...)
	args = append(args, scanID)
	args = append(args, kindArgs...)
	args = append(args, maxDepth)
	rows, err := s.db.QueryContext(ctx,
		`WITH RECURSIVE walk(depth, node, ids, kinds, strengths, revs) AS (
		   SELECT 1,
		     CASE WHEN e.src_id = ? THEN e.dst_id ELSE e.src_id END,
		     '|' || CAST(? AS TEXT) || '|' ||
		       CAST(CASE WHEN e.src_id = ? THEN e.dst_id ELSE e.src_id END AS TEXT) || '|',
		     '|' || e.kind || '|',
		     '|' || e.strength || '|',
		     '|' || CASE WHEN e.src_id = ? THEN '0' ELSE '1' END || '|'
		   FROM edges e
		   WHERE e.scan_id = ? AND (e.src_id = ? OR e.dst_id = ?)
		     AND e.src_id <> e.dst_id`+kindFilter+`
		   UNION ALL
		   SELECT w.depth + 1,
		     CASE WHEN e.src_id = w.node THEN e.dst_id ELSE e.src_id END,
		     w.ids || CAST(CASE WHEN e.src_id = w.node THEN e.dst_id ELSE e.src_id END AS TEXT) || '|',
		     w.kinds || e.kind || '|',
		     w.strengths || e.strength || '|',
		     w.revs || CASE WHEN e.dst_id = w.node THEN '1' ELSE '0' END || '|'
		   FROM walk w
		   JOIN edges e
		     ON e.scan_id = ?
		       AND (e.src_id = w.node OR e.dst_id = w.node)`+kindFilter+`
		   WHERE w.depth < ?
		     AND instr(w.ids,
		       '|' || CAST(CASE WHEN e.src_id = w.node THEN e.dst_id ELSE e.src_id END AS TEXT) || '|') = 0
		 )
		 SELECT depth, ids, kinds, strengths, revs
		 FROM walk
		 ORDER BY depth, ids`,
		args...)
	if err != nil {
		return nil, fmt.Errorf("chain: %w", err)
	}
	defer func() { _ = rows.Close() }()

	type raw struct {
		depth           int
		ids, kinds      string
		strengths, revs string
	}
	var raws []raw
	need := map[int64]bool{}
	for rows.Next() {
		var r raw
		if err := rows.Scan(&r.depth, &r.ids, &r.kinds, &r.strengths, &r.revs); err != nil {
			return nil, fmt.Errorf("chain: %w", err)
		}
		for _, id := range splitPipeInts(r.ids) {
			need[id] = true
		}
		raws = append(raws, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("chain: %w", err)
	}
	if len(raws) == 0 {
		return nil, nil
	}

	meta, err := s.nodeMeta(ctx, need)
	if err != nil {
		return nil, err
	}
	out := make([]ChainRow, 0, len(raws))
	for _, r := range raws {
		ids := splitPipeInts(r.ids)
		kinds := splitPipeStrings(r.kinds)
		strengths := splitPipeStrings(r.strengths)
		revs := splitPipeStrings(r.revs)
		if len(ids) != r.depth+1 || len(kinds) != r.depth ||
			len(strengths) != r.depth || len(revs) != r.depth {
			return nil, fmt.Errorf("chain: malformed path %q at depth %d", r.ids, r.depth)
		}
		row := ChainRow{
			Depth:     r.depth,
			EdgeKinds: kinds,
			Strengths: strengths,
			Reversed:  make([]bool, 0, len(revs)),
		}
		for _, id := range ids {
			row.Nodes = append(row.Nodes, meta[id])
		}
		for _, rev := range revs {
			row.Reversed = append(row.Reversed, rev == "1")
		}
		out = append(out, row)
	}
	return out, nil
}

// nodeMeta resolves kind/name/identity_key for every id on some path.
func (s *Store) nodeMeta(ctx context.Context, ids map[int64]bool) (map[int64]ChainNode, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	query := `SELECT id, kind, name, identity_key FROM entities WHERE id IN (?`
	var args []any
	first := true
	for id := range ids {
		if first {
			first = false
		} else {
			query += ",?"
		}
		args = append(args, id)
	}
	query += ")"

	rs, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("chain node meta: %w", err)
	}
	defer func() { _ = rs.Close() }()

	meta := make(map[int64]ChainNode, len(ids))
	for rs.Next() {
		var n ChainNode
		if err := rs.Scan(&n.ID, &n.Kind, &n.Name, &n.IdentityKey); err != nil {
			return nil, fmt.Errorf("chain node meta: %w", err)
		}
		meta[n.ID] = n
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("chain node meta: %w", err)
	}
	return meta, nil
}

// splitPipeInts parses "|1|5|" into [1 5]; empty segments dropped.
func splitPipeInts(s string) []int64 {
	var out []int64
	for _, part := range strings.Split(s, "|") {
		if part == "" {
			continue
		}
		n, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			continue
		}
		out = append(out, n)
	}
	return out
}

// splitPipeStrings parses "|a|b|" into [a b]; empty segments dropped.
func splitPipeStrings(s string) []string {
	var out []string
	for _, part := range strings.Split(s, "|") {
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}
