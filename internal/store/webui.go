package store

import (
	"context"
	"encoding/json"
	"fmt"
)

// ListRow is one entity joined with its verdict state for the web UI
// components table.
type ListRow struct {
	ID           int64
	Kind         string
	Name         string
	IdentityKey  string
	State        string // verdict state, "" when no verdict recorded
	Coverage     string
	LastActivity string // newest evidence observed_at, "" when none
}

// ListFilter carries the web UI table's filter/sort parameters. Empty
// fields mean "no filter" / default order.
type ListFilter struct {
	Kind     string
	Status   string
	Coverage string
	Sort     string // name | kind | status | coverage | last_activity
	Desc     bool
}

// listSortColumns maps the allowed sort keys to SQL expressions so
// user input never reaches the query text.
var listSortColumns = map[string]string{
	"name":          "e.name",
	"kind":          "e.kind",
	"status":        "state",
	"coverage":      "coverage",
	"last_activity": "last_at",
}

// ListEntitiesFiltered lists the scan's entities joined with the
// newest verdict and last evidence timestamp, filtered and sorted per
// the web UI table.
func (s *Store) ListEntitiesFiltered(ctx context.Context, scanID int64, f ListFilter) ([]ListRow, error) {
	orderBy, ok := listSortColumns[f.Sort]
	if !ok {
		orderBy = "e.name"
	}
	dir := "ASC"
	if f.Desc {
		dir = "DESC"
	}
	q := `SELECT e.id, e.kind, e.name, e.identity_key,
	             COALESCE(v.state, ''), COALESCE(v.coverage, ''),
	             COALESCE(last_ev.last_at, '')
	      FROM entities e
	      LEFT JOIN (
	        SELECT entity_id, state, coverage FROM verdicts v2
	        WHERE v2.scan_id = ? AND v2.id = (
	          SELECT MAX(id) FROM verdicts v3
	          WHERE v3.entity_id = v2.entity_id AND v3.scan_id = v2.scan_id)
	      ) v ON v.entity_id = e.id
	      LEFT JOIN (
	        SELECT entity_id, MAX(observed_at) AS last_at
	        FROM evidence GROUP BY entity_id
	      ) last_ev ON last_ev.entity_id = e.id
	      WHERE e.scan_id = ?
	        AND (? = '' OR e.kind = ?)
	        AND (? = '' OR COALESCE(v.state, '') = ?)
	        AND (? = '' OR COALESCE(v.coverage, '') = ?)
	      ORDER BY ` + orderBy + ` ` + dir + `, e.id`
	rs, err := s.db.QueryContext(ctx, q,
		scanID, scanID,
		f.Kind, f.Kind,
		f.Status, f.Status,
		f.Coverage, f.Coverage)
	if err != nil {
		return nil, fmt.Errorf("list entities: %w", err)
	}
	defer func() { _ = rs.Close() }()

	var out []ListRow
	for rs.Next() {
		var r ListRow
		if err := rs.Scan(&r.ID, &r.Kind, &r.Name, &r.IdentityKey,
			&r.State, &r.Coverage, &r.LastActivity); err != nil {
			return nil, fmt.Errorf("list entities: %w", err)
		}
		out = append(out, r)
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("list entities: %w", err)
	}
	return out, nil
}

// EntityByID loads one entity by primary key — the web UI detail page
// resolves the numeric id straight from the URL.
func (s *Store) EntityByID(ctx context.Context, id int64) (EntityRow, error) {
	rows, err := s.queryEntities(ctx,
		`SELECT id, kind, name, identity_key, attributes_json
		 FROM entities WHERE id = ?`, id)
	if err != nil {
		return EntityRow{}, fmt.Errorf("entity %d: %w", id, err)
	}
	if len(rows) == 0 {
		return EntityRow{}, fmt.Errorf("entity %d: not found", id)
	}
	return rows[0], nil
}

// GraphNode is one node of the whole-scan graph for the web UI.
type GraphNode struct {
	ID   int64  `json:"id"`
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// GraphEdge is one directed edge with the evidence channel and raw
// reference that justified it.
type GraphEdge struct {
	Src      int64  `json:"src"`
	Dst      int64  `json:"dst"`
	Kind     string `json:"kind"`
	Strength string `json:"strength"`
	Channel  string `json:"channel"`
	RawRef   string `json:"raw_ref"`
}

// GraphRows loads every entity and edge of one scan in a single pass
// each — the payload behind the web UI graph page.
func (s *Store) GraphRows(ctx context.Context, scanID int64) ([]GraphNode, []GraphEdge, error) {
	nrs, err := s.db.QueryContext(ctx,
		`SELECT id, kind, name FROM entities WHERE scan_id = ? ORDER BY id`, scanID)
	if err != nil {
		return nil, nil, fmt.Errorf("graph nodes: %w", err)
	}
	var nodes []GraphNode
	for nrs.Next() {
		var n GraphNode
		if err := nrs.Scan(&n.ID, &n.Kind, &n.Name); err != nil {
			_ = nrs.Close()
			return nil, nil, fmt.Errorf("graph nodes: %w", err)
		}
		nodes = append(nodes, n)
	}
	if err := nrs.Err(); err != nil {
		_ = nrs.Close()
		return nil, nil, fmt.Errorf("graph nodes: %w", err)
	}
	_ = nrs.Close()

	ers, err := s.db.QueryContext(ctx,
		`SELECT ed.src_id, ed.dst_id, ed.kind, ed.strength,
		        COALESCE(ev.channel, ''), COALESCE(ev.raw_ref, '')
		 FROM edges ed LEFT JOIN evidence ev ON ev.id = ed.evidence_id
		 WHERE ed.scan_id = ? ORDER BY ed.id`, scanID)
	if err != nil {
		return nil, nil, fmt.Errorf("graph edges: %w", err)
	}
	defer func() { _ = ers.Close() }()
	var edges []GraphEdge
	for ers.Next() {
		var e GraphEdge
		if err := ers.Scan(&e.Src, &e.Dst, &e.Kind, &e.Strength, &e.Channel, &e.RawRef); err != nil {
			return nil, nil, fmt.Errorf("graph edges: %w", err)
		}
		edges = append(edges, e)
	}
	if err := ers.Err(); err != nil {
		return nil, nil, fmt.Errorf("graph edges: %w", err)
	}
	return nodes, edges, nil
}

// HistoryRow is one evidence observation of an identity across every
// scan — the append-only activity trail behind the History tab.
type HistoryRow struct {
	ScanID     int64
	ObservedAt string
	Channel    string
	Polarity   string
	Strength   string
	RawRef     string
	Value      map[string]string
}

// HistoryFor lists every evidence row recorded for one identity key
// across all scans, newest first.
func (s *Store) HistoryFor(ctx context.Context, identityKey string) ([]HistoryRow, error) {
	rs, err := s.db.QueryContext(ctx,
		`SELECT ev.observed_at, ev.channel, ev.polarity, ev.strength,
		        ev.raw_ref, ev.value_json, e.scan_id
		 FROM evidence ev
		 JOIN entities e ON e.id = ev.entity_id
		 WHERE e.identity_key = ?
		 ORDER BY ev.observed_at DESC, ev.id DESC`, identityKey)
	if err != nil {
		return nil, fmt.Errorf("history for %s: %w", identityKey, err)
	}
	defer func() { _ = rs.Close() }()

	var out []HistoryRow
	for rs.Next() {
		var r HistoryRow
		var valueJSON string
		if err := rs.Scan(&r.ObservedAt, &r.Channel, &r.Polarity,
			&r.Strength, &r.RawRef, &valueJSON, &r.ScanID); err != nil {
			return nil, fmt.Errorf("history for %s: %w", identityKey, err)
		}
		r.Value = map[string]string{}
		if valueJSON != "" && valueJSON != "null" {
			_ = json.Unmarshal([]byte(valueJSON), &r.Value)
		}
		out = append(out, r)
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("history for %s: %w", identityKey, err)
	}
	return out, nil
}

// PlanByID loads one plan with its owning entity's name/kind for the
// web UI plan viewer header.
func (s *Store) PlanByID(ctx context.Context, planID int64) (planIDOut int64, entityID int64, name, kind string, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT p.id, p.entity_id, e.name, e.kind
		 FROM plans p JOIN entities e ON e.id = p.entity_id
		 WHERE p.id = ?`, planID).Scan(&planIDOut, &entityID, &name, &kind)
	if err != nil {
		return 0, 0, "", "", fmt.Errorf("plan %d: %w", planID, err)
	}
	return planIDOut, entityID, name, kind, nil
}

// EntityKinds returns the distinct kinds present in a scan — the
// filter dropdown source for the web UI components table.
func (s *Store) EntityKinds(ctx context.Context, scanID int64) ([]string, error) {
	rs, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT kind FROM entities WHERE scan_id = ? ORDER BY kind`, scanID)
	if err != nil {
		return nil, fmt.Errorf("entity kinds: %w", err)
	}
	defer func() { _ = rs.Close() }()
	var out []string
	for rs.Next() {
		var k string
		if err := rs.Scan(&k); err != nil {
			return nil, fmt.Errorf("entity kinds: %w", err)
		}
		out = append(out, k)
	}
	return out, rs.Err()
}
