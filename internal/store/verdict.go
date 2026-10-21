package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"archaeologist/internal/verdict"
)

// BuildInput gathers every fact the rule engine needs for one entity
// of one scan: evidence with ids, entity-scoped blind spots, incident
// edges with neighbor state, undirected paths (explain Chain) restricted to
// the edge kinds blockers pattern-match on, observation buckets, and
// the observation window.
func (s *Store) BuildInput(ctx context.Context, scanID, entityID int64) (verdict.Input, error) {
	win, err := s.inputWindow(ctx, scanID)
	if err != nil {
		return verdict.Input{}, err
	}
	return s.BuildInputWithWindow(ctx, scanID, entityID, win)
}

// Window returns the observation window for a scan. Bulk callers compute
// it once instead of once per entity (it does not depend on the entity).
func (s *Store) Window(ctx context.Context, scanID int64) (verdict.Window, error) {
	return s.inputWindow(ctx, scanID)
}

// BuildInputWithWindow is BuildInput with a precomputed scan window.
func (s *Store) BuildInputWithWindow(ctx context.Context, scanID, entityID int64, win verdict.Window) (verdict.Input, error) {
	in := verdict.Input{EntityID: entityID, Attributes: map[string]string{}}

	var attrsJSON string
	err := s.db.QueryRowContext(ctx,
		`SELECT kind, name, identity_key, attributes_json
		 FROM entities WHERE id = ? AND scan_id = ?`, entityID, scanID).
		Scan(&in.Kind, &in.Name, &in.IdentityKey, &attrsJSON)
	if err != nil {
		return verdict.Input{}, fmt.Errorf("build input: entity %d: %w", entityID, err)
	}
	_ = json.Unmarshal([]byte(attrsJSON), &in.Attributes)
	if in.Attributes == nil {
		in.Attributes = map[string]string{}
	}

	if in.Evidence, err = s.inputEvidence(ctx, entityID); err != nil {
		return verdict.Input{}, err
	}
	if in.Blinds, err = s.inputBlinds(ctx, entityID); err != nil {
		return verdict.Input{}, err
	}
	if in.Edges, err = s.inputEdges(ctx, scanID, entityID); err != nil {
		return verdict.Input{}, err
	}
	if in.Paths, err = s.inputPaths(ctx, scanID, entityID); err != nil {
		return verdict.Input{}, err
	}
	if in.Observations, err = s.inputObservations(ctx, entityID); err != nil {
		return verdict.Input{}, err
	}
	in.Window = win
	return in, nil
}

// BuildInputs gathers the inputs for every entity of a scan with one
// query per fact table instead of one query per entity and fact. The
// verdict loop stays entity-ordered and the per-entity slices keep the
// exact ordering (evidence/blind/edge row ids) of the single-entity
// builder, so results are observationally identical.
func (s *Store) BuildInputs(ctx context.Context, scanID int64) (map[int64]verdict.Input, error) {
	win, err := s.Window(ctx, scanID)
	if err != nil {
		return nil, err
	}
	inputs, err := s.loadInputEntities(ctx, scanID, win)
	if err != nil {
		return nil, err
	}
	if err := s.bulkEvidence(ctx, scanID, inputs); err != nil {
		return nil, err
	}
	if err := s.bulkBlinds(ctx, scanID, inputs); err != nil {
		return nil, err
	}
	if err := s.bulkEdges(ctx, scanID, inputs); err != nil {
		return nil, err
	}
	if err := s.bulkObservations(ctx, scanID, inputs); err != nil {
		return nil, err
	}

	gates, err := s.pathGates(ctx, scanID)
	if err != nil {
		return nil, err
	}
	for id, in := range inputs {
		if in.Paths, err = s.inputPathsWithGates(ctx, scanID, id, gates); err != nil {
			return nil, err
		}
		inputs[id] = in
	}
	return inputs, nil
}

func (s *Store) loadInputEntities(ctx context.Context, scanID int64, win verdict.Window) (map[int64]verdict.Input, error) {
	rs, err := s.db.QueryContext(ctx,
		`SELECT id, kind, name, identity_key, attributes_json
		 FROM entities WHERE scan_id = ? ORDER BY id`, scanID)
	if err != nil {
		return nil, fmt.Errorf("build input: entities: %w", err)
	}
	defer func() { _ = rs.Close() }()

	inputs := map[int64]verdict.Input{}
	for rs.Next() {
		var (
			id                     int64
			kind, name, key, attrs string
		)
		if err := rs.Scan(&id, &kind, &name, &key, &attrs); err != nil {
			return nil, fmt.Errorf("build input: entities: %w", err)
		}
		attributes := map[string]string{}
		_ = json.Unmarshal([]byte(attrs), &attributes)
		if attributes == nil {
			attributes = map[string]string{}
		}
		inputs[id] = verdict.Input{
			EntityID:    id,
			Kind:        kind,
			Name:        name,
			IdentityKey: key,
			Attributes:  attributes,
			Window:      win,
		}
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("build input: entities: %w", err)
	}
	return inputs, nil
}

func (s *Store) bulkEvidence(ctx context.Context, scanID int64, inputs map[int64]verdict.Input) error {
	rs, err := s.db.QueryContext(ctx,
		`SELECT ev.entity_id, ev.id, ev.polarity, ev.channel, ev.strength,
		        ev.observed_at, ev.raw_ref, ev.value_json
		 FROM evidence ev
		 JOIN entities e ON e.id = ev.entity_id
		 WHERE e.scan_id = ?
		 ORDER BY ev.entity_id, ev.id`, scanID)
	if err != nil {
		return fmt.Errorf("build input: evidence: %w", err)
	}
	defer func() { _ = rs.Close() }()
	for rs.Next() {
		var entityID int64
		var e verdict.Evidence
		var valueJSON string
		if err := rs.Scan(&entityID, &e.ID, &e.Polarity, &e.Channel, &e.Strength,
			&e.ObservedAt, &e.RawRef, &valueJSON); err != nil {
			return fmt.Errorf("build input: evidence: %w", err)
		}
		e.Value = map[string]string{}
		if valueJSON != "" && valueJSON != "null" {
			_ = json.Unmarshal([]byte(valueJSON), &e.Value)
		}
		if e.Value == nil {
			e.Value = map[string]string{}
		}
		in, ok := inputs[entityID]
		if !ok {
			continue
		}
		in.Evidence = append(in.Evidence, e)
		inputs[entityID] = in
	}
	if err := rs.Err(); err != nil {
		return fmt.Errorf("build input: evidence: %w", err)
	}
	return nil
}

func (s *Store) bulkBlinds(ctx context.Context, scanID int64, inputs map[int64]verdict.Input) error {
	rs, err := s.db.QueryContext(ctx,
		`SELECT b.entity_id, b.id, b.channel, b.reason, b.detail_json
		 FROM blind_spots b
		 JOIN entities e ON e.id = b.entity_id
		 WHERE e.scan_id = ?
		 ORDER BY b.entity_id, b.id`, scanID)
	if err != nil {
		return fmt.Errorf("build input: blind spots: %w", err)
	}
	defer func() { _ = rs.Close() }()
	for rs.Next() {
		var entityID int64
		var b verdict.Blind
		var detailJSON string
		if err := rs.Scan(&entityID, &b.ID, &b.Channel, &b.Reason, &detailJSON); err != nil {
			return fmt.Errorf("build input: blind spots: %w", err)
		}
		b.Detail = map[string]string{}
		if detailJSON != "" {
			_ = json.Unmarshal([]byte(detailJSON), &b.Detail)
		}
		if b.Detail == nil {
			b.Detail = map[string]string{}
		}
		in, ok := inputs[entityID]
		if !ok {
			continue
		}
		in.Blinds = append(in.Blinds, b)
		inputs[entityID] = in
	}
	if err := rs.Err(); err != nil {
		return fmt.Errorf("build input: blind spots: %w", err)
	}
	return nil
}

// bulkEdges reads every edge once and appends one fact to each endpoint
// (direction relative to that endpoint). A self-loop keeps the single
// "in" fact the per-entity query produces.
func (s *Store) bulkEdges(ctx context.Context, scanID int64, inputs map[int64]verdict.Input) error {
	rs, err := s.db.QueryContext(ctx,
		`SELECT e.src_id, e.dst_id, e.kind, e.strength, e.evidence_id, ev.raw_ref,
		        s.id, s.kind, s.name, s.attributes_json,
		        COALESCE((SELECT GROUP_CONCAT(DISTINCT x.channel) FROM evidence x
		                  WHERE x.entity_id = s.id AND x.polarity = 'in_use'), ''),
		        d.id, d.kind, d.name, d.attributes_json,
		        COALESCE((SELECT GROUP_CONCAT(DISTINCT x.channel) FROM evidence x
		                  WHERE x.entity_id = d.id AND x.polarity = 'in_use'), '')
		 FROM edges e
		 JOIN entities s ON s.id = e.src_id
		 JOIN entities d ON d.id = e.dst_id
		 JOIN evidence ev ON ev.id = e.evidence_id
		 WHERE e.scan_id = ?
		 ORDER BY e.id`, scanID)
	if err != nil {
		return fmt.Errorf("build input: edges: %w", err)
	}
	defer func() { _ = rs.Close() }()

	appendEdge := func(id int64, f verdict.EdgeFact) {
		in, ok := inputs[id]
		if !ok {
			return
		}
		in.Edges = append(in.Edges, f)
		inputs[id] = in
	}
	for rs.Next() {
		var (
			srcID, dstID                 int64
			kind, strength, rawRef       string
			evID                         int64
			sID                          int64
			sKind, sName, sAttrs, sInUse string
			dID                          int64
			dKind, dName, dAttrs, dInUse string
		)
		if err := rs.Scan(&srcID, &dstID, &kind, &strength, &evID, &rawRef,
			&sID, &sKind, &sName, &sAttrs, &sInUse,
			&dID, &dKind, &dName, &dAttrs, &dInUse); err != nil {
			return fmt.Errorf("build input: edges: %w", err)
		}
		src := edgeNeighbor(sID, sKind, sName, sAttrs, sInUse)
		dst := edgeNeighbor(dID, dKind, dName, dAttrs, dInUse)
		if srcID == dstID {
			// The per-entity CASE checks dst first, so a self-loop
			// yields one inbound fact, never an extra outbound one.
			appendEdge(srcID, verdict.EdgeFact{
				Kind: kind, Strength: strength, Dir: "in",
				EvidenceID: evID, RawRef: rawRef, Neighbor: src,
			})
			continue
		}
		appendEdge(srcID, verdict.EdgeFact{
			Kind: kind, Strength: strength, Dir: "out",
			EvidenceID: evID, RawRef: rawRef, Neighbor: dst,
		})
		appendEdge(dstID, verdict.EdgeFact{
			Kind: kind, Strength: strength, Dir: "in",
			EvidenceID: evID, RawRef: rawRef, Neighbor: src,
		})
	}
	if err := rs.Err(); err != nil {
		return fmt.Errorf("build input: edges: %w", err)
	}
	return nil
}

func edgeNeighbor(id int64, kind, name, attrsJSON, inUseCSV string) verdict.Neighbor {
	attributes := map[string]string{}
	_ = json.Unmarshal([]byte(attrsJSON), &attributes)
	if attributes == nil {
		attributes = map[string]string{}
	}
	return verdict.Neighbor{
		ID:            id,
		Kind:          kind,
		Name:          name,
		Attributes:    attributes,
		InUseChannels: splitCSV(inUseCSV),
	}
}

// bulkObservations keeps the twin lookup of the single-entity query:
// buckets attached to any entity sharing the identity key still
// contribute, ordered by observation id.
func (s *Store) bulkObservations(ctx context.Context, scanID int64, inputs map[int64]verdict.Input) error {
	rs, err := s.db.QueryContext(ctx,
		`SELECT cur.id, o.id, o.last_seen_at, o.count
		 FROM entities cur
		 JOIN entities twin ON twin.identity_key = cur.identity_key
		 JOIN observations o ON o.entity_id = twin.id
		 WHERE cur.scan_id = ?
		 ORDER BY cur.id, o.id`, scanID)
	if err != nil {
		return fmt.Errorf("build input: observations: %w", err)
	}
	defer func() { _ = rs.Close() }()
	for rs.Next() {
		var entityID int64
		var o verdict.Observation
		if err := rs.Scan(&entityID, &o.ID, &o.LastSeenAt, &o.Count); err != nil {
			return fmt.Errorf("build input: observations: %w", err)
		}
		in, ok := inputs[entityID]
		if !ok {
			continue
		}
		in.Observations = append(in.Observations, o)
		inputs[entityID] = in
	}
	if err := rs.Err(); err != nil {
		return fmt.Errorf("build input: observations: %w", err)
	}
	return nil
}

func (s *Store) inputEvidence(ctx context.Context, entityID int64) ([]verdict.Evidence, error) {
	rs, err := s.db.QueryContext(ctx,
		`SELECT id, polarity, channel, strength, observed_at, raw_ref, value_json
		 FROM evidence WHERE entity_id = ? ORDER BY id`, entityID)
	if err != nil {
		return nil, fmt.Errorf("build input: evidence: %w", err)
	}
	defer func() { _ = rs.Close() }()
	var out []verdict.Evidence
	for rs.Next() {
		var e verdict.Evidence
		var valueJSON string
		if err := rs.Scan(&e.ID, &e.Polarity, &e.Channel, &e.Strength,
			&e.ObservedAt, &e.RawRef, &valueJSON); err != nil {
			return nil, fmt.Errorf("build input: evidence: %w", err)
		}
		e.Value = map[string]string{}
		if valueJSON != "" && valueJSON != "null" {
			_ = json.Unmarshal([]byte(valueJSON), &e.Value)
		}
		if e.Value == nil {
			e.Value = map[string]string{}
		}
		out = append(out, e)
	}
	return out, rs.Err()
}

func (s *Store) inputBlinds(ctx context.Context, entityID int64) ([]verdict.Blind, error) {
	rs, err := s.db.QueryContext(ctx,
		`SELECT id, channel, reason, detail_json
		 FROM blind_spots WHERE entity_id = ? ORDER BY id`, entityID)
	if err != nil {
		return nil, fmt.Errorf("build input: blind spots: %w", err)
	}
	defer func() { _ = rs.Close() }()
	var out []verdict.Blind
	for rs.Next() {
		var b verdict.Blind
		var detailJSON string
		if err := rs.Scan(&b.ID, &b.Channel, &b.Reason, &detailJSON); err != nil {
			return nil, fmt.Errorf("build input: blind spots: %w", err)
		}
		b.Detail = map[string]string{}
		if detailJSON != "" {
			_ = json.Unmarshal([]byte(detailJSON), &b.Detail)
		}
		if b.Detail == nil {
			b.Detail = map[string]string{}
		}
		out = append(out, b)
	}
	return out, rs.Err()
}

// inputEdges lists incident edges with neighbor kind/name/attrs and
// the neighbor's in_use channels (used to grade running subjects).
func (s *Store) inputEdges(ctx context.Context, scanID, entityID int64) ([]verdict.EdgeFact, error) {
	rs, err := s.db.QueryContext(ctx,
		`SELECT e.kind, e.strength, e.evidence_id, ev.raw_ref,
		        CASE WHEN e.dst_id = ? THEN 'in' ELSE 'out' END,
		        n.id, n.kind, n.name, n.attributes_json,
		        COALESCE((
		          SELECT GROUP_CONCAT(DISTINCT x.channel) FROM evidence x
		          WHERE x.entity_id = n.id AND x.polarity = 'in_use'
		        ), '')
		 FROM edges e
		 JOIN entities n ON n.id = CASE WHEN e.src_id = ? THEN e.dst_id ELSE e.src_id END
		 JOIN evidence ev ON ev.id = e.evidence_id
		 WHERE e.scan_id = ? AND (e.src_id = ? OR e.dst_id = ?)
		 ORDER BY e.id`,
		entityID, entityID, scanID, entityID, entityID)
	if err != nil {
		return nil, fmt.Errorf("build input: edges: %w", err)
	}
	defer func() { _ = rs.Close() }()

	var out []verdict.EdgeFact
	for rs.Next() {
		var f verdict.EdgeFact
		var attrsJSON, inUseCSV string
		if err := rs.Scan(&f.Kind, &f.Strength, &f.EvidenceID, &f.RawRef, &f.Dir,
			&f.Neighbor.ID, &f.Neighbor.Kind, &f.Neighbor.Name, &attrsJSON, &inUseCSV); err != nil {
			return nil, fmt.Errorf("build input: edges: %w", err)
		}
		f.Neighbor.Attributes = map[string]string{}
		_ = json.Unmarshal([]byte(attrsJSON), &f.Neighbor.Attributes)
		if f.Neighbor.Attributes == nil {
			f.Neighbor.Attributes = map[string]string{}
		}
		f.Neighbor.InUseChannels = splitCSV(inUseCSV)
		out = append(out, f)
	}
	return out, rs.Err()
}

// chainPathKey rebuilds the id sequence the recursive walk orders by,
// so callers can merge walks of different edge shapes and sort them
// back into the single-walk order.
func chainPathKey(c ChainRow) string {
	var b strings.Builder
	for _, n := range c.Nodes {
		b.WriteByte('|')
		b.WriteString(strconv.FormatInt(n.ID, 10))
	}
	b.WriteByte('|')
	return b.String()
}

// scanHasKind reports whether the scan contains an entity of any of
// the given kinds. Used to skip optional path shapes (no listener in
// the scan means no B6 path can exist).
func (s *Store) scanHasKind(ctx context.Context, scanID int64, kinds []string) (bool, error) {
	if len(kinds) == 0 {
		return true, nil
	}
	args := []any{scanID}
	for _, k := range kinds {
		args = append(args, k)
	}
	var one int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM entities WHERE scan_id = ? AND kind IN (`+placeholders(len(kinds))+`) LIMIT 1`,
		args...).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// inputPaths converts explain Chain rows into engine paths, keeping only
// the edge kinds blockers pattern-match (B1 proxies/listens, B4
// belongs/depends, B6 listens/manages). Each blocker only accepts
// paths whose edge kinds are a subset of its own shape, so walking
// the full graph once is wasted work — and on a host with a dense
// depends_on graph it explodes. Three kind-filtered walks produce the
// same candidate set for far less work; walks over a shape the scan
// cannot satisfy (no listener, no nginx route, no compose service)
// are skipped entirely.
// pathGates is the per-scan presence check for optional path shapes:
// a walk over a kind no entity has can never produce a blocker.
type pathGates struct {
	nginx    bool
	compose  bool
	listener bool
}

func (s *Store) pathGates(ctx context.Context, scanID int64) (pathGates, error) {
	var g pathGates
	var err error
	if g.nginx, err = s.scanHasKind(ctx, scanID, []string{"nginx_route", "nginx_upstream"}); err != nil {
		return g, fmt.Errorf("build input: chain: %w", err)
	}
	if g.compose, err = s.scanHasKind(ctx, scanID, []string{"compose_service"}); err != nil {
		return g, fmt.Errorf("build input: chain: %w", err)
	}
	if g.listener, err = s.scanHasKind(ctx, scanID, []string{"listener"}); err != nil {
		return g, fmt.Errorf("build input: chain: %w", err)
	}
	return g, nil
}

func (s *Store) inputPaths(ctx context.Context, scanID, entityID int64) ([]verdict.Path, error) {
	gates, err := s.pathGates(ctx, scanID)
	if err != nil {
		return nil, err
	}
	return s.inputPathsWithGates(ctx, scanID, entityID, gates)
}

// inputPathsWithGates runs the three kind-filtered walks allowed by the
// scan's entity kinds and merges them into single-walk order.
func (s *Store) inputPathsWithGates(ctx context.Context, scanID, entityID int64, gates pathGates) ([]verdict.Path, error) {
	type walk struct {
		kinds []string
		depth int
		on    bool
	}
	walks := []walk{
		{[]string{"proxies_to", "listens_on"}, 4, gates.nginx},
		{[]string{"belongs_to", "depends_on"}, 4, gates.compose},
		{[]string{"listens_on", "manages"}, 3, gates.listener},
	}
	var chains []ChainRow
	for _, w := range walks {
		if !w.on {
			continue
		}
		rows, err := s.ChainKinds(ctx, scanID, entityID, w.depth, w.kinds)
		if err != nil {
			return nil, fmt.Errorf("build input: chain: %w", err)
		}
		chains = append(chains, rows...)
	}
	// Restore the single-walk order (depth, then node-id path) so the
	// split stays observationally identical to one unfiltered walk.
	sort.SliceStable(chains, func(i, j int) bool {
		if chains[i].Depth != chains[j].Depth {
			return chains[i].Depth < chains[j].Depth
		}
		return chainPathKey(chains[i]) < chainPathKey(chains[j])
	})
	kindsAllowed := map[string]bool{
		"proxies_to": true, "listens_on": true, "belongs_to": true,
		"depends_on": true, "manages": true,
	}
	out := make([]verdict.Path, 0, len(chains))
	for _, c := range chains {
		allowed := true
		for _, k := range c.EdgeKinds {
			if !kindsAllowed[k] {
				allowed = false
				break
			}
		}
		// A usable path has ≥1 hop: edges = nodes − 1.
		if !allowed || len(c.EdgeKinds) == 0 ||
			len(c.EdgeKinds) != len(c.Nodes)-1 ||
			len(c.Strengths) != len(c.EdgeKinds) ||
			len(c.Reversed) != len(c.EdgeKinds) {
			continue
		}
		p := verdict.Path{
			NodeIDs:   make([]int64, 0, len(c.Nodes)),
			NodeKinds: make([]string, 0, len(c.Nodes)),
			NodeNames: make([]string, 0, len(c.Nodes)),
			EdgeKinds: c.EdgeKinds,
			Strengths: c.Strengths,
			Reversed:  c.Reversed,
		}
		for _, n := range c.Nodes {
			p.NodeIDs = append(p.NodeIDs, n.ID)
			p.NodeKinds = append(p.NodeKinds, n.Kind)
			p.NodeNames = append(p.NodeNames, n.Name)
		}
		last := len(c.Nodes) - 1
		lastEdge := len(c.EdgeKinds) - 1
		evID, rawRef, err := s.edgeEvidence(ctx, scanID, c.EdgeKinds[lastEdge],
			c.Nodes[last-1].ID, c.Nodes[last].ID)
		if err != nil {
			return nil, err
		}
		p.EvidenceID, p.RawRef = evID, rawRef
		if c.Nodes[last].Kind == "listener" {
			// A live socket at the end of the path is what B6 proves.
			var csv string
			if err := s.db.QueryRowContext(ctx,
				`SELECT COALESCE(GROUP_CONCAT(DISTINCT channel), '') FROM evidence
				 WHERE entity_id = ? AND polarity = 'in_use'`,
				c.Nodes[last].ID).Scan(&csv); err != nil {
				return nil, fmt.Errorf("build input: listener channels: %w", err)
			}
			p.FarInUse = splitCSV(csv)
		}
		out = append(out, p)
	}
	return out, nil
}

// edgeEvidence resolves the evidence behind one edge between two nodes.
func (s *Store) edgeEvidence(ctx context.Context, scanID int64, kind string, a, b int64) (int64, string, error) {
	var evID int64
	var rawRef string
	err := s.db.QueryRowContext(ctx,
		`SELECT e.evidence_id, ev.raw_ref
		 FROM edges e JOIN evidence ev ON ev.id = e.evidence_id
		 WHERE e.scan_id = ? AND e.kind = ?
		   AND ((e.src_id = ? AND e.dst_id = ?) OR (e.src_id = ? AND e.dst_id = ?))
		 ORDER BY e.id LIMIT 1`,
		scanID, kind, a, b, b, a).Scan(&evID, &rawRef)
	if err == sql.ErrNoRows {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", fmt.Errorf("build input: edge evidence: %w", err)
	}
	return evID, rawRef, nil
}

func (s *Store) inputObservations(ctx context.Context, entityID int64) ([]verdict.Observation, error) {
	// Buckets stay attached to the entity that was current when the
	// daemon wrote them; twins under the same identity key in a newer
	// scan keep contributing (the daemon does not migrate rows).
	rs, err := s.db.QueryContext(ctx,
		`SELECT o.id, o.last_seen_at, o.count
		 FROM observations o
		 JOIN entities cur ON cur.id = ?
		 JOIN entities twin ON twin.identity_key = cur.identity_key
		 WHERE o.entity_id = twin.id
		 ORDER BY o.id`, entityID)
	if err != nil {
		return nil, fmt.Errorf("build input: observations: %w", err)
	}
	defer func() { _ = rs.Close() }()
	var out []verdict.Observation
	for rs.Next() {
		var o verdict.Observation
		if err := rs.Scan(&o.ID, &o.LastSeenAt, &o.Count); err != nil {
			return nil, fmt.Errorf("build input: observations: %w", err)
		}
		out = append(out, o)
	}
	return out, rs.Err()
}

// inputWindow derives the observation window per D3: start = earliest
// observation bucket reachable through the entity's identity key in
// any scan (so the window survives rescans), otherwise host
// first-seen; end = the later of the latest evidence observation and
// the latest observation bucket, capped below by start.
func (s *Store) inputWindow(ctx context.Context, scanID int64) (verdict.Window, error) {
	var start sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT MIN(o.bucket_start)
		 FROM observations o
		 JOIN entities old ON old.id = o.entity_id
		 JOIN entities cur ON cur.identity_key = old.identity_key
		 WHERE cur.scan_id = ?`, scanID).Scan(&start)
	if err != nil {
		return verdict.Window{}, fmt.Errorf("build input: window: %w", err)
	}
	w := verdict.Window{Source: "observations"}
	if start.Valid {
		w.Start = start.String
	} else {
		w.Source = "first_seen"
		var firstSeen sql.NullString
		if err := s.db.QueryRowContext(ctx,
			`SELECT h.first_seen_at FROM scans s JOIN hosts h ON h.id = s.host_id
			 WHERE s.id = ?`, scanID).Scan(&firstSeen); err != nil {
			return verdict.Window{}, fmt.Errorf("build input: window: %w", err)
		}
		if firstSeen.Valid {
			w.Start = firstSeen.String
		}
	}

	var latestEvidence sql.NullString
	if err := s.db.QueryRowContext(ctx,
		`SELECT MAX(ev.observed_at)
		 FROM evidence ev JOIN entities en ON en.id = ev.entity_id
		 WHERE en.scan_id = ?`, scanID).Scan(&latestEvidence); err != nil {
		return verdict.Window{}, fmt.Errorf("build input: window: %w", err)
	}
	var latestObserved sql.NullString
	if err := s.db.QueryRowContext(ctx,
		`SELECT MAX(o.last_seen_at)
		 FROM observations o
		 JOIN entities old ON old.id = o.entity_id
		 JOIN entities cur ON cur.identity_key = old.identity_key
		 WHERE cur.scan_id = ?`, scanID).Scan(&latestObserved); err != nil {
		return verdict.Window{}, fmt.Errorf("build input: window: %w", err)
	}
	w.End = w.Start
	for _, cand := range []sql.NullString{latestEvidence, latestObserved} {
		if !cand.Valid || cand.String == "" {
			continue
		}
		if w.End == w.Start || stampAfter(cand.String, w.End) {
			w.End = cand.String
		}
	}
	if w.End != w.Start {
		if endT, err1 := parseStamp(w.End); err1 == nil {
			if startT, err2 := parseStamp(w.Start); err2 == nil && endT.Before(startT) {
				w.End = w.Start
			}
		}
	}
	w.Days = windowDays(w.Start, w.End)
	return w, nil
}

// stampAfter reports whether a is strictly later than b; unparsable
// stamps never win.
func stampAfter(a, b string) bool {
	ta, errA := parseStamp(a)
	tb, errB := parseStamp(b)
	if errA != nil || errB != nil {
		return false
	}
	return ta.After(tb)
}

// windowDays floors the span between two timestamps to whole days.
func windowDays(start, end string) int {
	if start == "" || end == "" {
		return 0
	}
	a, ea := parseStamp(start)
	b, eb := parseStamp(end)
	if ea != nil || eb != nil {
		return 0
	}
	d := int(b.Sub(a).Hours() / 24)
	if d < 0 {
		return 0
	}
	return d
}

func parseStamp(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unparsable timestamp %q", s)
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	return append(out, cur)
}

// VerdictRecord is one stored verdict (verdicts table).
type VerdictRecord struct {
	ID         int64
	EntityID   int64
	ScanID     int64
	State      string
	Coverage   string
	Blockers   []verdict.Item
	Signals    []verdict.Item
	Blinds     []verdict.Blind
	Window     verdict.Window
	Reasons    []string
	RulesHash  string
	ComputedAt string
}

// SaveVerdict replaces any stored verdict for the entity/scan with
// the compute result, keyed by rules hash.
func (s *Store) SaveVerdict(ctx context.Context, entityID, scanID int64, res verdict.Result, rulesHash string) error {
	rec := VerdictRecord{
		EntityID:   entityID,
		ScanID:     scanID,
		State:      res.State,
		Coverage:   res.Coverage,
		Blockers:   res.Blockers,
		Signals:    res.Signals,
		Blinds:     res.Blinds,
		Window:     res.Window,
		Reasons:    res.Reasons,
		RulesHash:  rulesHash,
		ComputedAt: nowRFC3339(),
	}
	return s.UpsertVerdict(ctx, rec)
}

// UpsertVerdict stores rec as the single verdict row for its
// entity/scan pair (latest wins; the table is a cache, evidence stays
// authoritative).
func (s *Store) UpsertVerdict(ctx context.Context, rec VerdictRecord) error {
	blockers, err := json.Marshal(rec.Blockers)
	if err != nil {
		return fmt.Errorf("upsert verdict: blockers: %w", err)
	}
	signals, err := json.Marshal(rec.Signals)
	if err != nil {
		return fmt.Errorf("upsert verdict: signals: %w", err)
	}
	blinds, err := json.Marshal(rec.Blinds)
	if err != nil {
		return fmt.Errorf("upsert verdict: blinds: %w", err)
	}
	window, err := json.Marshal(rec.Window)
	if err != nil {
		return fmt.Errorf("upsert verdict: window: %w", err)
	}
	reasons, err := json.Marshal(rec.Reasons)
	if err != nil {
		return fmt.Errorf("upsert verdict: reasons: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("upsert verdict: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM verdicts WHERE entity_id = ? AND scan_id = ?`,
		rec.EntityID, rec.ScanID); err != nil {
		return fmt.Errorf("upsert verdict: %w", err)
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO verdicts
		   (entity_id, scan_id, state, coverage, blockers_json, signals_json,
		    blind_spots_json, observation_window_json, reasons_json,
		    rules_hash, computed_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.EntityID, rec.ScanID, rec.State, rec.Coverage,
		string(blockers), string(signals), string(blinds),
		string(window), string(reasons), rec.RulesHash, rec.ComputedAt)
	if err != nil {
		return fmt.Errorf("upsert verdict: %w", err)
	}
	if rec.ID == 0 {
		if id, err := res.LastInsertId(); err == nil {
			rec.ID = id
		}
	}
	return tx.Commit()
}

// VerdictFor returns the stored verdict for one entity/scan. The
// second return is sql.ErrNoRows when none exists.
func (s *Store) VerdictFor(ctx context.Context, entityID, scanID int64) (VerdictRecord, error) {
	var rec VerdictRecord
	var blockers, signals, blinds, window, reasons string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, entity_id, scan_id, state, coverage, blockers_json,
		        signals_json, blind_spots_json, observation_window_json,
		        reasons_json, rules_hash, computed_at
		 FROM verdicts WHERE entity_id = ? AND scan_id = ?
		 ORDER BY id DESC LIMIT 1`, entityID, scanID).
		Scan(&rec.ID, &rec.EntityID, &rec.ScanID, &rec.State, &rec.Coverage,
			&blockers, &signals, &blinds, &window, &reasons,
			&rec.RulesHash, &rec.ComputedAt)
	if err != nil {
		return VerdictRecord{}, err
	}
	_ = json.Unmarshal([]byte(blockers), &rec.Blockers)
	_ = json.Unmarshal([]byte(signals), &rec.Signals)
	_ = json.Unmarshal([]byte(blinds), &rec.Blinds)
	_ = json.Unmarshal([]byte(window), &rec.Window)
	_ = json.Unmarshal([]byte(reasons), &rec.Reasons)
	return rec, nil
}

// VerdictRollup counts stored verdicts by state for one scan. States
// with no rows are absent from the map.
func (s *Store) VerdictRollup(ctx context.Context, scanID int64) (map[string]int, error) {
	rs, err := s.db.QueryContext(ctx,
		`SELECT state, count(*) FROM verdicts WHERE scan_id = ? GROUP BY state`,
		scanID)
	if err != nil {
		return nil, fmt.Errorf("verdict rollup: %w", err)
	}
	defer func() { _ = rs.Close() }()
	out := map[string]int{}
	for rs.Next() {
		var state string
		var n int
		if err := rs.Scan(&state, &n); err != nil {
			return nil, err
		}
		out[state] = n
	}
	return out, rs.Err()
}

// HasBrokenRoute reports whether the entity carries a BROKEN_ROUTE
// finding in the given scan.
func (s *Store) HasBrokenRoute(ctx context.Context, scanID, entityID int64) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM findings
		 WHERE scan_id = ? AND entity_id = ? AND kind = 'BROKEN_ROUTE'`,
		scanID, entityID).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("broken route check: %w", err)
	}
	return n > 0, nil
}

// EntitiesInScan lists every entity of one scan (id, kind, name,
// identity key) ordered by identity key — the rollup loop input.
func (s *Store) EntitiesInScan(ctx context.Context, scanID int64) ([]EntityRow, error) {
	rows, err := s.queryEntities(ctx,
		`SELECT id, kind, name, identity_key, attributes_json FROM entities
		 WHERE scan_id = ? ORDER BY identity_key`, scanID)
	if err != nil {
		return nil, fmt.Errorf("entities in scan: %w", err)
	}
	return rows, nil
}
