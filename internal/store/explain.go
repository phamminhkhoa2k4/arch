package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

// EntityRow describes one entity as resolved for the explain command.
type EntityRow struct {
	ID          int64
	Kind        string
	Name        string
	IdentityKey string
	Attributes  map[string]string
}

// EvidenceRow describes one evidence row as listed by explain.
type EvidenceRow struct {
	ID         int64
	Polarity   string
	Channel    string
	Strength   string
	ObservedAt string
	RawRef     string
	Value      map[string]string
}

// BlindRow describes one entity-scoped blind spot as listed by explain.
type BlindRow struct {
	Channel string
	Reason  string
	Detail  map[string]string
}

// LatestScanID returns the id of the most recently started scan.
func (s *Store) LatestScanID(ctx context.Context) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM scans ORDER BY started_at DESC, id DESC LIMIT 1`).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, fmt.Errorf("latest scan: no scans recorded")
	}
	if err != nil {
		return 0, fmt.Errorf("latest scan: %w", err)
	}
	return id, nil
}

// FindEntities resolves one reference within a scan: an exact
// identity_key match wins outright; otherwise entities with an exact
// name match are returned (possibly several, so the caller can ask the
// user to disambiguate). No match yields an empty slice.
func (s *Store) FindEntities(ctx context.Context, scanID int64, ref string) ([]EntityRow, error) {
	rows, err := s.queryEntities(ctx,
		`SELECT id, kind, name, identity_key, attributes_json FROM entities
		 WHERE scan_id = ? AND identity_key = ? ORDER BY identity_key`,
		scanID, ref)
	if err != nil {
		return nil, fmt.Errorf("find entities: %w", err)
	}
	if len(rows) > 0 {
		return rows, nil
	}
	rows, err = s.queryEntities(ctx,
		`SELECT id, kind, name, identity_key, attributes_json FROM entities
		 WHERE scan_id = ? AND name = ? ORDER BY identity_key`,
		scanID, ref)
	if err != nil {
		return nil, fmt.Errorf("find entities: %w", err)
	}
	return rows, nil
}

func (s *Store) queryEntities(ctx context.Context, query string, args ...any) ([]EntityRow, error) {
	rs, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rs.Close() }()

	var out []EntityRow
	for rs.Next() {
		var r EntityRow
		var attrsJSON string
		if err := rs.Scan(&r.ID, &r.Kind, &r.Name, &r.IdentityKey, &attrsJSON); err != nil {
			return nil, err
		}
		r.Attributes = map[string]string{}
		if err := json.Unmarshal([]byte(attrsJSON), &r.Attributes); err != nil {
			r.Attributes = map[string]string{}
		}
		out = append(out, r)
	}
	return out, rs.Err()
}

// EvidenceFor lists one entity's evidence rows in insertion order.
func (s *Store) EvidenceFor(ctx context.Context, entityID int64) ([]EvidenceRow, error) {
	rs, err := s.db.QueryContext(ctx,
		`SELECT id, polarity, channel, strength, observed_at, raw_ref, value_json
		 FROM evidence WHERE entity_id = ? ORDER BY id`, entityID)
	if err != nil {
		return nil, fmt.Errorf("evidence for %d: %w", entityID, err)
	}
	defer func() { _ = rs.Close() }()

	var out []EvidenceRow
	for rs.Next() {
		var r EvidenceRow
		var valueJSON string
		if err := rs.Scan(&r.ID, &r.Polarity, &r.Channel, &r.Strength, &r.ObservedAt, &r.RawRef, &valueJSON); err != nil {
			return nil, fmt.Errorf("evidence for %d: %w", entityID, err)
		}
		r.Value = map[string]string{}
		if valueJSON != "" && valueJSON != "null" {
			if err := json.Unmarshal([]byte(valueJSON), &r.Value); err != nil {
				r.Value = map[string]string{}
			}
		}
		if r.Value == nil {
			r.Value = map[string]string{}
		}
		out = append(out, r)
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("evidence for %d: %w", entityID, err)
	}
	return out, nil
}

// BlindSpotsFor lists the blind spots attached to one entity. Host-wide
// gaps (entity_id NULL) are not entity-scoped and are excluded.
func (s *Store) BlindSpotsFor(ctx context.Context, entityID int64) ([]BlindRow, error) {
	rs, err := s.db.QueryContext(ctx,
		`SELECT channel, reason, detail_json
		 FROM blind_spots WHERE entity_id = ? ORDER BY id`, entityID)
	if err != nil {
		return nil, fmt.Errorf("blind spots for %d: %w", entityID, err)
	}
	defer func() { _ = rs.Close() }()

	var out []BlindRow
	for rs.Next() {
		var r BlindRow
		var detailJSON string
		if err := rs.Scan(&r.Channel, &r.Reason, &detailJSON); err != nil {
			return nil, fmt.Errorf("blind spots for %d: %w", entityID, err)
		}
		_ = json.Unmarshal([]byte(detailJSON), &r.Detail)
		if r.Detail == nil {
			r.Detail = map[string]string{}
		}
		out = append(out, r)
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("blind spots for %d: %w", entityID, err)
	}
	return out, nil
}
