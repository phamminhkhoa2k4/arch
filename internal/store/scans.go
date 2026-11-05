package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"archaeologist/internal/verdict"
)

// ErrNoScan reports that a scan id is not recorded in this database.
var ErrNoScan = errors.New("scan not recorded")

// ScanRow describes one recorded scan as listed by the scan history
// command, together with its rollup counts.
type ScanRow struct {
	ID         int64
	StartedAt  string
	FinishedAt string // empty while the scan never finished (crashed or running)
	Host       string
	Status     string
	Entities   int
	BlindSpots int
	Findings   int
}

// scanRowSelect carries the rollup counts as correlated subqueries so
// one pass produces a complete history row.
const scanRowSelect = `
	SELECT s.id, s.started_at, COALESCE(s.finished_at, ''), h.hostname,
 s.status,
	       (SELECT count(*) FROM entities e WHERE e.scan_id = s.id),
	       (SELECT count(*) FROM blind_spots b WHERE b.scan_id = s.id),
	       (SELECT count(*) FROM findings f WHERE f.scan_id = s.id)
	FROM scans s JOIN hosts h ON h.id = s.host_id`

// scanRows runs the shared history query with an optional filter,
// newest scan first.
func (s *Store) scanRows(ctx context.Context, where string, args ...any) ([]ScanRow, error) {
	query := scanRowSelect + " " + where + " ORDER BY s.started_at DESC, s.id DESC"
	rs, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rs.Close() }()

	var out []ScanRow
	for rs.Next() {
		var r ScanRow
		if err := rs.Scan(&r.ID, &r.StartedAt, &r.FinishedAt, &r.Host,
			&r.Status, &r.Entities, &r.BlindSpots, &r.Findings); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rs.Err()
}

// ListScans returns every recorded scan, newest first.
func (s *Store) ListScans(ctx context.Context) ([]ScanRow, error) {
	rows, err := s.scanRows(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}
	return rows, nil
}

// ScanInfo returns one recorded scan with its rollup counts. The error
// wraps ErrNoScan when the id is unknown.
func (s *Store) ScanInfo(ctx context.Context, scanID int64) (ScanRow, error) {
	rows, err := s.scanRows(ctx, "WHERE s.id = ?", scanID)
	if err != nil {
		return ScanRow{}, fmt.Errorf("scan %d: %w", scanID, err)
	}
	if len(rows) == 0 {
		return ScanRow{}, fmt.Errorf("scan %d: %w", scanID, ErrNoScan)
	}
	return rows[0], nil
}

// VerdictSnapshot is one entity's stored verdict, shaped for comparing
// two scans.
type VerdictSnapshot struct {
	IdentityKey string
	Kind        string
	Name        string
	State       string
	Coverage    string
	Blockers    []verdict.Item
}

// VerdictsInScan returns the stored verdicts of one scan keyed by
// entity identity key. Entities without a stored verdict are absent.
func (s *Store) VerdictsInScan(ctx context.Context, scanID int64) (map[string]VerdictSnapshot, error) {
	rs, err := s.db.QueryContext(ctx,
		`SELECT e.identity_key, e.kind, e.name, v.state, v.coverage, v.blockers_json
		 FROM verdicts v JOIN entities e ON e.id = v.entity_id
		 WHERE v.scan_id = ?
		 ORDER BY e.identity_key`, scanID)
	if err != nil {
		return nil, fmt.Errorf("verdicts in scan %d: %w", scanID, err)
	}
	defer func() { _ = rs.Close() }()

	out := map[string]VerdictSnapshot{}
	for rs.Next() {
		var r VerdictSnapshot
		var blockersJSON string
		if err := rs.Scan(&r.IdentityKey, &r.Kind, &r.Name, &r.State, &r.Coverage, &blockersJSON); err != nil {
			return nil, fmt.Errorf("verdicts in scan %d: %w", scanID, err)
		}
		_ = json.Unmarshal([]byte(blockersJSON), &r.Blockers)
		out[r.IdentityKey] = r
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("verdicts in scan %d: %w", scanID, err)
	}
	return out, nil
}
