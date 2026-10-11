package store

import (
	"context"
	"encoding/json"
	"fmt"
)

// FindingRow describes one finding joined with its entity for the
// report command.
type FindingRow struct {
	ID         int64
	Kind       string
	Severity   string
	Detail     map[string]string
	EvidenceID int64 // 0 when the finding cites no single evidence row
	EntityKind string
	EntityName string
	Identity   string
}

// BlindRowScan describes one blind spot at scan scope: entity fields
// are empty for host-wide gaps (entity_id NULL, e.g. a failed
// collector).
type BlindRowScan struct {
	Channel    string
	Reason     string
	Detail     map[string]string
	EntityKind string
	EntityName string
}

// FindingsInScan lists every finding of one scan with the owning
// entity's kind and name, ordered by severity then id so the report is
// deterministic.
func (s *Store) FindingsInScan(ctx context.Context, scanID int64) ([]FindingRow, error) {
	rs, err := s.db.QueryContext(ctx,
		`SELECT f.id, f.kind, f.severity, f.detail_json, f.evidence_id,
		        e.kind, e.name, e.identity_key
		 FROM findings f JOIN entities e ON e.id = f.entity_id
		 WHERE f.scan_id = ?
		 ORDER BY f.severity DESC, f.id`, scanID)
	if err != nil {
		return nil, fmt.Errorf("findings in scan %d: %w", scanID, err)
	}
	defer func() { _ = rs.Close() }()

	var out []FindingRow
	for rs.Next() {
		var r FindingRow
		var detailJSON string
		var evidenceID *int64
		if err := rs.Scan(&r.ID, &r.Kind, &r.Severity, &detailJSON, &evidenceID,
			&r.EntityKind, &r.EntityName, &r.Identity); err != nil {
			return nil, fmt.Errorf("findings in scan %d: %w", scanID, err)
		}
		if evidenceID != nil {
			r.EvidenceID = *evidenceID
		}
		r.Detail = map[string]string{}
		if detailJSON != "" && detailJSON != "null" {
			_ = json.Unmarshal([]byte(detailJSON), &r.Detail)
		}
		out = append(out, r)
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("findings in scan %d: %w", scanID, err)
	}
	return out, nil
}

// BlindSpotsInScan lists every blind spot of one scan — host-wide rows
// included — with the owning entity's kind/name when attached.
func (s *Store) BlindSpotsInScan(ctx context.Context, scanID int64) ([]BlindRowScan, error) {
	rs, err := s.db.QueryContext(ctx,
		`SELECT b.channel, b.reason, b.detail_json, e.kind, e.name
		 FROM blind_spots b LEFT JOIN entities e ON e.id = b.entity_id
		 WHERE b.scan_id = ?
		 ORDER BY b.id`, scanID)
	if err != nil {
		return nil, fmt.Errorf("blind spots in scan %d: %w", scanID, err)
	}
	defer func() { _ = rs.Close() }()

	var out []BlindRowScan
	for rs.Next() {
		var r BlindRowScan
		var detailJSON string
		var entityKind, entityName *string
		if err := rs.Scan(&r.Channel, &r.Reason, &detailJSON, &entityKind, &entityName); err != nil {
			return nil, fmt.Errorf("blind spots in scan %d: %w", scanID, err)
		}
		if entityKind != nil {
			r.EntityKind = *entityKind
		}
		if entityName != nil {
			r.EntityName = *entityName
		}
		r.Detail = map[string]string{}
		if detailJSON != "" && detailJSON != "null" {
			_ = json.Unmarshal([]byte(detailJSON), &r.Detail)
		}
		out = append(out, r)
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("blind spots in scan %d: %w", scanID, err)
	}
	return out, nil
}

// ScanHostStatus returns the hostname and status of one scan for the
// report header.
func (s *Store) ScanHostStatus(ctx context.Context, scanID int64) (host, status string, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT h.hostname, s.status FROM scans s
		 JOIN hosts h ON h.id = s.host_id WHERE s.id = ?`, scanID).
		Scan(&host, &status)
	if err != nil {
		return "", "", fmt.Errorf("scan header %d: %w", scanID, err)
	}
	return host, status, nil
}
