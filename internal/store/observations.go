package store

import (
	"context"
	"fmt"
)

// ListenerRow identifies one listener entity of the latest scan.
type ListenerRow struct {
	ID          int64
	IdentityKey string
}

// LatestListeners returns the listener entities of the newest scan —
// the match set the observation daemon samples against.
func (s *Store) LatestListeners(ctx context.Context) ([]ListenerRow, error) {
	scanID, err := s.LatestScanID(ctx)
	if err != nil {
		return nil, err
	}
	rs, err := s.db.QueryContext(ctx,
		`SELECT id, identity_key FROM entities
		 WHERE scan_id = ? AND kind = 'listener' ORDER BY id`, scanID)
	if err != nil {
		return nil, fmt.Errorf("latest listeners: %w", err)
	}
	defer func() { _ = rs.Close() }()
	var out []ListenerRow
	for rs.Next() {
		var r ListenerRow
		if err := rs.Scan(&r.ID, &r.IdentityKey); err != nil {
			return nil, fmt.Errorf("latest listeners: %w", err)
		}
		out = append(out, r)
	}
	return out, rs.Err()
}

// UpsertObservation records one sample hit. A repeated hit inside the
// same hour grows count and moves last_seen_at; the UNIQUE triple
// keeps the table bound to distinct (entity, remote, hour) rows.
func (s *Store) UpsertObservation(ctx context.Context, entityID int64, remoteKey, bucketStart, lastSeenAt string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO observations (entity_id, remote_key, bucket_start, count, last_seen_at)
		 VALUES (?, ?, ?, 1, ?)
		 ON CONFLICT (entity_id, remote_key, bucket_start)
		 DO UPDATE SET count = count + 1, last_seen_at = excluded.last_seen_at`,
		entityID, remoteKey, bucketStart, lastSeenAt)
	if err != nil {
		return fmt.Errorf("upsert observation: %w", err)
	}
	return nil
}

// PruneObservations drops buckets starting before the cut-off (D2
// retention) and reports the number of rows removed.
func (s *Store) PruneObservations(ctx context.Context, before string) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM observations WHERE bucket_start < ?`, before)
	if err != nil {
		return 0, fmt.Errorf("prune observations: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("prune observations: %w", err)
	}
	return n, nil
}
