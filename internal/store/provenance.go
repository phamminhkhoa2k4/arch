package store

import (
	"context"
	"database/sql"
	"fmt"
)

// ScanExists reports whether scanID is still recorded. A cleanup plan
// pins its verdict to one scan, so a re-check needs to know whether
// that scan survived.
func (s *Store) ScanExists(ctx context.Context, scanID int64) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM scans WHERE id = ?`, scanID).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("scan %d exists: %w", scanID, err)
	}
	return n > 0, nil
}

// EntityFingerprint returns the fingerprint recorded for identityKey
// within scanID. An empty string with no error means the entity is not
// in that scan.
func (s *Store) EntityFingerprint(ctx context.Context, scanID int64, identityKey string) (string, error) {
	var fp string
	err := s.db.QueryRowContext(ctx,
		`SELECT fingerprint FROM entities WHERE scan_id = ? AND identity_key = ?`,
		scanID, identityKey).Scan(&fp)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("fingerprint for %q in scan %d: %w", identityKey, scanID, err)
	}
	return fp, nil
}
