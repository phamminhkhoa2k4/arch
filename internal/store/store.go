// Package store owns the SQLite persistence layer.
//
// The store is append-only per scan: evidence and edges are never rewritten.
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

// Store wraps the SQLite database handle.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at path and runs migrations.
func Open(ctx context.Context, path string) (*Store, error) {
	// WAL lets a concurrent scan writer and the observe daemon write
	// without the ping-pong that starved busy_timeout in journal mode
	// DELETE; the timeout covers the residual writer-writer overlap.
	dsn := fmt.Sprintf("file:%s?_pragma=foreign_keys(1)&_pragma=busy_timeout(15000)&_pragma=journal_mode(WAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// modernc.org/sqlite serializes access poorly with multiple writers;
	// a single connection keeps behavior deterministic for a local CLI.
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.Migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Migrate creates every schema object on an empty database.
// Running it repeatedly is a no-op (IF NOT EXISTS throughout).
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schemaSQL); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// Tables reports the names of user tables created by the schema.
func (s *Store) Tables(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT name FROM sqlite_master
		 WHERE type='table' AND name NOT LIKE 'sqlite_%'
		 ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}

// InsertHost records the scanned host and returns its id.
func (s *Store) InsertHost(ctx context.Context, hostname, os, kernel string) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO hosts (hostname, os, kernel, first_seen_at, last_seen_at)
		 VALUES (?, ?, ?, ?, ?)`,
		hostname, os, kernel, now, now)
	if err != nil {
		return 0, fmt.Errorf("insert host: %w", err)
	}
	return res.LastInsertId()
}

// InsertScan starts a scan record and returns its id.
func (s *Store) InsertScan(ctx context.Context, hostID int64, toolVersion, collectorVersions string) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO scans (started_at, host_id, tool_version, collector_versions_json)
		 VALUES (?, ?, ?, ?)`,
		now, hostID, toolVersion, collectorVersions)
	if err != nil {
		return 0, fmt.Errorf("insert scan: %w", err)
	}
	return res.LastInsertId()
}

// FinishScan closes a scan record with a final status.
func (s *Store) FinishScan(ctx context.Context, scanID int64, status string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx,
		`UPDATE scans SET finished_at = ?, status = ? WHERE id = ?`,
		now, status, scanID)
	return err
}

// Summary is the per-scan rollup printed by the scan command.
type Summary struct {
	Entities   map[string]int // entity kind → count
	BlindSpots int
	Findings   int
}

// ScanSummary counts entities by kind plus blind spots and findings for
// one scan.
func (s *Store) ScanSummary(ctx context.Context, scanID int64) (Summary, error) {
	sum := Summary{Entities: map[string]int{}}

	rows, err := s.db.QueryContext(ctx,
		`SELECT kind, count(*) FROM entities WHERE scan_id = ? GROUP BY kind`,
		scanID)
	if err != nil {
		return sum, fmt.Errorf("scan summary: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var kind string
		var n int
		if err := rows.Scan(&kind, &n); err != nil {
			return sum, fmt.Errorf("scan summary: %w", err)
		}
		sum.Entities[kind] = n
	}
	if err := rows.Err(); err != nil {
		return sum, fmt.Errorf("scan summary: %w", err)
	}

	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM blind_spots WHERE scan_id = ?`,
		scanID).Scan(&sum.BlindSpots); err != nil {
		return sum, fmt.Errorf("scan summary: %w", err)
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM findings WHERE scan_id = ?`,
		scanID).Scan(&sum.Findings); err != nil {
		return sum, fmt.Errorf("scan summary: %w", err)
	}
	return sum, nil
}

// DB exposes the handle for read-only diagnostics and tests that need
// queries outside this package's API.
func (s *Store) DB() *sql.DB { return s.db }

// Close releases the database handle.
func (s *Store) Close() error {
	return s.db.Close()
}
