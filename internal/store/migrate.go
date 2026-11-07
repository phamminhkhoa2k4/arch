package store

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// SchemaVersion is the highest database schema version this build
// understands. It is stored in the SQLite header field PRAGMA
// user_version and written after every successful migration step.
const SchemaVersion = 1

// ErrSchemaTooNew marks a database written by a newer build: opening
// it could silently drop columns this build does not know about, so
// the only safe action is to refuse and ask for an upgrade.
var ErrSchemaTooNew = errors.New("database schema is newer than this build")

// ErrNotArchaeologistDB marks a SQLite file that does not hold the
// core tables — pointing --db at the wrong file must fail loudly
// instead of adopting foreign tables.
var ErrNotArchaeologistDB = errors.New("not an archaeologist database")

// migration is one ordered schema step. A step runs only when the
// database's user_version is below version, so every step must be
// safe to run once against the state the previous steps produced.
type migration struct {
	version int
	apply   func(ctx context.Context, db *sql.DB) error
}

// migrations lists every step up to SchemaVersion. The first step is
// the initial schema: it is idempotent (IF NOT EXISTS throughout), so
// it also adopts databases created before versioning existed.
var migrations = []migration{
	{version: 1, apply: func(ctx context.Context, db *sql.DB) error {
		_, err := db.ExecContext(ctx, schemaSQL)
		return err
	}},
}

// Migrate brings the database up to SchemaVersion. It refuses a
// database from a newer build and a foreign SQLite file, adopts a
// pre-versioning database (user_version 0 with the core tables), and
// stamps every step it applies. Running it on an up-to-date database
// is a no-op.
func (s *Store) Migrate(ctx context.Context) error {
	current, err := s.userVersion(ctx)
	if err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if current > SchemaVersion {
		return fmt.Errorf("%w: database has schema v%d, this build supports v%d — upgrade archaeologist or point --db at a different file",
			ErrSchemaTooNew, current, SchemaVersion)
	}
	if current == 0 {
		core, any, err := s.tablePresence(ctx)
		if err != nil {
			return fmt.Errorf("inspect schema: %w", err)
		}
		if any && !core {
			return fmt.Errorf("%w: no core tables (hosts, scans, entities) — point --db at the scan database",
				ErrNotArchaeologistDB)
		}
	}
	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		if err := m.apply(ctx, s.db); err != nil {
			return fmt.Errorf("migrate to schema v%d: %w", m.version, err)
		}
		if err := s.setUserVersion(ctx, m.version); err != nil {
			return err
		}
		current = m.version
	}
	return nil
}

// userVersion reads PRAGMA user_version (0 on a fresh database).
func (s *Store) userVersion(ctx context.Context) (int, error) {
	var v int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
		return 0, err
	}
	return v, nil
}

// setUserVersion stamps the header field and checkpoints the WAL so
// the value lands in the main file: header readers (doctor) must not
// depend on an unmerged write-ahead log.
func (s *Store) setUserVersion(ctx context.Context, v int) error {
	if _, err := s.db.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", v)); err != nil {
		return fmt.Errorf("set schema version: %w", err)
	}
	_, _ = s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	return nil
}

// tablePresence reports whether the core tables exist and whether the
// database has any user table at all.
func (s *Store) tablePresence(ctx context.Context) (core, any bool, err error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT name FROM sqlite_master
		 WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return false, false, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return false, false, err
		}
		any = true
		switch n {
		case "hosts", "scans", "entities":
			core = true
		}
	}
	return core, any, rows.Err()
}

// ReadSchemaVersion reports the schema version stored in the SQLite
// file header at offset 60 without opening the database: doctor must
// stay read-only and must not create WAL sidecar files. exists is
// false when the file does not exist; an empty file reports version 0
// (a fresh database).
func ReadSchemaVersion(path string) (version int, exists bool, err error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = f.Close() }()

	const headerLen = 64
	hdr := make([]byte, headerLen)
	n, err := io.ReadFull(f, hdr)
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		if n == 0 {
			return 0, true, nil // empty file: SQLite treats it as new
		}
		return 0, true, fmt.Errorf("%s: truncated SQLite header", path)
	}
	if err != nil {
		return 0, true, err
	}
	if string(hdr[:16]) != "SQLite format 3\x00" {
		return 0, true, fmt.Errorf("%s: not a SQLite database", path)
	}
	return int(binary.BigEndian.Uint32(hdr[60:64])), true, nil
}
