package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// A fresh database ends up stamped with the current schema version,
// both through PRAGMA and in the file header doctor reads.
func TestMigrateStampsSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stamp.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = s.Close() }()

	var v int
	if err := s.DB().QueryRowContext(context.Background(),
		"PRAGMA user_version").Scan(&v); err != nil {
		t.Fatalf("user_version: %v", err)
	}
	if v != SchemaVersion {
		t.Errorf("user_version = %d, want %d", v, SchemaVersion)
	}
	got, exists, err := ReadSchemaVersion(path)
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	if !exists {
		t.Fatal("database file should exist after Open")
	}
	if got != SchemaVersion {
		t.Errorf("header version = %d, want %d", got, SchemaVersion)
	}
}

// A database created before versioning (user_version 0 with the core
// tables) is adopted instead of refused.
func TestMigrateAdoptsPreVersioningDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Simulate a pre-versioning file: same tables, version zero.
	if _, err := s.DB().ExecContext(context.Background(),
		"PRAGMA user_version = 0"); err != nil {
		t.Fatalf("reset version: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s2, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("reopen legacy: %v", err)
	}
	defer func() { _ = s2.Close() }()
	var v int
	if err := s2.DB().QueryRowContext(context.Background(),
		"PRAGMA user_version").Scan(&v); err != nil {
		t.Fatalf("user_version: %v", err)
	}
	if v != SchemaVersion {
		t.Errorf("adopted version = %d, want %d", v, SchemaVersion)
	}
	if _, err := s2.Tables(context.Background()); err != nil {
		t.Errorf("tables after adoption: %v", err)
	}
}

// A database from a newer build is refused with an actionable error
// instead of being silently downgraded or half-migrated.
func TestMigrateRefusesNewerDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "future.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := s.DB().ExecContext(context.Background(),
		"PRAGMA user_version = 9999"); err != nil {
		t.Fatalf("set future version: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, err = Open(context.Background(), path)
	if !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("open future db: err = %v, want ErrSchemaTooNew", err)
	}
}

// A SQLite file that is not an archaeologist database must fail
// loudly: adopting foreign tables would corrupt unrelated data.
func TestMigrateRefusesForeignDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "foreign.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("create foreign: %v", err)
	}
	if _, err := db.ExecContext(context.Background(),
		"CREATE TABLE unrelated (id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, err = Open(context.Background(), path)
	if !errors.Is(err, ErrNotArchaeologistDB) {
		t.Fatalf("open foreign db: err = %v, want ErrNotArchaeologistDB", err)
	}
}

// ReadSchemaVersion reports a missing file as not exists and never
// creates it (doctor stays read-only).
func TestReadSchemaVersionMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.db")
	v, exists, err := ReadSchemaVersion(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if exists {
		t.Error("exists = true for a missing file")
	}
	if v != 0 {
		t.Errorf("version = %d, want 0", v)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Error("ReadSchemaVersion must not create the file")
	}
}

// Opening the database forces owner-only permissions, even when the
// file already exists with a loose mode.
func TestOpenEnforcesOwnerOnlyPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "perm.db")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = s.Close() }()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("db mode = %o, want 600", got)
	}
}
