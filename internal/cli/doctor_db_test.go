package cli

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSQLiteHeader writes a file whose first 64 bytes carry the
// SQLite magic and the requested user_version at offset 60 — enough
// for the read-only header probe without opening a database.
func writeSQLiteHeader(t *testing.T, path string, version int) {
	t.Helper()
	hdr := make([]byte, 64)
	copy(hdr, "SQLite format 3\x00")
	binary.BigEndian.PutUint32(hdr[60:], uint32(version))
	if err := os.WriteFile(path, append(hdr, make([]byte, 4096)...), 0o600); err != nil {
		t.Fatalf("write header: %v", err)
	}
}

// A missing database passes: the first command creates it at the
// current schema version.
func TestDoctorSchemaVersionFreshFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.db")
	if err := checkSchemaVersion(path)(); err != nil {
		t.Errorf("fresh path must pass, got: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("probe must not create the file")
	}
}

// A database stamped with the current version passes.
func TestDoctorSchemaVersionCurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "current.db")
	writeSQLiteHeader(t, path, 1)
	if err := checkSchemaVersion(path)(); err != nil {
		t.Errorf("current version must pass, got: %v", err)
	}
}

// A database from a newer build fails with the upgrade hint instead
// of being opened.
func TestDoctorSchemaVersionTooNew(t *testing.T) {
	path := filepath.Join(t.TempDir(), "future.db")
	writeSQLiteHeader(t, path, 9999)
	err := checkSchemaVersion(path)()
	if err == nil {
		t.Fatal("newer schema must fail the probe")
	}
	if !strings.Contains(err.Error(), "9999") || !strings.Contains(err.Error(), "v1") {
		t.Errorf("detail must name both versions: %v", err)
	}
	var re *richError
	if !errors.As(err, &re) || !strings.Contains(re.hint, "upgrade archaeologist") {
		t.Errorf("hint must say to upgrade: %v", err)
	}
}

// A non-SQLite file at the --db path fails with an actionable detail.
func TestDoctorSchemaVersionNotSQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "garbage.db")
	if err := os.WriteFile(path, make([]byte, 100), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := checkSchemaVersion(path)()
	if err == nil {
		t.Fatal("non-sqlite file must fail the probe")
	}
	var re *richError
	if !errors.As(err, &re) || !strings.Contains(re.detail, "not a SQLite database") {
		t.Errorf("detail must say not-a-database: %v", err)
	}
}

// A world-readable database fails the permission probe with the exact
// chmod remedy; an owner-only file passes.
func TestDoctorDBPermissions(t *testing.T) {
	dir := t.TempDir()

	loose := filepath.Join(dir, "loose.db")
	if err := os.WriteFile(loose, nil, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.Chmod(loose, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	err := checkDBPermissions(loose)()
	if err == nil {
		t.Fatal("world-readable database must fail the probe")
	}
	var re *richError
	if !errors.As(err, &re) {
		t.Fatalf("want richError, got %T", err)
	}
	if !strings.Contains(re.detail, "0644") || !strings.Contains(re.hint, "chmod 600") {
		t.Errorf("detail/hint must name mode and remedy: %v / %s", re.detail, re.hint)
	}

	locked := filepath.Join(dir, "locked.db")
	if err := os.WriteFile(locked, nil, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := checkDBPermissions(locked)(); err != nil {
		t.Errorf("owner-only database must pass, got: %v", err)
	}
	if err := checkDBPermissions(filepath.Join(dir, "fresh.db"))(); err != nil {
		t.Errorf("missing database must pass, got: %v", err)
	}
}

// runDoctor prints the rich detail and hint a probe attaches instead
// of the static fail/hint pair.
func TestDoctorUsesRichErrorDetail(t *testing.T) {
	buf := new(bytes.Buffer)
	ok := runDoctor(buf, []doctorCheck{
		{
			fail: "static fail",
			hint: "static hint",
			run: func() error {
				return &richError{detail: "dynamic detail", hint: "dynamic hint"}
			},
		},
	})
	if ok {
		t.Error("runDoctor must report the gap")
	}
	out := buf.String()
	if !strings.Contains(out, "dynamic detail") || !strings.Contains(out, "dynamic hint") {
		t.Errorf("rich detail/hint not printed:\n%s", out)
	}
	if strings.Contains(out, "static fail") {
		t.Errorf("static text must be replaced:\n%s", out)
	}
}
