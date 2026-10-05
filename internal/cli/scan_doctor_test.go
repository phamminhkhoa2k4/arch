package cli

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"archaeologist/internal/store"
)

// `scan` runs the real collectors against this host's /proc
// (read-only) and records a scan row with entities — no stub anymore.
func TestScanRunsAgainstHostProc(t *testing.T) {
	root := rootCmd()
	addCommands(root)
	db := filepath.Join(t.TempDir(), "scan.db")
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"scan", "--db", db})

	if err := root.Execute(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "status=") || !strings.Contains(out, "blind spots:") {
		t.Errorf("summary missing fields:\n%s", out)
	}

	st, err := store.Open(context.Background(), db)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer func() { _ = st.Close() }()

	var scans, entities int
	var status string
	ctx := context.Background()
	if err := st.DB().QueryRowContext(ctx,
		`SELECT count(*), min(status) FROM scans`).Scan(&scans, &status); err != nil {
		t.Fatalf("query scans: %v", err)
	}
	if scans != 1 || (status != "ok" && status != "partial") {
		t.Errorf("scans=%d status=%q, want 1 scan with ok/partial", scans, status)
	}
	if err := st.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM entities`).Scan(&entities); err != nil {
		t.Fatalf("query entities: %v", err)
	}
	if entities == 0 {
		t.Error("scan emitted no process entities — /proc walk failed")
	}
}

// All probes available → the exact success line is printed.
func TestDoctorAllSourcesAvailable(t *testing.T) {
	buf := new(bytes.Buffer)
	ok := runDoctor(buf, []doctorCheck{
		{pass: "A", run: func() error { return nil }},
		{pass: "B", run: func() error { return nil }},
	})
	if !ok {
		t.Error("runDoctor must report available")
	}
	if !strings.Contains(buf.String(), "✅ Tất cả nguồn khả dụng") {
		t.Errorf("missing success line:\n%s", buf.String())
	}
}

// Non-root output lists each gap with a remediation hint.
func TestDoctorListsGapsWithHints(t *testing.T) {
	buf := new(bytes.Buffer)
	ok := runDoctor(buf, []doctorCheck{
		{
			fail: "Không đọc được process của user khác",
			hint: "chạy bằng sudo/root",
			run:  func() error { return errDenied },
		},
		{
			fail: "Không truy cập Docker socket",
			hint: "sudo usermod -aG docker $USER",
			run:  func() error { return errDenied },
		},
		{
			pass: "Log paths (/var/log)",
			run:  func() error { return nil },
		},
	})
	if ok {
		t.Error("runDoctor must report gaps")
	}
	out := buf.String()
	for _, want := range []string{
		"Không đọc được process của user khác",
		"Không truy cập Docker socket",
		"Gợi ý: chạy bằng sudo/root",
		"Gợi ý: sudo usermod -aG docker $USER",
		"✓ Log paths",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "✅ Tất cả nguồn khả dụng") {
		t.Errorf("success line must not appear when gaps exist:\n%s", out)
	}
}

// errDenied simulates a permission failure without touching the system.
var errDenied = errors.New("permission denied")
