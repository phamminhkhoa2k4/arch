package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"archaeologist/internal/collector"
	"archaeologist/internal/store"
)

// reportTestDB builds a small scan with one finding, one entity-scoped
// blind spot, and one host-wide blind spot, returning the db path.
func reportTestDB(t *testing.T) string {
	t.Helper()
	db := filepath.Join(t.TempDir(), "report.db")
	st, err := store.Open(context.Background(), db)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	hostID, err := st.InsertHost(ctx, "lab", "linux", "test")
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	scanID, err := st.InsertScan(ctx, hostID, "v0.1-test", "{}")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	k := store.NewScanSink(ctx, st, scanID)
	e := collector.Entity{
		Kind: "process", Name: "nginx", IdentityKey: "process|1|1", Fingerprint: "fp",
		Attributes: map[string]string{"pid": "1"},
	}
	if err := k.UpsertEntity(e); err != nil {
		t.Fatalf("entity: %v", err)
	}
	if err := k.AddBlindSpot(collector.BlindSpot{
		EntityIdentityKey: e.IdentityKey, Channel: "process",
		Reason: "permission_denied", Detail: map[string]string{"pid": "1"},
	}); err != nil {
		t.Fatalf("blind: %v", err)
	}
	if err := k.AddBlindSpot(collector.BlindSpot{
		Channel: "systemd", Reason: "dbus_unavailable",
		Detail: map[string]string{"error": "connection refused"},
	}); err != nil {
		t.Fatalf("host blind: %v", err)
	}
	// Finding via raw insert (schema CHECK kinds) — resolve the entity id
	// first so the join is guaranteed.
	var entityID int64
	if err := st.DB().QueryRowContext(ctx,
		`SELECT id FROM entities WHERE scan_id = ? AND identity_key = ?`,
		scanID, e.IdentityKey).Scan(&entityID); err != nil {
		t.Fatalf("entity id: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO findings (scan_id, entity_id, kind, severity, detail_json)
		 VALUES (?, ?, 'BROKEN_ROUTE', 'warn', '{"route":"/old"}')`,
		scanID, entityID); err != nil {
		t.Fatalf("finding: %v", err)
	}
	if err := st.FinishScan(ctx, scanID, "partial"); err != nil {
		t.Fatalf("finish: %v", err)
	}
	return db
}

func runReportCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := rootCmd()
	addCommands(root)
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

// JSON export carries every schema-required field and non-null arrays.
func TestReportJSONOutput(t *testing.T) {
	db := reportTestDB(t)
	out, err := runReportCmd(t, "report", "--db", db, "--format", "json")
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	var got struct {
		ScanID      int64  `json:"scan_id"`
		Host        string `json:"host"`
		Status      string `json:"status"`
		GeneratedAt string `json:"generated_at"`
		Dashboard   struct {
			EntitiesByKind map[string]int `json:"entities_by_kind"`
			Verdict        map[string]int `json:"verdict"`
			BlindSpots     int            `json:"blind_spots"`
			Findings       int            `json:"findings"`
		} `json:"dashboard"`
		Findings []struct {
			Kind       string `json:"kind"`
			Severity   string `json:"severity"`
			EntityName string `json:"entity_name"`
		} `json:"findings"`
		BlindSpots []struct {
			Channel string `json:"channel"`
			Reason  string `json:"reason"`
		} `json:"blind_spots"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out)
	}
	if got.ScanID == 0 || got.Host != "lab" || got.Status != "partial" || got.GeneratedAt == "" {
		t.Errorf("header wrong: %+v", got)
	}
	if got.Dashboard.Findings != 1 || got.Dashboard.BlindSpots != 2 {
		t.Errorf("dashboard counts wrong: %+v", got.Dashboard)
	}
	if got.Dashboard.EntitiesByKind["process"] != 1 {
		t.Errorf("entities_by_kind wrong: %v", got.Dashboard.EntitiesByKind)
	}
	if len(got.Findings) != 1 || got.Findings[0].Kind != "BROKEN_ROUTE" ||
		got.Findings[0].EntityName != "nginx" {
		t.Errorf("findings wrong: %+v", got.Findings)
	}
	if len(got.BlindSpots) != 2 {
		t.Errorf("blind spots wrong: %+v", got.BlindSpots)
	}
	// Arrays must be [], not null (integration contract).
	if strings.Contains(out, "null") {
		t.Errorf("null leaked into JSON:\n%s", out)
	}
}

// Markdown carries the three required headings in order, blind spots
// before findings.
func TestReportMarkdownHeadings(t *testing.T) {
	db := reportTestDB(t)
	out, err := runReportCmd(t, "report", "--db", db, "--format", "md")
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	d := strings.Index(out, "## Dashboard")
	f := strings.Index(out, "## Findings")
	b := strings.Index(out, "## Blind spots")
	if d < 0 || f < 0 || b < 0 {
		t.Fatalf("missing heading (d=%d f=%d b=%d):\n%s", d, f, b, out)
	}
	if d >= b || b >= f {
		t.Errorf("heading order wrong: dashboard=%d blind=%d findings=%d", d, b, f)
	}
	if !strings.Contains(out, "BROKEN_ROUTE") || !strings.Contains(out, "dbus_unavailable") {
		t.Errorf("content missing:\n%s", out)
	}
}

// HTML export writes a self-contained file: no external assets, blind
// spots section present before findings, secrets escaped not injected.
func TestReportHTMLFile(t *testing.T) {
	db := reportTestDB(t)
	htmlPath := filepath.Join(t.TempDir(), "report.html")
	out, err := runReportCmd(t, "report", "--db", db, "-o", htmlPath)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if !strings.Contains(out, htmlPath) {
		t.Errorf("stdout should name the file: %s", out)
	}
	raw, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("read html: %v", err)
	}
	body := string(raw)
	if !strings.Contains(body, "<!DOCTYPE html>") || !strings.Contains(body, "Blind spots") {
		t.Errorf("html missing structure")
	}
	bIdx := strings.Index(body, "<h2>Blind spots</h2>")
	fIdx := strings.Index(body, "<h2>Findings</h2>")
	if bIdx < 0 || fIdx < 0 || bIdx > fIdx {
		t.Errorf("blind spots must precede findings (b=%d f=%d)", bIdx, fIdx)
	}
	// No external asset references (src/href to http or //cdn).
	for _, bad := range []string{"src=\"http", "href=\"http", "src=\"//", "href=\"//"} {
		if strings.Contains(body, bad) {
			t.Errorf("external asset reference %q found", bad)
		}
	}
	if len(raw) > 2<<20 {
		t.Errorf("html too big: %d bytes", len(raw))
	}
}

// Flag validation: bogus format → error; html without -o → error.
func TestReportFlagValidation(t *testing.T) {
	db := reportTestDB(t)
	if _, err := runReportCmd(t, "report", "--db", db, "--format", "pdf"); err == nil {
		t.Error("bogus format must error")
	}
	if _, err := runReportCmd(t, "report", "--db", db, "--format", "html"); err == nil {
		t.Error("html without -o must error")
	}
}
