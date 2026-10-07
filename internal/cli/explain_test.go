package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"archaeologist/internal/collector"
	"archaeologist/internal/store"
)

const explainRouteKey = "nginx_route|/etc/nginx/conf.d/lab.conf#8080#_#/web/"

// seedExplain opens a fresh db with one scan and returns both the
// store and its id.
func seedExplain(t *testing.T, db string) (*store.Store, int64) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, db)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	hostID, err := st.InsertHost(ctx, "lab", "linux", "test")
	if err != nil {
		t.Fatalf("insert host: %v", err)
	}
	scanID, err := st.InsertScan(ctx, hostID, "v0.1-test", "{}")
	if err != nil {
		t.Fatalf("insert scan: %v", err)
	}
	return st, scanID
}

// seedRoute stores one route with evidence and a blind spot, then
// closes the scan.
func seedRoute(t *testing.T, st *store.Store, scanID int64, key, name string) {
	t.Helper()
	ctx := context.Background()
	k := store.NewScanSink(ctx, st, scanID)
	if err := k.UpsertEntity(collector.Entity{
		Kind:        "nginx_route",
		Name:        name,
		IdentityKey: key,
		Fingerprint: "f",
		Attributes:  map[string]string{"location": name},
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := k.AddEvidence(collector.Evidence{
		EntityIdentityKey: key,
		Polarity:          collector.PolarityInUse,
		Channel:           "nginx_access_log",
		Strength:          collector.StrengthDeterministic,
		ObservedAt:        "2026-10-07T10:00:00Z",
		RawRef:            "/var/log/nginx/lab_access.log:12",
		Value:             map[string]string{"last_request_at": "2026-10-07T09:58:00Z", "count": "3"},
	}); err != nil {
		t.Fatalf("add evidence: %v", err)
	}
	if err := k.AddBlindSpot(collector.BlindSpot{
		EntityIdentityKey: key,
		Channel:           "log",
		Reason:            "log_retention_short",
		Detail:            map[string]string{"retention_days": "7"},
	}); err != nil {
		t.Fatalf("add blind: %v", err)
	}
	if err := st.FinishScan(ctx, scanID, "ok"); err != nil {
		t.Fatalf("finish scan: %v", err)
	}
}

func runExplainCmd(t *testing.T, args ...string) (string, error) {
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

// US-6.4: explain lists every evidence with a copyable source line
// and the blind spots attached to the same component.
func TestExplainShowsEvidenceAndBlindSpots(t *testing.T) {
	db := filepath.Join(t.TempDir(), "e.db")
	st, scanID := seedExplain(t, db)
	seedRoute(t, st, scanID, explainRouteKey, "/web/")
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	out, err := runExplainCmd(t, "explain", explainRouteKey, "--db", db)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	for _, want := range []string{
		"nginx_route",
		"/web/",
		"scan #",
		"Identity:  " + explainRouteKey,
		"Evidence (1)",
		"in_use",
		"nginx_access_log",
		"nguồn: /var/log/nginx/lab_access.log:12",
		"last_request_at=2026-10-07T09:58:00Z",
		"Blind spots (1)",
		"log_retention_short",
		"retention_days=7",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// An unknown reference is an error (exit code 2), not empty output.
func TestExplainNotFound(t *testing.T) {
	db := filepath.Join(t.TempDir(), "e.db")
	st, scanID := seedExplain(t, db)
	seedRoute(t, st, scanID, explainRouteKey, "/web/")
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, err := runExplainCmd(t, "explain", "no-such-component", "--db", db)
	if err == nil {
		t.Fatal("unknown reference must fail")
	}
	if !strings.Contains(err.Error(), "không tìm thấy") {
		t.Errorf("err = %v", err)
	}
}

// Several entities sharing a name must be disambiguated by
// identity_key instead of picking one silently.
func TestExplainAmbiguousNameListsKeys(t *testing.T) {
	db := filepath.Join(t.TempDir(), "e.db")
	st, scanID := seedExplain(t, db)
	seedRoute(t, st, scanID, "nginx_route|a.conf#8080#_#/web/", "/web/")
	seedRoute(t, st, scanID, "nginx_route|b.conf#8080#_#/web/", "/web/")
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, err := runExplainCmd(t, "explain", "/web/", "--db", db)
	if err == nil {
		t.Fatal("ambiguous name must fail")
	}
	for _, want := range []string{"nginx_route|a.conf#8080#_#/web/", "nginx_route|b.conf#8080#_#/web/", "identity_key"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err missing %q: %v", want, err)
		}
	}
}

// An exact identity_key beats a name that happens to be identical.
func TestExplainIdentityKeyBeatsName(t *testing.T) {
	db := filepath.Join(t.TempDir(), "e.db")
	st, scanID := seedExplain(t, db)
	seedRoute(t, st, scanID, "special-key", "route-a")
	seedRoute(t, st, scanID, "other-key", "special-key")
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	out, err := runExplainCmd(t, "explain", "special-key", "--db", db)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	if !strings.Contains(out, "route-a") || strings.Contains(out, "other-key") {
		t.Errorf("output must resolve the identity_key entity:\n%s", out)
	}
}

// Only the latest scan is consulted.
func TestExplainUsesLatestScan(t *testing.T) {
	db := filepath.Join(t.TempDir(), "e.db")
	ctx := context.Background()
	st, scanID := seedExplain(t, db)
	seedRoute(t, st, scanID, explainRouteKey, "/web/")
	// A newer scan without the entity: explain must look there.
	empty, err := st.InsertScan(ctx, 1, "v0.1-test", "{}")
	if err != nil {
		t.Fatalf("insert empty scan: %v", err)
	}
	if err := st.FinishScan(ctx, empty, "ok"); err != nil {
		t.Fatalf("finish: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, err = runExplainCmd(t, "explain", explainRouteKey, "--db", db)
	if err == nil {
		t.Fatal("entity only in an older scan must not resolve")
	}
}
