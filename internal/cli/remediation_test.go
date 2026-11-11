package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"archaeologist/internal/collector"
	"archaeologist/internal/store"
)

// Every known blind-spot reason maps to a category, permission gaps
// name the credential to add, and unknown reasons still get advice.
func TestRemedyForKnownReasons(t *testing.T) {
	cases := []struct {
		reason   string
		category string
		contains string
	}{
		{"journald_unreadable", remedyPermission, "systemd-journal"},
		{"cron_source_unreadable", remedyPermission, "root"},
		{"docker_log_unreadable", remedyPermission, "docker"},
		{"nginx_target_unresolved", remedyResolve, "nginx -T"},
		{"haproxy_config_unreadable", remedyPermission, "haproxy.cfg"},
		{"haproxy_target_unresolved", remedyResolve, "server address"},
		{"traefik_config_unreadable", remedyPermission, "traefik.yml"},
		{"traefik_provider_unsupported", remedyLimitation, "no action"},
		{"traefik_target_unresolved", remedyResolve, "server URL"},
		{"apache_config_unreadable", remedyPermission, "apache2.conf"},
		{"apache_include_unreadable", remedyPermission, "included"},
		{"apache_target_unresolved", remedyResolve, "backend address"},
		{"podman_api_unreadable", remedyPermission, "podman"},
		{"podman_log_unreadable", remedyPermission, "podman"},
		{"containerd_bundle_unreadable", remedyPermission, "containerd"},
		{"containerd_shim_unparsed", remedyManual, "manually"},
		{"socket_unit_unreadable", remedyPermission, "socket unit file"},
		{"socket_service_unresolved", remedyResolve, "Service="},
		{"socket_unit_missing", remedyManual, "transient"},
		{"resolv_conf_unreadable", remedyPermission, "resolv.conf"},
		{"dmi_unavailable", remedyPermission, "sys/class/dmi/id"},
		{"cron_env_unresolved", remedyResolve, "/etc/environment"},
		{"log_retention_short", remedyLimitation, "no action"},
		{"cron_schedule_unparsed", remedyManual, "manually"},
	}
	for _, tc := range cases {
		r := remedyFor(tc.reason)
		if r.Category != tc.category {
			t.Errorf("%s: category = %q, want %q", tc.reason, r.Category, tc.category)
		}
		if !strings.Contains(r.Advice, tc.contains) {
			t.Errorf("%s: advice %q lacks %q", tc.reason, r.Advice, tc.contains)
		}
	}

	// A reason from a future collector must still produce advice.
	unknown := remedyFor("brand_new_reason")
	if unknown.Category != remedyManual || unknown.Advice == "" {
		t.Errorf("unknown reason fallback = %+v, want manual advice", unknown)
	}
}

// explainNextFixture writes one scan with a permission blind spot on a
// single unit and no observations (so the window is short).
func explainNextFixture(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	db := filepath.Join(t.TempDir(), "explain.db")
	st, err := store.Open(ctx, db)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	host, err := st.InsertHost(ctx, "lab-host", "linux", "6.1")
	if err != nil {
		t.Fatalf("insert host: %v", err)
	}
	scan, err := st.InsertScan(ctx, host, "v0", "{}")
	if err != nil {
		t.Fatalf("insert scan: %v", err)
	}
	sink := store.NewScanSink(ctx, st, scan)
	mustEmitEntity(t, sink, "systemd_unit", "journ.service", "systemd_unit|journ.service")
	if err := sink.AddBlindSpot(collector.BlindSpot{
		EntityIdentityKey: "systemd_unit|journ.service",
		Channel:           "systemd",
		Reason:            "journald_unreadable",
		Detail:            map[string]string{"unit": "journ.service"},
	}); err != nil {
		t.Fatalf("blind spot: %v", err)
	}
	if err := st.FinishScan(ctx, scan, "ok"); err != nil {
		t.Fatalf("finish scan: %v", err)
	}
	return db
}

// explain --next prints the window advice and one remediation line per
// blind spot; permission gaps name the group to add.
func TestExplainNextText(t *testing.T) {
	db := explainNextFixture(t)
	out, err := runCLI(t, "explain", "journ.service", "--db", db, "--next")
	if err != nil {
		t.Fatalf("explain --next: %v\n%s", err, out)
	}
	want := []string{
		"Next steps:",
		"window: observe 14 more days — earliest sufficient date",
		"[systemd] journald_unreadable (permission):",
		"systemd-journal group",
		"Blind spots (1):",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("explain --next missing %q:\n%s", w, out)
		}
	}
}

// explain --format json --next adds the stable "next" object with the
// window progress and per-blind-spot remediation.
func TestExplainNextJSON(t *testing.T) {
	db := explainNextFixture(t)
	doc := decodeCLI(t, "explain", "journ.service", "--db", db, "--next", "--format", "json")

	next, ok := doc["next"].(map[string]any)
	if !ok {
		t.Fatalf("next object missing:\n%s", marshalDoc(t, doc))
	}
	window, ok := next["window"].(map[string]any)
	if !ok {
		t.Fatalf("next.window missing:\n%s", marshalDoc(t, next))
	}
	if window["ready"] != false {
		t.Errorf("ready = %v, want false (no observations)", window["ready"])
	}
	if window["days_remaining"] != float64(14) {
		t.Errorf("days_remaining = %v, want 14", window["days_remaining"])
	}
	if window["ready_at"] == nil {
		t.Error("ready_at is null; want the earliest sufficient date")
	}
	blinds, ok := next["blind_spots"].([]any)
	if !ok || len(blinds) != 1 {
		t.Fatalf("blind_spots = %v, want one entry", next["blind_spots"])
	}
	step := blinds[0].(map[string]any)
	if step["category"] != remedyPermission || step["channel"] != "systemd" {
		t.Errorf("step = %v, want permission/systemd", step)
	}
	if !strings.Contains(step["advice"].(string), "systemd-journal") {
		t.Errorf("advice %v lacks the required group", step["advice"])
	}
}

// Without --next the JSON payload stays exactly as before: no "next"
// key.
func TestExplainWithoutNextHasNoNextKey(t *testing.T) {
	db := explainNextFixture(t)
	doc := decodeCLI(t, "explain", "journ.service", "--db", db, "--format", "json")
	if _, exists := doc["next"]; exists {
		t.Errorf("next key present without --next:\n%s", marshalDoc(t, doc))
	}
	// The text view stays clean too.
	out, err := runCLI(t, "explain", "journ.service", "--db", db)
	if err != nil {
		t.Fatalf("explain: %v\n%s", err, out)
	}
	if strings.Contains(out, "Next steps:") {
		t.Errorf("next section printed without --next:\n%s", out)
	}
}

// A component without blind spots still gets the window advice and an
// explicit all-clear line.
func TestExplainNextNoBlindSpots(t *testing.T) {
	ctx := context.Background()
	db := filepath.Join(t.TempDir(), "clean.db")
	st, err := store.Open(ctx, db)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	host, err := st.InsertHost(ctx, "lab-host", "linux", "6.1")
	if err != nil {
		t.Fatalf("insert host: %v", err)
	}
	scan, err := st.InsertScan(ctx, host, "v0", "{}")
	if err != nil {
		t.Fatalf("insert scan: %v", err)
	}
	sink := store.NewScanSink(ctx, st, scan)
	mustEmitEntity(t, sink, "script", "orphan.sh", "script|orphan.sh")
	if err := st.FinishScan(ctx, scan, "ok"); err != nil {
		t.Fatalf("finish scan: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	out, err := runCLI(t, "explain", "orphan.sh", "--db", db, "--next")
	if err != nil {
		t.Fatalf("explain --next: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Next steps:") || !strings.Contains(out, "window: observe 14 more days") {
		t.Errorf("window advice missing:\n%s", out)
	}
	if !strings.Contains(out, "blind spots: none — nothing to remediate") {
		t.Errorf("all-clear line missing:\n%s", out)
	}
}
