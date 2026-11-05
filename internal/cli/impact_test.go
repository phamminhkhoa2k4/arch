package cli

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"archaeologist/internal/collector"
	"archaeologist/internal/store"
	"archaeologist/internal/verdict"
)

// impactFixture writes one scan with a component that has an inbound
// dependent, an inbound broken route, and a stored verdict — the
// positive case the shipped lab fixtures cannot provide (their
// verdict tables are empty and no broken route touches a component).
func impactFixture(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	db := filepath.Join(t.TempDir(), "impact.db")
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
	mustEmitEntity(t, sink, "systemd_unit", "app.service", "systemd_unit|app.service")
	mustEmitEntity(t, sink, "systemd_unit", "dep.service", "systemd_unit|dep.service")
	mustEmitEntity(t, sink, "nginx_route", "/dead/", "nginx_route|/dead/")

	for _, ev := range []collector.Evidence{
		{
			EntityIdentityKey: "systemd_unit|dep.service",
			Polarity:          collector.PolarityInUse,
			Channel:           "systemd",
			Strength:          collector.StrengthDeterministic,
			ObservedAt:        "2026-11-01T00:00:00Z",
			RawRef:            "/etc/systemd/system/dep.service:3",
			Ref:               "ev-dep",
		},
		{
			EntityIdentityKey: "nginx_route|/dead/",
			Polarity:          collector.PolarityNeutral,
			Channel:           "nginx",
			Strength:          collector.StrengthDeterministic,
			ObservedAt:        "2026-11-01T00:00:00Z",
			RawRef:            "/etc/nginx/conf.d/lab.conf:24",
			Ref:               "ev-route",
		},
	} {
		if err := sink.AddEvidence(ev); err != nil {
			t.Fatalf("add evidence: %v", err)
		}
	}
	edges := []collector.Edge{
		{
			SrcIdentityKey: "systemd_unit|dep.service",
			DstIdentityKey: "systemd_unit|app.service",
			Kind:           "depends_on",
			Strength:       collector.StrengthDeterministic,
			EvidenceRef:    "ev-dep",
		},
		{
			SrcIdentityKey: "nginx_route|/dead/",
			DstIdentityKey: "systemd_unit|app.service",
			Kind:           "proxies_to",
			Strength:       collector.StrengthDeterministic,
			EvidenceRef:    "ev-route",
		},
	}
	for _, e := range edges {
		if err := sink.UpsertEdge(e); err != nil {
			t.Fatalf("add edge: %v", err)
		}
	}
	if err := sink.AddFinding(collector.Finding{
		EntityIdentityKey: "nginx_route|/dead/",
		Kind:              "BROKEN_ROUTE",
		Severity:          "warn",
		Detail:            map[string]string{"reason": "no listener on tcp/9999 at scan time"},
	}); err != nil {
		t.Fatalf("add finding: %v", err)
	}
	saveVerdict(t, st, scan, "systemd_unit|app.service", store.VerdictRecord{
		State:     verdict.StateUnknown,
		Coverage:  "LOW",
		Blockers:  []verdict.Item{{Code: "B1", Text: "referenced by a cron job"}},
		RulesHash: "rules-1",
	})
	if err := st.FinishScan(ctx, scan, "ok"); err != nil {
		t.Fatalf("finish scan: %v", err)
	}
	return db
}

// The roadmap's first fixture: a compose container is listed with its
// outbound edges, related kinds, and empty risk sections.
func TestImpactLabWorkerFixture(t *testing.T) {
	db := copyFixtureDB(t)
	out, err := runCLI(t, "impact", "lab-worker", "--db", db)
	if err != nil {
		t.Fatalf("impact lab-worker: %v\n%s", err, out)
	}
	want := []string{
		"Impact: container lab-worker (scan #2)",
		"identity:     container|c26ac25798ddc117519028bf99d605e0fe8ba59eec682c46dfa74409965dfd1f",
		"verdict:      no verdict stored",
		"inbound dependents (0):",
		"outbound dependencies (2):",
		"[deterministic] belongs_to — compose_service worker",
		"[deterministic] manages — process sleep",
		"source: docker docker:/containers/json",
		"scheduled by (0):",
		"related components by kind (2 kinds):",
		"compose_service: worker",
		"process: sleep",
		"broken-route risk (0):",
		"blind spots (0):",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("impact output missing %q:\n%s", w, out)
		}
	}
}

// The roadmap's second fixture: a systemd unit with its script,
// process, and target dependencies.
func TestImpactLabAppServiceFixture(t *testing.T) {
	db := copyFixtureDB(t)
	out, err := runCLI(t, "impact", "lab-app.service", "--db", db)
	if err != nil {
		t.Fatalf("impact lab-app.service: %v\n%s", err, out)
	}
	want := []string{
		"Impact: systemd_unit lab-app.service (scan #2)",
		"outbound dependencies (3):",
		"[deterministic] depends_on — systemd_unit network.target",
		"[deterministic] manages — process socat",
		"[deterministic] runs_as — script /opt/lab/scripts/app.sh",
		"source: systemd /etc/systemd/system/lab-app.service:3",
		"related components by kind (3 kinds):",
		"process: socat",
		"script: /opt/lab/scripts/app.sh",
		"systemd_unit: network.target",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("impact output missing %q:\n%s", w, out)
		}
	}
}

// The roadmap's third name is absent from the fixture (the lab has no
// caddy component): impact reports the unknown component as an
// execution error.
func TestImpactCaddyServiceUnknown(t *testing.T) {
	db := copyFixtureDB(t)
	out, err := runCLI(t, "impact", "caddy.service", "--db", db)
	if err == nil {
		t.Fatalf("expected an error, got:\n%s", out)
	}
	if exitCodeOf(err) != ExitError {
		t.Errorf("exit = %d, want %d", exitCodeOf(err), ExitError)
	}
	if !strings.Contains(err.Error(), `no component matches "caddy.service"`) {
		t.Errorf("error not actionable: %v", err)
	}
}

// The positive case: verdict, inbound dependents (including the route
// proxying to the component), the broken route in the neighbourhood,
// and the JSON payload.
func TestImpactShowsRisksAndVerdict(t *testing.T) {
	db := impactFixture(t)
	out, err := runCLI(t, "impact", "app.service", "--db", db)
	if err != nil {
		t.Fatalf("impact app.service: %v\n%s", err, out)
	}
	want := []string{
		"Impact: systemd_unit app.service (scan #1)",
		"verdict:      UNKNOWN (coverage LOW, 1 blockers)",
		"inbound dependents (2):",
		"[deterministic] depends_on — systemd_unit dep.service",
		"[deterministic] proxies_to — nginx_route /dead/",
		"outbound dependencies (0):",
		"related components by kind (2 kinds):",
		"nginx_route: /dead/",
		"systemd_unit: dep.service",
		"broken-route risk (1):",
		"[warn] /dead/ (nginx_route): no listener on tcp/9999 at scan time",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("impact output missing %q:\n%s", w, out)
		}
	}
}

// JSON output mirrors the text sections as machine-readable arrays.
func TestImpactJSONPayload(t *testing.T) {
	db := impactFixture(t)
	out, err := runCLI(t, "impact", "app.service", "--db", db, "--format", "json")
	if err != nil {
		t.Fatalf("impact: %v\n%s", err, out)
	}
	var doc impactJSON
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("json parse: %v\noutput:\n%s", err, out)
	}
	if doc.ScanID != 1 || doc.Kind != "systemd_unit" || doc.Name != "app.service" {
		t.Errorf("identity fields wrong: %+v", doc)
	}
	if doc.Verdict == nil || doc.Verdict.State != verdict.StateUnknown ||
		doc.Verdict.Blockers != 1 {
		t.Errorf("verdict = %+v, want UNKNOWN with 1 blocker", doc.Verdict)
	}
	if len(doc.Inbound) != 2 || len(doc.Outbound) != 0 {
		t.Errorf("inbound/outbound = %d/%d, want 2/0", len(doc.Inbound), len(doc.Outbound))
	}
	if len(doc.RelatedByKind) != 2 {
		t.Errorf("related kinds = %d, want 2", len(doc.RelatedByKind))
	}
	if len(doc.BrokenRouteRisk) != 1 {
		t.Fatalf("broken route risk = %d, want 1", len(doc.BrokenRouteRisk))
	}
	if doc.BrokenRouteRisk[0].Detail["reason"] != "no listener on tcp/9999 at scan time" {
		t.Errorf("risk detail = %v", doc.BrokenRouteRisk[0].Detail)
	}
	if len(doc.BlindSpots) != 0 {
		t.Errorf("blind spots = %d, want 0", len(doc.BlindSpots))
	}
}

// The impact command appears in the root help.
func TestImpactInRootHelp(t *testing.T) {
	out, err := runCLI(t, "--help")
	if err != nil {
		t.Fatalf("--help: %v", err)
	}
	if !strings.Contains(out, "impact") {
		t.Errorf("root help missing impact:\n%s", out)
	}
}
