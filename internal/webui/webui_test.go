package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"archaeologist/internal/collector"
	"archaeologist/internal/report"
	"archaeologist/internal/store"
	"archaeologist/internal/verdict"
)

// seedServer builds a store with one scan, two entities (one with an
// orphan verdict, one active), evidence, and returns a ready server.
func seedServer(t *testing.T) (*Server, *store.Store, int64) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ui.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	host, err := st.InsertHost(ctx, "testhost", "linux", "6.x")
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	scanID, err := st.InsertScan(ctx, host, "v-test", "{}")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if err := st.FinishScan(ctx, scanID, "ok"); err != nil {
		t.Fatalf("finish: %v", err)
	}
	k := store.NewScanSink(ctx, st, scanID)
	seedEntity(t, k, "container", "old-app", "container|old-app", map[string]string{"path": "/opt/old"})
	seedEntity(t, k, "container", "live-app", "container|live-app", map[string]string{"path": "/opt/live"})
	if err := k.AddEvidence(collector.Evidence{
		EntityIdentityKey: "container|old-app",
		Polarity:          collector.PolarityNeutral,
		Channel:           "docker",
		Strength:          collector.StrengthDeterministic,
		ObservedAt:        "2026-10-01T00:00:00Z",
		RawRef:            "docker:/containers/json",
		Value:             map[string]string{"state": "exited"},
		Ref:               "ev-old",
	}); err != nil {
		t.Fatalf("evidence: %v", err)
	}
	ents, err := st.FindEntities(ctx, scanID, "container|old-app")
	if err != nil || len(ents) != 1 {
		t.Fatalf("find old: %v %v", ents, err)
	}
	oldID := ents[0].ID
	ents, err = st.FindEntities(ctx, scanID, "container|live-app")
	if err != nil || len(ents) != 1 {
		t.Fatalf("find live: %v %v", ents, err)
	}
	liveID := ents[0].ID
	if err := st.SaveVerdict(ctx, oldID, scanID, verdict.Result{
		State: "LIKELY_ORPHANED", Coverage: "HIGH",
		Reasons: []string{"no activity in window"},
	}, "hash"); err != nil {
		t.Fatalf("verdict old: %v", err)
	}
	if err := st.SaveVerdict(ctx, liveID, scanID, verdict.Result{
		State: "ACTIVE", Coverage: "HIGH",
		Blockers: []verdict.Item{{Code: "ROUTE", Text: "nginx route", RawRef: "nginx.conf:12"}},
	}, "hash"); err != nil {
		t.Fatalf("verdict live: %v", err)
	}
	srv, err := New(ctx, st)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return srv, st, scanID
}

func seedEntity(t *testing.T, k *store.ScanSink, kind, name, key string, attrs map[string]string) {
	t.Helper()
	e := collector.Entity{Kind: kind, Name: name, IdentityKey: key, Fingerprint: key}
	if attrs != nil {
		e.Attributes = attrs
	}
	if err := k.UpsertEntity(e); err != nil {
		t.Fatalf("upsert %s: %v", key, err)
	}
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func post(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Dashboard JSON must equal report.Build marshaled — the parity
// requirement of the dashboard story.
func TestDashboardParityWithReportJSON(t *testing.T) {
	srv, st, scanID := seedServer(t)
	rep, err := buildReport(context.Background(), st, scanID)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	want, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rec := get(t, srv.Handler(), "/api/dashboard")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	var got, wantParsed map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal got: %v", err)
	}
	if err := json.Unmarshal(want, &wantParsed); err != nil {
		t.Fatalf("unmarshal want: %v", err)
	}
	// generated_at differs between builds; compare the rest.
	delete(got, "generated_at")
	delete(wantParsed, "generated_at")
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(wantParsed)
	if string(g) != string(w) {
		t.Errorf("dashboard != report JSON:\ngot  %s\nwant %s", g, w)
	}
}

func TestDashboardPageRenders(t *testing.T) {
	srv, _, _ := seedServer(t)
	rec := get(t, srv.Handler(), "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Dashboard", "Things worth investigating", "Blind spots tổng quan", "scan #"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
}

// Filter by status must return exactly the backend count.
func TestComponentsFilterByStatus(t *testing.T) {
	srv, _, _ := seedServer(t)
	rec := get(t, srv.Handler(), "/api/components?status=LIKELY_ORPHANED")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var payload struct {
		Components []struct {
			Name  string `json:"name"`
			State string `json:"state"`
		} `json:"components"`
		Count int `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.Count != 1 || len(payload.Components) != 1 ||
		payload.Components[0].Name != "old-app" || payload.Components[0].State != "LIKELY_ORPHANED" {
		t.Fatalf("filter result = %+v", payload)
	}
}

func TestComponentsSortLastActivityDesc(t *testing.T) {
	srv, _, _ := seedServer(t)
	rec := get(t, srv.Handler(), "/api/components?sort=last_activity&desc=1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var payload struct {
		Components []struct {
			Name         string `json:"name"`
			LastActivity string `json:"last_activity"`
		} `json:"components"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(payload.Components) != 2 {
		t.Fatalf("want 2 rows, got %d", len(payload.Components))
	}
	// old-app has evidence at 2026-10-01; live-app has none → desc puts
	// the dated row first.
	if payload.Components[0].Name != "old-app" || payload.Components[0].LastActivity == "" {
		t.Errorf("desc order = %+v", payload.Components)
	}
}

func TestComponentsPageRenders(t *testing.T) {
	srv, _, _ := seedServer(t)
	rec := get(t, srv.Handler(), "/components")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Components", "old-app", "live-app", "Last activity"} {
		if !strings.Contains(body, want) {
			t.Errorf("components page missing %q", want)
		}
	}
}

func TestDetailPageHasBlindPanelOutsideTabs(t *testing.T) {
	srv, st, scanID := seedServer(t)
	ents, err := st.FindEntities(context.Background(), scanID, "container|old-app")
	if err != nil || len(ents) != 1 {
		t.Fatalf("find: %v %v", ents, err)
	}
	rec := get(t, srv.Handler(), "/components/"+itoa(ents[0].ID))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `id="blind-panel"`) {
		t.Error("blind-spot panel missing from detail page")
	}
	if !strings.Contains(body, "Không có vùng mù nào") {
		t.Error("empty blind panel must still render the explanation")
	}
	if !strings.Contains(body, `id="delete-check-btn"`) {
		t.Error("delete-check button missing")
	}
}

func TestDetailOverviewTabMatchesStore(t *testing.T) {
	srv, st, scanID := seedServer(t)
	ents, _ := st.FindEntities(context.Background(), scanID, "container|old-app")
	rec := get(t, srv.Handler(), "/api/components/"+itoa(ents[0].ID)+"/overview")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var payload struct {
		Entity struct {
			Name string `json:"Name"`
		} `json:"entity"`
		Verdict struct {
			State string `json:"state"`
		} `json:"verdict"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.Entity.Name != "old-app" || payload.Verdict.State != "LIKELY_ORPHANED" {
		t.Errorf("overview = %+v", payload)
	}
}

func TestDetailEvidenceTabHasRawRef(t *testing.T) {
	srv, st, scanID := seedServer(t)
	ents, _ := st.FindEntities(context.Background(), scanID, "container|old-app")
	rec := get(t, srv.Handler(), "/api/components/"+itoa(ents[0].ID)+"/evidence")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "docker:/containers/json") {
		t.Errorf("evidence JSON missing raw_ref: %s", rec.Body)
	}
}

func TestDetailUnknownTab404(t *testing.T) {
	srv, st, scanID := seedServer(t)
	ents, _ := st.FindEntities(context.Background(), scanID, "container|old-app")
	rec := get(t, srv.Handler(), "/api/components/"+itoa(ents[0].ID)+"/nope")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// The modal data: blocked entity refuses plan generation; eligible
// entity creates one and links to the viewer.
func TestVerdictModalBlockerRefusesPlan(t *testing.T) {
	srv, st, scanID := seedServer(t)
	ents, _ := st.FindEntities(context.Background(), scanID, "container|live-app")
	id := itoa(ents[0].ID)
	rec := get(t, srv.Handler(), "/api/components/"+id+"/verdict")
	if rec.Code != http.StatusOK {
		t.Fatalf("verdict status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"has_blockers":true`) {
		t.Errorf("verdict JSON = %s", rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "nginx route") {
		t.Errorf("blocker text missing: %s", rec.Body)
	}
	prec := post(t, srv.Handler(), "/api/components/"+id+"/plan")
	if prec.Code != http.StatusConflict {
		t.Errorf("plan POST status = %d, want 409", prec.Code)
	}
}

func TestGeneratePlanEligibleAndViewerSync(t *testing.T) {
	srv, st, scanID := seedServer(t)
	ents, _ := st.FindEntities(context.Background(), scanID, "container|old-app")
	id := itoa(ents[0].ID)
	prec := post(t, srv.Handler(), "/api/components/"+id+"/plan")
	if prec.Code != http.StatusCreated {
		t.Fatalf("plan POST = %d, body %s", prec.Code, prec.Body)
	}
	var created struct {
		PlanID int64  `json:"plan_id"`
		Href   string `json:"href"`
	}
	if err := json.Unmarshal(prec.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if created.PlanID == 0 || !strings.HasPrefix(created.Href, "/plans/") {
		t.Fatalf("created = %+v", created)
	}
	// Viewer JSON lists all six stages, matching plan status.
	vrec := get(t, srv.Handler(), "/api/plans/"+itoa(created.PlanID))
	if vrec.Code != http.StatusOK {
		t.Fatalf("plan JSON = %d", vrec.Code)
	}
	var plan struct {
		Stages []struct {
			Stage  string `json:"Stage"`
			Status string `json:"Status"`
		} `json:"stages"`
	}
	if err := json.Unmarshal(vrec.Body.Bytes(), &plan); err != nil {
		t.Fatalf("unmarshal plan: %v", err)
	}
	if len(plan.Stages) != 6 || plan.Stages[0].Stage != "Candidate" {
		t.Fatalf("stages = %+v", plan.Stages)
	}
	// Confirm Candidate through HTTP, then store must show it done —
	// the same path `plan confirm` uses.
	crec := post(t, srv.Handler(), "/api/plans/"+itoa(created.PlanID)+"/stages/Candidate")
	if crec.Code != http.StatusOK {
		t.Fatalf("confirm = %d, body %s", crec.Code, crec.Body)
	}
	states, err := st.PlanStageStates(context.Background(), created.PlanID)
	if err != nil {
		t.Fatalf("stages: %v", err)
	}
	if states[0].Status != "done" {
		t.Errorf("Candidate not persisted: %+v", states[0])
	}
	// Out-of-order confirm is a 409, same enforcement as the CLI.
	srec := post(t, srv.Handler(), "/api/plans/"+itoa(created.PlanID)+"/stages/Removed")
	if srec.Code != http.StatusConflict {
		t.Errorf("out-of-order confirm = %d, want 409", srec.Code)
	}
}

func TestGraphJSONCountsAndDirection(t *testing.T) {
	_, st, scanID := seedServer(t)
	ctx := context.Background()
	k := store.NewScanSink(ctx, st, scanID)
	// The sink resolves edges against entities it has seen this run;
	// re-upsert the container so both endpoints resolve.
	seedEntity(t, k, "container", "old-app", "container|old-app", map[string]string{"path": "/opt/old"})
	seedEntity(t, k, "process", "p1", "process|p1", nil)
	if err := k.AddEvidence(collector.Evidence{
		EntityIdentityKey: "process|p1",
		Polarity:          collector.PolarityNeutral,
		Channel:           "procfs",
		Strength:          collector.StrengthDeterministic,
		ObservedAt:        "2026-10-01T00:00:00Z",
		RawRef:            "/proc/1",
		Ref:               "ev-p1",
	}); err != nil {
		t.Fatalf("evidence p1: %v", err)
	}
	if err := k.UpsertEdge(collector.Edge{
		SrcIdentityKey: "process|p1",
		DstIdentityKey: "container|old-app",
		Kind:           "depends_on",
		Strength:       collector.StrengthDeterministic,
		EvidenceRef:    "ev-p1",
	}); err != nil {
		t.Fatalf("edge: %v", err)
	}
	// Rebuild server so it sees the new edge (scan id is stable).
	srv2, err := New(context.Background(), st)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	rec := get(t, srv2.Handler(), "/api/graph")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var payload struct {
		Nodes []struct {
			ID   int64  `json:"id"`
			Kind string `json:"kind"`
		} `json:"nodes"`
		Edges []struct {
			Src      int64  `json:"src"`
			Dst      int64  `json:"dst"`
			Kind     string `json:"kind"`
			Strength string `json:"strength"`
			RawRef   string `json:"raw_ref"`
		} `json:"edges"`
		Truncated bool `json:"truncated"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(payload.Nodes) != 3 {
		t.Errorf("nodes = %d, want 3", len(payload.Nodes))
	}
	if len(payload.Edges) != 1 {
		t.Fatalf("edges = %d, want 1", len(payload.Edges))
	}
	e := payload.Edges[0]
	if e.Kind != "depends_on" || e.Strength != "deterministic" || e.RawRef != "/proc/1" {
		t.Errorf("edge = %+v", e)
	}
	// Direction: src must be process p1, dst the container.
	var srcKind, dstKind string
	for _, n := range payload.Nodes {
		if n.ID == e.Src {
			srcKind = n.Kind
		}
		if n.ID == e.Dst {
			dstKind = n.Kind
		}
	}
	if srcKind != "process" || dstKind != "container" {
		t.Errorf("direction %s -> %s wrong", srcKind, dstKind)
	}
}

func TestGraphPageRenders(t *testing.T) {
	srv, _, _ := seedServer(t)
	rec := get(t, srv.Handler(), "/graph")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `id="graph-svg"`) {
		t.Error("graph svg missing")
	}
}

func TestStaticAssetsServed(t *testing.T) {
	srv, _, _ := seedServer(t)
	for _, path := range []string{"/static/style.css", "/static/app.js"} {
		rec := get(t, srv.Handler(), path)
		if rec.Code != http.StatusOK {
			t.Errorf("%s status = %d", path, rec.Code)
		}
	}
}

// itoa is the test-local integer formatter.
func itoa(v int64) string { return strconv.FormatInt(v, 10) }

// buildReport is the report.Build wrapper used by the parity test.
func buildReport(ctx context.Context, st *store.Store, scanID int64) (report.Report, error) {
	return report.Build(ctx, st, scanID)
}

// Empty tab payloads must be [] not null so the page scripts can
// iterate unconditionally.
func TestEmptyTabPayloadsAreArraysNotNull(t *testing.T) {
	srv, st, scanID := seedServer(t)
	ents, _ := st.FindEntities(context.Background(), scanID, "container|old-app")
	id := itoa(ents[0].ID)
	for _, tab := range []string{"dependencies", "evidence", "history", "blindspots"} {
		rec := get(t, srv.Handler(), "/api/components/"+id+"/"+tab)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d", tab, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "null") {
			t.Errorf("%s payload contains null: %s", tab, rec.Body)
		}
	}
}
