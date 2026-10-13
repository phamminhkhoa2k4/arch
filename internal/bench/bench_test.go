package bench

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

// seedBench opens a fresh db at path with one scan and returns the sink.
func seedBench(t *testing.T, path string) (*store.Store, *store.ScanSink, int64) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, path)
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
	return st, store.NewScanSink(ctx, st, scanID), scanID
}

func benchEntity(t *testing.T, k *store.ScanSink, kind, name, key string, attrs map[string]string) {
	t.Helper()
	if err := k.UpsertEntity(collector.Entity{
		Kind: kind, Name: name, IdentityKey: key, Fingerprint: "f", Attributes: attrs,
	}); err != nil {
		t.Fatalf("upsert %s: %v", key, err)
	}
}

func benchEdge(t *testing.T, k *store.ScanSink, tag, src, dst, kind string, strength collector.Strength) {
	t.Helper()
	ref := "ref-" + tag
	if err := k.AddEvidence(collector.Evidence{
		EntityIdentityKey: src,
		Polarity:          collector.PolarityNeutral,
		Channel:           "test",
		Strength:          strength,
		ObservedAt:        "2026-10-07T10:00:00Z",
		RawRef:            "/x:1",
		Ref:               ref,
	}); err != nil {
		t.Fatalf("add evidence %s: %v", tag, err)
	}
	if err := k.UpsertEdge(collector.Edge{
		SrcIdentityKey: src, DstIdentityKey: dst, Kind: kind,
		Strength: strength, EvidenceRef: ref,
	}); err != nil {
		t.Fatalf("upsert edge %s: %v", tag, err)
	}
}

func listenerKey(port int) string {
	return "listener|tcp|0.0.0.0|" + itoa(port) + "|1"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func listenerAttrs(port int) map[string]string {
	return map[string]string{"proto": "tcp", "addr": "0.0.0.0", "port": itoa(port)}
}

// A fully resolved lab: one owned listener, one simple route chain.
// Both metrics hit their targets and no warning annotation appears.
func TestBenchPass(t *testing.T) {
	db := filepath.Join(t.TempDir(), "scan.db")
	st, k, _ := seedBench(t, db)
	benchEntity(t, k, "listener", "0.0.0.0:8081", listenerKey(8081), listenerAttrs(8081))
	benchEntity(t, k, "container", "lab-web", "container|abc", nil)
	benchEntity(t, k, "nginx_route", "/web/", "nginx_route|/x/lab.conf#8080#_#/web/",
		map[string]string{"location": "/web/", "file": "/x/lab.conf"})
	benchEdge(t, k, "listens", listenerKey(8081), "container|abc", "listens_on", collector.StrengthDeterministic)
	benchEdge(t, k, "proxy", "nginx_route|/x/lab.conf#8080#_#/web/", listenerKey(8081), "proxies_to", collector.StrengthDeterministic)
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	gt := &GroundTruth{
		Listeners: []GTListener{{
			ID: "listener-web", Proto: "tcp", Addr: "0.0.0.0", Port: 8081,
			ExpectedOwner: Owner{Kind: "container", Name: "lab-web"},
		}},
		RouteChains: []GTRouteChain{{
			ID: "chain-web", Location: "/web/", File: "lab.conf", Simple: true,
			Expected: []ExpectedRoute{{Proto: "tcp", Port: 8081,
				Owner: Owner{Kind: "container", Name: "lab-web"}}},
		}},
	}
	rep, err := Measure(db, gt)
	if err != nil {
		t.Fatalf("measure: %v", err)
	}
	if rep.OwnedOK != 1 || rep.OwnedTotal != 1 || rep.OwnedPct != 100.0 {
		t.Errorf("owned = %d/%d %.1f%%, want 1/1 100%%", rep.OwnedOK, rep.OwnedTotal, rep.OwnedPct)
	}
	if rep.RoutesOK != 1 || rep.RoutesTotal != 1 || rep.RoutesPct != 100.0 {
		t.Errorf("routes = %d/%d %.1f%%, want 1/1 100%%", rep.RoutesOK, rep.RoutesTotal, rep.RoutesPct)
	}

	var out bytes.Buffer
	if err := rep.Write(&out); err != nil {
		t.Fatalf("write: %v", err)
	}
	if strings.Contains(out.String(), "::warning") {
		t.Errorf("pass report must not warn:\n%s", out.String())
	}
}

// Wrong owner, an unowned listener, a ground-truth listener missing
// from the scan and a broken chain: both metrics miss, warnings print,
// and the exit stays 0 (Write returns nil).
func TestBenchWarnBelowThreshold(t *testing.T) {
	db := filepath.Join(t.TempDir(), "scan.db")
	st, k, _ := seedBench(t, db)
	benchEntity(t, k, "listener", "0.0.0.0:8081", listenerKey(8081), listenerAttrs(8081))
	benchEntity(t, k, "container", "other", "container|xyz", nil)
	benchEntity(t, k, "listener", "0.0.0.0:6378", listenerKey(6378), listenerAttrs(6378))
	benchEntity(t, k, "nginx_route", "/web/", "nginx_route|/x/lab.conf#8080#_#/web/",
		map[string]string{"location": "/web/", "file": "/x/lab.conf"})
	// Wrong owner: 8081 serves container "other", GT wants lab-web.
	benchEdge(t, k, "listens", listenerKey(8081), "container|xyz", "listens_on", collector.StrengthDeterministic)
	benchEdge(t, k, "proxy", "nginx_route|/x/lab.conf#8080#_#/web/", listenerKey(8081), "proxies_to", collector.StrengthDeterministic)
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	gt := &GroundTruth{
		Listeners: []GTListener{
			{ID: "listener-web", Proto: "tcp", Addr: "0.0.0.0", Port: 8081,
				ExpectedOwner: Owner{Kind: "container", Name: "lab-web"}},
			// Pin a listener the scan does not see (lab drift).
			{ID: "listener-cache", Proto: "tcp", Addr: "127.0.0.1", Port: 6379,
				ExpectedOwner: Owner{Kind: "container", Name: "lab-cache"}},
		},
		RouteChains: []GTRouteChain{{
			ID: "chain-web", Location: "/web/", File: "lab.conf", Simple: true,
			Expected: []ExpectedRoute{{Proto: "tcp", Port: 8081,
				Owner: Owner{Kind: "container", Name: "lab-web"}}},
		}},
	}
	rep, err := Measure(db, gt)
	if err != nil {
		t.Fatalf("measure: %v", err)
	}
	// 3 listeners total: 2 in db + 1 missing GT pin; none owned.
	if rep.OwnedOK != 0 || rep.OwnedTotal != 3 {
		t.Errorf("owned = %d/%d, want 0/3", rep.OwnedOK, rep.OwnedTotal)
	}
	if rep.RoutesOK != 0 || rep.RoutesTotal != 1 {
		t.Errorf("routes = %d/%d, want 0/1", rep.RoutesOK, rep.RoutesTotal)
	}

	var out bytes.Buffer
	if err := rep.Write(&out); err != nil {
		t.Fatalf("write must stay exit-0: %v", err)
	}
	text := out.String()
	for _, want := range []string{
		"::warning title=benchmark::Listeners with owner",
		"::warning title=benchmark::Correct route chains",
		"no owner: " + listenerKey(8081),
		"gt:listener-cache (missing from scan)",
		"broken chain: chain-web",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("warn report missing %q:\n%s", want, text)
		}
	}
}

// Unparsable ground truth is a tool error, not a warning.
func TestBenchToolErrorBadGT(t *testing.T) {
	if _, err := LoadGT(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("missing GT file must fail")
	}

	broken := filepath.Join(t.TempDir(), "gt.yaml")
	if err := os.WriteFile(broken, []byte("version: 1\n"), 0o644); err != nil {
		t.Fatalf("write gt: %v", err)
	}
	if _, err := LoadGT(broken); err == nil || !strings.Contains(err.Error(), "listeners") {
		t.Errorf("GT without listeners block: err = %v, want listeners complaint", err)
	}

	db := filepath.Join(t.TempDir(), "scan.db")
	st, k, _ := seedBench(t, db)
	benchEntity(t, k, "listener", "x", listenerKey(8081), listenerAttrs(8081))
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	err := Run(db, broken, "", "", "", &bytes.Buffer{})
	if err == nil {
		t.Fatal("Run with empty-benchmark GT must fail")
	}
}

// A database without scans is a tool error too.
func TestBenchToolErrorEmptyDB(t *testing.T) {
	ctx := context.Background()
	empty := filepath.Join(t.TempDir(), "empty.db")
	st, err := store.Open(ctx, empty)
	if err != nil {
		t.Fatalf("open empty: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	gtPath := filepath.Join(t.TempDir(), "gt.yaml")
	gtYAML := `
listeners:
  - id: l1
    proto: tcp
    addr: "0.0.0.0"
    port: 8081
    expected_owner: {kind: container, name: lab-web}
route_chains:
  - id: c1
    location: /web/
    file: lab.conf
    simple: true
    expected: [{proto: tcp, port: 8081, owner: {kind: container, name: lab-web}}]
components:
  - id: container-lab-web
    kind: container
    ref: lab-web
    expected: ACTIVE
`
	if err := os.WriteFile(gtPath, []byte(gtYAML), 0o644); err != nil {
		t.Fatalf("write gt: %v", err)
	}
	err = Run(empty, gtPath, "", "", "", &bytes.Buffer{})
	if err == nil {
		t.Fatal("db without scans must fail")
	}
	if !strings.Contains(err.Error(), "no scans") {
		t.Errorf("err = %v, want no scans complaint", err)
	}
}

// LoadGT parses the real ground-truth shape written by the lab step.
func TestLoadGTValidFile(t *testing.T) {
	gtPath := filepath.Join(t.TempDir(), "gt.yaml")
	gtYAML := `
listeners:
  - id: listener-web-8081
    proto: tcp
    addr: "0.0.0.0"
    port: 8081
    expected_owner:
      kind: container
      name: lab-web
    reason: "docker publish"
route_chains:
  - id: chain-web
    location: "/web/"
    file: lab.conf
    simple: true
    expected:
      - proto: tcp
        port: 8081
        owner:
          kind: container
          name: lab-web
    reason: "static route"
components:
  - id: container-lab-web
    kind: container
    name: lab-web
    ref: lab-web
    expected: ACTIVE
  - id: cron-monthly
    kind: cron_job
    name: monthly
    ref: 'cron_job|/etc/cron.d/lab-monthly#root#/opt/lab/scripts/monthly-report.sh'
    expected: ACTIVE
    must_not_verdict: [LIKELY_ORPHANED, ORPHANED]
    trap: monthly_cron
traps:
  - monthly_cron
`
	if err := os.WriteFile(gtPath, []byte(gtYAML), 0o644); err != nil {
		t.Fatalf("write gt: %v", err)
	}
	gt, err := LoadGT(gtPath)
	if err != nil {
		t.Fatalf("load gt: %v", err)
	}
	if len(gt.Listeners) != 1 || gt.Listeners[0].Port != 8081 {
		t.Errorf("listeners = %+v", gt.Listeners)
	}
	if len(gt.RouteChains) != 1 || !gt.RouteChains[0].Simple {
		t.Errorf("route_chains = %+v", gt.RouteChains)
	}
	if len(gt.Components) != 2 || gt.Components[1].Trap != "monthly_cron" {
		t.Errorf("components = %+v", gt.Components)
	}
	if !strings.Contains(gt.Components[1].Ref, "lab-monthly") {
		t.Errorf("component ref not parsed: %+v", gt.Components[1])
	}
	if len(gt.Traps) != 1 || gt.Traps[0] != "monthly_cron" {
		t.Errorf("traps = %+v", gt.Traps)
	}
	if got := gt.findListener("tcp", "0.0.0.0", "8081"); got == nil || got.ID != "listener-web-8081" {
		t.Errorf("findListener = %+v", got)
	}
	if got := gt.findListener("tcp", "127.0.0.1", "6379"); got != nil {
		t.Errorf("findListener miss = %+v, want nil", got)
	}
}

// An empty denominator passes vacuously instead of dividing by zero.
func TestPercentEmptyDenominator(t *testing.T) {
	if got := percent(0, 0); got != 100.0 {
		t.Errorf("percent(0,0) = %.1f, want 100", got)
	}
	if got := percent(1, 4); got != 25.0 {
		t.Errorf("percent(1,4) = %.1f, want 25", got)
	}
}

// Integrity metrics on the golden fixture: raw_ref is 100%, the scan
// duration is derivable, and a missing sampler log yields n/a.
func TestMeasureIntegrityOnLabFixture(t *testing.T) {
	working, cleanup, err := copyDB(filepath.Join("..", "..", "lab", "fixtures", "scan.db"))
	if err != nil {
		t.Fatalf("copy fixture: %v", err)
	}
	defer cleanup()
	rep, err := MeasureIntegrity(working, "")
	if err != nil {
		t.Fatalf("integrity: %v", err)
	}
	if rep.RawRefTotal == 0 || rep.RawRefOK != rep.RawRefTotal || rep.RawRefPct != 100.0 {
		t.Errorf("raw_ref = %d/%d = %.1f%%, want full coverage",
			rep.RawRefOK, rep.RawRefTotal, rep.RawRefPct)
	}
	if rep.ScanSeconds == nil || *rep.ScanSeconds <= 0 {
		t.Errorf("ScanSeconds = %v, want positive duration", rep.ScanSeconds)
	}
	if !strings.Contains(rep.Observe, "n/a") {
		t.Errorf("Observe = %q, want n/a without sampler log", rep.Observe)
	}
	var buf bytes.Buffer
	if err := rep.Write(&buf); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !strings.Contains(buf.String(), "Evidence with raw_ref") ||
		!strings.Contains(buf.String(), "Overhead observe") {
		t.Errorf("integrity section incomplete:\n%s", buf.String())
	}
}

// A well-formed sampler log is parsed into CPU and RAM numbers.
func TestParseObserveLog(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "observe-sla.log")
	content := "" +
		"2026-10-07T20:00:00Z pid=100 utime=1000 stime=200 rss_kb=40960\n" +
		"2026-10-07T20:10:00Z pid=100 utime=1600 stime=260 rss_kb=51200\n"
	if err := os.WriteFile(logPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := parseObserveLog(logPath)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Δticks=660 → 6.6s CPU over 600s wall = 1.1%; max RSS 51200 KB.
	if !strings.Contains(got, "CPU 1.10%") || !strings.Contains(got, "51200 KB") ||
		!strings.Contains(got, "2 samples") {
		t.Errorf("summary = %q, want CPU 1.10%% · max RAM 51200 KB (2 samples)", got)
	}
}

// One JSONL line per run, parseable, carrying sha and metrics.
func TestAppendHistory(t *testing.T) {
	history := filepath.Join(t.TempDir(), "bench", "history.jsonl")
	rep := &Report{OwnedPct: 100, RoutesPct: 100}
	cp := &CheckpointReport{NonOrphanExpected: 19, LikelyTP: 0, LikelyFP: 0,
		OrphanExpected: 4, OrphanHits: 4}
	integ := &IntegrityReport{RawRefOK: 10, RawRefTotal: 10, RawRefPct: 100,
		Observe: "n/a"}
	for i := 0; i < 2; i++ {
		if err := AppendHistory(history, newHistoryRecord(rep, cp, integ)); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	data, err := os.ReadFile(history)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}
	var rec HistoryRecord
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rec.GeneratedAt == "" || rec.GitSHA == "" {
		t.Errorf("metadata missing: %+v", rec)
	}
	if rec.Metrics.OrphanRecall != 100.0 || rec.Metrics.RawRefPct != 100.0 ||
		rec.Metrics.OwnedPct != 100.0 || rec.Metrics.ScanSeconds != nil {
		t.Errorf("metrics wrong: %+v", rec.Metrics)
	}
	if rec.Gates.CheckpointFailed {
		t.Error("gate should pass on this data")
	}
	// Empty path is a no-op.
	if err := AppendHistory("", rec); err != nil {
		t.Errorf("empty path must be no-op: %v", err)
	}
}
