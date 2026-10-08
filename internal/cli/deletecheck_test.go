package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"archaeologist/internal/collector"
	"archaeologist/internal/store"
)

// seedUnitPair stores two active units with evidence and a
// deterministic depends_on edge from app → db (B3 blocker on db).
func seedUnitPair(t *testing.T, st *store.Store, scanID int64) {
	t.Helper()
	ctx := context.Background()
	k := store.NewScanSink(ctx, st, scanID)
	units := []struct {
		key, name, evRef string
	}{
		{"unit|app.service", "app.service", "dep-app"},
		{"unit|db.service", "db.service", "dep-db"},
	}
	for _, u := range units {
		if err := k.UpsertEntity(collector.Entity{
			Kind:        "systemd_unit",
			Name:        u.name,
			IdentityKey: u.key,
			Fingerprint: "f",
			Attributes:  map[string]string{"active_state": "active", "file_state": "enabled"},
		}); err != nil {
			t.Fatalf("upsert %s: %v", u.key, err)
		}
		if err := k.AddEvidence(collector.Evidence{
			EntityIdentityKey: u.key,
			Polarity:          collector.PolarityNeutral,
			Channel:           "systemd",
			Strength:          collector.StrengthDeterministic,
			ObservedAt:        "2026-10-08T00:00:00Z",
			RawRef:            "unit:" + u.name + ":1",
			Value:             map[string]string{"active_state": "active"},
			Ref:               u.evRef,
		}); err != nil {
			t.Fatalf("evidence %s: %v", u.key, err)
		}
	}
	if err := k.UpsertEdge(collector.Edge{
		SrcIdentityKey: "unit|app.service",
		DstIdentityKey: "unit|db.service",
		Kind:           "depends_on",
		Strength:       collector.StrengthDeterministic,
		EvidenceRef:    "dep-app",
	}); err != nil {
		t.Fatalf("edge: %v", err)
	}
}

// seedComposeService stores one compose service with docker evidence
// (1/1 coverage candidate for orphan verdicts).
func seedComposeService(t *testing.T, st *store.Store, scanID int64, key, name string) {
	t.Helper()
	ctx := context.Background()
	k := store.NewScanSink(ctx, st, scanID)
	if err := k.UpsertEntity(collector.Entity{
		Kind:        "compose_service",
		Name:        name,
		IdentityKey: key,
		Fingerprint: "f",
		Attributes:  map[string]string{"project": "lab"},
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := k.AddEvidence(collector.Evidence{
		EntityIdentityKey: key,
		Polarity:          collector.PolarityInUse,
		Channel:           "docker",
		Strength:          collector.StrengthDeterministic,
		ObservedAt:        "2026-10-08T00:00:00Z",
		RawRef:            "docker:inspect:" + name,
		Value:             map[string]string{"state": "running"},
	}); err != nil {
		t.Fatalf("evidence: %v", err)
	}
}

// requireSectionOrder asserts every section header appears, in the
// fixed relative order.
func requireSectionOrder(t *testing.T, out string, sections ...string) {
	t.Helper()
	prev := -1
	prevName := ""
	for _, s := range sections {
		i := strings.Index(out, s)
		if i < 0 {
			t.Errorf("missing section %q in output:\n%s", s, out)
			continue
		}
		if i < prev {
			t.Errorf("section %q appears before %q — order violated:\n%s", s, prevName, out)
		}
		prev, prevName = i, s
	}
}

func requireCleanVerdictText(t *testing.T, out string) {
	t.Helper()
	if strings.Contains(out, "%") {
		t.Errorf("output leaks a percentage:\n%s", out)
	}
	if strings.Contains(strings.ToLower(out), "confidence") {
		t.Errorf("output leaks the word confidence:\n%s", out)
	}
}

// The ACTIVE verdict prints blockers first with an evidence trace, in
// the fixed section order, and never a percentage.
func TestDeleteCheckActiveBlockerTracesEvidence(t *testing.T) {
	db := filepath.Join(t.TempDir(), "dc.db")
	st, scanID := seedExplain(t, db)
	seedUnitPair(t, st, scanID)
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	out, err := runExplainCmd(t, "delete-check", "db.service", "--db", db)
	if err != nil {
		t.Fatalf("delete-check: %v", err)
	}
	requireSectionOrder(t, out,
		"Trạng thái:", "Cửa sổ quan sát:", "Evidence coverage:",
		"⛔ Blockers:", "⚠ Tín hiệu không-dùng:", "? Vùng mù:", "Hành động gợi ý:")
	requireCleanVerdictText(t, out)

	for _, want := range []string{
		"Trạng thái: ACTIVE",
		"B3",
		"depends_on",
		"⛔ KHÔNG an toàn để xóa",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "unit:app.service:1") {
		t.Errorf("blocker line must carry the raw_ref:\n%s", out)
	}

	// End-to-end: the evidence id printed in the trace exists in the DB.
	re := regexp.MustCompile(`evidence #(\d+)`)
	m := re.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no evidence trace in output:\n%s", out)
	}
	ctx := context.Background()
	st2, err := store.Open(ctx, db)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = st2.Close() }()
	scan2, err := st2.LatestScanID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ents, err := st2.FindEntities(ctx, scan2, "unit|app.service")
	if err != nil || len(ents) != 1 {
		t.Fatalf("find app.service: %v (%d)", err, len(ents))
	}
	rows, err := st2.EvidenceFor(ctx, ents[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	want := m[1]
	for _, r := range rows {
		if strconv.FormatInt(r.ID, 10) == want {
			found = true
		}
	}
	if !found {
		t.Errorf("evidence #%s not found for the traced entity", want)
	}
}

// The ORPHANED verdict lists every reason on its own line before the
// action line.
func TestDeleteCheckOrphanedListsFullReasons(t *testing.T) {
	db := filepath.Join(t.TempDir(), "dc.db")
	st, scanID := seedExplain(t, db)
	seedComposeService(t, st, scanID, "compose_service|lab#legacy-api", "legacy-api")
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	rulesPath := writeRules(t, `
thresholds: { observation_window_days: 0, no_deploy_days: 90, no_activity_days: 30 }
verdicts:
  likely_orphaned_requires: { coverage: [HIGH, MEDIUM], blockers: none }
  orphaned_requires: { coverage: [HIGH], blockers: none, window_sufficient: true }
  fallback: UNKNOWN
coverage:
  high_ratio: 0.90
  medium_ratio: 0.60
  channels:
    compose_service: [docker]
`)

	out, err := runExplainCmd(t, "delete-check", "legacy-api", "--db", db, "--rules-file", rulesPath)
	if err != nil {
		t.Fatalf("delete-check: %v", err)
	}
	requireSectionOrder(t, out,
		"Trạng thái:", "Cửa sổ quan sát:", "Evidence coverage:",
		"⛔ Blockers:", "⚠ Tín hiệu không-dùng:", "? Vùng mù:",
		"Lý do:", "Hành động gợi ý:")
	requireCleanVerdictText(t, out)

	for _, want := range []string{
		"Trạng thái: ORPHANED",
		"Evidence coverage: HIGH — thiếu: (không)",
		"⛔ Blockers: (không có)",
		"⚠ Tín hiệu không-dùng: (không có)",
		"? Vùng mù: (không có)",
		"không có blocker cứng nào",
		"cửa sổ quan sát",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	// Every reason is its own bullet line (three here: blockers,
	// window, coverage).
	if got := strings.Count(out, "\n  - "); got < 3 {
		t.Errorf("orphan verdict must list reasons on separate lines (got %d):\n%s", got, out)
	}
	if !strings.Contains(out, `archaeologist plan <component>`) {
		t.Errorf("action must point at plan:\n%s", out)
	}
}

// Changing the rules file changes the verdict on the same stored
// evidence — no rescan — and the stored row records the new hash.
func TestDeleteCheckRulesFileChangesVerdictWithoutRescan(t *testing.T) {
	db := filepath.Join(t.TempDir(), "dc.db")
	st, scanID := seedExplain(t, db)
	seedComposeService(t, st, scanID, "compose_service|lab#legacy-api", "legacy-api")
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	rulesA := writeRules(t, `
thresholds: { observation_window_days: 0, no_deploy_days: 90, no_activity_days: 30 }
verdicts:
  likely_orphaned_requires: { coverage: [HIGH, MEDIUM], blockers: none }
  orphaned_requires: { coverage: [HIGH], blockers: none, window_sufficient: true }
  fallback: UNKNOWN
coverage:
  high_ratio: 0.90
  medium_ratio: 0.60
  channels:
    compose_service: [docker]
`)
	rulesB := writeRules(t, `
thresholds: { observation_window_days: 0, no_deploy_days: 90, no_activity_days: 30 }
verdicts:
  likely_orphaned_requires: { coverage: [HIGH, MEDIUM], blockers: none }
  orphaned_requires: { coverage: [HIGH], blockers: none, window_sufficient: true }
  fallback: UNKNOWN
coverage:
  high_ratio: 0.90
  medium_ratio: 0.60
  channels:
    compose_service: [docker, docker_log]
`)

	outA, err := runExplainCmd(t, "delete-check", "legacy-api", "--db", db, "--rules-file", rulesA)
	if err != nil {
		t.Fatalf("delete-check A: %v", err)
	}
	if !strings.Contains(outA, "Trạng thái: ORPHANED") {
		t.Errorf("rules A must yield ORPHANED:\n%s", outA)
	}

	outB, err := runExplainCmd(t, "delete-check", "legacy-api", "--db", db, "--rules-file", rulesB)
	if err != nil {
		t.Fatalf("delete-check B: %v", err)
	}
	for _, want := range []string{"Trạng thái: UNKNOWN", "Evidence coverage: LOW", "thiếu: docker_log"} {
		if !strings.Contains(outB, want) {
			t.Errorf("rules B output missing %q:\n%s", want, outB)
		}
	}

	// The persisted verdict records the hash of the last rules file.
	raw, err := os.ReadFile(rulesB)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	ctx := context.Background()
	st2, err := store.Open(ctx, db)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = st2.Close() }()
	scan2, err := st2.LatestScanID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ents, err := st2.FindEntities(ctx, scan2, "compose_service|lab#legacy-api")
	if err != nil || len(ents) != 1 {
		t.Fatalf("find: %v (%d)", err, len(ents))
	}
	rec, err := st2.VerdictFor(ctx, ents[0].ID, scan2)
	if err != nil {
		t.Fatalf("VerdictFor: %v", err)
	}
	if rec.RulesHash != hex.EncodeToString(sum[:]) {
		t.Errorf("rules_hash = %s, want sha256 of rules B", rec.RulesHash)
	}
	if rec.State != "UNKNOWN" {
		t.Errorf("stored state = %s, want UNKNOWN", rec.State)
	}
}

// A broken rules file fails loudly with path:line — no silent default.
func TestDeleteCheckBadRulesFileReportsPathLine(t *testing.T) {
	db := filepath.Join(t.TempDir(), "dc.db")
	st, scanID := seedExplain(t, db)
	seedComposeService(t, st, scanID, "compose_service|lab#legacy-api", "legacy-api")
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	rulesPath := writeRules(t, `
thresholds:
  observation_window_days: 14
  bogus_field: 1
verdicts:
  likely_orphaned_requires: { coverage: [HIGH, MEDIUM], blockers: none }
  orphaned_requires: { coverage: [HIGH], blockers: none, window_sufficient: true }
  fallback: UNKNOWN
coverage:
  high_ratio: 0.90
  medium_ratio: 0.60
  channels:
    compose_service: [docker]
`)

	_, err := runExplainCmd(t, "delete-check", "legacy-api", "--db", db, "--rules-file", rulesPath)
	if err == nil {
		t.Fatal("invalid rules file must fail")
	}
	if !strings.Contains(err.Error(), rulesPath+":3:") {
		t.Errorf("err must be path:line: %v", err)
	}
}

// Unknown and ambiguous references fail the same way explain does.
func TestDeleteCheckReferenceErrors(t *testing.T) {
	db := filepath.Join(t.TempDir(), "dc.db")
	st, scanID := seedExplain(t, db)
	seedRoute(t, st, scanID, "nginx_route|a.conf#8080#_#/web/", "/web/")
	seedRoute(t, st, scanID, "nginx_route|b.conf#8080#_#/web/", "/web/")
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := runExplainCmd(t, "delete-check", "no-such", "--db", db); err == nil ||
		!strings.Contains(err.Error(), "không tìm thấy") {
		t.Errorf("unknown ref err = %v", err)
	}
	_, err := runExplainCmd(t, "delete-check", "/web/", "--db", db)
	if err == nil || !strings.Contains(err.Error(), "identity_key") {
		t.Errorf("ambiguous ref err = %v", err)
	}
}

func writeRules(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimPrefix(content, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
