package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustWrite(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "custom.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDefaultLoadsEmbedded(t *testing.T) {
	r, hash, err := Default()
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	if hash == "" || len(hash) != 64 {
		t.Fatalf("hash = %q, want 64 hex chars", hash)
	}
	if r.Thresholds.ObservationWindowDays != 14 ||
		r.Thresholds.NoDeployDays != 90 ||
		r.Thresholds.NoActivityDays != 30 {
		t.Errorf("thresholds = %+v", r.Thresholds)
	}
	if r.Verdicts.Fallback != "UNKNOWN" {
		t.Errorf("fallback = %q", r.Verdicts.Fallback)
	}
	if got := []string(r.Verdicts.LikelyOrphanedRequires.Coverage); len(got) != 2 || got[0] != "HIGH" || got[1] != "MEDIUM" {
		t.Errorf("likely coverage = %v", got)
	}
	if !r.Verdicts.OrphanedRequires.WindowSufficient {
		t.Error("orphaned_requires.window_sufficient must be true")
	}
	if r.Coverage.HighRatio != 0.90 || r.Coverage.MediumRatio != 0.60 {
		t.Errorf("ratios = %v/%v", r.Coverage.HighRatio, r.Coverage.MediumRatio)
	}
	want := map[string]bool{"listener": true, "systemd_unit": true, "container": true,
		"cron_job": true, "script": true, "nginx_route": true, "nginx_upstream": true}
	for kind := range want {
		if _, ok := r.Coverage.Channels[kind]; !ok {
			t.Errorf("coverage.channels missing %q", kind)
		}
	}
}

func TestLoadScalarCoverageAndHashStability(t *testing.T) {
	content := `thresholds:
  observation_window_days: 0
  no_deploy_days: 10
  no_activity_days: 5
verdicts:
  likely_orphaned_requires: { coverage: HIGH, blockers: none }
  orphaned_requires: { coverage: [HIGH], blockers: none, window_sufficient: true }
  fallback: UNKNOWN
coverage:
  high_ratio: 0.5
  medium_ratio: 0.25
  channels:
    cron_job: [cron]
`
	path := mustWrite(t, content)
	r, hash1, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := []string(r.Verdicts.LikelyOrphanedRequires.Coverage); len(got) != 1 || got[0] != "HIGH" {
		t.Errorf("scalar coverage = %v", got)
	}
	_, hash2, err := Load(path)
	if err != nil || hash1 != hash2 {
		t.Errorf("hash not stable: %v vs %v (%v)", hash1, hash2, err)
	}
	def, defHash, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if hash1 == defHash {
		t.Error("custom rules must not hash like embedded defaults")
	}
	if def.Thresholds.ObservationWindowDays != 14 {
		t.Error("Default() mutated")
	}
}

func TestLoadSyntaxErrorHasFileLine(t *testing.T) {
	path := mustWrite(t, "thresholds:\n  no_activity_days: [broken\n")
	_, _, err := Load(path)
	if err == nil {
		t.Fatal("want error for broken YAML")
	}
	if !strings.Contains(err.Error(), path+":") {
		t.Errorf("error %q must start with file path", err)
	}
	if !strings.Contains(err.Error(), ":2") && !strings.Contains(err.Error(), ":3") {
		t.Errorf("error %q must carry a line number", err)
	}
}

func TestLoadUnknownFieldHasFileLine(t *testing.T) {
	path := mustWrite(t, `thresholds:
  nonsense: 5
`)
	_, _, err := Load(path)
	if err == nil {
		t.Fatal("want error for unknown field")
	}
	msg := err.Error()
	if !strings.Contains(msg, path+":2") {
		t.Errorf("error %q must point at file:line", msg)
	}
	if !strings.Contains(msg, "not found") {
		t.Errorf("error %q must name the unknown field problem", msg)
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	base := func(fallback, high, med, channels string) string {
		return `thresholds:
  observation_window_days: 14
  no_deploy_days: 90
  no_activity_days: 30
verdicts:
  likely_orphaned_requires: { coverage: [HIGH], blockers: none }
  orphaned_requires: { coverage: [HIGH], blockers: none, window_sufficient: false }
  fallback: ` + fallback + `
coverage:
  high_ratio: ` + high + `
  medium_ratio: ` + med + `
  channels:
` + channels
	}
	cases := []struct {
		name, content, want string
	}{
		{"bad fallback", base("MAYBE", "0.9", "0.6", "    cron_job: [cron]\n"), "unknown state"},
		{"bad level", base("UNKNOWN", "0.9", "0.6", "    cron_job: [cron]\n"), ""},
		{"medium above high", base("UNKNOWN", "0.4", "0.6", "    cron_job: [cron]\n"), "medium_ratio"},
		{"empty channels", base("UNKNOWN", "0.9", "0.6", ""), "channels"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// "bad level" exercises coverage level validation via requirement.
			content := tc.content
			if tc.name == "bad level" {
				content = strings.Replace(content, "coverage: [HIGH]", "coverage: [MAX]", 1)
			}
			_, _, err := Load(mustWrite(t, content))
			if err == nil {
				t.Fatal("want validation error")
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q must contain %q", err, tc.want)
			}
		})
	}
}
