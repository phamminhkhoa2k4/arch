package cleanup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func systemdComp() Component {
	return Component{
		Kind: "systemd_unit", Name: "lab-legacy.service",
		IdentityKey: "systemd_unit|lab-legacy.service", Ref: "lab-legacy.service",
	}
}

func containerComp() Component {
	return Component{
		Kind: "container", Name: "lab-old-app",
		IdentityKey: "container|abc123", Ref: "lab-old-app",
		Attrs: map[string]string{
			"image":   "old/app:1.2",
			"volumes": "oldapp-data:/data, oldapp-cache:/cache",
		},
	}
}

func testRuntime() Runtime {
	return Runtime{
		DBPath:      "/tmp/arch-test/fixture.db",
		RulesPath:   "",
		RulesHash:   "ruleshash",
		BinaryPath:  "/usr/local/bin/archaeologist",
		ToolVersion: "v0.1.0",
		ScanID:      7,
	}
}

// A systemd unit plan carries the disable/enable rollback pair.
func TestBuildSystemdQuarantineRollback(t *testing.T) {
	p := Build(systemdComp(), testRuntime())
	if len(p.Stages) != 6 {
		t.Fatalf("stages = %d, want 6", len(p.Stages))
	}
	q := stageByName(t, p, "Quarantined")
	if !strings.Contains(q.Script, "systemctl disable --now 'lab-legacy.service'") {
		t.Errorf("quarantine script missing disable:\n%s", q.Script)
	}
	if !strings.Contains(q.Script, "# rollback: systemctl enable --now 'lab-legacy.service'") {
		t.Errorf("quarantine script missing rollback:\n%s", q.Script)
	}
	for _, st := range p.Stages {
		if st.Gate == "" || st.Action == "" || st.Confirmer == "" {
			t.Errorf("stage %s missing gate/action/confirmer", st.Name)
		}
		if !strings.Contains(st.Script, "# rollback:") &&
			st.Name != "Candidate" && st.Name != "Observed" && st.Name != "Archived" {
			t.Errorf("stage %s script must carry a rollback marker", st.Name)
		}
	}
}

// Stage scripts must pin the database they were generated from instead
// of assuming the default, so a plan built against one database cannot
// silently verify itself against another.
func TestScriptsPinRuntimePaths(t *testing.T) {
	rt := testRuntime()
	rt.RulesPath = "/etc/archaeologist/rules.yaml"
	p := Build(systemdComp(), rt)

	for _, name := range []string{"01-candidate.sh", "03-observed.sh", "06-verified.sh"} {
		st := stageByFile(t, p, name)
		if !strings.Contains(st.Script, "DB='/tmp/arch-test/fixture.db'") {
			t.Errorf("%s must pin the database path:\n%s", name, st.Script)
		}
		if !strings.Contains(st.Script, "ARCHAEOLOGIST='/usr/local/bin/archaeologist'") {
			t.Errorf("%s must pin the binary path:\n%s", name, st.Script)
		}
		if !strings.Contains(st.Script, "--rules-file '/etc/archaeologist/rules.yaml'") {
			t.Errorf("%s must pass the rules override it was generated with:\n%s", name, st.Script)
		}
	}
}

// With the embedded rules (no override) no --rules-file flag may appear,
// so a re-check keeps using the same defaults.
func TestScriptOmitsRulesFlagForEmbeddedRules(t *testing.T) {
	p := Build(systemdComp(), testRuntime())
	for _, name := range []string{"01-candidate.sh", "06-verified.sh"} {
		st := stageByFile(t, p, name)
		if strings.Contains(st.Script, "--rules-file") {
			t.Errorf("%s must not pass --rules-file when no override was used:\n%s", name, st.Script)
		}
	}
}

// The Verified stage must never swallow an execution error. It has to
// separate "the component is gone" from "the command could not run",
// and it must use the shared GoneSignal so both stay in sync.
func TestVerifiedScriptDistinguishesGoneFromError(t *testing.T) {
	p := Build(systemdComp(), testRuntime())
	st := stageByFile(t, p, "06-verified.sh")

	if strings.Contains(st.Script, "|| true") {
		t.Errorf("verified script must not swallow errors with `|| true`:\n%s", st.Script)
	}
	if !strings.Contains(st.Script, "grep -q '"+GoneSignal+"'") {
		t.Errorf("verified script must grep for the shared GoneSignal %q:\n%s", GoneSignal, st.Script)
	}
	for _, want := range []string{
		"exit 1",
		"could not run",
		"still resolves",
	} {
		if !strings.Contains(st.Script, want) {
			t.Errorf("verified script missing %q:\n%s", want, st.Script)
		}
	}
}

// A locally managed unit file may be removed by hand; a unit shipped by
// a package must be routed through the package manager instead.
func TestRemovedSystemdVendorUnitIsNotDeleted(t *testing.T) {
	vendor := systemdComp()
	vendor.Attrs = map[string]string{"fragment_path": "/usr/lib/systemd/system/legacy.service"}
	rm := stageByName(t, Build(vendor, testRuntime()), "Removed")

	if strings.Contains(rm.Script, "rm -f") {
		t.Errorf("vendor unit must not be deleted by hand:\n%s", rm.Script)
	}
	for _, want := range []string{"package manager", "apt-get remove", "dnf remove"} {
		if !strings.Contains(rm.Script, want) {
			t.Errorf("vendor unit script missing %q:\n%s", want, rm.Script)
		}
	}
}

func TestRemovedLocalUnitDeletesFragmentPath(t *testing.T) {
	local := systemdComp()
	local.Attrs = map[string]string{"fragment_path": "/etc/systemd/system/legacy.service"}
	rm := stageByName(t, Build(local, testRuntime()), "Removed")

	if !strings.Contains(rm.Script, "rm -f '/etc/systemd/system/legacy.service'") {
		t.Errorf("local unit script must delete its fragment path:\n%s", rm.Script)
	}
	if strings.Contains(rm.Script, "package manager") {
		t.Errorf("local unit must not defer to the package manager:\n%s", rm.Script)
	}
}

// Container removal prefers the immutable image ID over the mutable tag.
func TestContainerRemovedPrefersImageID(t *testing.T) {
	c := containerComp()
	c.Attrs["image_id"] = "sha256:deadbeef"
	rm := stageByName(t, Build(c, testRuntime()), "Removed")

	if !strings.Contains(rm.Script, "docker rmi 'sha256:deadbeef'") {
		t.Errorf("removed script must rmi by immutable image id:\n%s", rm.Script)
	}
}

// The container removal keeps container/image/volume separated with
// warnings and a commented-out volume removal.
func TestBuildContainerRemovedSections(t *testing.T) {
	p := Build(containerComp(), testRuntime())
	rm := stageByName(t, p, "Removed")
	for _, want := range []string{
		"docker rm 'lab-old-app'",
		"# --- image (separate — DO NOT merge with the container step) ---",
		"docker rmi 'old/app:1.2'",
		"# rollback: docker pull 'old/app:1.2'",
		"# --- volume (separate; only after your manual backup) ---",
		"# docker volume rm 'oldapp-data'",
		"# docker volume rm 'oldapp-cache'",
		"# Volume oldapp-data:/data may still hold data",
	} {
		if !strings.Contains(rm.Script, want) {
			t.Errorf("removed script missing %q:\n%s", want, rm.Script)
		}
	}
	if len(p.VolumeWarnings) != 2 {
		t.Errorf("volume warnings = %v, want 2", p.VolumeWarnings)
	}
	arch := stageByName(t, p, "Archived")
	if !strings.Contains(arch.Script, "archive-$(date") {
		t.Errorf("archive script must create timestamped dir:\n%s", arch.Script)
	}
	if !strings.Contains(arch.Script, "confirm your backup") {
		t.Errorf("archive script must warn about data volumes:\n%s", arch.Script)
	}
}

// A container without volumes produces no volume warning.
func TestBuildNoVolumesNoWarning(t *testing.T) {
	c := containerComp()
	c.Attrs = map[string]string{"image": "x:1"}
	p := Build(c, testRuntime())
	if len(p.VolumeWarnings) != 0 {
		t.Errorf("warnings = %v, want none", p.VolumeWarnings)
	}
}

// Cron jobs quarantine by renaming the file with a mv rollback.
func TestBuildCronQuarantine(t *testing.T) {
	c := Component{
		Kind: "cron_job", Name: "rotate", Ref: "rotate",
		Attrs: map[string]string{"file": "/etc/cron.d/rotate"},
	}
	p := Build(c, testRuntime())
	q := stageByName(t, p, "Quarantined")
	if !strings.Contains(q.Script, `mv '/etc/cron.d/rotate' '/etc/cron.d/rotate.disabled'`) {
		t.Errorf("cron quarantine missing mv:\n%s", q.Script)
	}
	if !strings.Contains(q.Script, "# rollback: mv") {
		t.Errorf("cron quarantine missing mv rollback:\n%s", q.Script)
	}
}

// A single quote in a host-derived path must not break out of its
// quoting context in a generated command.
func TestShellQuoteEscapesSingleQuote(t *testing.T) {
	c := Component{
		Kind: "cron_job", Name: "odd", Ref: "odd",
		Attrs: map[string]string{"file": "/etc/cron.d/it's-mine"},
	}
	q := stageByName(t, Build(c, testRuntime()), "Quarantined")
	if !strings.Contains(q.Script, `'/etc/cron.d/it'\''s-mine'`) {
		t.Errorf("cron path with a quote is not safely escaped:\n%s", q.Script)
	}
}

// The archive redirect must not place a host-derived name inside a
// double-quoted path, where a `$` or backtick would be expanded by the
// shell. It must concatenate a quoted directory with a quoted literal.
func TestArchiveFilenamesAreNotExpanded(t *testing.T) {
	c := systemdComp()
	c.Name = "weird$(id).service"
	c.Attrs = map[string]string{"fragment_path": "/etc/systemd/system/weird$(id).service"}
	arch := stageByName(t, Build(c, testRuntime()), "Archived")

	if strings.Contains(arch.Script, `"$ARCHIVE/weird$(id).service.txt"`) {
		t.Errorf("archive filename places a host value in an expandable context:\n%s", arch.Script)
	}
	if !strings.Contains(arch.Script, `"$ARCHIVE/"'weird$(id).service'.txt`) {
		t.Errorf("archive filename must quote the literal separately from the directory:\n%s", arch.Script)
	}
}

// Every generated script must have balanced double quotes, otherwise a
// stray quote swallows the rest of the line and silently changes what
// the script does.
func TestGeneratedScriptsHaveBalancedDoubleQuotes(t *testing.T) {
	comps := []Component{
		systemdComp(),
		containerComp(),
		{Name: "weird$(id).service", Kind: "systemd_unit", Ref: "x",
			Attrs: map[string]string{"fragment_path": "/etc/systemd/system/weird$(id).service"}},
		{Name: "c$(id)", Kind: "container", Ref: "c",
			Attrs: map[string]string{"image": "a/b:$(id)", "image_id": "sha256:1", "volumes": "d:/x"}},
		{Name: "j", Kind: "cron_job", Ref: "j",
			Attrs: map[string]string{"file": "/etc/cron.d/j"}},
		{Name: "/web/", Kind: "nginx_route", Ref: "/web/"},
	}
	for _, c := range comps {
		p := Build(c, testRuntime())
		for _, st := range p.Stages {
			if n := strings.Count(st.Script, `"`); n%2 != 0 {
				t.Errorf("%s (%s) has %d unbalanced double quotes:\n%s",
					ScriptFiles[st.Name], c.Kind, n, st.Script)
			}
		}
	}
}

// RenderMarkdown documents the stages, the provenance and the database
// the plan was built from.
func TestRenderMarkdown(t *testing.T) {
	p := Build(containerComp(), testRuntime())
	md := RenderMarkdown(p, Meta{
		VerdictState: "ORPHANED", Coverage: "HIGH",
		WindowLine:  "2026-10-01T00:00:00Z → 2026-10-10T00:00:00Z (9 days)",
		GeneratedAt: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC),
	})
	for _, want := range []string{
		"# Cleanup plan — lab-old-app (container)",
		"Verdict: **ORPHANED**",
		"## ⚠ Data volumes — manual backup required",
		"Gate condition",
		"06-verified.sh",
		"scan #7",
		"Evidence database: `/tmp/arch-test/fixture.db`",
		"--db '/tmp/arch-test/fixture.db'",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("plan.md missing %q:\n%s", want, md)
		}
	}
}

// WritePlan creates the markdown document, the six scripts and the
// provenance manifest, and never invokes any of them.
func TestWritePlanFiles(t *testing.T) {
	p := Build(systemdComp(), testRuntime())
	dir, files, err := WritePlan(t.TempDir(), p, Meta{
		VerdictState: "ORPHANED", Coverage: "HIGH", WindowLine: "d",
		GeneratedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("write plan: %v", err)
	}
	if len(files) != 8 {
		t.Errorf("files = %d, want 8 (plan.md + 6 scripts + %s)", len(files), ManifestFile)
	}
	if filepath.Base(dir) != "systemd_unit-lab-legacy-service" {
		t.Errorf("slug dir = %s", filepath.Base(dir))
	}
	body, err := os.ReadFile(filepath.Join(dir, "02-quarantined.sh"))
	if err != nil {
		t.Fatalf("read quarantine: %v", err)
	}
	if !strings.HasPrefix(string(body), "#!/usr/bin/env bash") {
		t.Error("script must be a bash script")
	}
	if _, err := os.Stat(filepath.Join(dir, ManifestFile)); err != nil {
		t.Errorf("manifest must be written: %v", err)
	}
}

// Slug sanitizes kind+name into a filesystem-safe directory name.
func TestSlug(t *testing.T) {
	cases := map[string]string{
		"systemd_unit-lab-legacy-service": Slug("systemd_unit", "lab-legacy.service"),
		"nginx_route-web":                 Slug("nginx_route", "/web/"),
		"container-lab-api":               Slug("container", "lab-api"),
	}
	for want, got := range cases {
		if got != want {
			t.Errorf("Slug = %q, want %q", got, want)
		}
	}
}

func stageByName(t *testing.T, p Plan, name string) Stage {
	t.Helper()
	for _, st := range p.Stages {
		if st.Name == name {
			return st
		}
	}
	t.Fatalf("stage %s not found", name)
	return Stage{}
}

func stageByFile(t *testing.T, p Plan, file string) Stage {
	t.Helper()
	for _, st := range p.Stages {
		if ScriptFiles[st.Name] == file {
			return st
		}
	}
	t.Fatalf("script %s not found", file)
	return Stage{}
}
