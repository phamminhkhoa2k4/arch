package cleanup

import (
	"strings"
	"testing"
)

// Every validator is an allowlist: a name must match, so the tests
// cover both a legal name that must pass and the hostile shapes that
// must be refused.

func TestValidUnitName(t *testing.T) {
	good := []string{
		"lab-legacy.service",
		"app@1.service", // template instance
		"nginx.timer",
		"a",
		"my_unit:v2",
	}
	for _, name := range good {
		if ok, reason := validUnitName(name); !ok {
			t.Errorf("validUnitName(%q) = false, want true (%s)", name, reason)
		}
	}

	bad := map[string]string{
		"":                      "empty",
		"bad name.service":      "space",
		"../../etc/passwd":      "parent dir",
		"/etc/passwd":           "path separator",
		"-dash.service":         "leading dash",
		"x$(id).service":        "shell metacharacter",
		"x`id`.service":         "backtick",
		"x\ny.service":          "newline",
		strings.Repeat("a", 257): "over length",
	}
	for name := range bad {
		if ok, reason := validUnitName(name); ok {
			t.Errorf("validUnitName(%q) = true, want false", name)
		} else if strings.TrimSpace(reason) == "" {
			t.Errorf("validUnitName(%q) refused without a reason", name)
		}
	}
}

func TestValidContainerName(t *testing.T) {
	good := []string{"lab-old-app", "a", "x_1.2", "A9"}
	for _, name := range good {
		if ok, reason := validContainerName(name); !ok {
			t.Errorf("validContainerName(%q) = false, want true (%s)", name, reason)
		}
	}

	bad := []string{
		"", "-leading-dash", "has space", "x$(id)", "x/y", "..",
		".leading-dot", strings.Repeat("a", 256),
	}
	for _, name := range bad {
		if ok, _ := validContainerName(name); ok {
			t.Errorf("validContainerName(%q) = true, want false", name)
		}
	}
}

func TestValidCronPath(t *testing.T) {
	good := []string{"/etc/cron.d/rotate", "/etc/crontab", "/a"}
	for _, p := range good {
		if ok, reason := validCronPath(p); !ok {
			t.Errorf("validCronPath(%q) = false, want true (%s)", p, reason)
		}
	}

	bad := []string{
		"", "relative/path", "/../etc/passwd", "/a\nb", "/a\rb",
	}
	for _, p := range bad {
		if ok, _ := validCronPath(p); ok {
			t.Errorf("validCronPath(%q) = true, want false", p)
		}
	}
}

func TestValidRouteLocation(t *testing.T) {
	good := []string{"/", "/web/", "/api/v1/things"}
	for _, loc := range good {
		if ok, reason := validRouteLocation(loc); !ok {
			t.Errorf("validRouteLocation(%q) = false, want true (%s)", loc, reason)
		}
	}

	// Regex, exact-match and prefixed-match locations all change how the
	// location line is written, so a generated text edit cannot be
	// trusted to match the real block.
	bad := []string{
		"", "~^/api", "= /exact", "^~ /prefixed", "no-slash", "/a\nb",
	}
	for _, loc := range bad {
		if ok, _ := validRouteLocation(loc); ok {
			t.Errorf("validRouteLocation(%q) = true, want false", loc)
		}
	}
}

func TestSafePath(t *testing.T) {
	if ok, _ := safePath("/etc/systemd/system/x.service"); !ok {
		t.Error("an absolute path must be safe")
	}
	for _, p := range []string{"", "relative", "/a/../b", "/a\nb"} {
		if ok, _ := safePath(p); ok {
			t.Errorf("safePath(%q) = true, want false", p)
		}
	}
}

// A name outside the allowlist still produces a full plan — the operator
// keeps the gates, the confirmer and the provenance — but the mutating
// stages carry no command, so nothing in them can name the wrong target.
func TestInvalidUnitNameDropsMutatingCommands(t *testing.T) {
	c := systemdComp()
	c.Name = "bad name.service"
	c.Ref = c.Name
	p := Build(c, testRuntime())

	if len(p.Stages) != 6 {
		t.Fatalf("stages = %d, want 6 — the plan must still be generated", len(p.Stages))
	}
	for _, stage := range []string{"Quarantined", "Removed"} {
		s := stageByName(t, p, stage)
		if !strings.Contains(s.Script, "SKIPPED") {
			t.Errorf("%s must say the name was skipped:\n%s", stage, s.Script)
		}
		if strings.Contains(s.Script, "systemctl disable --now") ||
			strings.Contains(s.Script, "systemctl enable --now") ||
			strings.Contains(s.Script, "rm -f") {
			t.Errorf("%s must emit no command for an invalid name:\n%s", stage, s.Script)
		}
		if s.Action == "" || s.Gate == "" || s.Confirmer == "" {
			t.Errorf("%s must keep its action, gate and confirmer", stage)
		}
	}
}

// A regex nginx location cannot be matched by a generated text edit, so
// the route stays manual instead of being edited by a pattern that would
// not match the real block.
func TestRegexLocationIsNotAutoEdited(t *testing.T) {
	c := Component{Kind: "nginx_route", Name: "~^/api", Ref: "~^/api"}
	p := Build(c, testRuntime())

	q := stageByName(t, p, "Quarantined")
	if !strings.Contains(q.Script, "SKIPPED") {
		t.Errorf("a regex location must be skipped:\n%s", q.Script)
	}
	if strings.Contains(q.Script, "sed") {
		t.Errorf("a regex location must not get a sed edit:\n%s", q.Script)
	}
}

// A plain prefix location keeps the generated edit, so the allowlist is
// not so tight that ordinary routes are pushed to manual.
func TestValidNamesKeepCommands(t *testing.T) {
	cases := []struct {
		comp    Component
		stage   string
		contains string
		notContains string
	}{
		{systemdComp(), "Quarantined", "systemctl disable --now 'lab-legacy.service'", "SKIPPED"},
		{containerComp(), "Quarantined", "docker stop 'lab-old-app'", "SKIPPED"},
		{Component{Kind: "cron_job", Name: "rotate", Ref: "rotate",
			Attrs: map[string]string{"file": "/etc/cron.d/rotate"}},
			"Quarantined", "mv '/etc/cron.d/rotate'", "SKIPPED"},
		{Component{Kind: "nginx_route", Name: "/web/", Ref: "/web/"},
			"Quarantined", "nginx -t && systemctl reload nginx", "SKIPPED"},
	}
	for _, tc := range cases {
		s := stageByName(t, Build(tc.comp, testRuntime()), tc.stage)
		if !strings.Contains(s.Script, tc.contains) {
			t.Errorf("kind %s missing %q:\n%s", tc.comp.Kind, tc.contains, s.Script)
		}
		if strings.Contains(s.Script, tc.notContains) {
			t.Errorf("kind %s must not be skipped:\n%s", tc.comp.Kind, s.Script)
		}
	}
}

// A timer is a legal unit name and must not be pushed to manual, so the
// allowlist does not reject the template-instance and suffix shapes
// systemd really produces.
func TestTimerAndInstanceNamesAreAccepted(t *testing.T) {
	timer := Component{Kind: "timer", Name: "lab-rotate.timer", Ref: "lab-rotate.timer"}
	q := stageByName(t, Build(timer, testRuntime()), "Quarantined")
	if !strings.Contains(q.Script, "systemctl disable --now 'lab-rotate.timer'") {
		t.Errorf("a timer name must keep its command:\n%s", q.Script)
	}

	instance := Component{Kind: "systemd_unit", Name: "app@1.service", Ref: "app@1.service"}
	q2 := stageByName(t, Build(instance, testRuntime()), "Quarantined")
	if !strings.Contains(q2.Script, "systemctl disable --now 'app@1.service'") {
		t.Errorf("a template instance name must keep its command:\n%s", q2.Script)
	}
}

// The archived file for a unit whose name is outside the allowlist is
// still written, just under a stage-named file so the hostile name never
// reaches the destination path.
func TestArchiveFallsBackWhenNameInvalid(t *testing.T) {
	c := containerComp()
	c.Name = "bad container"
	c.Ref = c.Name
	arch := stageByName(t, Build(c, testRuntime()), "Archived")

	if !strings.Contains(arch.Script, `"$ARCHIVE/"'inspect-container'.json`) {
		t.Errorf("archive must fall back to a stage-named file:\n%s", arch.Script)
	}
	if strings.Contains(arch.Script, `'inspect-bad container'`) {
		t.Errorf("archive must not carry the invalid name in its destination:\n%s", arch.Script)
	}
	// The read-only inspect command itself still runs: it is quoted, and
	// it is the only way to recover the artifact.
	if !strings.Contains(arch.Script, "docker inspect 'bad container'") {
		t.Errorf("archive must still run the read-only inspect:\n%s", arch.Script)
	}
}

// An empty fragment path must not be reported as owned by a package —
// there is simply nothing to name.
func TestRemovedWithoutFragmentPathIsManual(t *testing.T) {
	c := systemdComp() // no fragment_path attribute
	rm := stageByName(t, Build(c, testRuntime()), "Removed")

	if !strings.Contains(rm.Script, "No fragment path was recorded") {
		t.Errorf("an empty fragment path needs its own guidance:\n%s", rm.Script)
	}
	if strings.Contains(rm.Script, "rm -f") {
		t.Errorf("an empty fragment path must not produce a delete command:\n%s", rm.Script)
	}
}

// A fragment path that is not absolute, or that walks the parent
// directory, must not reach an rm -f even when it sits under /etc.
func TestRemovedRejectsUnsafeFragmentPath(t *testing.T) {
	c := systemdComp()
	c.Attrs = map[string]string{"fragment_path": "/etc/systemd/system/../../../bin/sh"}
	rm := stageByName(t, Build(c, testRuntime()), "Removed")

	if strings.Contains(rm.Script, "rm -f") {
		t.Errorf("a fragment path with '..' must not be deleted:\n%s", rm.Script)
	}
	if !strings.Contains(rm.Script, "SKIPPED") {
		t.Errorf("an unsafe fragment path must be reported:\n%s", rm.Script)
	}
}

// A cron file outside the allowlist must not be archived by an automated
// copy either: a path that cannot be named safely cannot be backed up
// safely, and the Removed stage would delete it.
func TestCronArchiveRejectsUnsafePath(t *testing.T) {
	c := Component{Kind: "cron_job", Name: "j", Ref: "j",
		Attrs: map[string]string{"file": "../../etc/crontab"}}
	p := Build(c, testRuntime())

	arch := stageByName(t, p, "Archived")
	if !strings.Contains(arch.Script, "SKIPPED") {
		t.Errorf("an unsafe cron path must be skipped at Archived:\n%s", arch.Script)
	}
	if strings.Contains(arch.Script, "cp ../../etc/crontab") {
		t.Errorf("an unsafe cron path must not be copied:\n%s", arch.Script)
	}
	rm := stageByName(t, p, "Removed")
	if !strings.Contains(rm.Script, "SKIPPED") {
		t.Errorf("an unsafe cron path must be skipped at Removed:\n%s", rm.Script)
	}
}
