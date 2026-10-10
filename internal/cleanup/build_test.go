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

// A systemd unit plan carries the disable/enable rollback pair.
func TestBuildSystemdQuarantineRollback(t *testing.T) {
	p := Build(systemdComp())
	if len(p.Stages) != 6 {
		t.Fatalf("stages = %d, want 6", len(p.Stages))
	}
	q := stageByName(t, p, "Quarantined")
	if !strings.Contains(q.Script, "systemctl disable --now lab-legacy.service") {
		t.Errorf("quarantine script missing disable:\n%s", q.Script)
	}
	if !strings.Contains(q.Script, "# rollback: systemctl enable --now lab-legacy.service") {
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

// Container removal splits container/image/volume into separate
// sections, each with its own rollback; data volumes are warned and
// the rm stays commented until a manual backup.
func TestBuildContainerRemovedSections(t *testing.T) {
	p := Build(containerComp())
	rm := stageByName(t, p, "Removed")
	for _, want := range []string{
		"docker rm lab-old-app",
		"# --- image (riêng biệt, KHÔNG gộp với container) ---",
		"docker rmi old/app:1.2",
		"# rollback: docker pull old/app:1.2",
		"# --- volume (riêng biệt; chỉ khi đã backup tay) ---",
		"# docker volume rm oldapp-data",
		"# docker volume rm oldapp-cache",
		"# Volume oldapp-data:/data có thể còn dữ liệu",
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
	if !strings.Contains(arch.Script, "xác nhận đã backup") {
		t.Errorf("archive script must warn about data volumes:\n%s", arch.Script)
	}
}

// A container without volumes produces no volume warning.
func TestBuildNoVolumesNoWarning(t *testing.T) {
	c := containerComp()
	c.Attrs = map[string]string{"image": "x:1"}
	p := Build(c)
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
	p := Build(c)
	q := stageByName(t, p, "Quarantined")
	if !strings.Contains(q.Script, `mv "/etc/cron.d/rotate" "/etc/cron.d/rotate.disabled"`) {
		t.Errorf("cron quarantine missing mv:\n%s", q.Script)
	}
	if !strings.Contains(q.Script, "# rollback: mv") {
		t.Errorf("cron quarantine missing mv rollback:\n%s", q.Script)
	}
}

// RenderMarkdown documents the six stages with their gates.
func TestRenderMarkdown(t *testing.T) {
	p := Build(containerComp())
	md := RenderMarkdown(p, Meta{
		VerdictState: "ORPHANED", Coverage: "HIGH",
		WindowLine:  "2026-10-01T00:00:00Z → 2026-10-10T00:00:00Z (9 ngày)",
		GeneratedAt: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC),
	})
	for _, want := range []string{
		"# Kế hoạch dọn dẹp — lab-old-app (container)",
		"Verdict: **ORPHANED**",
		"## ⚠ Volume dữ liệu — bắt buộc backup tay",
		"Điều kiện qua cổng (gate)",
		"06-verified.sh",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("plan.md missing %q", want)
		}
	}
}

// WritePlan creates the plan dir with the markdown plan document plus six executable
// scripts and never invokes any of them.
func TestWritePlanFiles(t *testing.T) {
	p := Build(systemdComp())
	dir, files, err := WritePlan(t.TempDir(), p, Meta{
		VerdictState: "ORPHANED", Coverage: "HIGH", WindowLine: "d",
		GeneratedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("write plan: %v", err)
	}
	if len(files) != 7 {
		t.Errorf("files = %d, want 7 (plan.md + 6 scripts)", len(files))
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
}

// Slug sanitizes kind+name into a safe directory name.
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
