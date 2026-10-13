package cleanup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// WritePlan renders the plan into outDir/<slug>/: one markdown plan
// document plus the six numbered stage scripts. It only writes files — no command in any
// script is ever executed here. Returns the plan directory and
// every file created.
func WritePlan(outDir string, p Plan, meta Meta) (string, []string, error) {
	slug := Slug(p.Component.Kind, p.Component.Name)
	dir := filepath.Join(outDir, slug)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", nil, fmt.Errorf("create plan dir: %w", err)
	}
	var files []string

	md := filepath.Join(dir, "plan.md")
	if err := os.WriteFile(md, []byte(RenderMarkdown(p, meta)), 0o644); err != nil {
		return dir, files, fmt.Errorf("write plan.md: %w", err)
	}
	files = append(files, md)

	for _, st := range p.Stages {
		name := ScriptFiles[st.Name]
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(st.Script), 0o755); err != nil {
			return dir, files, fmt.Errorf("write %s: %w", name, err)
		}
		files = append(files, path)
	}
	return dir, files, nil
}

// Meta is the provenance header rendered into the plan document.
type Meta struct {
	VerdictState string
	Coverage     string
	WindowLine   string
	Blockers     []string
	Signals      []string
	GeneratedAt  time.Time
}

// RenderMarkdown builds the human-readable plan document.
func RenderMarkdown(p Plan, meta Meta) string {
	var b strings.Builder
	c := p.Component
	fmt.Fprintf(&b, "# Cleanup plan — %s (%s)\n\n", c.Name, c.Kind)
	fmt.Fprintf(&b, "- Verdict: **%s** · Coverage: %s · Window: %s\n",
		meta.VerdictState, meta.Coverage, meta.WindowLine)
	fmt.Fprintf(&b, "- Identity: `%s`\n", c.IdentityKey)
	fmt.Fprintf(&b, "- Generated at: %s (the tool itself runs NO commands — you run each script by hand)\n",
		meta.GeneratedAt.UTC().Format(time.RFC3339))

	if len(meta.Blockers) > 0 {
		fmt.Fprintf(&b, "\n## Blockers at plan generation time\n\n")
		for _, bl := range meta.Blockers {
			fmt.Fprintf(&b, "- %s\n", bl)
		}
	}
	if len(meta.Signals) > 0 {
		fmt.Fprintf(&b, "\n## Non-delete signals (for reference)\n\n")
		for _, sg := range meta.Signals {
			fmt.Fprintf(&b, "- %s\n", sg)
		}
	}
	if len(p.VolumeWarnings) > 0 {
		fmt.Fprintf(&b, "\n## ⚠ Data volumes — manual backup required\n\n")
		for _, v := range p.VolumeWarnings {
			fmt.Fprintf(&b, "- `%s` — may still hold data; confirm your backup before the Removed stage.\n", v)
		}
	}

	fmt.Fprintf(&b, "\n## 6 stages\n\n")
	for i, st := range p.Stages {
		fmt.Fprintf(&b, "### %d. %s\n\n", i+1, st.Name)
		fmt.Fprintf(&b, "- **Action:** %s\n", st.Action)
		fmt.Fprintf(&b, "- **Gate condition:** %s\n", st.Gate)
		fmt.Fprintf(&b, "- **Confirmer:** %s\n", st.Confirmer)
		fmt.Fprintf(&b, "- **Script:** `%s` — run by hand after reading; every mutating command carries a `# rollback:` line.\n\n",
			ScriptFiles[st.Name])
	}
	fmt.Fprintf(&b, "## Progress\n\n```\narchaeologist plan status %q\narchaeologist plan confirm %q <Stage>\n```\n",
		c.Ref, c.Ref)
	return b.String()
}

// Slug turns kind+name into a filesystem-safe directory name.
func Slug(kind, name string) string {
	raw := strings.ToLower(kind + "-" + name)
	var b strings.Builder
	lastDash := false
	for _, r := range raw {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.TrimRight(b.String(), "-")
}
