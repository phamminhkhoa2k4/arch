package cleanup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Manifest is the machine-readable provenance document written next to
// the stage scripts. It pins a plan to the exact scan, rules and
// binary that produced it, and records a hash of every generated script
// so a later edit is detectable. WritePlan only writes files — no
// command in any script is ever executed here.
type Manifest struct {
	ManifestVersion int    `json:"manifest_version"`
	ToolVersion     string `json:"tool_version"`
	GeneratedAt     string `json:"generated_at"`
	ScanID          int64  `json:"scan_id"`
	RulesHash       string `json:"rules_hash"`
	DBPath          string `json:"db_path"`
	RulesPath       string `json:"rules_path,omitempty"`
	BinaryPath      string `json:"binary_path"`
	Component       struct {
		Kind        string `json:"kind"`
		Name        string `json:"name"`
		IdentityKey string `json:"identity_key"`
		Ref         string `json:"ref"`
		Fingerprint string `json:"fingerprint,omitempty"`
	} `json:"component"`
	Verdict struct {
		State    string `json:"state"`
		Coverage string `json:"coverage"`
		Window   string `json:"window"`
	} `json:"verdict"`
	// Scripts maps each stage script file name to the SHA-256 of its
	// bytes at generation time.
	Scripts map[string]string `json:"scripts"`
}

// ManifestVersion identifies the manifest schema this build emits.
const ManifestVersion = 1

// WritePlan renders the plan into outDir/<slug>/: one markdown plan
// document, the six numbered stage scripts, and the provenance
// manifest. It only writes files — no command in any script is ever
// executed here. Returns the plan directory and every file created.
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

	hashes := make(map[string]string, len(p.Stages))
	for _, st := range p.Stages {
		name := ScriptFiles[st.Name]
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(st.Script), 0o755); err != nil {
			return dir, files, fmt.Errorf("write %s: %w", name, err)
		}
		files = append(files, path)
		sum := sha256.Sum256([]byte(st.Script))
		hashes[name] = hex.EncodeToString(sum[:])
	}

	mf := filepath.Join(dir, ManifestFile)
	if err := os.WriteFile(mf, []byte(buildManifest(p, meta, hashes)), 0o644); err != nil {
		return dir, files, fmt.Errorf("write %s: %w", ManifestFile, err)
	}
	files = append(files, mf)

	return dir, files, nil
}

// buildManifest renders the provenance document for one plan.
func buildManifest(p Plan, meta Meta, hashes map[string]string) string {
	rt := p.Runtime
	m := Manifest{
		ManifestVersion: ManifestVersion,
		ToolVersion:     rt.ToolVersion,
		GeneratedAt:     meta.GeneratedAt.UTC().Format(time.RFC3339),
		ScanID:          rt.ScanID,
		RulesHash:       rt.RulesHash,
		DBPath:          rt.DBPath,
		RulesPath:       rt.RulesPath,
		BinaryPath:      rt.BinaryPath,
		Scripts:         hashes,
	}
	m.Component.Kind = p.Component.Kind
	m.Component.Name = p.Component.Name
	m.Component.IdentityKey = p.Component.IdentityKey
	m.Component.Ref = p.Component.Ref
	m.Component.Fingerprint = p.Component.Fingerprint
	m.Verdict.State = meta.VerdictState
	m.Verdict.Coverage = meta.Coverage
	m.Verdict.Window = meta.WindowLine

	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		// The struct holds only strings, an int64 and a string map, so
		// marshalling cannot fail; fall back to a minimal document
		// rather than leaving the plan without provenance.
		return fmt.Sprintf("{\n  \"manifest_version\": %d\n}\n", ManifestVersion)
	}
	return string(out) + "\n"
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
	rt := p.Runtime
	fmt.Fprintf(&b, "# Cleanup plan — %s (%s)\n\n", c.Name, c.Kind)
	fmt.Fprintf(&b, "- Verdict: **%s** · Coverage: %s · Window: %s\n",
		meta.VerdictState, meta.Coverage, meta.WindowLine)
	fmt.Fprintf(&b, "- Identity: `%s`\n", c.IdentityKey)
	fmt.Fprintf(&b, "- Generated at: %s (the tool itself runs NO commands — you run each script by hand)\n",
		meta.GeneratedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "- Provenance: scan #%d · rules `%s` · tool `%s`\n",
		rt.ScanID, provenanceShort(rt.RulesHash), provenanceShort(rt.ToolVersion))
	fmt.Fprintf(&b, "- Evidence database: `%s`\n", defaultStr(rt.DBPath, "archaeologist.db"))
	if rt.RulesPath != "" {
		fmt.Fprintf(&b, "- Rules override: `%s`\n", rt.RulesPath)
	}

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
	dbFlag := ""
	if rt.DBPath != "" && rt.DBPath != "archaeologist.db" {
		dbFlag = fmt.Sprintf(" --db %s", ShellQuote(rt.DBPath))
	}
	fmt.Fprintf(&b, "## Progress\n\n```\narchaeologist plan status %q%s\narchaeologist plan confirm %q <Stage>%s\narchaeologist plan check %q%s\n```\n",
		c.Ref, dbFlag, c.Ref, dbFlag, c.Ref, dbFlag)
	return b.String()
}

// provenanceShort trims a long opaque value for the markdown header
// while keeping enough to correlate against the manifest.
func provenanceShort(s string) string {
	if s == "" {
		return "unknown"
	}
	if len(s) <= 12 {
		return s
	}
	return s[:12]
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
