package cleanup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// CheckResult reports whether a generated plan directory still matches
// its provenance manifest. It never runs anything.
type CheckResult struct {
	// Dir is the plan directory that was checked.
	Dir string
	// Manifest is the parsed manifest, valid even when OK is false as
	// long as no error was returned.
	Manifest Manifest
	// Problems are conditions that make the plan unsafe to run.
	Problems []string
	// Warnings are conditions worth reviewing that do not by themselves
	// make the plan unsafe.
	Warnings []string
}

// OK reports whether the plan passed every hard check.
func (r CheckResult) OK() bool { return len(r.Problems) == 0 }

// Problem adds one hard failure line.
func (r *CheckResult) Problem(format string, args ...any) {
	r.Problems = append(r.Problems, fmt.Sprintf(format, args...))
}

// Warning adds one advisory line.
func (r *CheckResult) Warning(format string, args ...any) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, args...))
}

// Check reads dir/plan.json and verifies every generated script still
// matches the hash recorded at generation time. It reports a missing
// or unreadable manifest as a problem rather than an error, so an
// operator gets one consolidated answer.
//
// The caller is responsible for the checks that need the database or
// the rules file — those live in the CLI layer, which owns those
// dependencies.
func Check(dir string) (CheckResult, error) {
	res := CheckResult{Dir: dir}

	raw, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		res.Problem("%s", err)
		return res, nil
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		res.Problem("%s is not valid JSON: %v", ManifestFile, err)
		return res, nil
	}
	res.Manifest = m

	if m.ManifestVersion != ManifestVersion {
		res.Problem("manifest version %d is not supported by this tool (expected %d) — regenerate the plan",
			m.ManifestVersion, ManifestVersion)
	}
	if len(m.Scripts) == 0 {
		res.Problem("%s records no scripts — regenerate the plan", ManifestFile)
	}

	for _, name := range sortedScriptNames(m.Scripts) {
		want := m.Scripts[name]
		got, err := fileSHA256(filepath.Join(dir, name))
		switch {
		case os.IsNotExist(err):
			res.Problem("script %s is missing", name)
		case err != nil:
			res.Problem("script %s is unreadable: %v", name, err)
		case got != want:
			res.Problem("script %s was modified after generation (hash %s, manifest %s) — regenerate the plan",
				name, shortHash(got), shortHash(want))
		}
	}

	if m.RulesHash == "" {
		res.Warning("manifest records no rules hash — the verdict provenance cannot be re-verified")
	}
	if m.ScanID <= 0 {
		res.Warning("manifest records no scan id — the plan cannot be pinned to a scan")
	}
	if m.Component.Fingerprint == "" {
		res.Warning("manifest records no entity fingerprint — the plan cannot detect that the component changed")
	}

	return res, nil
}

// sortedScriptNames returns the manifest's script names in a stable
// order so problems are reported deterministically.
func sortedScriptNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// fileSHA256 returns the hex SHA-256 of the file at path.
func fileSHA256(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// shortHash trims a hex digest for a compact diagnostic.
func shortHash(s string) string {
	if s == "" {
		return "empty"
	}
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

// Format renders a check result as the CLI report body.
func (r CheckResult) Format() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Plan: %s\n", r.Dir)
	fmt.Fprintf(&b, "  component: %s (%s)\n", r.Manifest.Component.Name, r.Manifest.Component.Kind)
	fmt.Fprintf(&b, "  identity:  %s\n", defaultStr(r.Manifest.Component.IdentityKey, "unknown"))
	fmt.Fprintf(&b, "  scan:      #%d\n", r.Manifest.ScanID)
	fmt.Fprintf(&b, "  database:  %s\n", defaultStr(r.Manifest.DBPath, "archaeologist.db"))
	if r.Manifest.RulesPath != "" {
		fmt.Fprintf(&b, "  rules:     %s\n", r.Manifest.RulesPath)
	} else {
		fmt.Fprintf(&b, "  rules:     embedded defaults\n")
	}
	fmt.Fprintf(&b, "  verdict:   %s (coverage %s)\n", r.Manifest.Verdict.State, r.Manifest.Verdict.Coverage)

	if len(r.Problems) > 0 {
		fmt.Fprintf(&b, "\nProblems (%d) — the plan is NOT safe to run:\n", len(r.Problems))
		for _, p := range r.Problems {
			fmt.Fprintf(&b, "  ✗ %s\n", p)
		}
	}
	if len(r.Warnings) > 0 {
		fmt.Fprintf(&b, "\nWarnings (%d):\n", len(r.Warnings))
		for _, w := range r.Warnings {
			fmt.Fprintf(&b, "  ! %s\n", w)
		}
	}
	if r.OK() {
		fmt.Fprintf(&b, "\nAll %d stage scripts match the manifest.\n", len(r.Manifest.Scripts))
	}
	return b.String()
}
