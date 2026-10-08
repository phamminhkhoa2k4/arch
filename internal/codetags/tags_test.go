// Package codetags holds the repository guard that keeps documentation
// identifiers out of code files. Rule and authority: AGENTS.md
// "Documentation Tags In Code".
package codetags

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// docTagPatterns are the documentation identifier classes banned from
// code. The guard file itself is exempt because these literals live
// here; every other scanned file must stay free of them.
var docTagPatterns = []struct {
	class string
	re    *regexp.Regexp
}{
	{`user-story code (US-*)`, regexp.MustCompile(`(?i)\bUS-[0-9]`)},
	{`epic code (E0-E18)`, regexp.MustCompile(`(?i)\bE(1[0-8]|[0-9])\b`)},
	{`spec reference ("specs")`, regexp.MustCompile(`(?i)\bspecs\b`)},
	{`spec section (§ followed by a number)`, regexp.MustCompile(`§[0-9]`)},
	{`backlog name`, regexp.MustCompile(`(?i)product-backlog`)},
	{`ADR reference`, regexp.MustCompile(`(?i)\bADR\b`)},
	{`epic wording`, regexp.MustCompile(`(?i)\bepics?\b`)},
}

// codeExt lists the scanned extensions; Makefile is matched by name.
// Directories that hold documentation or tooling config are out of
// scope: only executable/validation files count as code.
var codeExt = map[string]bool{".go": true, ".sh": true, ".yaml": true, ".yml": true}

var skipDirs = map[string]bool{".git": true, "docs": true, ".agents": true}

// TestNoDocTagsInCode scans every code file in the repository and
// fails on any documentation identifier, naming the file, line, class,
// rule, and the compliant next action.
func TestNoDocTagsInCode(t *testing.T) {
	root := repoRoot(t)
	self := callerPath(t)

	scanned := 0
	violations := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if path == self || !isCodeFile(path) {
			return nil
		}
		scanned++
		found, scanErr := scanFile(path, root)
		if scanErr != nil {
			return scanErr
		}
		for _, v := range found {
			violations++
			t.Errorf(
				"%s: documentation tag in code (%s)\n"+
					"rule: no documentation identifiers in code files — AGENTS.md \"Documentation Tags In Code\"\n"+
					"next action: reword the comment without the tag; keep the reference in docs/ (plans, specs)",
				v, docTagClass(v))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}
	if scanned == 0 {
		t.Fatalf("scanned 0 code files under %s — guard scope is broken", root)
	}
	t.Logf("scanned %d code files, %d violations", scanned, violations)
}

// scanFile returns "rel:line: text" for each violating line.
func scanFile(path, root string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	rel, err := filepath.Rel(root, path)
	if err != nil {
		return nil, err
	}
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		for _, p := range docTagPatterns {
			if loc := p.re.FindStringIndex(text); loc != nil {
				out = append(out, fmt.Sprintf("%s:%d: %q", rel, line, strings.TrimSpace(text)))
				break
			}
		}
	}
	return out, sc.Err()
}

// docTagClass names the matched class for the diagnostic.
func docTagClass(v string) string {
	for _, p := range docTagPatterns {
		if p.re.MatchString(v) {
			return p.class
		}
	}
	return "documentation identifier"
}

func isCodeFile(path string) bool {
	base := filepath.Base(path)
	if base == "Makefile" {
		return true
	}
	return codeExt[strings.ToLower(filepath.Ext(base))]
}

// callerPath returns the absolute path of this test file.
func callerPath(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	abs, err := filepath.Abs(self)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	return abs
}

// repoRoot walks up from this file until it finds go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir := filepath.Dir(callerPath(t))
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above " + dir)
		}
		dir = parent
	}
}
