package report

import (
	"strings"
	"testing"
)

func TestScrubMap(t *testing.T) {
	in := map[string]string{
		"route":   "/old --password=hunter2",
		"plain":   "ok",
		"command": "app --token abc123 --verbose",
	}
	out := scrubMap(in)
	if strings.Contains(out["route"], "hunter2") {
		t.Errorf("inline secret survived: %q", out["route"])
	}
	if out["plain"] != "ok" {
		t.Errorf("plain value changed: %q", out["plain"])
	}
	if strings.Contains(out["command"], "abc123") {
		t.Errorf("inline token survived: %q", out["command"])
	}
}

// Markdown of an empty report still carries the three headings and the
// "no entries" placeholders.
func TestWriteMarkdownEmpty(t *testing.T) {
	r := Report{
		ScanID: 1, Host: "lab", Status: "ok", GeneratedAt: "2026-01-01T00:00:00Z",
		Dashboard:  Dashboard{EntitiesByKind: map[string]int{}, Verdict: map[string]int{}},
		Findings:   []Finding{},
		BlindSpots: []Blind{},
	}
	var b strings.Builder
	if err := WriteMarkdown(&b, r); err != nil {
		t.Fatalf("markdown: %v", err)
	}
	out := b.String()
	for _, want := range []string{"## Dashboard", "## Blind spots", "## Findings",
		"_No findings._", "_No blind spots._"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

// HTML of an empty report renders without error and stays self-contained.
func TestWriteHTMLEmpty(t *testing.T) {
	r := Report{
		ScanID: 1, Host: "lab", Status: "ok", GeneratedAt: "2026-01-01T00:00:00Z",
		Dashboard:  Dashboard{EntitiesByKind: map[string]int{"process": 2}, Verdict: map[string]int{"ACTIVE": 1}},
		Findings:   []Finding{},
		BlindSpots: []Blind{},
	}
	var b strings.Builder
	if err := WriteHTML(&b, r); err != nil {
		t.Fatalf("html: %v", err)
	}
	out := b.String()
	if !strings.Contains(out, "<!DOCTYPE html>") || !strings.Contains(out, "process") {
		t.Errorf("html incomplete:\n%.300s", out)
	}
	if strings.Contains(out, "src=\"http") || strings.Contains(out, "href=\"http") {
		t.Error("external asset reference present")
	}
}
