package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// WriteMarkdown renders the report as Markdown with the three required
// headings — Dashboard, Findings, Blind spots — in that order (blind
// spots stay visible, never buried).
func WriteMarkdown(w io.Writer, r Report) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# Archaeologist report — %s (scan #%d)\n\n", r.Host, r.ScanID)
	fmt.Fprintf(&b, "Status: `%s` · Generated: `%s`\n\n", r.Status, r.GeneratedAt)

	b.WriteString("## Dashboard\n\n")
	b.WriteString("| Metric | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| Entities | %d |\n", sumCounts(r.Dashboard.EntitiesByKind))
	fmt.Fprintf(&b, "| Findings | %d |\n", r.Dashboard.Findings)
	fmt.Fprintf(&b, "| Blind spots | %d |\n\n", r.Dashboard.BlindSpots)

	b.WriteString("### Verdicts\n\n")
	for _, k := range sortedKeys(r.Dashboard.Verdict) {
		fmt.Fprintf(&b, "- **%s**: %d\n", k, r.Dashboard.Verdict[k])
	}
	b.WriteString("\n### Entities by kind\n\n")
	for _, k := range sortedKeys(r.Dashboard.EntitiesByKind) {
		fmt.Fprintf(&b, "- **%s**: %d\n", k, r.Dashboard.EntitiesByKind[k])
	}

	b.WriteString("\n## Blind spots\n\n")
	b.WriteString("_Vùng mù là dữ kiện: kết luận dưới đây có thể thiếu nguồn bị chặn._\n\n")
	if len(r.BlindSpots) == 0 {
		b.WriteString("_No blind spots._\n")
	}
	for _, s := range r.BlindSpots {
		scope := "host"
		if s.EntityName != "" {
			scope = s.EntityKind + " `" + s.EntityName + "`"
		}
		fmt.Fprintf(&b, "- [%s] %s — %s\n", s.Channel, s.Reason, scope)
	}

	b.WriteString("\n## Findings\n\n")
	if len(r.Findings) == 0 {
		b.WriteString("_No findings._\n")
	}
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "- **%s** (%s) — %s `%s`: %s\n",
			f.Kind, f.Severity, f.EntityKind, f.EntityName, formatDetail(f.Detail))
	}

	_, err := io.WriteString(w, b.String())
	return err
}

func sumCounts(m map[string]int) int {
	total := 0
	for _, v := range m {
		total += v
	}
	return total
}

func sortedKeys[V any, M ~map[string]V](m M) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func formatDetail(m map[string]string) string {
	if len(m) == 0 {
		return "(no detail)"
	}
	parts := make([]string, 0, len(m))
	for _, k := range sortedKeys(m) {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, ", ")
}
