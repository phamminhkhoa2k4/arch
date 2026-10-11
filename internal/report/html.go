package report

import (
	"embed"
	"fmt"
	"html/template"
	"io"
)

//go:embed report.html.tmpl
var tmplFS embed.FS

var htmlTmpl = template.Must(template.New("report.html.tmpl").Funcs(template.FuncMap{
	"entityTotal":  entityTotal,
	"detailInline": detailInline,
}).ParseFS(tmplFS, "report.html.tmpl"))

// WriteHTML renders the report as one self-contained HTML file: CSS is
// inline, there are no external scripts, stylesheets, or images, so
// the file opens offline with nothing missing.
func WriteHTML(w io.Writer, r Report) error {
	if err := htmlTmpl.ExecuteTemplate(w, "report.html.tmpl", r); err != nil {
		return fmt.Errorf("render html report: %w", err)
	}
	return nil
}

// entityTotal sums the per-kind entity counts for the dashboard table.
func entityTotal(m map[string]int) int { return sumCounts(m) }

// detailInline renders a detail map as "k=v, k=v" inside HTML.
func detailInline(m map[string]string) string {
	if len(m) == 0 {
		return "(no detail)"
	}
	return formatDetail(m)
}
