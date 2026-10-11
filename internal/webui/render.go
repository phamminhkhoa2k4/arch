package webui

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
)

// templateFS holds the embedded pages and the shared stylesheet/script.
//
//go:embed templates/*.html static/*
var templateFS embed.FS

// staticFS is the embedded static directory served under /static/.
var staticFS = mustSubFS(templateFS, "static")

// mustSubFS extracts an embedded subdirectory at init time.
func mustSubFS(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic(err)
	}
	return sub
}

// pageTmpl is parsed lazily once per process.
var pageTmpl = template.Must(template.ParseFS(templateFS, "templates/*.html"))

// render executes the named page inside the shared layout.
func (s *Server) render(w http.ResponseWriter, page string, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pageTmpl.ExecuteTemplate(w, page, data); err != nil {
		// The header is already out; surface the error in the body.
		_, _ = w.Write([]byte("template error: " + err.Error()))
	}
}
