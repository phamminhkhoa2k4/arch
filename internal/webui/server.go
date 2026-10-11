// Package webui serves the local interactive UI over the evidence
// database: dashboard parity with the JSON report, a filterable
// components table, per-entity detail with first-class blind spots,
// the whole-scan graph, the delete-decision modal, and the cleanup
// plan viewer. It binds to localhost by default and never performs
// network egress.
package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"archaeologist/internal/store"
)

// Server is the local web UI. One instance serves the latest scan of
// one database.
type Server struct {
	st     *store.Store
	scanID int64
	mux    *http.ServeMux
}

// New builds the server for the latest scan in st.
func New(ctx context.Context, st *store.Store) (*Server, error) {
	scanID, err := st.LatestScanID(ctx)
	if err != nil {
		return nil, err
	}
	s := &Server{st: st, scanID: scanID, mux: http.NewServeMux()}
	s.routes()
	return s, nil
}

// Handler returns the full route table.
func (s *Server) Handler() http.Handler { return s.mux }

// ListenAndServe blocks until the context is cancelled, then shuts
// down gracefully within five seconds.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{Addr: addr, Handler: s.mux}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	}
}

// writeJSON writes a JSON response body with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// httpError writes a JSON error body with the given status.
func httpError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// errBadRequest is the shared validation error for bad path/query
// input.
func errBadRequest(msg string) error {
	return &badRequestError{msg: msg}
}

type badRequestError struct{ msg string }

func (e *badRequestError) Error() string { return e.msg }
