package webui

import (
	"net/http"

	"archaeologist/internal/report"
)

// handleDashboard renders the dashboard page. The data is exactly
// report.Build — the same source the JSON export uses — so the parity
// requirement holds by construction.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	rep, err := report.Build(r.Context(), s.st, s.scanID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.render(w, "dashboard", map[string]any{
		"Title":  "Dashboard",
		"ScanID": s.scanID,
		"Report": rep,
	})
}

// handleDashboardJSON serves the same report model as JSON — the
// reference document the dashboard numbers must match.
func (s *Server) handleDashboardJSON(w http.ResponseWriter, r *http.Request) {
	rep, err := report.Build(r.Context(), s.st, s.scanID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rep)
}
