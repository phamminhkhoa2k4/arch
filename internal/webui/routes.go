package webui

import "net/http"

// routes wires every page and JSON endpoint. HTML pages render the
// layout; /api/* endpoints return JSON consumed by the page scripts
// (and asserted directly by tests).
func (s *Server) routes() {
	s.mux.Handle("GET /static/", http.StripPrefix("/static/",
		http.FileServer(http.FS(staticFS))))
	s.mux.HandleFunc("GET /{$}", s.handleDashboard)
	s.mux.HandleFunc("GET /api/dashboard", s.handleDashboardJSON)
	s.mux.HandleFunc("GET /components", s.handleComponents)
	s.mux.HandleFunc("GET /api/components", s.handleComponentsJSON)
	s.mux.HandleFunc("GET /components/{id}", s.handleDetail)
	s.mux.HandleFunc("GET /api/components/{id}/{tab}", s.handleDetailTab)
	s.mux.HandleFunc("GET /api/components/{id}/verdict", s.handleVerdict)
	s.mux.HandleFunc("POST /api/components/{id}/plan", s.handleGeneratePlan)
	s.mux.HandleFunc("GET /graph", s.handleGraph)
	s.mux.HandleFunc("GET /api/graph", s.handleGraphJSON)
	s.mux.HandleFunc("GET /plans/{id}", s.handlePlan)
	s.mux.HandleFunc("GET /api/plans/{id}", s.handlePlanJSON)
	s.mux.HandleFunc("POST /api/plans/{id}/stages/{stage}", s.handleConfirmStage)
}

