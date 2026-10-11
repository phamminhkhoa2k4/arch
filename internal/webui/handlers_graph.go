package webui

import "net/http"

// graphNodeCap bounds one graph payload so a huge scan cannot freeze
// the browser; the page shows the truncation banner.
const graphNodeCap = 500

// handleGraph renders the graph page shell; the script fetches
// /api/graph and draws the SVG.
func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	s.render(w, "graph", map[string]any{
		"Title":  "Graph",
		"ScanID": s.scanID,
		"Cap":    graphNodeCap,
	})
}

// handleGraphJSON serves the whole-scan node/edge payload, truncated
// to the render cap. Node ids referenced by a kept edge are always
// kept.
func (s *Server) handleGraphJSON(w http.ResponseWriter, r *http.Request) {
	nodes, edges, err := s.st.GraphRows(r.Context(), s.scanID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	truncated := false
	if len(nodes) > graphNodeCap {
		truncated = true
		keep := map[int64]bool{}
		for i, e := range edges {
			if i >= 2000 { // edge cap keeps the payload bounded too
				edges = edges[:i]
				break
			}
			keep[e.Src] = true
			keep[e.Dst] = true
		}
		kept := nodes[:0:graphNodeCap]
		for _, n := range nodes {
			if keep[n.ID] && len(kept) < graphNodeCap {
				kept = append(kept, n)
			}
		}
		// Fall back to the first N nodes when no edges reference any.
		if len(kept) == 0 {
			kept = nodes[:graphNodeCap]
		}
		nodes = kept
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes":     nodes,
		"edges":     edges,
		"truncated": truncated,
		"total":     len(nodes),
	})
}
