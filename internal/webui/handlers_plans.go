package webui

import (
	"net/http"
	"strconv"
)

// handlePlan renders the plan viewer page for one plan id.
func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request) {
	planID, ok := s.pathPlanID(w, r)
	if !ok {
		return
	}
	_, _, name, kind, err := s.st.PlanByID(r.Context(), planID)
	if err != nil {
		httpError(w, http.StatusNotFound, "kế hoạch không tồn tại")
		return
	}
	s.render(w, "plan", map[string]any{
		"Title":  "Kế hoạch #" + strconv.FormatInt(planID, 10),
		"ScanID": s.scanID,
		"PlanID": planID,
		"Name":   name,
		"Kind":   kind,
	})
}

// handlePlanJSON serves the plan header plus all six stage states —
// the same data `plan status` prints in the CLI.
func (s *Server) handlePlanJSON(w http.ResponseWriter, r *http.Request) {
	planID, ok := s.pathPlanID(w, r)
	if !ok {
		return
	}
	_, entityID, name, kind, err := s.st.PlanByID(r.Context(), planID)
	if err != nil {
		httpError(w, http.StatusNotFound, "kế hoạch không tồn tại")
		return
	}
	states, err := s.st.PlanStageStates(r.Context(), planID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"plan_id":   planID,
		"entity_id": entityID,
		"name":      name,
		"kind":      kind,
		"stages":    states,
	})
}

// handleConfirmStage marks one stage done through the same
// order-enforced store method the CLI uses, so the web UI and
// `plan confirm` stay in sync.
func (s *Server) handleConfirmStage(w http.ResponseWriter, r *http.Request) {
	planID, ok := s.pathPlanID(w, r)
	if !ok {
		return
	}
	stage := r.PathValue("stage")
	if stage == "" {
		httpError(w, http.StatusBadRequest, "thiếu tên giai đoạn")
		return
	}
	if err := s.st.ConfirmPlanStage(r.Context(), planID, stage); err != nil {
		httpError(w, http.StatusConflict, err.Error())
		return
	}
	states, err := s.st.PlanStageStates(r.Context(), planID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"stages": states})
}

// pathPlanID parses the {id} path parameter as a plan id.
func (s *Server) pathPlanID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		httpError(w, http.StatusBadRequest, "id kế hoạch không hợp lệ")
		return 0, false
	}
	return id, true
}
