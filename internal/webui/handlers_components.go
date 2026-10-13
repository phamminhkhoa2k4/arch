package webui

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"

	"archaeologist/internal/store"
)

// handleComponents renders the filterable components table page.
func (s *Server) handleComponents(w http.ResponseWriter, r *http.Request) {
	f := listFilter(r)
	rows, err := s.st.ListEntitiesFiltered(r.Context(), s.scanID, f)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	kinds, err := s.st.EntityKinds(r.Context(), s.scanID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.render(w, "components", map[string]any{
		"Title":  "Components",
		"ScanID": s.scanID,
		"Rows":   rows,
		"Kinds":  kinds,
		"Filter": f,
		"Count":  len(rows),
	})
}

// handleComponentsJSON serves the filtered list as JSON; tests assert
// filter/sort correctness against the store counts.
func (s *Server) handleComponentsJSON(w http.ResponseWriter, r *http.Request) {
	rows, err := s.st.ListEntitiesFiltered(r.Context(), s.scanID, listFilter(r))
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	type row struct {
		ID           int64  `json:"id"`
		Kind         string `json:"kind"`
		Name         string `json:"name"`
		IdentityKey  string `json:"identity_key"`
		State        string `json:"state"`
		Coverage     string `json:"coverage"`
		LastActivity string `json:"last_activity"`
	}
	out := make([]row, 0, len(rows))
	for _, e := range rows {
		out = append(out, row{
			ID: e.ID, Kind: e.Kind, Name: e.Name, IdentityKey: e.IdentityKey,
			State: e.State, Coverage: e.Coverage, LastActivity: e.LastActivity,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"components": out, "count": len(out)})
}

// listFilter maps query parameters onto the store filter. Unknown
// sort keys fall back to the store default.
func listFilter(r *http.Request) store.ListFilter {
	q := r.URL.Query()
	return store.ListFilter{
		Kind:     q.Get("kind"),
		Status:   q.Get("status"),
		Coverage: q.Get("coverage"),
		Sort:     q.Get("sort"),
		Desc:     q.Get("desc") == "1" || q.Get("desc") == "true",
	}
}

// pathID parses the {id} path parameter as an entity id.
func pathID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, errBadRequest("id must be a positive integer")
	}
	return id, nil
}

// entityOr404 loads the entity or writes the error response.
func (s *Server) entityOr404(w http.ResponseWriter, r *http.Request) (store.EntityRow, bool) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return store.EntityRow{}, false
	}
	ent, err := s.st.EntityByID(r.Context(), id)
	if err != nil {
		httpError(w, http.StatusNotFound, "entity does not exist")
		return store.EntityRow{}, false
	}
	// The detail page only shows entities of the latest scan.
	if ent.ID == 0 {
		httpError(w, http.StatusNotFound, "entity does not belong to the latest scan")
		return store.EntityRow{}, false
	}
	return ent, true
}

// handleDetail renders the entity detail page: header, tabs host,
// always-visible blind-spot panel, and the delete-decision modal
// shell. Tab contents load from the JSON endpoints.
func (s *Server) handleDetail(w http.ResponseWriter, r *http.Request) {
	ent, ok := s.entityOr404(w, r)
	if !ok {
		return
	}
	blinds, err := s.st.BlindSpotsFor(r.Context(), ent.ID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.render(w, "detail", map[string]any{
		"Title":  ent.Name,
		"ScanID": s.scanID,
		"Entity": ent,
		"Blinds": blinds,
	})
}

// detailTabFuncs maps the tab name to its store query so the tab
// handler stays a thin dispatcher.
func (s *Server) handleDetailTab(w http.ResponseWriter, r *http.Request) {
	ent, ok := s.entityOr404(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	switch tab := r.PathValue("tab"); tab {
	case "overview":
		rec, err := s.st.VerdictFor(ctx, ent.ID, s.scanID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			httpError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"entity":     ent,
			"verdict":    verdictView(rec),
			"attributes": ent.Attributes,
		})
	case "dependencies":
		rows, err := s.st.NeighborRows(ctx, s.scanID, ent.ID)
		if err != nil {
			httpError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if rows == nil {
			rows = []store.NeighborRow{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"neighbors": rows})
	case "activity":
		ev, err := s.st.EvidenceFor(ctx, ent.ID)
		if err != nil {
			httpError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if ev == nil {
			ev = []store.EvidenceRow{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"evidence": ev})
	case "evidence":
		ev, err := s.st.EvidenceFor(ctx, ent.ID)
		if err != nil {
			httpError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if ev == nil {
			ev = []store.EvidenceRow{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"evidence": ev})
	case "history":
		rows, err := s.st.HistoryFor(ctx, ent.IdentityKey)
		if err != nil {
			httpError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if rows == nil {
			rows = []store.HistoryRow{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"history": rows})
	case "blindspots":
		rows, err := s.st.BlindSpotsFor(ctx, ent.ID)
		if err != nil {
			httpError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if rows == nil {
			rows = []store.BlindRow{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"blind_spots": rows})
	default:
		httpError(w, http.StatusNotFound, "unknown tab: "+tab)
	}
}

// handleVerdict serves the delete-decision data: state, coverage,
// blockers, signals, blind spots. The modal template consumes this.
func (s *Server) handleVerdict(w http.ResponseWriter, r *http.Request) {
	ent, ok := s.entityOr404(w, r)
	if !ok {
		return
	}
	rec, err := s.st.VerdictFor(r.Context(), ent.ID, s.scanID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, verdictView(rec))
}

// handleGeneratePlan creates the cleanup plan for an eligible entity
// and returns the plan viewer URL. A verdict with blockers (or an
// ineligible state) is refused with the reason.
func (s *Server) handleGeneratePlan(w http.ResponseWriter, r *http.Request) {
	ent, ok := s.entityOr404(w, r)
	if !ok {
		return
	}
	rec, err := s.st.VerdictFor(r.Context(), ent.ID, s.scanID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(rec.Blockers) > 0 {
		httpError(w, http.StatusConflict, "verdict has blockers — remove them before generating a plan")
		return
	}
	if !planEligible(rec.State) {
		httpError(w, http.StatusConflict,
			"verdict "+rec.State+" is not eligible — only LIKELY_ORPHANED or ORPHANED")
		return
	}
	planID, err := s.st.EnsurePlan(r.Context(), ent.ID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"plan_id": planID,
		"href":    "/plans/" + strconv.FormatInt(planID, 10),
	})
}

// planEligible mirrors the CLI gate: only the orphan band may produce
// a cleanup plan.
func planEligible(state string) bool {
	return state == "LIKELY_ORPHANED" || state == "ORPHANED"
}

// verdictView is the JSON shape the modal consumes; nil-ish records
// become an explicit unknown verdict so the modal still renders.
func verdictView(rec store.VerdictRecord) map[string]any {
	state := rec.State
	if state == "" {
		state = "UNKNOWN"
	}
	coverage := rec.Coverage
	if coverage == "" {
		coverage = "LOW"
	}
	blockers := make([]map[string]any, 0, len(rec.Blockers))
	for _, b := range rec.Blockers {
		blockers = append(blockers, map[string]any{
			"code": b.Code, "text": b.Text, "raw_ref": b.RawRef,
		})
	}
	signals := make([]map[string]any, 0, len(rec.Signals))
	for _, s := range rec.Signals {
		signals = append(signals, map[string]any{
			"code": s.Code, "text": s.Text, "raw_ref": s.RawRef,
		})
	}
	blinds := make([]map[string]any, 0, len(rec.Blinds))
	for _, b := range rec.Blinds {
		blinds = append(blinds, map[string]any{
			"channel": b.Channel, "reason": b.Reason,
		})
	}
	return map[string]any{
		"state":           state,
		"coverage":        coverage,
		"blockers":        blockers,
		"signals":         signals,
		"blind_spots":     blinds,
		"window":          rec.Window,
		"reasons":         rec.Reasons,
		"plan_eligible": planEligible(state) && len(blockers) == 0,
		"has_blockers":  len(blockers) > 0,
	}
}
