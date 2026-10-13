package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// PlanStages is the ordered cleanup-stage machine (schema CHECK'd).
var PlanStages = []string{
	"Candidate", "Quarantined", "Observed", "Archived", "Removed", "Verified",
}

// PlanStageState is one stage of one plan.
type PlanStageState struct {
	Stage       string
	Status      string // pending | done
	ConfirmedAt string // RFC3339, empty while pending
}

// EnsurePlan returns the newest plan row for entityID, creating one at
// the Candidate stage when none exists. Re-running plan generation
// keeps prior stage progress.
func (s *Store) EnsurePlan(ctx context.Context, entityID int64) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM plans WHERE entity_id = ? ORDER BY id DESC LIMIT 1`,
		entityID).Scan(&id)
	switch err {
	case nil:
		return id, nil
	case sql.ErrNoRows:
		// fall through to insert
	default:
		return 0, fmt.Errorf("select plan: %w", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO plans (entity_id, created_at, current_stage) VALUES (?, ?, 'Candidate')`,
		entityID, now)
	if err != nil {
		return 0, fmt.Errorf("insert plan: %w", err)
	}
	return res.LastInsertId()
}

// LatestPlanID returns the newest plan id for entityID, or
// sql.ErrNoRows when the component has never had a plan.
func (s *Store) LatestPlanID(ctx context.Context, entityID int64) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM plans WHERE entity_id = ? ORDER BY id DESC LIMIT 1`,
		entityID).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

// PlanStageStates lists all six stages of planID in order; missing
// rows read as pending so a freshly created plan shows the full path.
func (s *Store) PlanStageStates(ctx context.Context, planID int64) ([]PlanStageState, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT stage, status, COALESCE(confirmed_at, '')
		 FROM plan_stages WHERE plan_id = ?`, planID)
	if err != nil {
		return nil, fmt.Errorf("select stages: %w", err)
	}
	defer func() { _ = rows.Close() }()
	have := map[string]PlanStageState{}
	for rows.Next() {
		var st PlanStageState
		if err := rows.Scan(&st.Stage, &st.Status, &st.ConfirmedAt); err != nil {
			return nil, err
		}
		have[st.Stage] = st
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]PlanStageState, 0, len(PlanStages))
	for _, name := range PlanStages {
		if st, ok := have[name]; ok {
			out = append(out, st)
			continue
		}
		out = append(out, PlanStageState{Stage: name, Status: "pending"})
	}
	return out, nil
}

// ConfirmPlanStage marks stage done. Confirmation must follow the
// machine order: every earlier stage has to be done first. The
// plan's current_stage moves to the next pending stage.
func (s *Store) ConfirmPlanStage(ctx context.Context, planID int64, stage string) error {
	idx := -1
	for i, name := range PlanStages {
		if name == stage {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("invalid stage %q (must be one of %v)", stage, PlanStages)
	}
	states, err := s.PlanStageStates(ctx, planID)
	if err != nil {
		return err
	}
	for i := 0; i < idx; i++ {
		if states[i].Status != "done" {
			return fmt.Errorf("stage %s not confirmed yet — %s must be completed first", states[i].Stage, stage)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	// UPDATE is a no-op when the row does not exist yet; the
	// INSERT OR IGNORE then persists the first confirmation.
	if _, err := s.db.ExecContext(ctx,
		`UPDATE plan_stages SET status = 'done', confirmed_at = ?
		 WHERE plan_id = ? AND stage = ?`, now, planID, stage); err != nil {
		return fmt.Errorf("update stage: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO plan_stages (plan_id, stage, status, confirmed_at)
		 VALUES (?, ?, 'done', ?)`, planID, stage, now); err != nil {
		return fmt.Errorf("insert stage: %w", err)
	}
	// current_stage: the next pending stage, or Verified when done.
	next := "Verified"
	for i := idx + 1; i < len(states); i++ {
		if states[i].Status != "done" {
			next = states[i].Stage
			break
		}
	}
	if idx == len(PlanStages)-1 {
		next = PlanStages[len(PlanStages)-1]
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE plans SET current_stage = ? WHERE id = ?`, next, planID); err != nil {
		return fmt.Errorf("update plan stage: %w", err)
	}
	return nil
}
