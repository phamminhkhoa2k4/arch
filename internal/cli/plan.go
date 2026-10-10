package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"archaeologist/internal/cleanup"
	"archaeologist/internal/rules"
	"archaeologist/internal/store"
	"archaeologist/internal/verdict"
)

// newPlanCmd wires the cleanup plan builder: generate a six-stage
// plan for one component, then track/confirm stages. The tool only
// writes plan files — it never executes a single cleanup command.
func newPlanCmd() *cobra.Command {
	var (
		dbPath    string
		rulesPath string
		outDir    string
	)
	cmd := &cobra.Command{
		Use:   "plan <component>",
		Short: "Generate a staged cleanup plan with rollback commands",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPlanGenerate(cmd.Context(), cmd.OutOrStdout(),
				args[0], dbPath, rulesPath, outDir)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "archaeologist.db",
		"path to the SQLite evidence database")
	cmd.Flags().StringVar(&rulesPath, "rules-file", "",
		"path to a rules.yaml override (default: embedded rules)")
	cmd.Flags().StringVar(&outDir, "out", "cleanup-plans",
		"directory the plan files are written into")
	cmd.AddCommand(newPlanStatusCmd(), newPlanConfirmCmd())
	return cmd
}

func newPlanStatusCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "status <component>",
		Short: "Show the current cleanup stage and what remains",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPlanStatus(cmd.Context(), cmd.OutOrStdout(), args[0], dbPath)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "archaeologist.db",
		"path to the SQLite evidence database")
	return cmd
}

func newPlanConfirmCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "confirm <component> <stage>",
		Short: "Mark a cleanup stage as done (order-enforced, persisted)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPlanConfirm(cmd.Context(), cmd.OutOrStdout(),
				args[0], args[1], dbPath)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "archaeologist.db",
		"path to the SQLite evidence database")
	return cmd
}

func runPlanGenerate(ctx context.Context, w io.Writer, ref, dbPath, rulesPath, outDir string) error {
	st, res, ent, err := evaluateComponent(ctx, dbPath, rulesPath, ref)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	if !planEligible(res.State) {
		if err := printPlanRefusal(w, res); err != nil {
			return err
		}
		return attention(fmt.Errorf("verdict %s không đủ điều kiện để sinh kế hoạch", res.State))
	}
	planID, err := st.EnsurePlan(ctx, ent.ID)
	if err != nil {
		return err
	}
	plan := cleanup.Build(cleanup.Component{
		Kind:        ent.Kind,
		Name:        ent.Name,
		IdentityKey: ent.IdentityKey,
		Ref:         ref,
		Attrs:       planAttrs(ent),
	})
	dir, files, err := cleanup.WritePlan(outDir, plan, planMeta(res))
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "Đã sinh kế hoạch 6 giai đoạn cho %s (%s) — %d file tại %s\n",
		ent.Name, ent.Kind, len(files), dir)
	_, _ = fmt.Fprintf(w, "Verdict: %s · plan id %d · KHÔNG lệnh nào được tự chạy — bạn chạy tay từng script.\n",
		res.State, planID)
	_, _ = fmt.Fprintf(w, "Tiến độ: archaeologist plan status %q\n", ref)
	return nil
}

func runPlanStatus(ctx context.Context, w io.Writer, ref, dbPath string) error {
	st, _, ent, err := evaluateComponent(ctx, dbPath, "", ref)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	planID, err := st.LatestPlanID(ctx, ent.ID)
	if err != nil {
		_, _ = fmt.Fprintf(w, "Component %s chưa có kế hoạch — chạy `archaeologist plan %q` trước.\n",
			ent.Name, ref)
		return nil
	}
	states, err := st.PlanStageStates(ctx, planID)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "Kế hoạch #%d cho %s (%s):\n", planID, ent.Name, ent.Kind)
	current := ""
	for _, s := range states {
		mark := " "
		if s.Status == "done" {
			mark = "✓"
		}
		note := ""
		if s.ConfirmedAt != "" {
			note = " — " + s.ConfirmedAt
		}
		_, _ = fmt.Fprintf(w, "  [%s] %s%s\n", mark, s.Stage, note)
		if s.Status != "done" && current == "" {
			current = s.Stage
		}
	}
	if current == "" {
		_, _ = fmt.Fprintln(w, "Toàn bộ 6 giai đoạn đã hoàn tất.")
		return nil
	}
	_, _ = fmt.Fprintf(w, "Giai đoạn hiện tại: %s (còn lại: %s)\n",
		current, remainingAfter(states, current))
	return nil
}

func runPlanConfirm(ctx context.Context, w io.Writer, ref, stage, dbPath string) error {
	st, _, ent, err := evaluateComponent(ctx, dbPath, "", ref)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	planID, err := st.LatestPlanID(ctx, ent.ID)
	if err != nil {
		return fmt.Errorf("component %q chưa có kế hoạch — chạy `archaeologist plan %q` trước", ref, ref)
	}
	stage = canonicalStage(stage)
	if err := st.ConfirmPlanStage(ctx, planID, stage); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "Đã confirm %s (plan #%d cho %s).\n", stage, planID, ent.Name)
	return nil
}

// evaluateComponent resolves the ref, loads rules and computes the
// verdict — the same path delete-check uses.
func evaluateComponent(ctx context.Context, dbPath, rulesPath, ref string) (*store.Store, verdict.Result, store.EntityRow, error) {
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		return nil, verdict.Result{}, store.EntityRow{}, fmt.Errorf("open db: %w", err)
	}
	scanID, err := st.LatestScanID(ctx)
	if err != nil {
		_ = st.Close()
		return nil, verdict.Result{}, store.EntityRow{}, err
	}
	ent, err := resolveComponent(ctx, st, scanID, ref)
	if err != nil {
		_ = st.Close()
		return nil, verdict.Result{}, store.EntityRow{}, err
	}
	r, _, err := rules.Load(rulesPath)
	if err != nil {
		_ = st.Close()
		return nil, verdict.Result{}, store.EntityRow{}, err
	}
	in, err := st.BuildInput(ctx, scanID, ent.ID)
	if err != nil {
		_ = st.Close()
		return nil, verdict.Result{}, store.EntityRow{}, err
	}
	return st, verdict.Compute(in, r, time.Now().UTC()), ent, nil
}

// planEligible reports whether a verdict may produce a cleanup plan:
// only the orphan band does.
func planEligible(state string) bool {
	return state == verdict.StateLikelyOrphaned || state == verdict.StateOrphaned
}

// printPlanRefusal rejects the plan and points at the real blockers —
// an ACTIVE component gets "remove the blocker first" guidance.
func printPlanRefusal(w io.Writer, res verdict.Result) error {
	_, _ = fmt.Fprintf(w, "KHÔNG sinh kế hoạch xóa: verdict là %s.\n", res.State)
	switch res.State {
	case verdict.StateActive:
		_, _ = fmt.Fprintln(w, "Component đang hoạt động — gỡ blocker trước, ví dụ:")
		for _, b := range res.Blockers {
			_, _ = fmt.Fprintf(w, "  - gỡ %s → quan sát 14 ngày (observe) → chạy lại plan\n", b.Text)
		}
	case verdict.StateUnknown:
		_, _ = fmt.Fprintln(w, "Chưa đủ bằng chứng để lên kế hoạch — mở rộng quan sát (observe) rồi chạy lại delete-check/plan.")
	default:
		_, _ = fmt.Fprintf(w, "Chỉ LIKELY_ORPHANED hoặc ORPHANED mới có kế hoạch dọn; verdict hiện tại: %s\n",
			res.State)
	}
	return nil
}

// planMeta packages the verdict facts for the plan document header.
func planMeta(res verdict.Result) cleanup.Meta {
	blockers := make([]string, 0, len(res.Blockers))
	for _, b := range res.Blockers {
		blockers = append(blockers, b.Code+" "+b.Text)
	}
	signals := make([]string, 0, len(res.Signals))
	for _, s := range res.Signals {
		signals = append(signals, s.Code+" "+s.Text)
	}
	return cleanup.Meta{
		VerdictState: res.State,
		Coverage:     res.Coverage,
		WindowLine: fmt.Sprintf("%s → %s (%d ngày)",
			res.Window.Start, res.Window.End, res.Window.Days),
		Blockers:    blockers,
		Signals:     signals,
		GeneratedAt: time.Now().UTC(),
	}
}

// planAttrs passes the entity attributes the builder needs.
func planAttrs(ent store.EntityRow) map[string]string {
	return ent.Attributes
}

// canonicalStage matches a stage name case-insensitively.
func canonicalStage(s string) string {
	for _, name := range cleanup.StageNames {
		if strings.EqualFold(name, s) {
			return name
		}
	}
	return s
}

// remainingAfter lists the pending stages from current onwards.
func remainingAfter(states []store.PlanStageState, current string) string {
	var out []string
	seen := false
	for _, s := range states {
		if s.Stage == current {
			seen = true
		}
		if seen && s.Status != "done" {
			out = append(out, s.Stage)
		}
	}
	return strings.Join(out, ", ")
}
