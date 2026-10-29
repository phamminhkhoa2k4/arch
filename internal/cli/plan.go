package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"archaeologist/internal/cleanup"
	"archaeologist/internal/rules"
	"archaeologist/internal/store"
	"archaeologist/internal/verdict"
)

// defaultPlanOut is the directory plans are written into unless the
// operator overrides it.
const defaultPlanOut = "cleanup-plans"

// newPlanCmd wires the cleanup plan builder: generate a six-stage
// plan for one component, then track/confirm/check stages. The tool
// only writes plan files — it never executes a single cleanup command.
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
	cmd.Flags().StringVar(&outDir, "out", defaultPlanOut,
		"directory the plan files are written into")
	cmd.AddCommand(newPlanStatusCmd(), newPlanConfirmCmd(), newPlanCheckCmd())
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

// newPlanCheckCmd verifies a generated plan still matches the scan,
// rules and scripts it was built from. It never runs a stage script.
func newPlanCheckCmd() *cobra.Command {
	var (
		dbPath    string
		rulesPath string
		outDir    string
	)
	cmd := &cobra.Command{
		Use:   "check <component>",
		Short: "Verify a generated plan still matches its scan, rules and scripts",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPlanCheck(cmd.Context(), cmd.OutOrStdout(),
				args[0], dbPath, rulesPath, outDir)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "archaeologist.db",
		"path to the SQLite evidence database")
	cmd.Flags().StringVar(&rulesPath, "rules-file", "",
		"path to a rules.yaml override (default: embedded rules)")
	cmd.Flags().StringVar(&outDir, "out", defaultPlanOut,
		"directory holding the generated plan")
	return cmd
}

func runPlanGenerate(ctx context.Context, w io.Writer, ref, dbPath, rulesPath, outDir string) error {
	ev, err := evaluateComponent(ctx, dbPath, rulesPath, ref)
	if err != nil {
		return err
	}
	defer func() { _ = ev.st.Close() }()
	if !planEligible(ev.res.State) {
		if err := printPlanRefusal(w, ev.res); err != nil {
			return err
		}
		return attention(fmt.Errorf("verdict %s is not eligible for a cleanup plan", ev.res.State))
	}
	planID, err := ev.st.EnsurePlan(ctx, ev.ent.ID)
	if err != nil {
		return err
	}
	rt, err := planRuntime(dbPath, rulesPath, ev.rulesHash, ev.scanID)
	if err != nil {
		return err
	}
	plan := cleanup.Build(cleanup.Component{
		Kind:        ev.ent.Kind,
		Name:        ev.ent.Name,
		IdentityKey: ev.ent.IdentityKey,
		Ref:         ref,
		Attrs:       planAttrs(ev.ent),
		Fingerprint: ev.fingerprint,
	}, rt)
	dir, files, err := cleanup.WritePlan(outDir, plan, planMeta(ev.res))
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "Generated a 6-stage plan for %s (%s) — %d files in %s\n",
		ev.ent.Name, ev.ent.Kind, len(files), dir)
	_, _ = fmt.Fprintf(w, "Verdict: %s · plan id %d · no command is auto-executed — you run each script by hand.\n",
		ev.res.State, planID)
	_, _ = fmt.Fprintf(w, "Progress: archaeologist plan status %s --db %s\n",
		cleanup.ShellQuote(ref), cleanup.ShellQuote(dbPath))
	_, _ = fmt.Fprintf(w, "Before running anything: archaeologist plan check %s --db %s\n",
		cleanup.ShellQuote(ref), cleanup.ShellQuote(dbPath))
	return nil
}

func runPlanStatus(ctx context.Context, w io.Writer, ref, dbPath string) error {
	ev, err := evaluateComponent(ctx, dbPath, "", ref)
	if err != nil {
		return err
	}
	defer func() { _ = ev.st.Close() }()
	planID, err := ev.st.LatestPlanID(ctx, ev.ent.ID)
	if err != nil {
		_, _ = fmt.Fprintf(w, "Component %s has no plan yet — run `archaeologist plan %s` first.\n",
			ev.ent.Name, cleanup.ShellQuote(ref))
		return nil
	}
	states, err := ev.st.PlanStageStates(ctx, planID)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "Plan #%d for %s (%s):\n", planID, ev.ent.Name, ev.ent.Kind)
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
		_, _ = fmt.Fprintln(w, "All 6 stages are complete.")
		return nil
	}
	_, _ = fmt.Fprintf(w, "Current stage: %s (remaining: %s)\n",
		current, remainingAfter(states, current))
	return nil
}

func runPlanConfirm(ctx context.Context, w io.Writer, ref, stage, dbPath string) error {
	ev, err := evaluateComponent(ctx, dbPath, "", ref)
	if err != nil {
		return err
	}
	defer func() { _ = ev.st.Close() }()
	planID, err := ev.st.LatestPlanID(ctx, ev.ent.ID)
	if err != nil {
		return fmt.Errorf("component %q has no plan yet — run `archaeologist plan %s` first",
			ref, cleanup.ShellQuote(ref))
	}
	stage = canonicalStage(stage)
	if err := ev.st.ConfirmPlanStage(ctx, planID, stage); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "Confirmed %s (plan #%d for %s).\n", stage, planID, ev.ent.Name)
	return nil
}

// runPlanCheck verifies a generated plan against its manifest and,
// where the database and rules file are readable, against the current
// scan and rules. It never runs a stage script.
func runPlanCheck(ctx context.Context, w io.Writer, ref, dbPath, rulesPath, outDir string) error {
	ev, err := evaluateComponent(ctx, dbPath, rulesPath, ref)
	if err != nil {
		return err
	}
	defer func() { _ = ev.st.Close() }()

	dir := filepath.Join(outDir, cleanup.Slug(ev.ent.Kind, ev.ent.Name))
	res, err := cleanup.Check(dir)
	if err != nil {
		return err
	}

	// Cross-check the manifest against the live database and rules so a
	// plan built from an older scan or a different rule set is caught
	// even when every script hash still matches.
	if id := res.Manifest.ScanID; id > 0 {
		exists, err := ev.st.ScanExists(ctx, id)
		if err != nil {
			return err
		}
		if !exists {
			res.Problem("scan #%d recorded in %s no longer exists in the database — regenerate the plan",
				id, cleanup.ManifestFile)
		} else if id != ev.scanID {
			res.Warning("plan was generated from scan #%d but the latest scan is #%d — re-verify the verdict before acting",
				id, ev.scanID)
		}
	}

	if want := res.Manifest.RulesHash; want != "" && want != ev.rulesHash {
		res.Problem("rules changed since generation (manifest %s, current %s) — regenerate the plan",
			shortHash(want), shortHash(ev.rulesHash))
	}

	if want := res.Manifest.Component.IdentityKey; want != "" {
		fp, err := ev.st.EntityFingerprint(ctx, ev.scanID, want)
		if err != nil {
			return err
		}
		switch {
		case fp == "":
			res.Warning("component %q is no longer in the latest scan — confirm it was removed as planned", want)
		case res.Manifest.Component.Fingerprint != "" && fp != res.Manifest.Component.Fingerprint:
			res.Warning("component %q changed since the plan was generated (fingerprint %s -> %s) — review the plan before acting",
				want, shortHash(res.Manifest.Component.Fingerprint), shortHash(fp))
		}
	}

	if _, err := io.WriteString(w, res.Format()); err != nil {
		return err
	}
	if !res.OK() {
		return attention(fmt.Errorf("plan check found %d problem(s)", len(res.Problems)))
	}
	return nil
}

// evalResult is one resolved component plus the provenance a cleanup
// plan must be pinned to: the scan it came from and the hash of the
// rules that produced the verdict.
type evalResult struct {
	st          *store.Store
	res         verdict.Result
	ent         store.EntityRow
	scanID      int64
	rulesHash   string
	fingerprint string
}

// evaluateComponent resolves the ref, loads rules and computes the
// verdict — the same path delete-check uses.
func evaluateComponent(ctx context.Context, dbPath, rulesPath, ref string) (evalResult, error) {
	var out evalResult
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		return out, fmt.Errorf("open db: %w", err)
	}
	scanID, err := st.LatestScanID(ctx)
	if err != nil {
		_ = st.Close()
		return out, err
	}
	ent, err := resolveComponent(ctx, st, scanID, ref)
	if err != nil {
		_ = st.Close()
		return out, err
	}
	r, rulesHash, err := rules.Load(rulesPath)
	if err != nil {
		_ = st.Close()
		return out, err
	}
	in, err := st.BuildInput(ctx, scanID, ent.ID)
	if err != nil {
		_ = st.Close()
		return out, err
	}
	fp, err := st.EntityFingerprint(ctx, scanID, ent.IdentityKey)
	if err != nil {
		_ = st.Close()
		return out, err
	}
	return evalResult{
		st:          st,
		res:         verdict.Compute(in, r, time.Now().UTC()),
		ent:         ent,
		scanID:      scanID,
		rulesHash:   rulesHash,
		fingerprint: fp,
	}, nil
}

// planRuntime pins the environment a plan's stage scripts assume. The
// binary path is resolved through symlinks so a plan generated from
// /usr/local/bin/archaeologist records the real file rather than the
// link that may later change target.
func planRuntime(dbPath, rulesPath, rulesHash string, scanID int64) (cleanup.Runtime, error) {
	bin, err := os.Executable()
	if err != nil {
		bin = "archaeologist"
	} else if resolved, rerr := filepath.EvalSymlinks(bin); rerr == nil {
		bin = resolved
	}
	return cleanup.Runtime{
		DBPath:      dbPath,
		RulesPath:   rulesPath,
		RulesHash:   rulesHash,
		BinaryPath:  bin,
		ToolVersion: Version,
		ScanID:      scanID,
	}, nil
}

// planEligible reports whether a verdict may produce a cleanup plan:
// only the orphan band does.
func planEligible(state string) bool {
	return state == verdict.StateLikelyOrphaned || state == verdict.StateOrphaned
}

// printPlanRefusal rejects the plan and points at the real blockers —
// an ACTIVE component gets "remove the blocker first" guidance.
func printPlanRefusal(w io.Writer, res verdict.Result) error {
	_, _ = fmt.Fprintf(w, "No cleanup plan generated: verdict is %s.\n", res.State)
	switch res.State {
	case verdict.StateActive:
		_, _ = fmt.Fprintln(w, "The component is active — remove the blockers first, for example:")
		for _, b := range res.Blockers {
			_, _ = fmt.Fprintf(w, "  - remove %s → observe for 14 days (observe) → re-run plan\n", b.Text)
		}
	case verdict.StateUnknown:
		_, _ = fmt.Fprintln(w, "Not enough evidence to plan — extend observation (observe) then re-run delete-check/plan.")
	default:
		_, _ = fmt.Fprintf(w, "Only LIKELY_ORPHANED or ORPHANED can produce a cleanup plan; current verdict: %s\n",
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
		WindowLine: fmt.Sprintf("%s → %s (%d days)",
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

// shortHash trims a hex digest for a compact diagnostic.
func shortHash(s string) string {
	if s == "" {
		return "empty"
	}
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

// canonicalStage matches a stage name case-insensitively.
func canonicalStage(s string) string {
	for _, name := range cleanup.StageNames {
		if strings.EqualFold(s, name) {
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
