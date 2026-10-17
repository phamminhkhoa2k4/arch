package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"archaeologist/internal/llm"
	"archaeologist/internal/rules"
	"archaeologist/internal/store"
	"archaeologist/internal/verdict"
)

// newDeleteCheckCmd resolves one component against the latest scan and
// issues the evidence-backed verdict in the fixed section order.
func newDeleteCheckCmd() *cobra.Command {
	var dbPath, rulesPath string
	var explain bool
	cmd := &cobra.Command{
		Use:   "delete-check <component>",
		Short: "Issue an evidence-backed verdict for one component",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, _ := cmd.Flags().GetString("format")
			return runDeleteCheck(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(),
				dbPath, rulesPath, args[0], format, explain)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "archaeologist.db",
		"path to the SQLite evidence database")
	cmd.Flags().StringVar(&rulesPath, "rules-file", "",
		"path to a rules.yaml override (default: embedded rules)")
	cmd.Flags().BoolVar(&explain, "explain", false,
		"ask the configured LLM for a plain-language explanation (needs ARCHAEOLOGIST_LLM_API_KEY)")
	addFormatFlag(cmd)
	return cmd
}

func runDeleteCheck(ctx context.Context, w, errw io.Writer, dbPath, rulesPath, ref, format string, explain bool) error {
	if err := validateFormat(format); err != nil {
		return err
	}
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer func() { _ = st.Close() }()

	scanID, err := st.LatestScanID(ctx)
	if err != nil {
		return err
	}
	ent, err := resolveComponent(ctx, st, scanID, ref)
	if err != nil {
		return err
	}

	r, hash, err := rules.Load(rulesPath)
	if err != nil {
		return err
	}
	in, err := st.BuildInput(ctx, scanID, ent.ID)
	if err != nil {
		return err
	}
	res := verdict.Compute(in, r, time.Now().UTC())
	// Persist keyed by rules hash so a re-run with different rules
	// overwrites instead of piling up; verdicts recompute from stored
	// evidence, never rescanning.
	if err := st.SaveVerdict(ctx, ent.ID, scanID, res, hash); err != nil {
		return err
	}
	code := deleteCheckExitCode(ctx, st, scanID, ent.ID, res)
	var llmText string
	if explain {
		payload := map[string]any{
			"ref":       ref,
			"kind":      ent.Kind,
			"name":      ent.Name,
			"identity":  ent.IdentityKey,
			"verdict":   normalizeResult(res),
			"task":      "Explain this verdict to a server operator: why this state, what the blockers and blind spots mean, and what to check next.",
		}
		text, err := llmExplain(ctx, payload)
		if err != nil {
			if errors.Is(err, llm.ErrNotConfigured) {
				return err
			}
			_, _ = fmt.Fprintln(errw, "llm explain failed (continuing without):", err)
		}
		llmText = text
	}
	if format == formatJSON {
		out := deleteCheckJSON{
			Result:   normalizeResult(res),
			ScanID:   scanID,
			Ref:      ref,
			Identity: ent.IdentityKey,
			Kind:     ent.Kind,
			Name:     ent.Name,
			ExitCode: code,
		}
		if explain {
			out.LLMExplain = &llmExplainJSON{Label: labelExplanation, Text: llmText}
		}
		if err := writeJSON(w, out); err != nil {
			return err
		}
	} else {
		if err := printDeleteCheck(w, res); err != nil {
			return err
		}
		if explain && llmText != "" {
			if err := printLLMExplain(w, labelExplanation, llmText); err != nil {
				return err
			}
		}
	}
	if code != ExitOK {
		return attention(fmt.Errorf("verdict %s needs attention", res.State))
	}
	return nil
}

// deleteCheckExitCode maps the verdict (plus BROKEN_ROUTE findings)
// to the automation exit code.
func deleteCheckExitCode(ctx context.Context, st *store.Store, scanID, entityID int64, res verdict.Result) int {
	switch res.State {
	case verdict.StateActive:
		broken, err := st.HasBrokenRoute(ctx, scanID, entityID)
		if err == nil && broken {
			return ExitAttention
		}
		return ExitOK
	case verdict.StateLikelyOrphaned, verdict.StateOrphaned, verdict.StateUnknown:
		return ExitAttention
	default:
		return ExitAttention
	}
}

// deleteCheckJSON is the --format json shape for delete-check.
type deleteCheckJSON struct {
	verdict.Result
	ScanID    int64          `json:"scan_id"`
	Ref       string         `json:"ref"`
	Identity  string         `json:"identity"`
	Kind      string         `json:"kind"`
	Name      string         `json:"name"`
	ExitCode  int            `json:"exit_code"`
	LLMExplain *llmExplainJSON `json:"llm_explain,omitempty"`
}

// normalizeResult replaces nil slices with empty ones so the JSON
// shape is always an array (never null), matching the published
// schema.
func normalizeResult(res verdict.Result) verdict.Result {
	if res.Blockers == nil {
		res.Blockers = []verdict.Item{}
	}
	if res.Signals == nil {
		res.Signals = []verdict.Item{}
	}
	if res.Blinds == nil {
		res.Blinds = []verdict.Blind{}
	}
	if res.Applicable == nil {
		res.Applicable = []string{}
	}
	if res.Missing == nil {
		res.Missing = []string{}
	}
	if res.Reasons == nil {
		res.Reasons = []string{}
	}
	return res
}

// resolveComponent mirrors explain's resolution: one exact hit or a
// list of identity keys to disambiguate.
func resolveComponent(ctx context.Context, st *store.Store, scanID int64, ref string) (store.EntityRow, error) {
	entities, err := st.FindEntities(ctx, scanID, ref)
	if err != nil {
		return store.EntityRow{}, err
	}
	switch len(entities) {
	case 0:
		return store.EntityRow{}, fmt.Errorf("no component matches %q in scan #%d", ref, scanID)
	case 1:
		return entities[0], nil
	default:
		var b strings.Builder
		fmt.Fprintf(&b, "reference %q matches %d entities — use an identity_key:", ref, len(entities))
		for _, e := range entities {
			fmt.Fprintf(&b, "\n  %s", e.IdentityKey)
		}
		return store.EntityRow{}, errors.New(b.String())
	}
}

// printDeleteCheck renders the fixed section order (state, window,
// coverage, blockers, signals, blind, action). An optional
// "Reasons:" block (non-ACTIVE states list every reason, never a
// single line) sits directly before the final action line.
func printDeleteCheck(w io.Writer, res verdict.Result) error {
	var b strings.Builder

	fmt.Fprintf(&b, "State: %s\n", res.State)
	fmt.Fprintf(&b, "Observation window: %s → %s (%d days)\n",
		res.Window.Start, res.Window.End, res.Window.Days)
	fmt.Fprintf(&b, "Evidence coverage: %s — missing: %s\n",
		res.Coverage, missingList(res.Missing))

	if len(res.Blockers) == 0 {
		fmt.Fprintln(&b, "⛔ Blockers: (none)")
	} else {
		fmt.Fprintln(&b, "⛔ Blockers:")
		for _, item := range res.Blockers {
			fmt.Fprintf(&b, "  - %s %s%s\n", item.Code, item.Text, traceRef(item.EvidenceID, item.RawRef))
		}
	}

	if len(res.Signals) == 0 {
		fmt.Fprintln(&b, "⚠ Non-delete signals: (none)")
	} else {
		fmt.Fprintln(&b, "⚠ Non-delete signals:")
		for _, item := range res.Signals {
			fmt.Fprintf(&b, "  - %s %s%s\n", item.Code, item.Text, traceRef(item.EvidenceID, item.RawRef))
		}
	}

	if len(res.Blinds) == 0 {
		fmt.Fprintln(&b, "? Blind spots: (none)")
	} else {
		fmt.Fprintln(&b, "? Blind spots:")
		for _, bl := range res.Blinds {
			line := fmt.Sprintf("  - %s: %s", bl.Channel, bl.Reason)
			if len(bl.Detail) > 0 {
				line += " (" + joinKV(bl.Detail) + ")"
			}
			fmt.Fprintln(&b, line)
		}
	}

	if len(res.Reasons) > 0 {
		fmt.Fprintln(&b, "Reasons:")
		for _, r := range res.Reasons {
			fmt.Fprintf(&b, "  - %s\n", r)
		}
	}

	fmt.Fprintf(&b, "Suggested action: %s\n", res.Action)

	_, err := io.WriteString(w, b.String())
	return err
}

// missingList renders the missing-channel list for the coverage line.
func missingList(missing []string) string {
	if len(missing) == 0 {
		return "(none)"
	}
	return strings.Join(missing, ", ")
}

// traceRef prints the evidence trace (evidence #id — raw_ref).
// Observation-backed blockers
// point at an observations row, so the label names that table instead
// of claiming an evidence id.
func traceRef(id int64, rawRef string) string {
	if id <= 0 && rawRef == "" {
		return ""
	}
	if strings.HasPrefix(rawRef, "observations#") {
		return fmt.Sprintf(" (observation #%d — %s)", id, rawRef)
	}
	if id > 0 {
		return fmt.Sprintf(" (evidence #%d — %s)", id, rawRef)
	}
	return fmt.Sprintf(" (%s)", rawRef)
}
