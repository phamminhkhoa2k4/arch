package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"archaeologist/internal/rules"
	"archaeologist/internal/store"
	"archaeologist/internal/verdict"
)

// newDeleteCheckCmd resolves one component against the latest scan and
// issues the evidence-backed verdict in the fixed section order.
func newDeleteCheckCmd() *cobra.Command {
	var dbPath, rulesPath string
	cmd := &cobra.Command{
		Use:   "delete-check <component>",
		Short: "Issue an evidence-backed verdict for one component",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, _ := cmd.Flags().GetString("format")
			return runDeleteCheck(cmd.Context(), cmd.OutOrStdout(), dbPath, rulesPath, args[0], format)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "archaeologist.db",
		"path to the SQLite evidence database")
	cmd.Flags().StringVar(&rulesPath, "rules-file", "",
		"path to a rules.yaml override (default: embedded rules)")
	addFormatFlag(cmd)
	return cmd
}

func runDeleteCheck(ctx context.Context, w io.Writer, dbPath, rulesPath, ref, format string) error {
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
		if err := writeJSON(w, out); err != nil {
			return err
		}
	} else if err := printDeleteCheck(w, res); err != nil {
		return err
	}
	if code != ExitOK {
		return attention(fmt.Errorf("verdict %s cần chú ý", res.State))
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
	ScanID   int64  `json:"scan_id"`
	Ref      string `json:"ref"`
	Identity string `json:"identity"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	ExitCode int    `json:"exit_code"`
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
		return store.EntityRow{}, fmt.Errorf("không tìm thấy component nào khớp %q trong scan #%d", ref, scanID)
	case 1:
		return entities[0], nil
	default:
		var b strings.Builder
		fmt.Fprintf(&b, "tham chiếu %q khớp %d entity — dùng identity_key:", ref, len(entities))
		for _, e := range entities {
			fmt.Fprintf(&b, "\n  %s", e.IdentityKey)
		}
		return store.EntityRow{}, errors.New(b.String())
	}
}

// printDeleteCheck renders the fixed section order (state, window,
// coverage, blockers, signals, blind, action). An optional
// "Lý do:" block (non-ACTIVE states list every reason, never a single
// line) sits directly before the final action line.
func printDeleteCheck(w io.Writer, res verdict.Result) error {
	var b strings.Builder

	fmt.Fprintf(&b, "Trạng thái: %s\n", res.State)
	fmt.Fprintf(&b, "Cửa sổ quan sát: %s → %s (%d ngày)\n",
		res.Window.Start, res.Window.End, res.Window.Days)
	fmt.Fprintf(&b, "Evidence coverage: %s — thiếu: %s\n",
		res.Coverage, missingList(res.Missing))

	if len(res.Blockers) == 0 {
		fmt.Fprintln(&b, "⛔ Blockers: (không có)")
	} else {
		fmt.Fprintln(&b, "⛔ Blockers:")
		for _, item := range res.Blockers {
			fmt.Fprintf(&b, "  - %s %s%s\n", item.Code, item.Text, traceRef(item.EvidenceID, item.RawRef))
		}
	}

	if len(res.Signals) == 0 {
		fmt.Fprintln(&b, "⚠ Tín hiệu không-dùng: (không có)")
	} else {
		fmt.Fprintln(&b, "⚠ Tín hiệu không-dùng:")
		for _, item := range res.Signals {
			fmt.Fprintf(&b, "  - %s %s%s\n", item.Code, item.Text, traceRef(item.EvidenceID, item.RawRef))
		}
	}

	if len(res.Blinds) == 0 {
		fmt.Fprintln(&b, "? Vùng mù: (không có)")
	} else {
		fmt.Fprintln(&b, "? Vùng mù:")
		for _, bl := range res.Blinds {
			line := fmt.Sprintf("  - %s: %s", bl.Channel, bl.Reason)
			if len(bl.Detail) > 0 {
				line += " (" + joinKV(bl.Detail) + ")"
			}
			fmt.Fprintln(&b, line)
		}
	}

	if len(res.Reasons) > 0 {
		fmt.Fprintln(&b, "Lý do:")
		for _, r := range res.Reasons {
			fmt.Fprintf(&b, "  - %s\n", r)
		}
	}

	fmt.Fprintf(&b, "Hành động gợi ý: %s\n", res.Action)

	_, err := io.WriteString(w, b.String())
	return err
}

// missingList renders the missing-channel list for the coverage line.
func missingList(missing []string) string {
	if len(missing) == 0 {
		return "(không)"
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
