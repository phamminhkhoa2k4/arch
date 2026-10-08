// Package verdict is the rule engine: a pure function from stored
// evidence plus rules.yaml to one verdict. It never touches the
// database — store.BuildInput gathers the facts, Compute decides.
// Positive evidence (a hard blocker) always wins; weak heuristics
// never block.
package verdict

import (
	"fmt"
	"strconv"
	"time"

	"archaeologist/internal/rules"
)

// Verdict states (schema CHECK matches).
const (
	StateActive         = "ACTIVE"
	StateLikelyOrphaned = "LIKELY_ORPHANED"
	StateOrphaned       = "ORPHANED"
	StateUnknown        = "UNKNOWN"
)

// Evidence is one evidence row (with id for output tracing).
type Evidence struct {
	ID         int64
	Polarity   string
	Channel    string
	Strength   string
	ObservedAt string
	RawRef     string
	Value      map[string]string
}

// Blind is one entity-scoped blind spot.
type Blind struct {
	ID      int64             `json:"id"`
	Channel string            `json:"channel"`
	Reason  string            `json:"reason"`
	Detail  map[string]string `json:"detail,omitempty"`
}

// Neighbor is the entity on the other end of an incident edge.
type Neighbor struct {
	ID            int64
	Kind          string
	Name          string
	Attributes    map[string]string
	InUseChannels []string
}

// EdgeFact is one incident edge relative to the subject entity.
type EdgeFact struct {
	Kind       string
	Strength   string
	Dir        string // "in" (stored dst = subject) or "out" (stored src = subject)
	EvidenceID int64
	RawRef     string
	Neighbor   Neighbor
}

// Path is one undirected walk from the subject (explain Chain), recorded
// for blocker pattern matching. Reversed[i] is true when hop i was
// taken against the stored src→dst direction. A path with any weak
// hop never blocks (weak heuristics are never blockers).
type Path struct {
	NodeIDs    []int64
	NodeKinds  []string
	NodeNames  []string
	EdgeKinds  []string
	Strengths  []string
	Reversed   []bool
	EvidenceID int64 // evidence of the last hop
	RawRef     string
	// FarInUse lists the far node's in_use channels (used to prove a
	// live listener at the end of a path).
	FarInUse []string
}

// Observation is one observation bucket on the subject.
type Observation struct {
	ID         int64
	LastSeenAt string
	Count      int64
}

// Window is the observation window facts for this verdict.
type Window struct {
	Start  string `json:"start"`
	End    string `json:"end"`
	Days   int    `json:"days"`
	Source string `json:"source"`
}

// Input is everything Compute needs for one entity.
type Input struct {
	EntityID     int64
	Kind         string
	Name         string
	IdentityKey  string
	Attributes   map[string]string
	Evidence     []Evidence
	Blinds       []Blind
	Edges        []EdgeFact
	Paths        []Path
	Observations []Observation
	Window       Window
}

// Item is one blocker or signal line, traceable to a DB row.
type Item struct {
	Code       string `json:"code"`
	Text       string `json:"text"`
	EvidenceID int64  `json:"evidence_id,omitempty"`
	RawRef     string `json:"raw_ref,omitempty"`
}

// Result is the full verdict.
type Result struct {
	State      string
	Coverage   string
	Blockers   []Item
	Signals    []Item
	Blinds     []Blind
	Window     Window
	WindowOK   bool
	Applicable []string
	Missing    []string
	Reasons    []string
	Action     string
}

// Compute decides the verdict for in under r. Order: hard blockers
// (ACTIVE, overriding everything) → blind-spot guard (UNKNOWN) →
// Evidence Coverage bands → orphan rules → fallback.
func Compute(in Input, r rules.Rules, now time.Time) Result {
	res := Result{
		Window:   in.Window,
		WindowOK: in.Window.Days >= r.Thresholds.ObservationWindowDays,
		Blinds:   in.Blinds,
	}
	res.Blockers = blockers(in, r)
	res.Signals = signals(in, r, now)

	applicable, checked, missing, blindBlocked := coverage(in, r)
	res.Applicable = applicable
	res.Missing = missing

	switch {
	case len(res.Blockers) > 0:
		res.State = StateActive
		res.Coverage = coverageLevel(len(checked), len(applicable), res.WindowOK, r)
		res.Action = fmt.Sprintf("⛔ KHÔNG an toàn để xóa — %d blocker cứng", len(res.Blockers))
		return res
	}

	// Cycle-vs-window trap before every heuristic band: a cadence
	// longer than the observed window never had a chance to fire at
	// least once, so no orphan conclusion is allowed.
	if reason, ok := cyclePeriodUnknown(in); ok {
		res.State = StateUnknown
		res.Coverage = coverageLevel(len(checked), len(applicable), res.WindowOK, r)
		res.Reasons = []string{
			reason,
			fmt.Sprintf("evidence coverage %s — thiếu: %s", res.Coverage, missingOrNone(missing)),
		}
		res.Action = actionFor(res.State)
		return res
	}

	switch {
	case blindBlocked:
		res.State = StateUnknown
		res.Coverage = coverageLevel(len(checked), len(applicable), res.WindowOK, r)
		res.Reasons = []string{
			"vùng mù trên kênh quan trọng — không được kết luận “không dùng”",
			fmt.Sprintf("evidence coverage %s — thiếu: %s", res.Coverage, missingOrNone(missing)),
		}
		res.Action = actionFor(res.State)
		return res
	}

	res.Coverage = coverageLevel(len(checked), len(applicable), res.WindowOK, r)

	orphaned := meets(r.Verdicts.OrphanedRequires, res.Coverage, res.WindowOK)
	likely := meets(r.Verdicts.LikelyOrphanedRequires, res.Coverage, res.WindowOK)
	switch {
	case orphaned:
		res.State = StateOrphaned
	case likely:
		res.State = StateLikelyOrphaned
	default:
		res.State = r.Verdicts.Fallback
	}

	// Short window hard cap: below the configured observation threshold
	// no orphan conclusion is legal, whatever the rules file asks for.
	capped := false
	if !res.WindowOK &&
		(res.State == StateOrphaned || res.State == StateLikelyOrphaned) {
		res.State = StateUnknown
		capped = true
	}

	if res.State != StateActive {
		res.Reasons = reasons(in, res, r, len(checked), len(applicable))
		if capped {
			res.Reasons = append(res.Reasons,
				"chưa đủ quan sát — không được kết luận LIKELY_ORPHANED/ORPHANED")
		}
		res.Action = actionFor(res.State)
	}
	return res
}

// cyclePeriodUnknown reports the schedule-vs-window trap: when the
// entity's cadence (period_days) is longer than the observation
// window, the scheduled work never had a fair chance to run inside
// the window and the verdict must stay UNKNOWN instead of drifting
// into an orphan band. Silent while window_days is 0 (no daemon
// window yet) so pre-observation verdicts keep their old shape, and
// silent when no cadence was parsed.
func cyclePeriodUnknown(in Input) (string, bool) {
	if in.Window.Days <= 0 {
		return "", false
	}
	raw, ok := in.Attributes["period_days"]
	if !ok || raw == "" {
		return "", false
	}
	period, err := strconv.ParseFloat(raw, 64)
	if err != nil || period <= float64(in.Window.Days) {
		return "", false
	}
	return fmt.Sprintf("chu kỳ %s ngày > cửa sổ quan sát %d ngày — chưa có cơ hội chạy trong cửa sổ quan sát",
		raw, in.Window.Days), true
}

// meets reports whether coverage/window satisfy one requirement block.
func meets(req rules.Requirement, coverage string, windowOK bool) bool {
	if req.WindowSufficient && !windowOK {
		return false
	}
	for _, lvl := range req.Coverage {
		if string(lvl) == coverage {
			return true
		}
	}
	return false
}

// coverageLevel applies the D2 formula.
func coverageLevel(checked, applicable int, windowOK bool, r rules.Rules) string {
	if applicable == 0 {
		return "LOW"
	}
	score := float64(checked) / float64(applicable)
	switch {
	case score >= r.Coverage.HighRatio && windowOK:
		return "HIGH"
	case score >= r.Coverage.MediumRatio && windowOK:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// reasons builds the multi-line justification required for non-ACTIVE
// states.
func reasons(in Input, res Result, r rules.Rules, checked, applicable int) []string {
	out := []string{"không có blocker cứng nào trong 6 loại"}
	if res.WindowOK {
		out = append(out, fmt.Sprintf("cửa sổ quan sát %d ngày đạt ngưỡng %d",
			in.Window.Days, r.Thresholds.ObservationWindowDays))
	} else {
		out = append(out, fmt.Sprintf("cửa sổ quan sát %d ngày chưa đạt ngưỡng %d",
			in.Window.Days, r.Thresholds.ObservationWindowDays))
	}
	out = append(out, fmt.Sprintf("evidence coverage %s (%d/%d kênh áp dụng — thiếu: %s)",
		res.Coverage, checked, applicable, missingOrNone(res.Missing)))
	// Concrete schedule-run evidence when the scan probed it (cron and
	// timer entities): the orphan bands must cite when the job last ran
	// or that no run was seen at all.
	if seen, probed := in.Attributes["last_run_at"]; probed {
		if seen == "" {
			out = append(out, "không thấy lần chạy trong journal/systemd")
		} else {
			out = append(out, fmt.Sprintf("lần chạy gần nhất: %s", seen))
		}
	}
	return out
}

func actionFor(state string) string {
	switch state {
	case StateLikelyOrphaned:
		return `ứng viên dọn dẹp — chạy "archaeologist plan <component>" để lập kế hoạch có rollback`
	case StateOrphaned:
		return `có thể dọn — chạy "archaeologist plan <component>" trước khi xóa`
	default:
		return "chưa đủ bằng chứng — mở rộng quan sát (observe) hoặc cấp quyền rồi chạy lại"
	}
}

func missingOrNone(missing []string) string {
	if len(missing) == 0 {
		return "(không)"
	}
	out := ""
	for i, m := range missing {
		if i > 0 {
			out += ", "
		}
		out += m
	}
	return out
}
