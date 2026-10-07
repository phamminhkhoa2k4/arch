package cron

import (
	"strconv"
	"strings"
	"time"
)

// Sched is a parsed cron schedule with the cadence derived from it.
type Sched struct {
	Raw        string    // original schedule text
	Macro      string    // "@daily" and friends, "" for five fields
	PeriodDays float64   // distance between runs in days; 0 when unknowable
	Next       time.Time // next run after now, zero when unknowable
	Valid      bool      // false when the text cannot be parsed
}

// windowDays is the observation window the verdict engine compares
// periods against (a monthly job needs more than 14 days of history).
const windowDays = 14

// Sufficient reports whether one observation window covers the period.
func (s Sched) Sufficient() bool { return s.PeriodDays > 0 && s.PeriodDays <= windowDays }

// macroEquivalents map @macros onto their five-field form so next-run
// and period share one code path. @reboot has no period: it fires
// once at boot.
var macroEquivalents = map[string][5]string{
	"@hourly":   {"0", "*", "*", "*", "*"},
	"@daily":    {"0", "0", "*", "*", "*"},
	"@weekly":   {"0", "0", "*", "*", "0"},
	"@monthly":  {"0", "0", "1", "*", "*"},
	"@yearly":   {"0", "0", "1", "1", "*"},
	"@annually": {"0", "0", "1", "1", "*"},
}

// ParseSched parses a cron schedule and derives its period and next
// run from now (local time). An unparseable schedule returns
// Valid=false with no cadence: the caller reports it, never guesses.
func ParseSched(raw string, now time.Time) Sched {
	fields := strings.Fields(raw)
	if len(fields) == 1 && strings.HasPrefix(fields[0], "@") {
		m := fields[0]
		if m == "@reboot" {
			return Sched{Raw: raw, Macro: m, Valid: true}
		}
		exp, ok := macroEquivalents[m]
		if !ok {
			return Sched{Raw: raw}
		}
		return build(raw, m, exp, now)
	}
	if len(fields) != 5 {
		return Sched{Raw: raw}
	}
	return build(raw, "", [5]string{fields[0], fields[1], fields[2], fields[3], fields[4]}, now)
}

// build parses the five fields then derives period and next run.
func build(raw, macro string, fields [5]string, now time.Time) Sched {
	min, errMin := parseSet(fields[0], 0, 59)
	hour, errHour := parseSet(fields[1], 0, 23)
	dom, errDom := parseSet(fields[2], 1, 31)
	month, errMonth := parseSet(fields[3], 1, 12)
	dow, errDow := parseSet(fields[4], 0, 7)
	if errMin != nil || errHour != nil || errDom != nil || errMonth != nil || errDow != nil {
		return Sched{Raw: raw, Macro: macro}
	}
	return Sched{
		Raw:        raw,
		Macro:      macro,
		PeriodDays: periodDays(min, hour, dom, month, dow),
		Next:       nextRun(sched5{min: min, hour: hour, dom: dom, month: month, dow: dow}, now),
		Valid:      true,
	}
}

// sched5 is one parsed five-field schedule.
type sched5 struct {
	min, hour, dom, month, dow valueSet
}

// nextRun walks whole minutes from now up to a little over a year —
// long enough for yearly schedules, short enough to stay instant.
func nextRun(p sched5, now time.Time) time.Time {
	t := now.Truncate(time.Minute).Add(time.Minute)
	limit := t.AddDate(0, 0, 400)
	for t.Before(limit) {
		if p.month.has(int(t.Month())) && p.dayOK(t) &&
			p.hour.has(t.Hour()) && p.min.has(t.Minute()) {
			return t
		}
		t = t.Add(time.Minute)
	}
	return time.Time{}
}

// dayOK applies the classic cron rule: when both day-of-month and
// day-of-week are restricted, a match on either one fires the job.
func (p sched5) dayOK(t time.Time) bool {
	domRestricted := !p.dom.any
	dowRestricted := !p.dow.any
	switch {
	case domRestricted && dowRestricted:
		return p.dom.has(t.Day()) || p.dow.has(int(t.Weekday()))
	case domRestricted:
		return p.dom.has(t.Day())
	case dowRestricted:
		return p.dow.has(int(t.Weekday()))
	default:
		return true
	}
}

// periodDays derives the distance between consecutive runs from the
// coarsest restricted field: month → yearly, day → weekly/monthly,
// hour → daily, minute → hourly/sub-hourly.
func periodDays(min, hour, dom, month, dow valueSet) float64 {
	switch {
	case !month.any:
		return 365
	case !dom.any && !dow.any:
		return 7 // fires at least weekly (dom OR dow)
	case !dom.any:
		return 30
	case !dow.any:
		return 7
	case !hour.any:
		return 1
	case min.any:
		return minutesToDays(1)
	default:
		return minutesToDays(minGap(min.vals, 60))
	}
}

// minGap returns the smallest distance between set members, including
// the wrap from the highest value back to the lowest.
func minGap(vals map[int]struct{}, cycle int) int {
	sorted := make([]int, 0, len(vals))
	for v := range vals {
		sorted = append(sorted, v)
	}
	sortInts(sorted)
	gap := cycle - sorted[len(sorted)-1] + sorted[0]
	for i := 1; i < len(sorted); i++ {
		if d := sorted[i] - sorted[i-1]; d < gap {
			gap = d
		}
	}
	return gap
}

func sortInts(a []int) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

func minutesToDays(m int) float64 { return float64(m) / 1440 }

// FormatPeriod renders period_days as a compact decimal string.
func FormatPeriod(d float64) string {
	s := strconv.FormatFloat(d, 'f', 4, 64)
	s = strings.TrimRight(s, "0")
	s = strings.TrimRight(s, ".")
	return s
}

// valueSet is one parsed schedule field: every value, or a compact
// set of them.
type valueSet struct {
	any  bool
	vals map[int]struct{}
}

func (v valueSet) has(n int) bool {
	if v.any {
		return true
	}
	_, ok := v.vals[n]
	return ok
}

// errField marks a schedule field cron itself would reject.
type errField struct{ field string }

func (e errField) Error() string { return "invalid cron field " + e.field }

// parseSet parses one field: "*", "*/n", "a", "a-b", "a-b/n", "a/n"
// and comma lists of those. Day-of-week 7 folds onto 0 (Sunday).
func parseSet(s string, lo, hi int) (valueSet, error) {
	v := valueSet{vals: map[int]struct{}{}}
	for _, part := range strings.Split(s, ",") {
		if err := addPart(&v, s, part, lo, hi); err != nil {
			return valueSet{}, err
		}
	}
	full := hi - lo + 1
	if hi == 7 {
		full = 7 // dow: 7 is an alias for 0, not an eighth day
	}
	if len(v.vals) >= full {
		v.any = true
	}
	return v, nil
}

func addPart(v *valueSet, field, part string, lo, hi int) error {
	step := 1
	if i := strings.IndexByte(part, '/'); i >= 0 {
		n, err := strconv.Atoi(part[i+1:])
		if err != nil || n <= 0 {
			return errField{field}
		}
		step = n
		part = part[:i]
	}
	start, end := lo, hi
	switch {
	case part == "*":
		// the full range
	case strings.Contains(part, "-"):
		bounds := strings.SplitN(part, "-", 2)
		a, errA := strconv.Atoi(bounds[0])
		b, errB := strconv.Atoi(bounds[1])
		if errA != nil || errB != nil {
			return errField{field}
		}
		start, end = a, b
	default:
		a, err := strconv.Atoi(part)
		if err != nil {
			return errField{field}
		}
		start, end = a, a
		if step > 1 {
			end = hi // "a/n" runs from a to the top of the range
		}
	}
	if start < lo || end > hi || start > end {
		return errField{field}
	}
	for n := start; n <= end; n += step {
		m := n
		if hi == 7 && m == 7 {
			m = 0 // 7 and 0 are the same Sunday
		}
		v.vals[m] = struct{}{}
	}
	return nil
}
