package cron

import (
	"testing"
	"time"
)

// base is a fixed local reference: Wednesday, 2026-10-07 03:00.
var base = time.Date(2026, 10, 7, 3, 0, 0, 0, time.Local)

func TestParseSchedPeriods(t *testing.T) {
	cases := []struct {
		raw    string
		period string
		wantOK bool
	}{
		{"0 2 * * *", "1", true},     // AC: daily → 1 day
		{"0 0 1 * *", "30", true},    // AC: monthly → ~30 days
		{"0 6 * * 0", "7", true},     // weekly
		{"17 * * * *", "0.0417", true},  // hourly
		{"*/5 * * * *", "0.0035", true}, // every 5 minutes
		{"@daily", "1", true},
		{"@hourly", "0.0417", true},
		{"@weekly", "7", true},
		{"@monthly", "30", true},
		{"@yearly", "365", true},
		{"@reboot", "", true}, // no period by design
		{"61 * * * *", "", false},
		{"* * * *", "", false},
		{"@nope", "", false},
		{"not a schedule", "", false},
	}
	for _, c := range cases {
		s := ParseSched(c.raw, base)
		if s.Valid != c.wantOK {
			t.Errorf("%q valid = %v, want %v", c.raw, s.Valid, c.wantOK)
			continue
		}
		if !s.Valid {
			continue
		}
		got := ""
		if s.PeriodDays > 0 {
			got = FormatPeriod(s.PeriodDays)
		}
		if got != c.period {
			t.Errorf("%q period = %q, want %q", c.raw, got, c.period)
		}
	}
}

func TestParseSchedNextRun(t *testing.T) {
	cases := []struct {
		raw  string
		want time.Time
	}{
		{"0 2 * * *", time.Date(2026, 10, 8, 2, 0, 0, 0, time.Local)},   // tomorrow 02:00
		{"30 2 1 * *", time.Date(2026, 11, 1, 2, 30, 0, 0, time.Local)}, // Nov 1
		{"0 6 * * 0", time.Date(2026, 10, 11, 6, 0, 0, 0, time.Local)},  // next Sunday
		{"0 0 * * 7", time.Date(2026, 10, 11, 0, 0, 0, 0, time.Local)},  // 7 == Sunday
		{"17 * * * *", time.Date(2026, 10, 7, 3, 17, 0, 0, time.Local)}, // same hour
		{"@daily", time.Date(2026, 10, 8, 0, 0, 0, 0, time.Local)},
	}
	for _, c := range cases {
		s := ParseSched(c.raw, base)
		if !s.Valid {
			t.Fatalf("%q invalid", c.raw)
		}
		if !s.Next.Equal(c.want) {
			t.Errorf("%q next = %v, want %v", c.raw, s.Next, c.want)
		}
	}
}

func TestParseSchedRebootHasNoCadence(t *testing.T) {
	s := ParseSched("@reboot", base)
	if !s.Valid || s.Macro != "@reboot" {
		t.Fatalf("sched = %+v", s)
	}
	if !s.Next.IsZero() || s.PeriodDays != 0 {
		t.Errorf("reboot must have no period/next: %+v", s)
	}
}

func TestParseSchedDomDowOrSemantics(t *testing.T) {
	// day 1 OR Sunday: from Wed Oct 7 the next Sunday (Oct 11) beats Nov 1.
	s := ParseSched("0 0 1 * 0", base)
	if !s.Valid {
		t.Fatal("invalid")
	}
	want := time.Date(2026, 10, 11, 0, 0, 0, 0, time.Local)
	if !s.Next.Equal(want) {
		t.Errorf("next = %v, want %v (dom OR dow)", s.Next, want)
	}
}

func TestWindowSufficiency(t *testing.T) {
	if !ParseSched("0 2 * * *", base).Sufficient() {
		t.Error("daily must fit a 14-day window")
	}
	if ParseSched("0 0 1 * *", base).Sufficient() {
		t.Error("monthly must NOT fit a 14-day window (US-5.2 signal)")
	}
	if ParseSched("@reboot", base).Sufficient() {
		t.Error("unknown period must not claim sufficiency")
	}
}

func TestFormatPeriod(t *testing.T) {
	cases := map[float64]string{
		1: "1", 30: "30", 7: "7", 365: "365",
		1.0 / 24:        "0.0417",
		5.0 / 1440:      "0.0035",
		1.0 / 1440:      "0.0007",
	}
	for in, want := range cases {
		if got := FormatPeriod(in); got != want {
			t.Errorf("FormatPeriod(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestParseSchedStepAndList(t *testing.T) {
	// 0,15,30,45 → 15-minute gap → 0.0104 days.
	s := ParseSched("0,15,30,45 * * * *", base)
	if !s.Valid || FormatPeriod(s.PeriodDays) != "0.0104" {
		t.Errorf("list period = %s / %v", FormatPeriod(s.PeriodDays), s)
	}
	// Range with step: every 10 minutes between 8:00-8:50.
	s = ParseSched("0-50/10 8 * * *", base)
	if !s.Valid || s.Next.Hour() != 8 || s.Next.Minute() != 0 {
		t.Errorf("step range next = %v", s.Next)
	}
}
