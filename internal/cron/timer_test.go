package cron

import (
	"strings"
	"testing"
	"time"
)

func TestLoadTimers(t *testing.T) {
	f := baseFS()
	f.dirs[TimerDir] = []string{"lab-watchdog.timer", "other.service", ".hidden.timer"}
	f.files[TimerDir+"/lab-watchdog.timer"] = `[Unit]
Description=Lab watchdog timer

[Timer]
OnCalendar=*-*-* 03:30:00
Unit=lab-batch.service

[Install]
WantedBy=timers.target
`
	timers, errs := LoadTimers(f, TimerDir)
	if len(errs) != 0 {
		t.Fatalf("errs = %v", errs)
	}
	if len(timers) != 1 {
		t.Fatalf("timers = %+v, want exactly lab-watchdog.timer", timers)
	}
	tm := timers[0]
	if tm.Name != "lab-watchdog.timer" || tm.Unit != "lab-batch.service" ||
		tm.OnCalendar != "*-*-* 03:30:00" || tm.Line != 5 {
		t.Errorf("timer = %+v", tm)
	}
	if tm.Key() != "timer|lab-watchdog.timer" {
		t.Errorf("key = %q", tm.Key())
	}
	if tm.RawRef() != TimerDir+"/lab-watchdog.timer:5" {
		t.Errorf("raw ref = %q", tm.RawRef())
	}
	if tm.FingerprintOf() == "" {
		t.Error("fingerprint must not be empty")
	}
}

func TestLoadTimersMissingDirIsSilent(t *testing.T) {
	timers, errs := LoadTimers(baseFS(), TimerDir)
	if len(timers) != 0 || len(errs) != 0 {
		t.Fatalf("timers=%v errs=%v", timers, errs)
	}
}

func TestLoadTimersUnreadableIsReported(t *testing.T) {
	f := baseFS()
	f.dirs[TimerDir] = []string{"x.timer"}
	f.fileErr[TimerDir+"/x.timer"] = errPerm()
	_, errs := LoadTimers(f, TimerDir)
	if len(errs) != 1 {
		t.Fatalf("errs = %v, want one", errs)
	}
}

type permErr struct{}

func (permErr) Error() string { return "permission denied" }

func errPerm() error { return permErr{} }

func TestParseOnCalendar(t *testing.T) {
	now := time.Date(2026, 10, 7, 3, 0, 0, 0, time.Local)

	s, err := ParseOnCalendar("*-*-* 03:30:00", now)
	if err != nil || !s.Valid || s.PeriodDays != 1 {
		t.Fatalf("daily calendar: sched=%+v err=%v", s, err)
	}
	want := time.Date(2026, 10, 7, 3, 30, 0, 0, time.Local)
	if !s.Next.Equal(want) {
		t.Errorf("next = %v, want %v (later today)", s.Next, want)
	}

	// After 03:30 the same calendar rolls to tomorrow.
	s, err = ParseOnCalendar("*-*-* 03:30:00", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	want = time.Date(2026, 10, 8, 3, 30, 0, 0, time.Local)
	if !s.Next.Equal(want) {
		t.Errorf("next = %v, want %v (rolled to tomorrow)", s.Next, want)
	}

	s, err = ParseOnCalendar("*-*-* 12:00:00", now)
	if err != nil {
		t.Fatal(err)
	}
	want = time.Date(2026, 10, 7, 12, 0, 0, 0, time.Local)
	if !s.Next.Equal(want) {
		t.Errorf("next = %v, want %v (later today)", s.Next, want)
	}

	s, err = ParseOnCalendar("daily", now)
	if err != nil || s.PeriodDays != 1 {
		t.Errorf("keyword daily: sched=%+v err=%v", s, err)
	}

	for _, bad := range []string{
		"Mon..Fri *-*-* 09:00:00", // weekday set: unsupported subset
		"2026-10-07 03:30:00",     // fixed date: unsupported
		"banana",
		"*-*-* 25:00:00", // hour out of range
	} {
		if _, err := ParseOnCalendar(bad, now); err == nil {
			t.Errorf("ParseOnCalendar(%q) must fail (blind spot, not guess)", bad)
		}
	}
}

func TestTimerFingerprintChangesWithSchedule(t *testing.T) {
	a := Timer{File: "/etc/systemd/system/t.timer", FileDigest: "d", Name: "t.timer",
		OnCalendar: "*-*-* 03:00:00"}
	b := a
	b.OnCalendar = "*-*-* 04:00:00"
	if a.FingerprintOf() == b.FingerprintOf() {
		t.Error("calendar drift must change the fingerprint")
	}
	if !strings.Contains(a.RawRef(), "t.timer:1") {
		t.Errorf("raw ref without OnCalendar line = %q", a.RawRef())
	}
}
