package cron

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"archaeologist/internal/systemd"
)

// TimerDir is where systemd timer units normally live.
const TimerDir = "/etc/systemd/system"

// Timer is one parsed systemd timer unit.
type Timer struct {
	File       string // unit file path
	FileDigest string // sha256 of the file content
	Name       string // file name, e.g. "lab-watchdog.timer"
	Line       int    // OnCalendar directive line, 0 when absent
	Unit       string // Unit= target, "" when absent
	OnCalendar string // raw calendar expression, "" when absent
}

// Key is the deterministic identity of the timer.
func (t *Timer) Key() string { return "timer|" + t.Name }

// RawRef points at the OnCalendar line when there is one, the file
// otherwise.
func (t *Timer) RawRef() string {
	line := t.Line
	if line == 0 {
		line = 1
	}
	return fmt.Sprintf("%s:%d", t.File, line)
}

// FingerprintInput is what the fingerprint hashes — exposed for the
// collector's entity, kept in sync with the parse.
func (t *Timer) FingerprintOf() string {
	return digestOf(t.FileDigest, t.Name, t.Unit, t.OnCalendar)
}

// LoadTimers parses every *.timer unit under dir. A directory that
// does not exist is normal; unreadable files come back as errors for
// the caller to report.
func LoadTimers(fs systemd.FS, dir string) ([]Timer, []FileError) {
	var timers []Timer
	var errs []FileError

	names, err := fs.ReadDir(dir)
	if err != nil {
		if !missing(err) {
			errs = append(errs, FileError{File: dir, Err: err})
		}
		return nil, errs
	}
	for _, name := range names {
		if !strings.HasSuffix(name, ".timer") || strings.HasPrefix(name, ".") {
			continue
		}
		path := dir + "/" + name
		data, err := fs.ReadFile(path)
		if err != nil {
			if !missing(err) && !strings.Contains(err.Error(), "is a directory") {
				errs = append(errs, FileError{File: path, Err: err})
			}
			continue
		}
		f, err := systemd.ParseFile(path, data)
		if err != nil {
			errs = append(errs, FileError{File: path, Err: err})
			continue
		}
		t := Timer{File: path, FileDigest: digestOf(string(data)), Name: name}
		for _, d := range f.Dirs {
			if d.Section != "Timer" {
				continue
			}
			switch d.Key {
			case "OnCalendar":
				if t.OnCalendar == "" {
					t.OnCalendar = d.Value
					t.Line = d.Line
				}
			case "Unit":
				t.Unit = d.Value
			}
		}
		timers = append(timers, t)
	}
	return timers, errs
}

// calendarWords map systemd calendar keywords onto cron macros.
var calendarWords = map[string]string{
	"hourly":   "@hourly",
	"daily":    "@daily",
	"weekly":   "@weekly",
	"monthly":  "@monthly",
	"yearly":   "@yearly",
	"annually": "@annually",
	"minutely": "@every-minute",
}

// ParseOnCalendar parses the subset of systemd calendar expressions
// the scanner supports: keywords and "*-*-* HH:MM[:SS]" (every day at
// a fixed time). Anything else returns an error so the caller reports
// a blind spot instead of guessing.
func ParseOnCalendar(raw string, now time.Time) (Sched, error) {
	s := strings.TrimSpace(raw)
	if m, ok := calendarWords[s]; ok {
		if m == "@every-minute" {
			return Sched{Raw: raw, Valid: true, PeriodDays: minutesToDays(1),
				Next: nextRun(sched5{min: allOf(0, 59), hour: allOf(0, 23),
					dom: allOf(1, 31), month: allOf(1, 12), dow: allOf(0, 7)}, now)}, nil
		}
		return ParseSched(m, now), nil
	}

	fields := strings.Fields(s)
	if len(fields) != 2 || fields[0] != "*-*-*" {
		return Sched{}, fmt.Errorf("unsupported OnCalendar %q", raw)
	}
	parts := strings.Split(fields[1], ":")
	if len(parts) < 2 || len(parts) > 3 {
		return Sched{}, fmt.Errorf("unsupported OnCalendar %q", raw)
	}
	hh, errH := strconv.Atoi(parts[0])
	mm, errM := strconv.Atoi(parts[1])
	if errH != nil || errM != nil || hh < 0 || hh > 23 || mm < 0 || mm > 59 {
		return Sched{}, fmt.Errorf("unsupported OnCalendar %q", raw)
	}
	if len(parts) == 3 {
		if _, err := strconv.Atoi(parts[2]); err != nil {
			return Sched{}, fmt.Errorf("unsupported OnCalendar %q", raw)
		}
	}
	// Every day at HH:MM — same cadence as the equivalent cron macro.
	next := time.Date(now.Year(), now.Month(), now.Day(), hh, mm, 0, 0, now.Location())
	if !next.After(now) {
		next = next.AddDate(0, 0, 1)
	}
	return Sched{Raw: raw, Valid: true, PeriodDays: 1, Next: next}, nil
}

// allOf builds a valueSet covering every value in [lo, hi].
func allOf(lo, hi int) valueSet {
	v := valueSet{any: true, vals: map[int]struct{}{}}
	for n := lo; n <= hi; n++ {
		v.vals[n] = struct{}{}
	}
	return v
}
