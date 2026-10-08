package cron

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"
)

func TestParseCronCMDLine(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		wantOK  bool
		wantCmd string
	}{
		{"valid", "2026-10-08T18:25:01+07:00 host CRON[42]: (root) CMD (/opt/lab/scripts/heartbeat.sh)",
			true, "/opt/lab/scripts/heartbeat.sh"},
		{"no marker", "2026-10-08T18:25:01+07:00 host CRON[42]: (root) CMD NOT (x)", false, ""},
		{"trailing junk", "2026-10-08T18:25:01+07:00 host CRON[42]: (root) CMD (x) extra", false, ""},
		{"empty command", "2026-10-08T18:25:01+07:00 host CRON[42]: (root) CMD ()", false, ""},
		{"bad stamp", "not-a-time host CRON[42]: (root) CMD (/bin/true)", false, ""},
		{"empty line", "", false, ""},
		{"run-parts line", "2026-10-08T18:25:01+07:00 host CRON[42]: (root) run-parts /etc/cron.hourly",
			false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stamp, cmd, ok := parseCronCMDLine(tc.line)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if cmd != tc.wantCmd {
				t.Errorf("cmd = %q, want %q", cmd, tc.wantCmd)
			}
			if stamp.IsZero() {
				t.Error("stamp must parse")
			}
		})
	}
}

func TestParseCronRunsKeepsNewestFirstSighting(t *testing.T) {
	out := []byte(`2026-10-08T18:25:01+07:00 host CRON[1]: (root) CMD (/opt/a.sh)
2026-10-08T09:00:00+07:00 host CRON[1]: (root) CMD (/opt/a.sh)
2026-10-08T09:30:00+07:00 host CRON[2]: (root) CMD (/opt/b.sh)
`)
	runs := parseCronRuns(out)
	if len(runs) != 2 {
		t.Fatalf("runs = %v, want 2 commands", runs)
	}
	want := time.Date(2026, 10, 8, 18, 25, 1, 0, time.FixedZone("", 7*3600))
	if got := runs["/opt/a.sh"]; !got.Equal(want) {
		t.Errorf("a.sh = %s, want newest %s", got, want)
	}
}

// fakeExec swaps execCommand for a scripted shell.
func fakeExec(t *testing.T, script string) {
	t.Helper()
	orig := execCommand
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", script)
	}
	t.Cleanup(func() { execCommand = orig })
}

func TestExecLastRunCronRunsReadsJournal(t *testing.T) {
	fakeExec(t, `printf '%s\n' '2026-10-07T02:00:00+00:00 h CRON[9]: (root) CMD (/opt/lab/scripts/heartbeat.sh)'`)
	got, err := NewExecLastRun().CronRuns(context.Background())
	if err != nil {
		t.Fatalf("CronRuns: %v", err)
	}
	if _, ok := got["/opt/lab/scripts/heartbeat.sh"]; !ok {
		t.Errorf("runs = %v, want heartbeat command", got)
	}
}

func TestExecLastRunCronRunsJournalFailureIsError(t *testing.T) {
	fakeExec(t, `echo journalctl: permission denied >&2; exit 1`)
	if _, err := NewExecLastRun().CronRuns(context.Background()); err == nil {
		t.Fatal("unreadable journal must be an error, not a guess")
	}
}

func TestExecLastRunTimerTrigger(t *testing.T) {
	cases := []struct {
		name   string
		script string
		wantOK bool
	}{
		{"fired", `printf 'Wed 2026-10-07 02:00:00 UTC\n'`, true},
		{"never fired", `printf 'n/a\n'`, false},
		{"empty", `printf '\n'`, false},
		{"unparsable", `printf 'whenever\n'`, false},
		{"systemctl absent", `exit 1`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakeExec(t, tc.script)
			ts, ok, err := NewExecLastRun().TimerTrigger(context.Background(), "lab.timer")
			if err != nil {
				t.Fatalf("TimerTrigger: %v", err)
			}
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && ts.IsZero() {
				t.Error("timestamp must parse")
			}
		})
	}
}

func TestExecLastRunTimerTriggerRejectsDashedUnit(t *testing.T) {
	if _, _, err := NewExecLastRun().TimerTrigger(context.Background(), "-pwn"); err == nil {
		t.Fatal("unit starting with - must be rejected")
	}
}

// fakeLastRun is the in-memory probe used by the collect tests.
type fakeLastRun struct {
	runs    map[string]time.Time
	cronErr error
	timer   map[string]time.Time
	seen    []string
}

func (f *fakeLastRun) CronRuns(context.Context) (map[string]time.Time, error) {
	return f.runs, f.cronErr
}

func (f *fakeLastRun) TimerTrigger(_ context.Context, unit string) (time.Time, bool, error) {
	f.seen = append(f.seen, unit)
	ts, ok := f.timer[unit]
	return ts, ok, nil
}

func TestCollectSetsLastRunAttrWhenProbed(t *testing.T) {
	sink := newRecSink()
	seedForeignEntities(t, sink)
	c := New(labFS(), labIndex())
	hbStamp := time.Date(2026, 10, 7, 2, 0, 0, 0, time.UTC)
	c.SetLastRun(&fakeLastRun{
		runs:  map[string]time.Time{"/opt/lab/scripts/heartbeat.sh": hbStamp},
		timer: map[string]time.Time{"lab-watchdog.timer": time.Date(2026, 10, 6, 3, 30, 0, 0, time.UTC)},
	})
	if err := c.Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}

	hb := sink.entities["cron_job|/etc/crontab#root#/opt/lab/scripts/heartbeat.sh"]
	if got := hb.Attributes["last_run_at"]; got != "2026-10-07T02:00:00Z" {
		t.Errorf("heartbeat last_run_at = %q", got)
	}
	mo := sink.entities["cron_job|/etc/cron.d/lab-monthly#root#/opt/lab/scripts/monthly.sh"]
	if got, present := mo.Attributes["last_run_at"]; !present || got != "" {
		t.Errorf("monthly last_run_at = %q present=%v, want empty (probed, no run seen)", got, present)
	}
	tn := sink.entities["timer|lab-watchdog.timer"]
	if got := tn.Attributes["last_run_at"]; got != "2026-10-06T03:30:00Z" {
		t.Errorf("timer last_run_at = %q", got)
	}
}

func TestCollectSkipsLastRunAttrWhenProbeFails(t *testing.T) {
	sink := newRecSink()
	seedForeignEntities(t, sink)
	c := New(labFS(), labIndex())
	c.SetLastRun(&fakeLastRun{cronErr: errors.New("journal unreadable")})
	if err := c.Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	hb := sink.entities["cron_job|/etc/crontab#root#/opt/lab/scripts/heartbeat.sh"]
	if _, present := hb.Attributes["last_run_at"]; present {
		t.Errorf("failed probe must leave no attribute: %v", hb.Attributes)
	}
	tn := sink.entities["timer|lab-watchdog.timer"]
	if _, present := tn.Attributes["last_run_at"]; !present {
		t.Errorf("timer probe must still record the key when it answers: %v", tn.Attributes)
	}
}
