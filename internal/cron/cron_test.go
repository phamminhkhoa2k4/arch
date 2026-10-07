package cron

import (
	"errors"
	"io/fs"
	"reflect"
	"testing"
)

// fakeFS serves in-memory files and directories.
type fakeFS struct {
	files   map[string]string
	dirs    map[string][]string
	fileErr map[string]error
	dirErr  map[string]error
}

func (f fakeFS) ReadFile(path string) ([]byte, error) {
	if err, ok := f.fileErr[path]; ok {
		return nil, err
	}
	if content, ok := f.files[path]; ok {
		return []byte(content), nil
	}
	return nil, fs.ErrNotExist
}

func (f fakeFS) ReadDir(path string) ([]string, error) {
	if err, ok := f.dirErr[path]; ok {
		return nil, err
	}
	if names, ok := f.dirs[path]; ok {
		return names, nil
	}
	return nil, fs.ErrNotExist
}

func baseFS() fakeFS {
	return fakeFS{files: map[string]string{}, dirs: map[string][]string{},
		fileErr: map[string]error{}, dirErr: map[string]error{}}
}

func TestLoadCrontabAndCronDAndSpool(t *testing.T) {
	f := baseFS()
	f.files[CrontabPath] = `# comment
SHELL=/bin/sh
17 * * * * root /opt/lab/scripts/heartbeat.sh
`
	f.dirs[CronDir] = []string{"lab-backup", "lab-boot", "ignore.dot", "trail~"}
	f.files[CronDir+"/lab-backup"] = "30 2 * * * root /opt/lab/scripts/backup.sh\n"
	f.files[CronDir+"/lab-boot"] = "@reboot root /opt/lab/scripts/boot.sh\n"
	f.files[CronDir+"/ignore.dot"] = "0 0 * * * root /nowhere\n"
	f.files[CronDir+"/trail~"] = "0 0 * * * root /nowhere\n"
	f.dirs[SpoolDir] = []string{"root"}
	f.files[SpoolDir+"/root"] = "*/5 * * * * /opt/lab/scripts/monitor.sh\n"
	f.dirs[SpoolAltDir] = []string{"crontabs"} // subdir, not a job file
	f.files[SpoolAltDir+"/crontabs"] = "not a real file"

	cfg := NewLoaderFS(f).Load()
	if len(cfg.Errors) != 0 {
		t.Fatalf("errors = %v, want none", cfg.Errors)
	}
	if len(cfg.Jobs) != 4 {
		t.Fatalf("jobs = %d, want 4 (crontab + 2 cron.d + spool); got %+v", len(cfg.Jobs), cfg.Jobs)
	}

	byKey := map[string]Job{}
	for _, j := range cfg.Jobs {
		byKey[j.Key()] = j
	}
	heart, ok := byKey["cron_job|/etc/crontab#root#/opt/lab/scripts/heartbeat.sh"]
	if !ok {
		t.Fatalf("heartbeat job missing: %+v", cfg.Jobs)
	}
	if heart.Schedule != "17 * * * *" || heart.Line != 3 {
		t.Errorf("heartbeat = %+v", heart)
	}

	back, ok := byKey["cron_job|/etc/cron.d/lab-backup#root#/opt/lab/scripts/backup.sh"]
	if !ok {
		t.Fatalf("backup job missing")
	}
	if back.Schedule != "30 2 * * *" || back.Line != 1 {
		t.Errorf("backup = %+v", back)
	}

	boot, ok := byKey["cron_job|/etc/cron.d/lab-boot#root#/opt/lab/scripts/boot.sh"]
	if !ok {
		t.Fatalf("boot job missing")
	}
	if boot.Schedule != "@reboot" {
		t.Errorf("boot schedule = %q", boot.Schedule)
	}

	mon, ok := byKey["cron_job|/var/spool/cron/crontabs/root#root#/opt/lab/scripts/monitor.sh"]
	if !ok {
		t.Fatalf("monitor job missing: %+v", cfg.Jobs)
	}
	if mon.User != "root" || mon.Schedule != "*/5 * * * *" {
		t.Errorf("monitor = %+v", mon)
	}
}

func TestLoadMissingSourcesAreSilent(t *testing.T) {
	cfg := NewLoaderFS(baseFS()).Load()
	if len(cfg.Jobs) != 0 || len(cfg.Errors) != 0 {
		t.Fatalf("empty machine: jobs=%d errors=%v", len(cfg.Jobs), cfg.Errors)
	}
}

func TestLoadUnreadableSourceIsReported(t *testing.T) {
	f := baseFS()
	f.fileErr[CrontabPath] = errors.New("permission denied")
	cfg := NewLoaderFS(f).Load()
	if len(cfg.Errors) != 1 || cfg.Errors[0].File != CrontabPath {
		t.Fatalf("errors = %v, want one for /etc/crontab", cfg.Errors)
	}
}

func TestParseLineSkipsJunk(t *testing.T) {
	for _, line := range []string{
		"", "   ", "# comment", "SHELL=/bin/sh", "MAILTO=x",
		"* * * * root", "not a schedule at all here",
	} {
		if j, ok := parseLine("f", "d", 1, line, true, ""); ok {
			t.Errorf("line %q parsed as %+v, want skip", line, j)
		}
	}
	if _, ok := parseLine("f", "d", 1, "@reboot root", true, ""); ok {
		t.Error("macro without command must skip")
	}
}

func TestJobKeyAndFingerprint(t *testing.T) {
	j := Job{File: "/etc/crontab", User: "root", Schedule: "1 2 * * *",
		Command: "/bin/true", FileDigest: "abc"}
	other := j
	other.Schedule = "3 4 * * *"

	if j.Key() != "cron_job|/etc/crontab#root#/bin/true" {
		t.Errorf("key = %q", j.Key())
	}
	if j.Fingerprint() == other.Fingerprint() {
		t.Error("schedule drift must change the fingerprint")
	}
	same := j
	if j.Fingerprint() != same.Fingerprint() {
		t.Error("identical jobs must share a fingerprint")
	}
}

func TestJobScript(t *testing.T) {
	j := Job{Command: "/opt/lab/scripts/backup.sh arg"}
	if j.Script() != "/opt/lab/scripts/backup.sh" {
		t.Errorf("script = %q", j.Script())
	}
	j.Command = "redis-cli -h 127.0.0.1"
	if j.Script() != "" {
		t.Errorf("bare command must have no script, got %q", j.Script())
	}
}

func TestLoadJobsStableOrder(t *testing.T) {
	f := baseFS()
	f.files[CrontabPath] = "1 * * * * root /a\n2 * * * * root /b\n"
	first := NewLoaderFS(f).Load()
	second := NewLoaderFS(f).Load()
	var keys1, keys2 []string
	for _, j := range first.Jobs {
		keys1 = append(keys1, j.Key())
	}
	for _, j := range second.Jobs {
		keys2 = append(keys2, j.Key())
	}
	if !reflect.DeepEqual(keys1, keys2) {
		t.Errorf("load order unstable: %v vs %v", keys1, keys2)
	}
}
