package cron

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"

	"archaeologist/internal/collector"
	"archaeologist/internal/cron"
)

// recSink records output and enforces the same ordering rules as the
// real store: evidence only for known entities, no duplicate refs,
// edges only through known endpoints and refs.
type recSink struct {
	entities map[string]collector.Entity
	refs     map[string]bool
	edges    []collector.Edge
	evidence []collector.Evidence
	blinds   []collector.BlindSpot
	findings []collector.Finding
}

func newRecSink() *recSink {
	return &recSink{entities: map[string]collector.Entity{}, refs: map[string]bool{}}
}

func (r *recSink) UpsertEntity(e collector.Entity) error {
	if e.IdentityKey == "" {
		return fmt.Errorf("empty identity key")
	}
	r.entities[e.IdentityKey] = e
	return nil
}

func (r *recSink) AddEvidence(e collector.Evidence) error {
	if _, ok := r.entities[e.EntityIdentityKey]; !ok {
		return fmt.Errorf("evidence for unknown entity %q", e.EntityIdentityKey)
	}
	if e.RawRef == "" {
		return fmt.Errorf("evidence for %q: empty raw_ref", e.EntityIdentityKey)
	}
	if e.Channel != "cron" {
		return fmt.Errorf("evidence channel = %q, want cron", e.Channel)
	}
	if e.Ref != "" {
		if r.refs[e.Ref] {
			return fmt.Errorf("duplicate evidence ref %q", e.Ref)
		}
		r.refs[e.Ref] = true
	}
	r.evidence = append(r.evidence, e)
	return nil
}

func (r *recSink) UpsertEdge(e collector.Edge) error {
	if _, ok := r.entities[e.SrcIdentityKey]; !ok {
		return fmt.Errorf("edge %s: unknown src %q", e.Kind, e.SrcIdentityKey)
	}
	if _, ok := r.entities[e.DstIdentityKey]; !ok {
		return fmt.Errorf("edge %s: unknown dst %q", e.Kind, e.DstIdentityKey)
	}
	if !r.refs[e.EvidenceRef] {
		return fmt.Errorf("edge %s: unknown evidence ref %q", e.Kind, e.EvidenceRef)
	}
	r.edges = append(r.edges, e)
	return nil
}

func (r *recSink) AddBlindSpot(b collector.BlindSpot) error {
	if b.EntityIdentityKey != "" {
		if _, ok := r.entities[b.EntityIdentityKey]; !ok {
			return fmt.Errorf("blind spot for unknown entity %q", b.EntityIdentityKey)
		}
	}
	r.blinds = append(r.blinds, b)
	return nil
}

func (r *recSink) AddFinding(f collector.Finding) error {
	if _, ok := r.entities[f.EntityIdentityKey]; !ok {
		return fmt.Errorf("finding for unknown entity %q", f.EntityIdentityKey)
	}
	if f.EvidenceRef != "" && !r.refs[f.EvidenceRef] {
		return fmt.Errorf("finding %s: unknown evidence ref %q", f.Kind, f.EvidenceRef)
	}
	r.findings = append(r.findings, f)
	return nil
}

// fakeIndex serves fixed unit and container snapshots.
type fakeIndex struct {
	units      []collector.UnitRow
	containers []collector.ContainerRow
	err        error
}

func (f *fakeIndex) UnitRows() ([]collector.UnitRow, error) { return f.units, f.err }

func (f *fakeIndex) ContainerRows() ([]collector.ContainerRow, error) {
	return f.containers, f.err
}

// fakeFS serves in-memory files and directories.
type fakeFS struct {
	files   map[string]string
	dirs    map[string][]string
	fileErr map[string]error
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
	if names, ok := f.dirs[path]; ok {
		return names, nil
	}
	return nil, fs.ErrNotExist
}

func baseFS() fakeFS {
	return fakeFS{files: map[string]string{}, dirs: map[string][]string{},
		fileErr: map[string]error{}}
}

const labTimer = `[Unit]
Description=Lab watchdog

[Timer]
OnCalendar=*-*-* 03:30:00
Unit=lab-batch.service
`

// labIndex mirrors the lab's systemd/docker inventory.
func labIndex() *fakeIndex {
	return &fakeIndex{
		units: []collector.UnitRow{
			{IdentityKey: "systemd_unit|lab-batch.service", Name: "lab-batch.service"},
		},
		containers: []collector.ContainerRow{
			{IdentityKey: "container|abc123", Name: "lab-cache", Image: "redis:7-alpine"},
		},
	}
}

// seedForeignEntities creates the entities earlier collectors own:
// cron edges may only point at them, never mint them.
func seedForeignEntities(t *testing.T, s *recSink) {
	t.Helper()
	for _, e := range []collector.Entity{
		{Kind: "systemd_unit", Name: "lab-batch.service",
			IdentityKey: "systemd_unit|lab-batch.service", Fingerprint: "x"},
		{Kind: "container", Name: "lab-cache",
			IdentityKey: "container|abc123", Fingerprint: "y"},
	} {
		if err := s.UpsertEntity(e); err != nil {
			t.Fatal(err)
		}
	}
}

func labFS() fakeFS {
	f := baseFS()
	f.files[cron.CrontabPath] = "17 * * * * root /opt/lab/scripts/heartbeat.sh\n"
	f.dirs[cron.CronDir] = []string{"lab-backup", "lab-monthly"}
	f.files[cron.CronDir+"/lab-backup"] = "30 2 * * * root /opt/lab/scripts/backup.sh\n"
	f.files[cron.CronDir+"/lab-monthly"] = "0 0 1 * * root /opt/lab/scripts/monthly.sh\n"
	f.files["/opt/lab/scripts/heartbeat.sh"] = "#!/bin/sh\necho tick >> /var/log/lab-heartbeat.log\n"
	f.files["/opt/lab/scripts/backup.sh"] = "#!/bin/sh\n" +
		"redis-cli -h 127.0.0.1 -p 6379 BGSAVE\n" +
		"systemctl start --no-block lab-batch.service\n" +
		"echo done >> /var/log/lab-backup.log\n"
	f.files["/opt/lab/scripts/monthly.sh"] = "#!/bin/sh\necho monthly\n"
	f.dirs[cron.TimerDir] = []string{"lab-watchdog.timer"}
	f.files[cron.TimerDir+"/lab-watchdog.timer"] = labTimer
	return f
}

// systemdFS is the slice of systemd.FS the collector needs; it keeps
// the collect helper's signature short in tests.
type systemdFS interface {
	ReadFile(path string) ([]byte, error)
	ReadDir(path string) ([]string, error)
}

func collect(t *testing.T, fsys systemdFS, index Index) *recSink {
	t.Helper()
	sink := newRecSink()
	seedForeignEntities(t, sink)
	c := New(fsys, index)
	if err := c.Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return sink
}

func edge(s *recSink, src, dst, kind string) *collector.Edge {
	for i := range s.edges {
		e := &s.edges[i]
		if e.SrcIdentityKey == src && e.DstIdentityKey == dst && e.Kind == kind {
			return e
		}
	}
	return nil
}

func TestCollectJobsScriptsTimerAndEdges(t *testing.T) {
	s := collect(t, labFS(), labIndex())

	// Entities: three jobs, three scripts, one timer.
	for _, key := range []string{
		"cron_job|/etc/crontab#root#/opt/lab/scripts/heartbeat.sh",
		"cron_job|/etc/cron.d/lab-backup#root#/opt/lab/scripts/backup.sh",
		"cron_job|/etc/cron.d/lab-monthly#root#/opt/lab/scripts/monthly.sh",
		"script|/opt/lab/scripts/heartbeat.sh",
		"script|/opt/lab/scripts/backup.sh",
		"script|/opt/lab/scripts/monthly.sh",
		"timer|lab-watchdog.timer",
	} {
		if _, ok := s.entities[key]; !ok {
			t.Errorf("missing entity %q; have %d entities", key, len(s.entities))
		}
	}

	// Daily job cadence attrs.
	hb := s.entities["cron_job|/etc/crontab#root#/opt/lab/scripts/heartbeat.sh"]
	if hb.Attributes["schedule"] != "17 * * * *" ||
		hb.Attributes["period_days"] != "0.0417" ||
		hb.Attributes["window_14d_sufficient"] != "true" ||
		hb.Attributes["next_run_at"] == "" {
		t.Errorf("heartbeat attrs = %v", hb.Attributes)
	}

	// Monthly job: cadence parsed but outside the 14-day window.
	mo := s.entities["cron_job|/etc/cron.d/lab-monthly#root#/opt/lab/scripts/monthly.sh"]
	if mo.Attributes["period_days"] != "30" ||
		mo.Attributes["window_14d_sufficient"] != "false" {
		t.Errorf("monthly attrs = %v", mo.Attributes)
	}

	// Script edges: deterministic references from job to script.
	backupKey := "cron_job|/etc/cron.d/lab-backup#root#/opt/lab/scripts/backup.sh"
	if e := edge(s, backupKey, "script|/opt/lab/scripts/backup.sh", "references"); e == nil {
		t.Error("missing backup job -> script edge")
	} else if e.Strength != collector.StrengthDeterministic {
		t.Errorf("script edge strength = %s", e.Strength)
	}

	// Nested refs inside backup.sh: redis-cli -> container, systemctl
	// -> unit. Both edges source from the owning cron job.
	if e := edge(s, backupKey, "container|abc123", "references"); e == nil {
		t.Error("missing backup job -> lab-cache edge")
	} else if e.Strength != collector.StrengthStrongHeuristic {
		t.Errorf("container edge strength = %s, want strong_heuristic", e.Strength)
	}
	if e := edge(s, backupKey, "systemd_unit|lab-batch.service", "references"); e == nil {
		t.Error("missing backup job -> lab-batch edge")
	} else if e.Strength != collector.StrengthDeterministic {
		t.Errorf("unit edge strength = %s", e.Strength)
	}

	// scheduled_by: unit -> timer.
	if e := edge(s, "systemd_unit|lab-batch.service", "timer|lab-watchdog.timer", "scheduled_by"); e == nil {
		t.Error("missing lab-batch -> timer scheduled_by edge")
	}

	// Timer cadence attrs.
	tn := s.entities["timer|lab-watchdog.timer"]
	if tn.Attributes["on_calendar"] != "*-*-* 03:30:00" ||
		tn.Attributes["period_days"] != "1" ||
		tn.Attributes["next_run_at"] == "" {
		t.Errorf("timer attrs = %v", tn.Attributes)
	}

	// A clean machine: no findings, no blind spots.
	if len(s.findings) != 0 {
		t.Errorf("findings = %+v, want none", s.findings)
	}
	if len(s.blinds) != 0 {
		t.Errorf("blinds = %+v, want none", s.blinds)
	}

	// Evidence provenance: job lines point at the crontab, trace
	// evidence points at the script line that made the reference.
	var sawJob, sawTrace bool
	for _, ev := range s.evidence {
		switch ev.Ref {
		case "cron-job:" + "cron_job|/etc/crontab#root#/opt/lab/scripts/heartbeat.sh":
			sawJob = true
			if ev.RawRef != "/etc/crontab:1" {
				t.Errorf("job evidence raw_ref = %q", ev.RawRef)
			}
		}
		if ev.RawRef == "/opt/lab/scripts/backup.sh:2" {
			sawTrace = true
		}
	}
	if !sawJob || !sawTrace {
		t.Errorf("evidence provenance incomplete: job=%v trace=%v", sawJob, sawTrace)
	}
}

func TestOrphanCron(t *testing.T) {
	f := baseFS()
	f.files[cron.CrontabPath] = "0 6 * * 0 root /opt/lab/scripts/rotate-logs-gone.sh\n"

	s := collect(t, f, labIndex())
	if len(s.findings) != 1 {
		t.Fatalf("findings = %+v, want exactly one ORPHAN_CRON", s.findings)
	}
	fd := s.findings[0]
	if fd.Kind != "ORPHAN_CRON" || fd.Severity != "warn" {
		t.Errorf("finding = %+v", fd)
	}
	if fd.Detail["path"] != "/opt/lab/scripts/rotate-logs-gone.sh" {
		t.Errorf("detail = %v", fd.Detail)
	}
	if _, ok := s.entities["script|/opt/lab/scripts/rotate-logs-gone.sh"]; ok {
		t.Error("missing script must not become an entity")
	}
}

func TestEnvUnresolvedBlindSpot(t *testing.T) {
	f := baseFS()
	f.files[cron.CrontabPath] = "5 * * * * root $BACKUP_TOOL --full\n"

	s := collect(t, f, nil)
	if len(s.blinds) != 1 {
		t.Fatalf("blinds = %+v, want exactly one", s.blinds)
	}
	b := s.blinds[0]
	if b.Reason != "cron_env_unresolved" || b.Channel != "cron" ||
		b.Detail["variable"] != "$BACKUP_TOOL" {
		t.Errorf("blind = %+v", b)
	}
	if len(s.edges) != 0 {
		t.Errorf("unresolved target must produce no edge: %+v", s.edges)
	}
}

func TestScriptUnanalyzable(t *testing.T) {
	f := baseFS()
	f.files[cron.CrontabPath] = "0 3 * * * root /opt/lab/scripts/thing\n"
	f.files["/opt/lab/scripts/thing"] = "#!/bin/sh\x00binary\n"

	s := collect(t, f, labIndex())
	sc := s.entities["script|/opt/lab/scripts/thing"]
	if sc.Attributes["analyzable"] != "false" {
		t.Errorf("script attrs = %v", sc.Attributes)
	}
	found := false
	for _, b := range s.blinds {
		if b.Reason == "cron_script_unanalyzable" {
			found = true
		}
	}
	if !found {
		t.Errorf("blinds = %+v, want cron_script_unanalyzable", s.blinds)
	}
	// The script entity and the job->script edge survive; only the
	// nested tracing is skipped.
	if edge(s, "cron_job|/etc/crontab#root#/opt/lab/scripts/thing",
		"script|/opt/lab/scripts/thing", "references") == nil {
		t.Error("job -> script edge missing")
	}
}

func TestTimerUnparsableCalendar(t *testing.T) {
	f := baseFS()
	f.dirs[cron.TimerDir] = []string{"odd.timer"}
	f.files[cron.TimerDir+"/odd.timer"] = "[Timer]\nOnCalendar=Mon..Fri 09:00\nUnit=lab-batch.service\n"

	s := collect(t, f, labIndex())
	tm := s.entities["timer|odd.timer"]
	if tm.Attributes["period_days"] != "" || tm.Attributes["next_run_at"] != "" {
		t.Errorf("unparsable calendar must not claim cadence: %v", tm.Attributes)
	}
	found := false
	for _, b := range s.blinds {
		if b.Reason == "timer_calendar_unparsed" {
			found = true
		}
	}
	if !found {
		t.Errorf("blinds = %+v, want timer_calendar_unparsed", s.blinds)
	}
	// The unit edge is independent of calendar parsing.
	if edge(s, "systemd_unit|lab-batch.service", "timer|odd.timer", "scheduled_by") == nil {
		t.Error("scheduled_by edge missing")
	}
}

func TestNilIndexSkipsSnapshotEdges(t *testing.T) {
	f := baseFS()
	// Direct unit and container commands: no snapshot, no edges.
	f.files[cron.CrontabPath] = "0 * * * * root redis-cli ping\n1 1 * * * root systemctl restart lab-batch\n"

	s := collect(t, f, nil)
	if len(s.edges) != 0 {
		t.Errorf("nil index must skip snapshot edges: %+v", s.edges)
	}
	jobs := 0
	for k := range s.entities {
		if strings.HasPrefix(k, "cron_job|") {
			jobs++
		}
	}
	if jobs != 2 {
		t.Errorf("cron_job entities = %d, want 2", jobs)
	}
}

func TestDirectCommandContainerEdge(t *testing.T) {
	f := baseFS()
	f.files[cron.CrontabPath] = "0 * * * * root redis-cli -h 127.0.0.1 ping\n"

	s := collect(t, f, labIndex())
	jobKey := "cron_job|/etc/crontab#root#redis-cli -h 127.0.0.1 ping"
	e := edge(s, jobKey, "container|abc123", "references")
	if e == nil {
		t.Fatalf("missing direct command edge; edges=%+v", s.edges)
	}
	if e.Strength != collector.StrengthStrongHeuristic {
		t.Errorf("strength = %s", e.Strength)
	}
	if e.EvidenceRef != "cron-job:"+jobKey {
		t.Errorf("evidence ref = %q, want the job line", e.EvidenceRef)
	}
}

func TestSourceUnreadableBlindSpot(t *testing.T) {
	f := baseFS()
	f.fileErr[cron.CrontabPath] = os.ErrPermission

	s := collect(t, f, nil)
	if len(s.blinds) != 1 || s.blinds[0].Reason != "cron_source_unreadable" {
		t.Fatalf("blinds = %+v", s.blinds)
	}
	if s.blinds[0].Detail["file"] != cron.CrontabPath {
		t.Errorf("detail = %v", s.blinds[0].Detail)
	}
}

func TestIndexErrorPropagates(t *testing.T) {
	idx := &fakeIndex{err: os.ErrClosed}
	c := New(baseFS(), idx)
	err := c.Collect(context.Background(), newRecSink())
	if err == nil {
		t.Fatal("index error must surface")
	}
}

func TestUnreadableScriptBlindSpot(t *testing.T) {
	f := baseFS()
	f.files[cron.CrontabPath] = "0 4 * * * root /opt/lab/scripts/locked.sh\n"
	f.fileErr["/opt/lab/scripts/locked.sh"] = os.ErrPermission

	s := collect(t, f, nil)
	found := false
	for _, b := range s.blinds {
		if b.Reason == "cron_script_unreadable" &&
			b.Detail["path"] == "/opt/lab/scripts/locked.sh" {
			found = true
		}
	}
	if !found {
		t.Fatalf("blinds = %+v, want cron_script_unreadable", s.blinds)
	}
	if len(s.findings) != 0 {
		t.Errorf("unreadable is a blind spot, not ORPHAN_CRON: %+v", s.findings)
	}
	if _, ok := s.entities["script|/opt/lab/scripts/locked.sh"]; ok {
		t.Error("unreadable content must not mint a script entity")
	}
}

func TestUnknownUnitAndTimerWithoutTarget(t *testing.T) {
	f := baseFS()
	// Unit missing from the snapshot: no edge, no blind spot (the
	// systemd collector owns unit truth).
	f.files[cron.CrontabPath] = "0 2 * * * root systemctl restart nowhere.service\n"
	f.dirs[cron.TimerDir] = []string{"loose.timer"}
	f.files[cron.TimerDir+"/loose.timer"] = "[Timer]\nOnCalendar=daily\n"

	s := collect(t, f, labIndex())
	if len(s.edges) != 0 {
		t.Errorf("unknown unit and Unit-less timer must produce no edge: %+v", s.edges)
	}
	tm := s.entities["timer|loose.timer"]
	if tm.Attributes["period_days"] != "1" {
		t.Errorf("keyword calendar must still parse: %v", tm.Attributes)
	}
}

func TestUnitSuffixNormalization(t *testing.T) {
	f := baseFS()
	// Bare unit name without .service must still match the snapshot.
	f.files[cron.CrontabPath] = "0 2 * * * root systemctl restart lab-batch\n"

	s := collect(t, f, labIndex())
	if edge(s, "cron_job|/etc/crontab#root#systemctl restart lab-batch",
		"systemd_unit|lab-batch.service", "references") == nil {
		t.Fatalf("missing normalized unit edge; edges=%+v", s.edges)
	}
}

func TestContainerMatchThroughFullImageRef(t *testing.T) {
	f := baseFS()
	f.files[cron.CrontabPath] = "0 2 * * * root redis-cli ping\n"
	idx := &fakeIndex{
		containers: []collector.ContainerRow{
			{IdentityKey: "container|zz", Name: "cache",
				Image: "docker.io/library/redis:7-alpine"},
		},
	}
	sink := newRecSink()
	if err := sink.UpsertEntity(collector.Entity{Kind: "container", Name: "cache",
		IdentityKey: "container|zz", Fingerprint: "z"}); err != nil {
		t.Fatal(err)
	}
	if err := New(f, idx).Collect(context.Background(), sink); err != nil {
		t.Fatal(err)
	}
	if edge(sink, "cron_job|/etc/crontab#root#redis-cli ping",
		"container|zz", "references") == nil {
		t.Fatalf("alias must match registry-qualified image; edges=%+v", sink.edges)
	}
}

func TestNameAndVersion(t *testing.T) {
	c := New(nil, nil)
	if c.Name() != "cron" || c.Version() != "1.0.0" {
		t.Errorf("Name/Version = %q/%q", c.Name(), c.Version())
	}
	// nil filesystem falls back to the real one without panicking.
	if c.fsys == nil {
		t.Error("New(nil) must install the OS filesystem")
	}
}
