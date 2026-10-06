package systemd

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"archaeologist/internal/collector"
	"archaeologist/internal/systemd"
)

// recSink records everything the collector emits.
type recSink struct {
	entities map[string]collector.Entity
	edges    []collector.Edge
	evidence []collector.Evidence
	blinds   []collector.BlindSpot
	findings []collector.Finding
}

func newRecSink() *recSink { return &recSink{entities: map[string]collector.Entity{}} }

func (r *recSink) UpsertEntity(e collector.Entity) error {
	r.entities[e.IdentityKey] = e
	return nil
}
func (r *recSink) UpsertEdge(e collector.Edge) error {
	r.edges = append(r.edges, e)
	return nil
}
func (r *recSink) AddEvidence(e collector.Evidence) error {
	r.evidence = append(r.evidence, e)
	return nil
}
func (r *recSink) AddBlindSpot(b collector.BlindSpot) error {
	r.blinds = append(r.blinds, b)
	return nil
}
func (r *recSink) AddFinding(f collector.Finding) error {
	r.findings = append(r.findings, f)
	return nil
}

// fakeBus serves a fixed unit list or an error.
type fakeBus struct {
	units []systemd.UnitStatus
	err   error
}

func (b *fakeBus) Units() ([]systemd.UnitStatus, error) { return b.units, b.err }

// fakeIndex serves a fixed process snapshot.
type fakeIndex struct {
	rows map[string][]collector.ProcessRow
	err  error
}

func (i *fakeIndex) ProcessRowsByUnit() (map[string][]collector.ProcessRow, error) {
	return i.rows, i.err
}

// memFS is an in-memory systemd.FS for unit and target files.
type memFS struct {
	files map[string]string
	dirs  map[string][]string
}

func newMemFS() *memFS {
	return &memFS{files: map[string]string{}, dirs: map[string][]string{}}
}

func (f *memFS) ReadFile(p string) ([]byte, error) {
	v, ok := f.files[p]
	if !ok {
		return nil, &os.PathError{Op: "open", Path: p, Err: os.ErrNotExist}
	}
	return []byte(v), nil
}

func (f *memFS) ReadDir(p string) ([]string, error) {
	v, ok := f.dirs[p]
	if !ok {
		return nil, &os.PathError{Op: "open", Path: p, Err: os.ErrNotExist}
	}
	return v, nil
}

func scriptFS() *memFS {
	fs := newMemFS()
	fs.files["/usr/lib/systemd/system/lab-app.service"] =
		"[Unit]\nRequires=database.service\nAfter=database.service\n\n" +
			"[Service]\nEnvironment=APP_HOME=/opt/app\nExecStart=$APP_HOME/bin/worker --queue\n"
	fs.files["/usr/lib/systemd/system/lab-batch.service"] =
		"[Service]\nExecStart=/opt/legacy-worker/run.sh\n"
	fs.files["/usr/lib/systemd/system/lab-dead.service"] =
		"[Unit]\nRequires=missing.target\nWants=alsogone.service\n"
	fs.files["/usr/lib/systemd/system/lab-noenv.service"] =
		"[Service]\nExecStart=$UNDEFINED_VAR/run.sh\n"
	fs.files["/opt/app/bin/worker"] = "\x7fELF\x02fakebinary"
	fs.files["/opt/legacy-worker/run.sh"] = "#!/bin/sh\nexit 0\n"
	return fs
}

func labUnits() []systemd.UnitStatus {
	return []systemd.UnitStatus{
		{Name: "lab-app.service", LoadState: "loaded", ActiveState: "active",
			SubState: "running", UnitFileState: "enabled", Loaded: true,
			FragmentPath:         "/usr/lib/systemd/system/lab-app.service",
			ActiveEnterTimestamp: 1791265178052837},
		{Name: "lab-batch.service", LoadState: "loaded", ActiveState: "inactive",
			SubState: "dead", UnitFileState: "enabled", Loaded: true,
			FragmentPath: "/usr/lib/systemd/system/lab-batch.service"},
		{Name: "lab-dead.service", LoadState: "loaded", ActiveState: "active",
			SubState: "running", UnitFileState: "disabled", Loaded: true,
			FragmentPath: "/usr/lib/systemd/system/lab-dead.service"},
		{Name: "lab-noenv.service", LoadState: "loaded", ActiveState: "active",
			SubState: "running", UnitFileState: "static", Loaded: true,
			FragmentPath: "/usr/lib/systemd/system/lab-noenv.service"},
		// Transient unit: no file on disk, state only from the bus.
		{Name: "session-2.scope", LoadState: "loaded", ActiveState: "active",
			SubState: "running", UnitFileState: "transient", Loaded: true},
		// File-only unit: known from list-unit-files, never loaded.
		{Name: "vendor.service", UnitFileState: "static",
			FragmentPath: "/usr/lib/systemd/system/vendor.service"},
	}
}

func newLabCollector(index ProcessIndex) *Collector {
	return New(&fakeBus{units: labUnits()},
		systemd.LoadDir(scriptFS(), "/usr/lib/systemd/system"), index)
}

// Units become entities with state evidence: active → in_use, inactive →
// neutral; timestamps and file states land in attributes.
func TestCollectEmitsUnitEntitiesWithState(t *testing.T) {
	sink := newRecSink()
	if err := newLabCollector(nil).Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	// 6 units + the script/binary targets resolved from ExecStart.
	if len(sink.entities) != 8 {
		t.Fatalf("got %d entities, want 8: %v", len(sink.entities), keys(sink))
	}
	app := sink.entities["systemd_unit|lab-app.service"]
	if app.Kind != "systemd_unit" || app.Attributes["active_state"] != "active" ||
		app.Attributes["unit_file_state"] != "enabled" ||
		app.Attributes["active_enter_timestamp"] != "1791265178052837" {
		t.Errorf("lab-app attrs = %+v", app.Attributes)
	}
	if app.Fingerprint == "" || app.Fingerprint == sink.entities["systemd_unit|session-2.scope"].Fingerprint {
		t.Error("file-backed and file-less units must have non-empty fingerprints")
	}

	polarity := map[string]collector.Polarity{}
	rawRef := map[string]string{}
	for _, e := range sink.evidence {
		if e.Ref != "" && strings.HasPrefix(e.Ref, "unit-state:") {
			polarity[e.EntityIdentityKey] = e.Polarity
			rawRef[e.EntityIdentityKey] = e.RawRef
		}
	}
	if polarity["systemd_unit|lab-app.service"] != collector.PolarityInUse {
		t.Errorf("active unit polarity = %v, want in_use", polarity["systemd_unit|lab-app.service"])
	}
	if polarity["systemd_unit|lab-batch.service"] != collector.PolarityNeutral {
		t.Errorf("inactive unit polarity = %v, want neutral", polarity["systemd_unit|lab-batch.service"])
	}
	// Provenance: loaded units cite list-units, file-only units
	// list-unit-files; the file-only unit carries no runtime state.
	if rawRef["systemd_unit|lab-app.service"] != "dbus:org.freedesktop.systemd1.Manager.ListUnits" {
		t.Errorf("loaded raw_ref = %q", rawRef["systemd_unit|lab-app.service"])
	}
	vendorKey := "systemd_unit|vendor.service"
	if rawRef[vendorKey] != "dbus:org.freedesktop.systemd1.Manager.ListUnitFiles" {
		t.Errorf("file-only raw_ref = %q", rawRef[vendorKey])
	}
	vendor := sink.entities[vendorKey]
	if _, has := vendor.Attributes["active_state"]; has {
		t.Errorf("file-only unit must not claim active_state: %v", vendor.Attributes)
	}
	if vendor.Attributes["unit_file_state"] != "static" {
		t.Errorf("vendor file state = %v", vendor.Attributes)
	}
	if polarity[vendorKey] != collector.PolarityNeutral {
		t.Errorf("file-only polarity = %v, want neutral", polarity[vendorKey])
	}
}

// ExecStart resolves (env expanded) → script/binary entity + runs_as;
// unresolved env → blind spot, never a guessed path.
func TestCollectExecStartResolutionAndBlindSpots(t *testing.T) {
	sink := newRecSink()
	if err := newLabCollector(nil).Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}

	// $APP_HOME/bin/worker resolved → binary entity + edge.
	bin := sink.entities["binary|/opt/app/bin/worker"]
	if bin.Kind != "binary" || bin.Attributes["unit"] != "lab-app.service" {
		t.Errorf("worker entity = %+v", bin)
	}
	sh := sink.entities["script|/opt/legacy-worker/run.sh"]
	if sh.Kind != "script" {
		t.Errorf("run.sh entity = %+v", sh)
	}
	if !hasEdge(sink, "systemd_unit|lab-app.service", "binary|/opt/app/bin/worker", "runs_as") ||
		!hasEdge(sink, "systemd_unit|lab-batch.service", "script|/opt/legacy-worker/run.sh", "runs_as") {
		t.Errorf("missing runs_as edges: %+v", sink.edges)
	}

	// $UNDEFINED_VAR → blind spot on the unit, no guessed entity.
	if !hasBlind(sink, "systemd_unit|lab-noenv.service", "exec_start_unresolved") {
		t.Errorf("want exec_start_unresolved blind spot, got %+v", sink.blinds)
	}
	for k := range sink.entities {
		if strings.Contains(k, "UNDEFINED") {
			t.Errorf("guessed entity created: %s", k)
		}
	}
}

// Existing targets → deterministic depends_on; missing targets → a
// DANGLING_DEPENDS finding (not a blind spot).
func TestCollectDependsOnAndDanglingFinding(t *testing.T) {
	sink := newRecSink()
	if err := newLabCollector(nil).Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}

	// database.service is not in the unit list → lab-app's Requires and
	// After dangle too (only units we list count as present).
	for _, d := range sink.findings {
		if d.Kind != "DANGLING_DEPENDS" || d.Severity != "warn" {
			t.Errorf("finding = %+v, want DANGLING_DEPENDS/warn", d)
		}
		if d.EntityIdentityKey == "" || d.EvidenceRef == "" {
			t.Errorf("finding must link entity + evidence: %+v", d)
		}
	}
	var dangling []collector.Finding
	for _, d := range sink.findings {
		if d.Kind == "DANGLING_DEPENDS" {
			dangling = append(dangling, d)
		}
	}
	missing := map[string]bool{}
	for _, d := range dangling {
		missing[d.Detail["missing"]] = true
	}
	for _, want := range []string{"database.service", "missing.target", "alsogone.service"} {
		if !missing[want] {
			t.Errorf("missing finding for %s (got %v)", want, missing)
		}
	}
	// Dangling dependencies are findings — no blind spot may claim them.
	for _, b := range sink.blinds {
		if strings.Contains(b.Reason, "depends") || b.Detail["missing"] != "" {
			t.Errorf("dependency gap must be a finding, not a blind spot: %+v", b)
		}
	}
	// A target that IS present produces an edge, not a finding.
	if len(sink.edges) > 0 {
		for _, e := range sink.edges {
			if e.Kind == "depends_on" && e.Strength != collector.StrengthDeterministic {
				t.Errorf("depends_on must be deterministic: %+v", e)
			}
		}
	}
}

// Depends_on edge when both sides exist.
func TestCollectDependsOnEdgeWhenTargetPresent(t *testing.T) {
	fs := scriptFS()
	fs.files["/usr/lib/systemd/system/lab-app.service"] =
		"[Unit]\nRequires=lab-batch.service\n[Service]\nExecStart=/bin/true\n"
	fs.files["/opt/true"] = "\x7fELF"
	bus := &fakeBus{units: labUnits()}
	c := New(bus, systemd.LoadDir(fs, "/usr/lib/systemd/system"), nil)
	sink := newRecSink()
	if err := c.Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if !hasEdge(sink, "systemd_unit|lab-app.service", "systemd_unit|lab-batch.service", "depends_on") {
		t.Errorf("missing depends_on edge: %+v", sink.edges)
	}
}

// Processes are attached to units from the snapshot; processes whose
// cgroup names an unlisted unit are left alone (no guessed owner).
func TestCollectManagesEdgesFromIndex(t *testing.T) {
	idx := &fakeIndex{rows: map[string][]collector.ProcessRow{
		"lab-app.service":    {{IdentityKey: "process|100|555", Owner: "lab-app.service"}},
		"session-2.scope":    {{IdentityKey: "process|200|777", Owner: "session-2.scope"}},
		"not-listed.service": {{IdentityKey: "process|300|888", Owner: "not-listed.service"}},
		"":                   {{IdentityKey: "process|400|999"}}, // outside systemd: no unit key at all
	}}
	sink := newRecSink()
	if err := newLabCollector(idx).Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if !hasEdge(sink, "systemd_unit|lab-app.service", "process|100|555", "manages") {
		t.Errorf("missing manages edge for lab-app: %+v", sink.edges)
	}
	if !hasEdge(sink, "systemd_unit|session-2.scope", "process|200|777", "manages") {
		t.Errorf("transient scope must manage its processes: %+v", sink.edges)
	}
	for _, e := range sink.edges {
		if e.DstIdentityKey == "process|300|888" {
			t.Errorf("unlisted unit must not claim a process: %+v", e)
		}
		if e.Kind == "manages" && e.Strength != collector.StrengthDeterministic {
			t.Errorf("manages must be deterministic: %+v", e)
		}
	}
}

// D-Bus unreachable → Collect returns a clear error; the run loop turns
// it into a channel=systemd blind spot without crashing the scan.
func TestUnreachableBusBecomesBlindSpotNotCrash(t *testing.T) {
	c := New(&fakeBus{err: errors.New("connect system bus: no such socket")},
		systemd.LoadDir(scriptFS(), "/usr/lib/systemd/system"), nil)
	sink := newRecSink()
	err := c.Collect(context.Background(), sink)
	if err == nil || !strings.Contains(err.Error(), "D-Bus") {
		t.Fatalf("err = %v, want clear D-Bus error", err)
	}

	// Through the shared run loop: partial status + blind spot.
	runSink := newRecSink()
	res, runErr := collector.Run(context.Background(),
		[]collector.Collector{c}, runSink)
	if runErr != nil {
		t.Fatalf("run must not fail: %v", runErr)
	}
	if !res.Partial() {
		t.Error("result must be partial")
	}
	if len(runSink.blinds) != 1 || runSink.blinds[0].Channel != "systemd" {
		t.Fatalf("blinds = %+v, want 1 channel=systemd", runSink.blinds)
	}
}

func keys(s *recSink) []string {
	out := make([]string, 0, len(s.entities))
	for k := range s.entities {
		out = append(out, k)
	}
	return out
}

func hasEdge(s *recSink, src, dst, kind string) bool {
	for _, e := range s.edges {
		if e.SrcIdentityKey == src && e.DstIdentityKey == dst && e.Kind == kind {
			return true
		}
	}
	return false
}

func hasBlind(s *recSink, entity, reason string) bool {
	for _, b := range s.blinds {
		if (entity == "" || b.EntityIdentityKey == entity) &&
			(reason == "" || b.Reason == reason) {
			return true
		}
	}
	return false
}
