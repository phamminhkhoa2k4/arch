package socketactivation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"archaeologist/internal/collector"
	"archaeologist/internal/store"
	"archaeologist/internal/systemd"
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
		return fmt.Errorf("finding %s: unknown entity %q", f.Kind, f.EntityIdentityKey)
	}
	if f.EvidenceRef != "" && !r.refs[f.EvidenceRef] {
		return fmt.Errorf("finding %s: unknown evidence ref %q", f.Kind, f.EvidenceRef)
	}
	r.findings = append(r.findings, f)
	return nil
}

// fakeIndex serves fixed snapshots.
type fakeIndex struct {
	units     []collector.UnitRow
	listeners []collector.ListenerRow
	err       error
}

func (f *fakeIndex) UnitRows() ([]collector.UnitRow, error) { return f.units, f.err }
func (f *fakeIndex) ListenerRows() ([]collector.ListenerRow, error) {
	return f.listeners, f.err
}

type failingIndex struct{}

func (failingIndex) UnitRows() ([]collector.UnitRow, error) { return nil, errIndex }
func (failingIndex) ListenerRows() ([]collector.ListenerRow, error) {
	return nil, errIndex
}

var errIndex = errors.New("index down")

// writeUnits materializes unit files in a temp dir and returns a
// loader rooted there plus the directory.
func writeUnits(t *testing.T, files map[string]string) (*systemd.Loader, string) {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return systemd.LoadDir(systemd.OSFS{}, dir), dir
}

func evidenceByRef(evs []collector.Evidence) map[string]collector.Evidence {
	out := map[string]collector.Evidence{}
	for _, e := range evs {
		out[e.Ref] = e
	}
	return out
}

func edgeSet(edges []collector.Edge) map[string]collector.Edge {
	out := map[string]collector.Edge{}
	for _, e := range edges {
		out[e.Kind+" "+e.SrcIdentityKey+"->"+e.DstIdentityKey] = e
	}
	return out
}

func hasBlind(sink *recSink, reason string) bool {
	for _, b := range sink.blinds {
		if b.Reason == reason {
			return true
		}
	}
	return false
}

// An active socket unit with the default Service= target produces its
// configuration evidence, the activates edge to the service, and
// listens_on edges to every live listener matching its declared port
// on both address families.
func TestCollectActivatesServiceOnDemand(t *testing.T) {
	loader, dir := writeUnits(t, map[string]string{
		"ssh.socket": "[Unit]\nDescription=SSH socket\n\n" +
			"[Socket]\nListenStream=22\nAccept=no\n",
	})
	sockPath := filepath.Join(dir, "ssh.socket")
	idx := &fakeIndex{
		units: []collector.UnitRow{
			{IdentityKey: "systemd_unit|ssh.service", Name: "ssh.service",
				Attributes: map[string]string{"active_state": "inactive"}},
			{IdentityKey: "systemd_unit|ssh.socket", Name: "ssh.socket",
				Attributes: map[string]string{
					"fragment_path": sockPath,
					"active_state":  "active",
				}},
		},
		listeners: []collector.ListenerRow{
			{IdentityKey: "listener|tcp|0.0.0.0|22|777", Name: "0.0.0.0:22"},
			{IdentityKey: "listener|tcp6|::|22|888", Name: "[::]:22"},
			{IdentityKey: "listener|tcp|0.0.0.0|8080|999", Name: "0.0.0.0:8080"},
		},
	}
	sink := newRecSink()
	if err := seedUnits(sink, idx.units, idx.listeners); err != nil {
		t.Fatal(err)
	}
	c := New(loader, idx)
	if err := c.Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	key := "systemd_unit|ssh.socket"
	ev := evidenceByRef(sink.evidence)
	activate, ok := ev["socket-activate:ssh.socket"]
	if !ok {
		t.Fatalf("evidence = %+v, want socket-activate:ssh.socket", sink.evidence)
	}
	if activate.Channel != "systemd_socket" ||
		activate.Polarity != collector.PolarityInUse ||
		activate.Strength != collector.StrengthDeterministic {
		t.Errorf("activate evidence = %+v", activate)
	}
	if activate.Value["service"] != "ssh.service" || activate.Value["accept"] != "no" {
		t.Errorf("value = %+v", activate.Value)
	}
	if activate.Value["listen"] != "22" {
		t.Errorf("listen = %q, want 22", activate.Value["listen"])
	}
	if activate.RawRef == "" {
		t.Error("raw_ref must point at the unit file")
	}
	if activate.ObservedAt == "" {
		t.Error("observed_at must be set")
	}

	edges := edgeSet(sink.edges)
	if _, ok := edges["activates systemd_unit|ssh.socket->systemd_unit|ssh.service"]; !ok {
		t.Errorf("activates edge missing: %+v", sink.edges)
	}
	for _, lk := range []string{"listener|tcp|0.0.0.0|22|777", "listener|tcp6|::|22|888"} {
		if _, ok := edges["listens_on "+lk+"->"+key]; !ok {
			t.Errorf("listens_on edge from %s missing: %+v", lk, sink.edges)
		}
	}
	if _, ok := edges["listens_on listener|tcp|0.0.0.0|8080|999->"+key]; ok {
		t.Error("unrelated listener must not match the declared port")
	}
	listenEv, ok := ev["socket-listen:ssh.socket:"+sockPath+":5"]
	if !ok || listenEv.Value["port"] != "22" || listenEv.Value["proto"] != "tcp" {
		t.Errorf("listen evidence = %+v", listenEv)
	}
	if len(sink.blinds) != 0 {
		t.Errorf("unexpected blinds: %+v", sink.blinds)
	}
}

// An explicit Service= directive wins over the same-name default.
func TestCollectExplicitServiceDirective(t *testing.T) {
	loader, dir := writeUnits(t, map[string]string{
		"lab.socket": "[Socket]\nListenStream=9090\nService=lab-worker.service\n",
	})
	sockPath := filepath.Join(dir, "lab.socket")
	idx := &fakeIndex{units: []collector.UnitRow{
		{IdentityKey: "systemd_unit|lab.socket", Name: "lab.socket",
			Attributes: map[string]string{"fragment_path": sockPath}},
		{IdentityKey: "systemd_unit|lab-worker.service", Name: "lab-worker.service"},
	}}
	sink := newRecSink()
	if err := seedUnits(sink, idx.units, nil); err != nil {
		t.Fatal(err)
	}
	if err := New(loader, idx).Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	ev := evidenceByRef(sink.evidence)["socket-activate:lab.socket"]
	if ev.Value["service"] != "lab-worker.service" {
		t.Errorf("service = %q", ev.Value["service"])
	}
	edges := edgeSet(sink.edges)
	if _, ok := edges["activates systemd_unit|lab.socket->systemd_unit|lab-worker.service"]; !ok {
		t.Errorf("explicit activates edge missing: %+v", sink.edges)
	}
}

// An explicit Service= carrying a reference this scan cannot expand
// is reported as a blind spot; no edge and no target are guessed.
func TestCollectUnresolvedServiceReportsBlind(t *testing.T) {
	loader, dir := writeUnits(t, map[string]string{
		"app.socket": "[Socket]\nListenStream=7000\nService=app-%H.service\n",
	})
	sockPath := filepath.Join(dir, "app.socket")
	idx := &fakeIndex{units: []collector.UnitRow{
		{IdentityKey: "systemd_unit|app.socket", Name: "app.socket",
			Attributes: map[string]string{"fragment_path": sockPath}},
		{IdentityKey: "systemd_unit|app.service", Name: "app.service"},
	}}
	sink := newRecSink()
	if err := seedUnits(sink, idx.units, nil); err != nil {
		t.Fatal(err)
	}
	if err := New(loader, idx).Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !hasBlind(sink, "socket_service_unresolved") {
		t.Errorf("blinds = %+v, want socket_service_unresolved", sink.blinds)
	}
	for _, b := range sink.blinds {
		if b.Reason == "socket_service_unresolved" &&
			(b.Channel != "systemd_socket" || b.Detail["service"] != "app-%H.service") {
			t.Errorf("blind = %+v", b)
		}
	}
	for _, e := range sink.edges {
		if e.Kind == "activates" {
			t.Errorf("no activates edge may exist without a resolved target: %+v", e)
		}
	}
	ev := evidenceByRef(sink.evidence)["socket-activate:app.socket"]
	if ev.Value["service"] != "" {
		t.Errorf("service = %q, want empty while unresolved", ev.Value["service"])
	}
}

// A socket unit whose file cannot be found (transient unit) is
// reported; the gap attaches to the unit instead of a guessed target.
func TestCollectMissingUnitFileBlind(t *testing.T) {
	loader, _ := writeUnits(t, map[string]string{})
	idx := &fakeIndex{units: []collector.UnitRow{
		{IdentityKey: "systemd_unit|gone.socket", Name: "gone.socket",
			Attributes: map[string]string{
				"fragment_path": filepath.Join(t.TempDir(), "gone.socket"),
			}},
	}}
	sink := newRecSink()
	if err := seedUnits(sink, idx.units, nil); err != nil {
		t.Fatal(err)
	}
	if err := New(loader, idx).Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !hasBlind(sink, "socket_unit_missing") {
		t.Errorf("blinds = %+v, want socket_unit_missing", sink.blinds)
	}
	if len(sink.evidence) != 0 {
		t.Errorf("no evidence may exist without the file: %+v", sink.evidence)
	}
}

// An unreadable socket unit file (here: the fragment points at a
// directory) is a permission-class blind spot on the unit.
func TestCollectUnreadableUnitFileBlind(t *testing.T) {
	loader, _ := writeUnits(t, map[string]string{"ok.socket": "[Socket]\nListenStream=1\n"})
	idx := &fakeIndex{units: []collector.UnitRow{
		{IdentityKey: "systemd_unit|locked.socket", Name: "locked.socket",
			Attributes: map[string]string{"fragment_path": t.TempDir()}},
	}}
	sink := newRecSink()
	if err := seedUnits(sink, idx.units, nil); err != nil {
		t.Fatal(err)
	}
	if err := New(loader, idx).Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !hasBlind(sink, "socket_unit_unreadable") {
		t.Errorf("blinds = %+v, want socket_unit_unreadable", sink.blinds)
	}
}

// Non-socket units are the systemd collector's inventory: this
// collector never reads or reports them.
func TestCollectSkipsNonSocketUnits(t *testing.T) {
	loader, dir := writeUnits(t, map[string]string{
		"lab.service": "[Service]\nExecStart=/bin/true\n",
	})
	svcPath := filepath.Join(dir, "lab.service")
	idx := &fakeIndex{units: []collector.UnitRow{
		{IdentityKey: "systemd_unit|lab.service", Name: "lab.service",
			Attributes: map[string]string{"fragment_path": svcPath}},
	}}
	sink := newRecSink()
	if err := seedUnits(sink, idx.units, nil); err != nil {
		t.Fatal(err)
	}
	if err := New(loader, idx).Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(sink.evidence) != 0 || len(sink.blinds) != 0 || len(sink.edges) != 0 {
		t.Errorf("non-socket unit produced output: %+v", sink)
	}
}

// An inactive socket with no live listener yields neutral evidence
// and no edges — nothing is claimed to be listening.
func TestCollectInactiveSocketWithoutListenerIsQuiet(t *testing.T) {
	loader, dir := writeUnits(t, map[string]string{
		"idle.socket": "[Socket]\nListenStream=6500\n",
	})
	sockPath := filepath.Join(dir, "idle.socket")
	idx := &fakeIndex{units: []collector.UnitRow{
		{IdentityKey: "systemd_unit|idle.socket", Name: "idle.socket",
			Attributes: map[string]string{"fragment_path": sockPath}},
	}}
	sink := newRecSink()
	if err := seedUnits(sink, idx.units, nil); err != nil {
		t.Fatal(err)
	}
	if err := New(loader, idx).Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	ev := evidenceByRef(sink.evidence)["socket-activate:idle.socket"]
	if ev.Polarity != collector.PolarityNeutral {
		t.Errorf("polarity = %q, want neutral", ev.Polarity)
	}
	if len(sink.edges) != 0 {
		t.Errorf("no edges without a live listener: %+v", sink.edges)
	}
	if len(sink.blinds) != 0 {
		t.Errorf("unexpected blinds: %+v", sink.blinds)
	}
}

func TestCollectNoIndexReturnsNil(t *testing.T) {
	loader, _ := writeUnits(t, map[string]string{})
	sink := newRecSink()
	if err := New(loader, nil).Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(sink.evidence) != 0 || len(sink.blinds) != 0 {
		t.Errorf("version-only collector produced output: %+v", sink)
	}
}

func TestCollectIndexErrorReturns(t *testing.T) {
	loader, _ := writeUnits(t, map[string]string{})
	sink := newRecSink()
	if err := New(loader, failingIndex{}).Collect(context.Background(), sink); !errors.Is(err, errIndex) {
		t.Errorf("Collect error = %v, want the index error", err)
	}
}

func TestParseListen(t *testing.T) {
	cases := []struct {
		key   string
		value string
		proto string
		port  int
	}{
		{"ListenStream", "22", "tcp", 22},
		{"ListenStream", "0.0.0.0:8080", "tcp", 8080},
		{"ListenStream", "[::1]:9090", "tcp", 9090},
		{"ListenStream", "localhost:53", "tcp", 53},
		{"ListenDatagram", "127.0.0.1:5353", "udp", 5353},
		{"ListenStream", "/run/docker.sock", "", 0},
		{"ListenStream", "@abstract-sock", "", 0},
		{"ListenStream", "not-a-port", "", 0},
		{"ListenStream", "70000", "", 0},
		{"ListenSequentially", "/run/seq.sock", "", 0},
		{"ListenNetlink", "audit", "", 0},
		{"ListenStream", "", "", 0},
	}
	for _, tc := range cases {
		proto, port := parseListen(tc.key, tc.value)
		if proto != tc.proto || port != tc.port {
			t.Errorf("parseListen(%s, %q) = %q %d, want %q %d",
				tc.key, tc.value, proto, port, tc.proto, tc.port)
		}
	}
}

func TestCollectSchemaAcceptsRows(t *testing.T) {
	// Run the collector against a real store sink to prove every
	// evidence and edge it emits satisfies the database constraints.
	tmp := t.TempDir()
	db := filepath.Join(tmp, "scan.db")
	st, err := store.Open(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	hostID, err := st.InsertHost(ctx, "lab", "linux", "test")
	if err != nil {
		t.Fatal(err)
	}
	scanID, err := st.InsertScan(ctx, hostID, "v", "{}")
	if err != nil {
		t.Fatal(err)
	}
	sink := store.NewScanSink(ctx, st, scanID)

	loader, dir := writeUnits(t, map[string]string{
		"ssh.socket": "[Socket]\nListenStream=22\n",
	})
	sockPath := filepath.Join(dir, "ssh.socket")
	idx := &fakeIndex{
		units: []collector.UnitRow{
			{IdentityKey: "systemd_unit|ssh.socket", Name: "ssh.socket",
				Attributes: map[string]string{"fragment_path": sockPath}},
			{IdentityKey: "systemd_unit|ssh.service", Name: "ssh.service"},
		},
		listeners: []collector.ListenerRow{
			{IdentityKey: "listener|tcp|0.0.0.0|22|777", Name: "0.0.0.0:22"},
		},
	}
	if err := seedUnitsToSink(sink, idx.units, idx.listeners); err != nil {
		t.Fatal(err)
	}
	if err := New(loader, idx).Collect(ctx, sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
}

// seedUnits registers the fixture entities so the strict sink accepts
// the collector's evidence and edges.
func seedUnits(sink *recSink, units []collector.UnitRow, listeners []collector.ListenerRow) error {
	for _, u := range units {
		if err := sink.UpsertEntity(collector.Entity{
			Kind: "systemd_unit", Name: u.Name, IdentityKey: u.IdentityKey,
			Attributes: u.Attributes,
		}); err != nil {
			return err
		}
	}
	for _, lr := range listeners {
		if err := sink.UpsertEntity(collector.Entity{
			Kind: "listener", Name: lr.Name, IdentityKey: lr.IdentityKey,
		}); err != nil {
			return err
		}
	}
	return nil
}

// seedUnitsToSink is seedUnits against the shared Sink interface.
func seedUnitsToSink(sink collector.Sink, units []collector.UnitRow, listeners []collector.ListenerRow) error {
	for _, u := range units {
		if err := sink.UpsertEntity(collector.Entity{
			Kind: "systemd_unit", Name: u.Name, IdentityKey: u.IdentityKey,
			Attributes: u.Attributes,
		}); err != nil {
			return err
		}
	}
	for _, lr := range listeners {
		if err := sink.UpsertEntity(collector.Entity{
			Kind: "listener", Name: lr.Name, IdentityKey: lr.IdentityKey,
		}); err != nil {
			return err
		}
	}
	return nil
}
