package podman

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"archaeologist/internal/collector"
	"archaeologist/internal/docker"
	"archaeologist/internal/store"
)

const (
	idA    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	idB    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	idGone = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	img1   = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	img2   = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	img3   = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
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

// fakeAPI serves a fixed inventory with a per-endpoint error.
type fakeAPI struct {
	containers    []docker.Container
	images        []docker.Image
	volumes       []docker.Volume
	networks      []docker.Network
	containersErr error
	imagesErr     error
	volumesErr    error
	networksErr   error
	logs          map[string]time.Time // container id → newest log line
	logErrs       map[string]error
	logCalls      int
}

func (f *fakeAPI) Containers() ([]docker.Container, error) { return f.containers, f.containersErr }
func (f *fakeAPI) Images() ([]docker.Image, error)         { return f.images, f.imagesErr }
func (f *fakeAPI) Volumes() ([]docker.Volume, error)       { return f.volumes, f.volumesErr }
func (f *fakeAPI) Networks() ([]docker.Network, error)     { return f.networks, f.networksErr }

func (f *fakeAPI) ContainerLogs(id string, _ bool) (time.Time, bool, error) {
	f.logCalls++
	if err, ok := f.logErrs[id]; ok {
		return time.Time{}, false, err
	}
	ts, ok := f.logs[id]
	return ts, ok, nil
}

// fakeIndex serves fixed snapshots.
type fakeIndex struct {
	byContainer map[string][]collector.ProcessRow
	listeners   []collector.ListenerRow
	err         error
}

func (f *fakeIndex) ProcessRowsByContainer() (map[string][]collector.ProcessRow, error) {
	return f.byContainer, f.err
}
func (f *fakeIndex) ListenerRows() ([]collector.ListenerRow, error) { return f.listeners, f.err }

func baseInventory() *fakeAPI {
	return &fakeAPI{
		containers: []docker.Container{
			{
				ID: idA, Names: []string{"/lab-web-1"}, Image: "nginx:1.28", ImageID: img1,
				State: "running", Status: "Up 2 hours",
				Ports:     []docker.Port{{IP: "0.0.0.0", PrivatePort: 80, PublicPort: 8081, Type: "tcp"}},
				Labels:    map[string]string{},
				CreatedAt: "2026-10-05T10:00:00Z", StartedAt: "2026-10-05T10:00:05Z",
				NetworkMode: "lab_default", RestartPol: "always",
				Networks: []string{"lab_default"}, Volumes: []string{"voldata"},
			},
			{
				ID: idB, Names: []string{"lab-worker-1"}, Image: "busybox:1.36", ImageID: img2,
				State: "exited", Status: "Exited (0) 3 minutes ago",
				Ports:     []docker.Port{},
				Labels:    map[string]string{},
				CreatedAt: "2026-10-05T09:00:00Z", StartedAt: "0001-01-01T00:00:00Z",
				NetworkMode: "host", RestartPol: "no",
			},
		},
		images: []docker.Image{
			{ID: img1, Tags: []string{"nginx:1.28"}, Size: 67_000_000},
			{ID: img2, Tags: []string{"busybox:1.36"}, Size: 2_000_000},
			{ID: img3, Tags: []string{"ubuntu:24.04"}, Size: 119_000_000},
		},
		volumes: []docker.Volume{
			{Name: "voldata", Driver: "local", CreatedAt: "2026-10-05T09:00:00Z"},
			{Name: "orphan-vol", Driver: "local", CreatedAt: "2026-10-01T00:00:00Z"},
		},
		networks: []docker.Network{
			{ID: "n1", Name: "podman", Driver: "bridge", Scope: "local"},
			{ID: "n2", Name: "lab_default", Driver: "bridge", Scope: "local"},
		},
	}
}

// newTestCollector points the collector at a stand-in socket file and
// serves the fake inventory through the injected dialer.
func newTestCollector(t *testing.T, api docker.API, index Index) *Collector {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "podman.sock")
	if err := os.WriteFile(sock, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	c := New(index)
	c.sockets = []string{sock}
	c.dial = func(string) docker.API { return api }
	return c
}

func collect(t *testing.T, api docker.API, index Index) *recSink {
	t.Helper()
	c := newTestCollector(t, api, index)
	sink := newRecSink()
	if index != nil {
		if rows, err := index.ListenerRows(); err == nil {
			for _, r := range rows {
				if err := sink.UpsertEntity(collector.Entity{
					Kind: "listener", Name: r.Name, IdentityKey: r.IdentityKey,
				}); err != nil {
					t.Fatal(err)
				}
			}
		}
		if byID, err := index.ProcessRowsByContainer(); err == nil {
			for _, rows := range byID {
				for _, r := range rows {
					if err := sink.UpsertEntity(collector.Entity{
						Kind: "process", Name: r.IdentityKey, IdentityKey: r.IdentityKey,
					}); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	}
	if err := c.Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return sink
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

func TestCollectInventory(t *testing.T) {
	sink := collect(t, baseInventory(), nil)

	ca := sink.entities["podman_container|"+idA]
	if ca.Kind != "podman_container" || ca.Name != "lab-web-1" {
		t.Errorf("container A = %+v", ca)
	}
	// Names without a leading slash must survive intact.
	cb := sink.entities["podman_container|"+idB]
	if cb.Name != "lab-worker-1" {
		t.Errorf("container B name = %q, want lab-worker-1", cb.Name)
	}
	want := map[string]string{
		"image": "nginx:1.28", "state": "running", "status": "Up 2 hours",
		"created_at": "2026-10-05T10:00:00Z", "started_at": "2026-10-05T10:00:05Z",
		"restart_policy": "always", "network_mode": "lab_default",
		"ports": "8081:80/tcp", "networks": "lab_default", "volumes": "voldata",
	}
	for k, v := range want {
		if ca.Attributes[k] != v {
			t.Errorf("attr %s = %q, want %q", k, ca.Attributes[k], v)
		}
	}
	if _, ok := ca.Attributes["compose_project"]; ok {
		t.Error("podman containers must not carry compose attributes")
	}
	if ca.Fingerprint == "" {
		t.Error("container fingerprint must not be empty")
	}
	if sink.entities["podman_image|"+img1].Kind != "podman_image" {
		t.Error("img1 entity missing")
	}
	if sink.entities["podman_volume|voldata"].Kind != "podman_volume" {
		t.Error("voldata entity missing")
	}
	if sink.entities["podman_network|lab_default"].Kind != "podman_network" {
		t.Error("lab_default network entity missing")
	}

	ev := evidenceByRef(sink.evidence)
	if e, ok := ev["podman-container-state:"+idA]; !ok || e.Polarity != collector.PolarityInUse {
		t.Errorf("state evidence A = %+v, want in_use", e)
	}
	if e, ok := ev["podman-container-state:"+idB]; !ok || e.Polarity != collector.PolarityNeutral {
		t.Errorf("state evidence B = %+v, want neutral", e)
	}
	if e, ok := ev["podman-container-created:"+idA]; !ok || e.Channel != "podman_created" ||
		e.Value["last_deploy_at"] != "2026-10-05T10:00:00Z" {
		t.Errorf("created evidence = %+v", e)
	}
	for _, e := range sink.evidence {
		if e.Channel != "podman" && e.Channel != "podman_created" && e.Channel != "podman_log" {
			t.Errorf("evidence = %+v, want podman channel family", e)
		}
		if e.RawRef == "" {
			t.Errorf("evidence = %+v, empty raw_ref", e)
		}
	}
	if len(sink.blinds) != 0 {
		t.Errorf("unexpected blind spots: %+v", sink.blinds)
	}
}

func TestCollectUnusedFindsAndWarns(t *testing.T) {
	sink := collect(t, baseInventory(), nil)

	byKind := map[string][]collector.Finding{}
	for _, f := range sink.findings {
		byKind[f.Kind] = append(byKind[f.Kind], f)
	}
	if len(byKind["UNUSED_IMAGE"]) != 1 ||
		byKind["UNUSED_IMAGE"][0].EntityIdentityKey != "podman_image|"+img3 {
		t.Errorf("UNUSED_IMAGE = %+v, want only img3", byKind["UNUSED_IMAGE"])
	}
	if len(byKind["UNUSED_VOLUME"]) != 1 ||
		byKind["UNUSED_VOLUME"][0].EntityIdentityKey != "podman_volume|orphan-vol" {
		t.Errorf("UNUSED_VOLUME = %+v, want only orphan-vol", byKind["UNUSED_VOLUME"])
	}
	if ev := evidenceByRef(sink.evidence)["podman-volume-list:voldata"]; ev.Value["used"] != "true" {
		t.Errorf("voldata evidence = %+v, want used=true", ev.Value)
	}
}

func TestCollectListensOnPublishedPort(t *testing.T) {
	idx := &fakeIndex{listeners: []collector.ListenerRow{
		{IdentityKey: "listener|tcp|127.0.0.1|8081|4242", Name: "127.0.0.1:8081"},
		{IdentityKey: "listener|udp|0.0.0.0|8081|4343", Name: "0.0.0.0:8081/udp"},
	}}
	sink := collect(t, baseInventory(), idx)

	edges := edgeSet(sink.edges)
	if _, ok := edges["listens_on listener|tcp|127.0.0.1|8081|4242->podman_container|"+idA]; !ok {
		t.Errorf("listens_on edge missing: %+v", sink.edges)
	}
	if _, ok := edges["listens_on listener|udp|0.0.0.0|8081|4343->podman_container|"+idA]; ok {
		t.Error("udp listener must not match a tcp published port")
	}
	ev := evidenceByRef(sink.evidence)
	if e, ok := ev["podman-port-published:"+idA+":tcp:8081"]; !ok || e.RawRef == "" {
		t.Errorf("port-published evidence = %+v", e)
	}
}

func TestCollectManagesContainerProcesses(t *testing.T) {
	idx := &fakeIndex{byContainer: map[string][]collector.ProcessRow{
		idA:    {{IdentityKey: "process|100|111", Owner: idA}},
		idGone: {{IdentityKey: "process|101|222", Owner: idGone}}, // not in API: skip
	}}
	sink := collect(t, baseInventory(), idx)

	edges := edgeSet(sink.edges)
	if _, ok := edges["manages podman_container|"+idA+"->process|100|111"]; !ok {
		t.Errorf("manages edge missing: %+v", sink.edges)
	}
	if _, ok := edges["manages podman_container|"+idGone+"->process|101|222"]; ok {
		t.Error("process in unknown container must not gain an owner edge")
	}
	if e, ok := edges["manages podman_container|"+idA+"->process|100|111"]; ok &&
		e.EvidenceRef != "podman-container-state:"+idA {
		t.Errorf("manages evidence ref = %q", e.EvidenceRef)
	}
}

func TestCollectNotInstalledReturnsNil(t *testing.T) {
	c := New(nil)
	c.sockets = []string{filepath.Join(t.TempDir(), "absent.sock")}
	sink := newRecSink()
	if err := c.Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(sink.entities) != 0 || len(sink.blinds) != 0 {
		t.Errorf("not-installed host produced output: %+v", sink)
	}
}

func TestCollectPicksFirstExistingSocket(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "podman.sock")
	if err := os.WriteFile(live, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	c := New(nil)
	c.sockets = []string{filepath.Join(dir, "absent.sock"), live}
	c.dial = func(string) docker.API { return &fakeAPI{} }
	sink := newRecSink()
	if err := c.Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if c.sock != live {
		t.Errorf("chosen socket = %q, want %q", c.sock, live)
	}
}

// A failed container endpoint becomes a blind spot naming the
// endpoint; the reads that succeeded still yield inventory, and no
// unused claim is ever built on the missing container read.
func TestCollectContainerFailureBlindAndPartialInventory(t *testing.T) {
	api := baseInventory()
	api.containersErr = errors.New("permission denied")
	sink := collect(t, api, nil)

	var blind *collector.BlindSpot
	for i := range sink.blinds {
		if sink.blinds[i].Reason == "podman_api_unreadable" {
			blind = &sink.blinds[i]
		}
	}
	if blind == nil {
		t.Fatalf("blinds = %+v, want podman_api_unreadable", sink.blinds)
	}
	if blind.Channel != "podman" || blind.Detail["endpoint"] != "containers" ||
		blind.Detail["socket"] == "" {
		t.Errorf("blind = %+v", blind)
	}
	if _, ok := sink.entities["podman_container|"+idA]; ok {
		t.Error("no container entity may exist when the endpoint failed")
	}
	// Inventory from healthy endpoints still lands.
	if sink.entities["podman_image|"+img3].Kind != "podman_image" {
		t.Error("image inventory missing after container failure")
	}
	if sink.entities["podman_network|podman"].Kind != "podman_network" {
		t.Error("network inventory missing after container failure")
	}
	// ...but absence is never asserted without the container read.
	for _, f := range sink.findings {
		t.Errorf("no UNUSED claim without the container read: %+v", f)
	}
	if ev := evidenceByRef(sink.evidence)["podman-image-list:"+img3]; ev.Value["used"] != "" {
		t.Errorf("used must stay unclaimed, got %q", ev.Value["used"])
	}
	// Ports and ownership need the container read too.
	for _, e := range sink.edges {
		t.Errorf("no edges without the container read: %+v", e)
	}
}

func TestCollectLogEvidenceAndBlinds(t *testing.T) {
	api := baseInventory()
	ts := time.Date(2026, 10, 6, 8, 30, 0, 0, time.UTC)
	api.logs = map[string]time.Time{idA: ts}
	sink := collect(t, api, nil)

	ev := evidenceByRef(sink.evidence)
	if e, ok := ev["podman-container-log:"+idA]; !ok || e.Channel != "podman_log" ||
		e.Value["last_log_at"] != ts.Format(time.RFC3339) {
		t.Errorf("log evidence = %+v", e)
	}
	if got := sink.entities["podman_container|"+idA].Attributes["last_log_at"]; got != ts.Format(time.RFC3339) {
		t.Errorf("attr last_log_at = %q", got)
	}
	if _, ok := ev["podman-container-log:"+idB]; ok {
		t.Error("container B has no log line; no evidence expected")
	}

	// An unsupported driver is reported without reaching the API:
	// only the other container (default driver) is queried.
	api2 := baseInventory()
	api2.containers[0].LogDriver = "syslog"
	sink2 := collect(t, api2, nil)
	if !hasBlind(sink2, "log_driver_unsupported") {
		t.Errorf("blinds = %+v, want log_driver_unsupported", sink2.blinds)
	}
	if api2.logCalls != 1 {
		t.Errorf("log API called %d times, want 1 (only the readable container)", api2.logCalls)
	}

	// A read failure is a per-container blind, not a scan failure.
	api3 := baseInventory()
	api3.logErrs = map[string]error{idA: errors.New("driver refused")}
	sink3 := collect(t, api3, nil)
	if !hasBlind(sink3, "podman_log_unreadable") {
		t.Errorf("blinds = %+v, want podman_log_unreadable", sink3.blinds)
	}
}

// The none driver proves logs are disabled: no evidence, no blind.
func TestCollectNoneLogDriverIsQuiet(t *testing.T) {
	api := baseInventory()
	api.containers[0].LogDriver = "none"
	sink := collect(t, api, nil)
	if len(sink.blinds) != 0 {
		t.Errorf("blinds = %+v, want none", sink.blinds)
	}
	if _, ok := evidenceByRef(sink.evidence)["podman-container-log:"+idA]; ok {
		t.Error("no log evidence expected for the none driver")
	}
}

func TestCollectSchemaAcceptsRows(t *testing.T) {
	// Run the collector against a real store sink to prove every
	// entity, evidence, edge and finding it emits satisfies the
	// database constraints.
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

	listenerKey := "listener|tcp|127.0.0.1|8081|4242"
	processKey := "process|100|111"
	for _, e := range []collector.Entity{
		{Kind: "listener", Name: "127.0.0.1:8081", IdentityKey: listenerKey},
		{Kind: "process", Name: "app", IdentityKey: processKey},
	} {
		if err := sink.UpsertEntity(e); err != nil {
			t.Fatal(err)
		}
	}

	idx := &fakeIndex{
		listeners:   []collector.ListenerRow{{IdentityKey: listenerKey, Name: "127.0.0.1:8081"}},
		byContainer: map[string][]collector.ProcessRow{idA: {{IdentityKey: processKey, Owner: idA}}},
	}
	c := newTestCollector(t, baseInventory(), idx)
	if err := c.Collect(ctx, sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
}
