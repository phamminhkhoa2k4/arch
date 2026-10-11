package docker

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"archaeologist/internal/collector"
	"archaeologist/internal/docker"
)

const (
	idA    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	idB    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	idGone = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	img1   = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	img2   = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	img3   = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	img4   = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
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

// fakeAPI serves a fixed inventory or an error.
type fakeAPI struct {
	containers []docker.Container
	images     []docker.Image
	volumes    []docker.Volume
	networks   []docker.Network
	err        error
	logs       map[string]time.Time // container id → newest log line
	logErrs    map[string]error
	logCalls   int
}

func (f *fakeAPI) Containers() ([]docker.Container, error) { return f.containers, f.err }
func (f *fakeAPI) Images() ([]docker.Image, error)         { return f.images, f.err }
func (f *fakeAPI) Volumes() ([]docker.Volume, error)       { return f.volumes, f.err }
func (f *fakeAPI) Networks() ([]docker.Network, error)     { return f.networks, f.err }

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
				ID: idB, Names: []string{"/lab-worker-1"}, Image: "busybox:1.36", ImageID: img2,
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
			{ID: img4, Tags: []string{"alpine:3.20"}, Size: 8_000_000},
		},
		volumes: []docker.Volume{
			{Name: "voldata", Driver: "local", CreatedAt: "2026-10-05T09:00:00Z"},
			{Name: "orphan-vol", Driver: "local", CreatedAt: "2026-10-01T00:00:00Z"},
		},
		networks: []docker.Network{
			{ID: "n1", Name: "bridge", Driver: "bridge", Scope: "local"},
			{ID: "n2", Name: "lab_default", Driver: "bridge", Scope: "local"},
		},
	}
}

func writeCompose(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "docker-compose.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func edgeSet(edges []collector.Edge) map[string]collector.Edge {
	out := map[string]collector.Edge{}
	for _, e := range edges {
		out[e.Kind+" "+e.SrcIdentityKey+"->"+e.DstIdentityKey] = e
	}
	return out
}

func evidenceByRef(evs []collector.Evidence) map[string]collector.Evidence {
	out := map[string]collector.Evidence{}
	for _, e := range evs {
		out[e.Ref] = e
	}
	return out
}

func TestCollectContainerInventory(t *testing.T) {
	api := baseInventory()
	// container A points at a real compose file for this test
	path := writeCompose(t, "services:\n  web:\n    image: nginx:1.28\n    depends_on:\n      - helper\n  helper:\n    image: busybox\n")
	api.containers[0].Labels = map[string]string{
		"com.docker.compose.project":              "lab",
		"com.docker.compose.service":              "web",
		"com.docker.compose.project.config_files": path,
	}

	sink := newRecSink()
	c := New(api, nil, nil)
	if err := c.Collect(t.Context(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}

	ca := sink.entities["container|"+idA]
	if ca.Kind != "container" || ca.Name != "lab-web-1" {
		t.Errorf("container A = %+v", ca)
	}
	want := map[string]string{
		"image": "nginx:1.28", "state": "running", "status": "Up 2 hours",
		"created_at": "2026-10-05T10:00:00Z", "started_at": "2026-10-05T10:00:05Z",
		"restart_policy": "always", "network_mode": "lab_default",
		"ports": "8081:80/tcp", "networks": "lab_default", "volumes": "voldata",
		"compose_project": "lab", "compose_service": "web",
	}
	for k, v := range want {
		if ca.Attributes[k] != v {
			t.Errorf("attr %s = %q, want %q", k, ca.Attributes[k], v)
		}
	}
	if ca.Fingerprint == "" {
		t.Error("container fingerprint must not be empty")
	}

	// fingerprint changes when the shape changes
	changed := api.containers[0]
	changed.RestartPol = "no"
	if containerFingerprint(changed) == ca.Fingerprint {
		t.Error("restart policy change must change the fingerprint")
	}

	ev := evidenceByRef(sink.evidence)
	if e, ok := ev["container-state:"+idA]; !ok || e.Polarity != collector.PolarityInUse {
		t.Errorf("state evidence A = %+v, want in_use", e)
	}
	if e, ok := ev["container-state:"+idB]; !ok || e.Polarity != collector.PolarityNeutral {
		t.Errorf("state evidence B = %+v, want neutral", e)
	}

	if sink.entities["network|lab_default"].Kind != "network" {
		t.Error("lab_default network entity missing")
	}
	if sink.entities["volume|voldata"].Kind != "volume" {
		t.Error("voldata volume entity missing")
	}
	if len(sink.blinds) != 0 {
		t.Errorf("unexpected blind spots: %+v", sink.blinds)
	}
}

func TestCollectUnusedFindsAndWarns(t *testing.T) {
	sink := newRecSink()
	c := New(baseInventory(), nil, nil)
	if err := c.Collect(t.Context(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}

	byKind := map[string][]collector.Finding{}
	for _, f := range sink.findings {
		byKind[f.Kind] = append(byKind[f.Kind], f)
	}
	images := byKind["UNUSED_IMAGE"]
	if len(images) != 2 {
		t.Fatalf("UNUSED_IMAGE count = %d, want 2 (both unreferenced images)", len(images))
	}
	found := map[string]bool{}
	for _, f := range images {
		found[f.EntityIdentityKey] = true
		if f.Detail["size_bytes"] == "" {
			t.Errorf("UNUSED_IMAGE %s must carry the size", f.EntityIdentityKey)
		}
	}
	if !found["image|"+img3] || !found["image|"+img4] {
		t.Errorf("unused images = %v, want img3 and img4", found)
	}

	vols := byKind["UNUSED_VOLUME"]
	if len(vols) != 1 {
		t.Fatalf("UNUSED_VOLUME count = %d, want 1", len(vols))
	}
	if vols[0].EntityIdentityKey != "volume|orphan-vol" {
		t.Errorf("unused volume = %q", vols[0].EntityIdentityKey)
	}
	w := vols[0].Detail["warning"]
	if !strings.Contains(w, "do not delete without checking") {
		t.Errorf("warning = %q, want data-loss warning", w)
	}

	if ev := evidenceByRef(sink.evidence)["volume-list:voldata"]; ev.Value["used"] != "true" {
		t.Errorf("voldata evidence = %+v, want used=true", ev.Value)
	}
}

func TestCollectComposeMapping(t *testing.T) {
	path := writeCompose(t, "services:\n  web:\n    image: nginx:1.28\n    depends_on:\n      - helper\n  helper:\n    image: busybox\n")
	api := baseInventory()
	api.containers[0].Labels = map[string]string{
		"com.docker.compose.project":              "lab",
		"com.docker.compose.service":              "web",
		"com.docker.compose.project.config_files": path,
	}
	api.containers[1].Labels = map[string]string{
		"com.docker.compose.project":              "lab",
		"com.docker.compose.service":              "helper",
		"com.docker.compose.project.config_files": path,
	}

	sink := newRecSink()
	c := New(api, nil, nil)
	if err := c.Collect(t.Context(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}

	svc := sink.entities["compose_service|lab/web"]
	if svc.Kind != "compose_service" || svc.Fingerprint == "" {
		t.Fatalf("web service = %+v", svc)
	}
	if svc.Attributes["depends_on"] != "helper" {
		t.Errorf("depends_on = %q", svc.Attributes["depends_on"])
	}

	edges := edgeSet(sink.edges)
	if _, ok := edges["belongs_to container|"+idA+"->compose_service|lab/web"]; !ok {
		t.Errorf("belongs_to edge missing: %+v", sink.edges)
	}
	if _, ok := edges["depends_on compose_service|lab/web->compose_service|lab/helper"]; !ok {
		t.Errorf("depends_on edge missing: %+v", sink.edges)
	}
	// container B has no labels: no compose edge for it
	ev := evidenceByRef(sink.evidence)
	if e, ok := ev["container-compose:"+idA]; !ok || e.RawRef == "" {
		t.Errorf("container-compose evidence = %+v", e)
	}
	if e, ok := ev["compose-dep:lab:web:helper"]; !ok || e.RawRef != path+"#web.depends_on" {
		t.Errorf("compose-dep evidence raw_ref = %+v", e)
	}
}

func TestCollectComposeMissingFileBlindSpot(t *testing.T) {
	api := baseInventory()
	missing := filepath.Join(t.TempDir(), "gone.yml")
	api.containers[0].Labels = map[string]string{
		"com.docker.compose.project":              "lab",
		"com.docker.compose.service":              "web",
		"com.docker.compose.project.config_files": missing,
	}

	sink := newRecSink()
	c := New(api, nil, nil)
	if err := c.Collect(t.Context(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}

	if len(sink.blinds) != 1 {
		t.Fatalf("blinds = %+v, want 1", sink.blinds)
	}
	b := sink.blinds[0]
	if b.Reason != "compose_file_not_found" || b.Channel != "docker" {
		t.Errorf("blind spot = %+v", b)
	}
	if b.EntityIdentityKey != "container|"+idA {
		t.Errorf("blind spot entity = %q", b.EntityIdentityKey)
	}
	if b.Detail["path"] != missing {
		t.Errorf("blind spot path = %q", b.Detail["path"])
	}
	// labels still prove the service: entity exists with fallback fingerprint
	svc := sink.entities["compose_service|lab/web"]
	if svc.Kind != "compose_service" || svc.Fingerprint == "" {
		t.Errorf("service entity = %+v, want stable identity without file", svc)
	}
	// and no dependency edge is invented
	edges := edgeSet(sink.edges)
	if _, ok := edges["depends_on compose_service|lab/web->compose_service|lab/helper"]; ok {
		t.Error("dangling dependency must not produce an edge")
	}
}

func TestCollectListensOnPublishedPort(t *testing.T) {
	sink := newRecSink()
	idx := &fakeIndex{listeners: []collector.ListenerRow{
		// listener bound to 127.0.0.1 while container publishes on
		// 0.0.0.0: address must be ignored, only port+proto match
		{IdentityKey: "listener|tcp|127.0.0.1|8081|4242", Name: "127.0.0.1:8081"},
		// wrong proto: must not match
		{IdentityKey: "listener|udp|0.0.0.0|8081|4343", Name: "0.0.0.0:8081/udp"},
	}}
	c := New(baseInventory(), nil, idx)
	if err := c.Collect(t.Context(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}

	edges := edgeSet(sink.edges)
	if _, ok := edges["listens_on listener|tcp|127.0.0.1|8081|4242->container|"+idA]; !ok {
		t.Errorf("listens_on edge missing: %+v", sink.edges)
	}
	if _, ok := edges["listens_on listener|udp|0.0.0.0|8081|4343->container|"+idA]; ok {
		t.Error("udp listener must not match a tcp published port")
	}
	ev := evidenceByRef(sink.evidence)
	if e, ok := ev["port-published:"+idA+":tcp:8081"]; !ok || e.RawRef == "" {
		t.Errorf("port-published evidence = %+v", e)
	}
}

func TestCollectManagesContainerProcesses(t *testing.T) {
	sink := newRecSink()
	idx := &fakeIndex{byContainer: map[string][]collector.ProcessRow{
		idA:    {{IdentityKey: "process|100|111", Owner: idA}},
		idGone: {{IdentityKey: "process|101|222", Owner: idGone}}, // not in API: skip
	}}
	c := New(baseInventory(), nil, idx)
	if err := c.Collect(t.Context(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}

	edges := edgeSet(sink.edges)
	if _, ok := edges["manages container|"+idA+"->process|100|111"]; !ok {
		t.Errorf("manages edge missing: %+v", sink.edges)
	}
	if _, ok := edges["manages container|"+idGone+"->process|101|222"]; ok {
		t.Error("process in unknown container must not gain an owner edge")
	}
	if e, ok := edges["manages container|"+idA+"->process|100|111"]; ok && e.EvidenceRef != "container-state:"+idA {
		t.Errorf("manages evidence ref = %q", e.EvidenceRef)
	}
}

func TestCollectSurfacesAPIError(t *testing.T) {
	sink := newRecSink()
	c := New(&fakeAPI{err: errors.New("socket gone")}, nil, nil)
	if err := c.Collect(t.Context(), sink); err == nil {
		t.Fatal("Collect must return the API error for the run loop")
	}
}

func TestCollectNoComposeLabels(t *testing.T) {
	sink := newRecSink()
	c := New(baseInventory(), nil, nil)
	if err := c.Collect(t.Context(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	for _, e := range sink.entities {
		if e.Kind == "compose_service" {
			t.Errorf("unexpected compose entity %q without labels", e.IdentityKey)
		}
	}
	if len(sink.blinds) != 0 {
		t.Errorf("unexpected blind spots: %+v", sink.blinds)
	}
}

// A host-network container publishes no ports; it is still reached
// through its cgroup processes (manages), never through port matching.
func TestCollectHostNetworkContainer(t *testing.T) {
	api := baseInventory()
	host := docker.Container{
		ID: idB, Names: []string{"/lab-host-1"}, Image: "busybox:1.36", ImageID: img2,
		State: "running", Status: "Up 5 minutes",
		NetworkMode: "host",
	}
	api.containers = []docker.Container{api.containers[0], host}

	sink := newRecSink()
	idx := &fakeIndex{byContainer: map[string][]collector.ProcessRow{
		idB: {{IdentityKey: "process|300|555", Owner: idB}},
	}}
	c := New(api, nil, idx)
	if err := c.Collect(t.Context(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}

	edges := edgeSet(sink.edges)
	if _, ok := edges["manages container|"+idB+"->process|300|555"]; !ok {
		t.Errorf("host-network container must be linked via manages: %+v", sink.edges)
	}
	// no published port on the host container: nothing to match
	for _, e := range sink.edges {
		if e.Kind == "listens_on" && e.DstIdentityKey == "container|"+idB {
			t.Errorf("host-network container must not gain listens_on: %+v", e)
		}
	}
}

// A compose file may list services that have no container (scaled to
// zero, inactive profile). Their names must not produce evidence or
// edges for entities that were never proven — and must not fail the
// collector either.
func TestCollectComposeSkipsServicesWithoutContainers(t *testing.T) {
	path := writeCompose(t, "services:\n  web:\n    image: nginx:1.28\n    depends_on:\n      - helper\n  helper:\n    image: busybox\n  ghost:\n    image: busybox\n    depends_on:\n      - web\n")
	api := baseInventory()
	api.containers[0].Labels = map[string]string{
		"com.docker.compose.project":              "lab",
		"com.docker.compose.service":              "web",
		"com.docker.compose.project.config_files": path,
	}
	api.containers = append(api.containers, docker.Container{
		ID: idGone, Names: []string{"/lab-helper-1"}, Image: "busybox:1.36", ImageID: img2,
		State: "running", Status: "Up 1 minute",
		Labels: map[string]string{
			"com.docker.compose.project":              "lab",
			"com.docker.compose.service":              "helper",
			"com.docker.compose.project.config_files": path,
		},
	})

	sink := newRecSink()
	c := New(api, nil, nil)
	if err := c.Collect(t.Context(), sink); err != nil {
		t.Fatalf("collect must not fail on container-less services: %v", err)
	}
	edges := edgeSet(sink.edges)
	if _, ok := edges["depends_on compose_service|lab/web->compose_service|lab/helper"]; !ok {
		t.Errorf("web->helper edge missing: %+v", sink.edges)
	}
	for _, e := range sink.edges {
		if strings.Contains(e.SrcIdentityKey, "ghost") || strings.Contains(e.DstIdentityKey, "ghost") {
			t.Errorf("container-less service must not appear in edges: %+v", e)
		}
	}
	if _, ok := sink.entities["compose_service|lab/ghost"]; ok {
		t.Error("container-less service must not become an entity")
	}
}

// Every container referencing a missing compose file records its own
// blind spot; the cached failure must not swallow the later ones.
func TestCollectComposeMissingFileBlindSpotPerContainer(t *testing.T) {
	api := baseInventory()
	missing := filepath.Join(t.TempDir(), "gone.yml")
	labels := map[string]string{
		"com.docker.compose.project":              "lab",
		"com.docker.compose.service":              "web",
		"com.docker.compose.project.config_files": missing,
	}
	api.containers[0].Labels = labels
	api.containers[1].Labels = map[string]string{
		"com.docker.compose.project":              "lab",
		"com.docker.compose.service":              "helper",
		"com.docker.compose.project.config_files": missing,
	}

	sink := newRecSink()
	c := New(api, nil, nil)
	if err := c.Collect(t.Context(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(sink.blinds) != 2 {
		t.Fatalf("blinds = %+v, want one per referencing container", sink.blinds)
	}
	seen := map[string]bool{}
	for _, b := range sink.blinds {
		seen[b.EntityIdentityKey] = true
	}
	if !seen["container|"+idA] || !seen["container|"+idB] {
		t.Errorf("blind spot entities = %v, want both containers", seen)
	}
}

// Listeners bound on IPv6 wildcard carry the /proc family name
// (tcp6) while the engine publishes tcp; both must match.
func TestCollectTcp6ListenerMatchesPublishedPort(t *testing.T) {
	sink := newRecSink()
	idx := &fakeIndex{listeners: []collector.ListenerRow{
		{IdentityKey: "listener|tcp6|::|8081|5555", Name: ":::8081"},
	}}
	c := New(baseInventory(), nil, idx)
	if err := c.Collect(t.Context(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	edges := edgeSet(sink.edges)
	if _, ok := edges["listens_on listener|tcp6|::|8081|5555->container|"+idA]; !ok {
		t.Errorf("tcp6 listener must match tcp published port: %+v", sink.edges)
	}
}

// docker_created evidence carries the inspect Created
// timestamp as last_deploy_at, neutral polarity, traceable raw_ref.
func TestCollectCreatedEvidence(t *testing.T) {
	api := baseInventory()
	sink := newRecSink()
	c := New(api, nil, nil)
	if err := c.Collect(t.Context(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	e, ok := evidenceByRef(sink.evidence)["container-created:"+idA]
	if !ok {
		t.Fatal("created evidence missing")
	}
	if e.Channel != "docker_created" || e.Polarity != collector.PolarityNeutral ||
		e.Strength != collector.StrengthDeterministic {
		t.Errorf("created evidence = %+v", e)
	}
	if e.Value["last_deploy_at"] != "2026-10-05T10:00:00Z" {
		t.Errorf("last_deploy_at = %q", e.Value["last_deploy_at"])
	}
	if !strings.Contains(e.RawRef, idA) {
		t.Errorf("raw_ref = %q, want container id", e.RawRef)
	}
	if e.ObservedAt == "" {
		t.Error("observed_at must be set")
	}
}

// readable driver with a log line → docker_log evidence and a
// last_log_at attribute folded into the same entity upsert.
func TestCollectLogEvidence(t *testing.T) {
	api := baseInventory()
	ts := time.Date(2026, 10, 6, 8, 30, 0, 0, time.UTC)
	api.logs = map[string]time.Time{idA: ts}
	sink := newRecSink()
	c := New(api, nil, nil)
	if err := c.Collect(t.Context(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	e, ok := evidenceByRef(sink.evidence)["container-log:"+idA]
	if !ok {
		t.Fatal("log evidence missing")
	}
	if e.Channel != "docker_log" || e.Polarity != collector.PolarityInUse {
		t.Errorf("log evidence = %+v", e)
	}
	if e.Value["last_log_at"] != ts.Format(time.RFC3339) {
		t.Errorf("value = %+v", e.Value)
	}
	if got := sink.entities["container|"+idA].Attributes["last_log_at"]; got != ts.Format(time.RFC3339) {
		t.Errorf("attr last_log_at = %q", got)
	}
	if _, ok := evidenceByRef(sink.evidence)["container-log:"+idB]; ok {
		t.Error("container B has no log line; no evidence expected")
	}
	if len(sink.blinds) != 0 {
		t.Errorf("unexpected blinds: %+v", sink.blinds)
	}
}

// a driver that cannot be read becomes a blind spot and
// that container never reaches the log API.
func TestCollectUnsupportedLogDriverBlind(t *testing.T) {
	api := baseInventory()
	api.containers[0].LogDriver = "syslog"
	sink := newRecSink()
	c := New(api, nil, nil)
	if err := c.Collect(t.Context(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if api.logCalls != 1 {
		t.Errorf("log API called %d times, want 1 (only the readable container)", api.logCalls)
	}
	if len(sink.blinds) != 1 {
		t.Fatalf("blinds = %+v, want 1", sink.blinds)
	}
	b := sink.blinds[0]
	if b.Reason != "log_driver_unsupported" || b.Channel != "docker" ||
		b.EntityIdentityKey != "container|"+idA || b.Detail["driver"] != "syslog" {
		t.Errorf("blind = %+v", b)
	}
	if _, ok := evidenceByRef(sink.evidence)["container-log:"+idA]; ok {
		t.Error("docker_log evidence for unsupported driver")
	}
}

// A log read failure is reported per container instead of failing the scan.
func TestCollectLogReadErrorBlind(t *testing.T) {
	api := baseInventory()
	api.logErrs = map[string]error{idA: errors.New("driver refused")}
	sink := newRecSink()
	c := New(api, nil, nil)
	if err := c.Collect(t.Context(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(sink.blinds) != 1 || sink.blinds[0].Reason != "docker_log_unreadable" ||
		sink.blinds[0].EntityIdentityKey != "container|"+idA {
		t.Errorf("blinds = %+v", sink.blinds)
	}
}

// An image carrying the OCI source label links its container to a
// repo entity through a strong built_from edge; the image itself
// records the URL in repo_source.
func TestCollectOCILabelBuiltFrom(t *testing.T) {
	api := baseInventory()
	api.images[0].Label = map[string]string{
		ociSourceLabel: "https://github.com/lab/web",
	}
	sink := newRecSink()
	c := New(api, nil, nil)
	if err := c.Collect(t.Context(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	repo, ok := sink.entities["repo|https://github.com/lab/web"]
	if !ok {
		t.Fatal("repo entity missing")
	}
	if repo.Kind != "repo" || repo.Attributes["url"] != "https://github.com/lab/web" {
		t.Errorf("repo = %+v", repo)
	}
	if sink.entities["image|"+img1].Attributes["repo_source"] != "https://github.com/lab/web" {
		t.Errorf("image repo_source = %q", sink.entities["image|"+img1].Attributes["repo_source"])
	}
	edges := edgeSet(sink.edges)
	e, ok := edges["built_from container|"+idA+"->repo|https://github.com/lab/web"]
	if !ok {
		t.Fatalf("built_from edge missing: %+v", sink.edges)
	}
	if e.Strength != collector.StrengthStrongHeuristic || e.EvidenceRef == "" {
		t.Errorf("edge = %+v", e)
	}
}

// An image without the label just records repo_source=unknown; no
// blind spot, no repo entity.
func TestCollectOCIUnknownSourceIsQuiet(t *testing.T) {
	api := baseInventory()
	sink := newRecSink()
	c := New(api, nil, nil)
	if err := c.Collect(t.Context(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if got := sink.entities["image|"+img1].Attributes["repo_source"]; got != "unknown" {
		t.Errorf("repo_source = %q, want unknown", got)
	}
	for _, b := range sink.blinds {
		if strings.Contains(b.Reason, "oci") || strings.Contains(b.Reason, "repo") {
			t.Errorf("unexpected blind: %+v", b)
		}
	}
	for k := range sink.entities {
		if strings.HasPrefix(k, "repo|") {
			t.Errorf("unexpected repo entity %q", k)
		}
	}
}
