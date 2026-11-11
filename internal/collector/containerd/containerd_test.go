package containerd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"archaeologist/internal/collector"
	"archaeologist/internal/store"
)

const (
	k8sID  = "1111111111111111111111111111111111111111111111111111111111111111"
	mobyID = "2222222222222222222222222222222222222222222222222222222222222222"
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

// fakeIndex serves a fixed process snapshot.
type fakeIndex struct {
	byContainer map[string][]collector.ProcessRow
	err         error
}

func (f *fakeIndex) ProcessRowsByContainer() (map[string][]collector.ProcessRow, error) {
	return f.byContainer, f.err
}

// writeTree materializes a fixture tree: keys are slash-separated
// relative paths, values the file contents.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func cmdline(args ...string) string {
	return joinArgs(args...) + "\x00"
}

func joinArgs(args ...string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += "\x00"
		}
		out += a
	}
	return out
}

// baseShims is a proc fixture with one readable k8s container, one
// Docker-namespace shim (owned by the docker collector), a plain
// process, and a zombie with no argv.
func baseShims(t *testing.T) string {
	t.Helper()
	return writeTree(t, map[string]string{
		"832/cmdline": cmdline("/usr/bin/containerd-shim-runc-v2",
			"-namespace", "k8s.io", "-id", k8sID,
			"-address", "/run/containerd/containerd.sock"),
		"833/cmdline": cmdline("/usr/bin/containerd-shim-runc-v2",
			"-namespace", "moby", "-id", mobyID,
			"-address", "/run/containerd/containerd.sock"),
		"834/cmdline": cmdline("/usr/bin/sleep", "3600"),
		"835/cmdline": "",
	})
}

func collect(t *testing.T, procRoot string, index Index) *recSink {
	t.Helper()
	c := New(index)
	c.procRoot = procRoot
	sink := newRecSink()
	if index != nil {
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

func TestCollectShimInventoryAndBundleState(t *testing.T) {
	procRoot := baseShims(t)
	bundleRoot := writeTree(t, map[string]string{
		"k8s.io/" + k8sID + "/state.json": `{"status":"running","pid":900}`,
		"k8s.io/" + k8sID + "/config.json": `{"annotations":` +
			`{"io.kubernetes.cri.container-name":"web"}}`,
	})
	c := New(nil)
	c.procRoot = procRoot
	c.bundleRoot = bundleRoot
	sink := newRecSink()
	if err := c.Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	key := "containerd_container|k8s.io/" + k8sID
	ent, ok := sink.entities[key]
	if !ok {
		t.Fatalf("entities = %+v, want %s", sink.entities, key)
	}
	if ent.Kind != "containerd_container" || ent.Name != k8sID || ent.Fingerprint == "" {
		t.Errorf("entity = %+v", ent)
	}
	want := map[string]string{
		"namespace": "k8s.io", "id": k8sID, "state": "running",
		"shim": "containerd-shim-runc-v2", "pid": "832",
		"container_name": "web",
	}
	for k, v := range want {
		if ent.Attributes[k] != v {
			t.Errorf("attr %s = %q, want %q", k, ent.Attributes[k], v)
		}
	}
	if ent.Attributes["bundle"] == "" {
		t.Error("bundle path must be recorded")
	}

	// Only the non-Docker shim produced an entity.
	if len(sink.entities) != 1 {
		t.Errorf("entity count = %d, want 1 (moby skipped): %+v", len(sink.entities), sink.entities)
	}
	if len(sink.blinds) != 0 {
		t.Errorf("blinds = %+v, want none for a readable bundle", sink.blinds)
	}

	if len(sink.evidence) != 1 {
		t.Fatalf("evidence count = %d, want 1", len(sink.evidence))
	}
	ev := sink.evidence[0]
	if ev.Channel != "containerd" || ev.Strength != collector.StrengthDeterministic ||
		ev.Polarity != collector.PolarityInUse {
		t.Errorf("evidence = %+v", ev)
	}
	if ev.RawRef != "/proc/832/cmdline" {
		t.Errorf("raw_ref = %q, want /proc/832/cmdline", ev.RawRef)
	}
	if ev.Value["state"] != "running" || ev.Value["namespace"] != "k8s.io" {
		t.Errorf("value = %+v", ev.Value)
	}
	if ev.ObservedAt == "" {
		t.Error("observed_at must be set")
	}
}

// Without bundle access the container still exists — and the gap
// attaches to it, so its verdict cannot claim clean coverage.
func TestCollectBundleUnreadableBlind(t *testing.T) {
	procRoot := baseShims(t)
	c := New(nil)
	c.procRoot = procRoot
	c.bundleRoot = filepath.Join(t.TempDir(), "absent")
	sink := newRecSink()
	if err := c.Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	key := "containerd_container|k8s.io/" + k8sID
	if _, ok := sink.entities[key]; !ok {
		t.Fatalf("entities = %+v, want the shim's container", sink.entities)
	}
	var blind *collector.BlindSpot
	for i := range sink.blinds {
		if sink.blinds[i].Reason == "containerd_bundle_unreadable" {
			blind = &sink.blinds[i]
		}
	}
	if blind == nil {
		t.Fatalf("blinds = %+v, want containerd_bundle_unreadable", sink.blinds)
	}
	if blind.EntityIdentityKey != key || blind.Channel != "containerd" ||
		blind.Detail["bundle"] == "" || blind.Detail["error"] == "" {
		t.Errorf("blind = %+v", blind)
	}
	// No state is ever guessed.
	if _, ok := sink.entities[key].Attributes["state"]; ok {
		t.Error("state must stay absent when the bundle is unreadable")
	}
}

// A shim whose namespace/id flags cannot be read is reported, never
// dropped, and never becomes a guessed entity.
func TestCollectUnparsedShimBlind(t *testing.T) {
	procRoot := writeTree(t, map[string]string{
		"900/cmdline": cmdline("/usr/bin/containerd-shim-runc-v2",
			"-namespace", "k8s.io"),
	})
	sink := collect(t, procRoot, nil)

	if len(sink.entities) != 0 {
		t.Errorf("unparsed shim must not become an entity: %+v", sink.entities)
	}
	found := false
	for _, b := range sink.blinds {
		if b.Reason == "containerd_shim_unparsed" && b.Channel == "containerd" &&
			b.Detail["pid"] == "900" && b.Detail["cmdline"] != "" {
			found = true
		}
	}
	if !found {
		t.Errorf("blinds = %+v, want containerd_shim_unparsed for pid 900", sink.blinds)
	}
}

func TestCollectManagesContainerProcesses(t *testing.T) {
	procRoot := baseShims(t)
	idx := &fakeIndex{byContainer: map[string][]collector.ProcessRow{
		k8sID:  {{IdentityKey: "process|100|111", Owner: k8sID}},
		mobyID: {{IdentityKey: "process|101|222", Owner: mobyID}}, // not ours: skip
	}}
	sink := collect(t, procRoot, idx)

	key := "containerd_container|k8s.io/" + k8sID
	var edge *collector.Edge
	for i := range sink.edges {
		if sink.edges[i].SrcIdentityKey == key {
			edge = &sink.edges[i]
		}
	}
	if edge == nil {
		t.Fatalf("edges = %+v, want manages from %s", sink.edges, key)
	}
	if edge.DstIdentityKey != "process|100|111" || edge.Kind != "manages" ||
		edge.EvidenceRef != "containerd-shim:k8s.io/"+k8sID {
		t.Errorf("edge = %+v", edge)
	}
	if edge.Strength != collector.StrengthDeterministic {
		t.Errorf("strength = %q", edge.Strength)
	}
}

// A proc tree without shims yields nothing: an absent collector is
// not a gap.
func TestCollectNoShimsReturnsNothing(t *testing.T) {
	procRoot := writeTree(t, map[string]string{
		"42/cmdline": cmdline("/usr/bin/sleep", "5"),
	})
	sink := collect(t, procRoot, nil)
	if len(sink.entities) != 0 || len(sink.blinds) != 0 || len(sink.evidence) != 0 {
		t.Errorf("no-shim host produced output: %+v", sink)
	}
}

func TestCollectProcUnreadableReturnsError(t *testing.T) {
	c := New(nil)
	c.procRoot = filepath.Join(t.TempDir(), "absent")
	sink := newRecSink()
	if err := c.Collect(context.Background(), sink); err == nil {
		t.Fatal("Collect must return the procfs error for the run loop")
	}
}

func TestCollectSchemaAcceptsRows(t *testing.T) {
	// Run the collector against a real store sink to prove every
	// entity, evidence and edge it emits satisfies the database
	// constraints.
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

	processKey := "process|100|111"
	if err := sink.UpsertEntity(collector.Entity{
		Kind: "process", Name: "app", IdentityKey: processKey,
	}); err != nil {
		t.Fatal(err)
	}

	procRoot := baseShims(t)
	bundleRoot := writeTree(t, map[string]string{
		"k8s.io/" + k8sID + "/state.json": `{"status":"running"}`,
	})
	c := New(&fakeIndex{byContainer: map[string][]collector.ProcessRow{
		k8sID: {{IdentityKey: processKey, Owner: k8sID}},
	}})
	c.procRoot = procRoot
	c.bundleRoot = bundleRoot
	if err := c.Collect(ctx, sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
}

// shimFlags accepts both flag spellings the shim binaries accept and
// refuses a process that carries only one of the two required flags.
func TestShimFlags(t *testing.T) {
	ns, id, ok := shimFlags([]string{"shim", "-namespace", "k8s.io", "-id", "abc"})
	if !ok || ns != "k8s.io" || id != "abc" {
		t.Errorf("flags = %q %q %v", ns, id, ok)
	}
	ns, id, ok = shimFlags([]string{"shim", "--namespace", "k8s.io", "--id", "abc"})
	if !ok || ns != "k8s.io" || id != "abc" {
		t.Errorf("double-dash flags = %q %q %v", ns, id, ok)
	}
	if _, _, ok := shimFlags([]string{"shim", "-namespace", "k8s.io"}); ok {
		t.Error("missing -id must not parse")
	}
}

var errIndex = errors.New("index down")

type failingIndex struct{}

func (failingIndex) ProcessRowsByContainer() (map[string][]collector.ProcessRow, error) {
	return nil, errIndex
}

func TestCollectIndexErrorReturns(t *testing.T) {
	c := New(failingIndex{})
	c.procRoot = baseShims(t)
	sink := newRecSink()
	if err := c.Collect(context.Background(), sink); !errors.Is(err, errIndex) {
		t.Errorf("Collect error = %v, want the index error", err)
	}
}
