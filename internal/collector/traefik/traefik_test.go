package traefik

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"archaeologist/internal/collector"
	"archaeologist/internal/store"
	"archaeologist/internal/traefik"
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

// fakeIndex serves a fixed listener snapshot.
type fakeIndex struct {
	rows []collector.ListenerRow
	err  error
}

func (f *fakeIndex) ListenerRows() ([]collector.ListenerRow, error) { return f.rows, f.err }

func listenerKey(proto, addr string, port int, inode int) string {
	return fmt.Sprintf("listener|%s|%s|%d|%d", proto, addr, port, inode)
}

// writeFiles writes a name→content map under a fresh temp dir.
func writeFiles(t *testing.T, files map[string]string) (root, dir string) {
	t.Helper()
	dir = t.TempDir()
	writeFilesAt(t, dir, files)
	return filepath.Join(dir, "traefik.yml"), dir
}

// writeFilesAt writes a name→content map under dir, creating parent
// directories as needed.
func writeFilesAt(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func collect(t *testing.T, root string, index Index) *recSink {
	t.Helper()
	c := New(index)
	c.root = root
	sink := newRecSink()
	if index != nil {
		rows, err := index.ListenerRows()
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if err := sink.UpsertEntity(collector.Entity{
				Kind: "listener", Name: r.Name, IdentityKey: r.IdentityKey,
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := c.Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return sink
}

func entityByName(t *testing.T, sink *recSink, kind, name string) collector.Entity {
	t.Helper()
	for _, e := range sink.entities {
		if e.Kind == kind && e.Name == name {
			return e
		}
	}
	t.Fatalf("no %s named %q", kind, name)
	return collector.Entity{}
}

func countKind(sink *recSink, kind string) int {
	n := 0
	for _, e := range sink.entities {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

func edgesFrom(sink *recSink, src string) []collector.Edge {
	var out []collector.Edge
	for _, e := range sink.edges {
		if e.SrcIdentityKey == src {
			out = append(out, e)
		}
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

func hasFinding(sink *recSink, entityKey, kind string) bool {
	for _, f := range sink.findings {
		if f.EntityIdentityKey == entityKey && f.Kind == kind {
			return true
		}
	}
	return false
}

func TestCollectRoutesEdgesAndScope(t *testing.T) {
	dir := t.TempDir()
	dyn := filepath.Join(dir, "conf")
	writeFilesAt(t, dir, map[string]string{
		"traefik.yml": `
providers:
  file:
    directory: ` + dyn + `
`,
		"conf/routing.yml": `
http:
  routers:
    api:
      rule: "Host(` + "`api.example.test`" + `)"
      service: api-svc
    dash:
      rule: "Host(` + "`dash.example.test`" + `)"
      service: weighted-svc
  services:
    api-svc:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8080"
          - url: "https://192.0.2.10:8443"
    weighted-svc:
      weighted:
        services:
          - name: api-svc
`,
	})
	root := filepath.Join(dir, "traefik.yml")
	index := &fakeIndex{rows: []collector.ListenerRow{
		{IdentityKey: listenerKey("tcp", "0.0.0.0", 8080, 99), Name: "0.0.0.0:8080"},
	}}
	sink := collect(t, root, index)

	if got := countKind(sink, "traefik_router"); got != 2 {
		t.Errorf("traefik_router count = %d, want 2", got)
	}
	if got := countKind(sink, "traefik_service"); got != 2 {
		t.Errorf("traefik_service count = %d, want 2", got)
	}
	if len(sink.blinds) != 0 {
		t.Errorf("blinds = %+v, want none", sink.blinds)
	}

	// Router → service routing edges.
	apiRouter := entityByName(t, sink, "traefik_router", "api")
	if got := len(edgesFrom(sink, apiRouter.IdentityKey)); got != 1 {
		t.Errorf("api router edges = %d, want 1", got)
	}
	// The weighted service distributes to api-svc.
	weighted := entityByName(t, sink, "traefik_service", "weighted-svc")
	if got := len(edgesFrom(sink, weighted.IdentityKey)); got != 1 {
		t.Errorf("weighted-svc edges = %d, want 1 (to api-svc)", got)
	}
	// api-svc edges to its local listener; the external server only
	// shows up as scope, never as an edge.
	apiSvc := entityByName(t, sink, "traefik_service", "api-svc")
	if got := len(edgesFrom(sink, apiSvc.IdentityKey)); got != 1 {
		t.Errorf("api-svc edges = %d, want 1 (local only)", got)
	}
	if apiSvc.Attributes["servers"] == "" || !strings.Contains(apiSvc.Attributes["servers"], "192.0.2.10") {
		t.Errorf("api-svc servers attr = %q", apiSvc.Attributes["servers"])
	}

	// Every evidence row points back at its config with the channel.
	if len(sink.evidence) != 4 {
		t.Errorf("evidence count = %d, want 4", len(sink.evidence))
	}
	for _, ev := range sink.evidence {
		if ev.Channel != "traefik" || ev.RawRef == "" {
			t.Errorf("evidence = %+v, want traefik channel with raw_ref", ev)
		}
	}
}

func TestCollectUnresolvedAndMissingListener(t *testing.T) {
	dir := t.TempDir()
	dyn := filepath.Join(dir, "conf")
	writeFilesAt(t, dir, map[string]string{
		"traefik.yml": "providers:\n  file:\n    directory: " + dyn + "\n",
		"conf/r.yml": `
http:
  routers:
    r:
      rule: "Host(` + "`r.example.test`" + `)"
      service: r-svc
  services:
    r-svc:
      loadBalancer:
        servers:
          - url: "$BACKEND"
          - url: "http://127.0.0.1:9999"
`,
	})
	root := filepath.Join(dir, "traefik.yml")
	index := &fakeIndex{rows: []collector.ListenerRow{
		{IdentityKey: listenerKey("tcp", "0.0.0.0", 8080, 99), Name: "0.0.0.0:8080"},
	}}
	sink := collect(t, root, index)

	if !hasBlind(sink, "traefik_target_unresolved") {
		t.Fatalf("blinds = %+v, want traefik_target_unresolved", sink.blinds)
	}
	svc := entityByName(t, sink, "traefik_service", "r-svc")
	if !hasFinding(sink, svc.IdentityKey, "BROKEN_ROUTE") {
		t.Errorf("findings = %+v, want BROKEN_ROUTE for port 9999", sink.findings)
	}
}

func TestCollectReportsConfigProblems(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yml")
	missing := filepath.Join(dir, "missing") // never created
	writeFilesAt(t, dir, map[string]string{
		"traefik.yml": `
providers:
  file:
    filename: ` + bad + `
    directory: ` + missing + `
`,
		"bad.yml": "http: [\n",
	})
	root := filepath.Join(dir, "traefik.yml")
	sink := collect(t, root, nil)

	if !hasBlind(sink, "traefik_config_unreadable") {
		t.Errorf("blinds = %+v, want traefik_config_unreadable", sink.blinds)
	}
	if !hasBlind(sink, "traefik_config_parse_error") {
		t.Errorf("blinds = %+v, want traefik_config_parse_error", sink.blinds)
	}
}

func TestCollectReportsUnsupportedProvider(t *testing.T) {
	root, _ := writeFiles(t, map[string]string{
		"traefik.yml": "providers:\n  docker: {}\n",
	})
	sink := collect(t, root, nil)

	if !hasBlind(sink, "traefik_provider_unsupported") {
		t.Fatalf("blinds = %+v, want traefik_provider_unsupported", sink.blinds)
	}
	for _, b := range sink.blinds {
		if b.Reason == "traefik_provider_unsupported" && b.Detail["provider"] != "docker" {
			t.Errorf("provider detail = %v", b.Detail)
		}
	}
	if len(sink.entities) != 0 {
		t.Errorf("docker-only install produced entities: %+v", sink.entities)
	}
}

func TestCollectTomlOnlyReportsUnsupported(t *testing.T) {
	if firstExistingRoot() {
		t.Skip("traefik installed on this machine: default root exists")
	}
	toml := filepath.Join(t.TempDir(), "traefik.toml")
	if err := os.WriteFile(toml, []byte("[providers.docker]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := traefik.TOMLRoots
	traefik.TOMLRoots = []string{toml}
	t.Cleanup(func() { traefik.TOMLRoots = orig })

	c := New(nil) // root stays "": pickRoot finds nothing
	sink := newRecSink()
	if err := c.Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !hasBlind(sink, "traefik_config_unsupported") {
		t.Errorf("blinds = %+v, want traefik_config_unsupported", sink.blinds)
	}
}

func TestCollectNotInstalledReturnsNil(t *testing.T) {
	if firstExistingRoot() {
		t.Skip("traefik installed on this machine: default root exists")
	}
	c := New(nil)
	sink := newRecSink()
	if err := c.Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(sink.entities) != 0 || len(sink.blinds) != 0 {
		t.Errorf("not-installed host produced output: %+v", sink)
	}
}

// firstExistingRoot reports whether any standard Traefik config
// location exists on this machine.
func firstExistingRoot() bool {
	for _, p := range append([]string{traefik.DefaultRoot}, traefik.AltRoots...) {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
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

	dir := t.TempDir()
	dyn := filepath.Join(dir, "conf")
	writeFilesAt(t, dir, map[string]string{
		"traefik.yml": "providers:\n  file:\n    directory: " + dyn + "\n",
		"conf/r.yml": `
http:
  routers:
    r:
      rule: "Host(` + "`r.example.test`" + `)"
      service: r-svc
  services:
    r-svc:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8080"
          - url: "$BACKEND"
`,
	})
	// Seed the listener entity the edge targets.
	if err := sink.UpsertEntity(collector.Entity{
		Kind: "listener", Name: "0.0.0.0:8080",
		IdentityKey: listenerKey("tcp", "0.0.0.0", 8080, 1),
	}); err != nil {
		t.Fatal(err)
	}
	c := New(&fakeIndex{rows: []collector.ListenerRow{
		{IdentityKey: listenerKey("tcp", "0.0.0.0", 8080, 1), Name: "0.0.0.0:8080"},
	}})
	c.root = filepath.Join(dir, "traefik.yml")
	if err := c.Collect(ctx, sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
}
