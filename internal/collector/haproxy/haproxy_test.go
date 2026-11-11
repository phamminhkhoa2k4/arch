package haproxy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"archaeologist/internal/collector"
	"archaeologist/internal/haproxy"
	"archaeologist/internal/store"
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

// writeTree writes a config file under a temp dir and returns its
// path.
func writeTree(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
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
	root := writeTree(t, "haproxy.cfg", `
frontend fe_http
    bind :80
    default_backend be_app
    use_backend be_api if { hdr(host) -i api.example.test }

backend be_app
    server app1 127.0.0.1:8080 check
    server app2 192.0.2.10:8080 backup

backend be_api
    server api1 127.0.0.1:9000

backend be_sock
    server sock1 /run/app.sock

listen stats
    bind 127.0.0.1:8404
    server st1 127.0.0.1:8404
`)
	index := &fakeIndex{rows: []collector.ListenerRow{
		{IdentityKey: listenerKey("tcp", "0.0.0.0", 8080, 99), Name: "0.0.0.0:8080"},
		{IdentityKey: listenerKey("tcp", "0.0.0.0", 9000, 100), Name: "0.0.0.0:9000"},
		{IdentityKey: listenerKey("tcp", "127.0.0.1", 8404, 101), Name: "127.0.0.1:8404"},
	}}
	sink := collect(t, root, index)

	if got := countKind(sink, "haproxy_frontend"); got != 2 {
		t.Errorf("haproxy_frontend count = %d, want 2", got)
	}
	if got := countKind(sink, "haproxy_backend"); got != 3 {
		t.Errorf("haproxy_backend count = %d, want 3", got)
	}
	if len(sink.blinds) != 0 {
		t.Errorf("blinds = %+v, want none", sink.blinds)
	}

	fe := entityByName(t, sink, "haproxy_frontend", "fe_http")
	if fe.Attributes["bind"] != ":80" || fe.Attributes["default_backend"] != "be_app" {
		t.Errorf("frontend attrs = %v", fe.Attributes)
	}
	// Routing edges: default_backend plus the conditional use_backend.
	if got := len(edgesFrom(sink, fe.IdentityKey)); got != 2 {
		t.Errorf("frontend edges = %d, want 2", got)
	}

	// Local servers edge to their listeners; the external backup
	// server becomes a shared destination entity.
	beApp := entityByName(t, sink, "haproxy_backend", "be_app")
	beAppEdges := edgesFrom(sink, beApp.IdentityKey)
	if len(beAppEdges) != 2 {
		t.Fatalf("be_app edges = %d, want 2 (local listener + external backup)", len(beAppEdges))
	}
	linked := false
	for _, e := range beAppEdges {
		if e.DstIdentityKey == "external_host|192.0.2.10:8080" {
			linked = true
		}
	}
	if !linked {
		t.Errorf("be_app edges = %+v, want one to external_host|192.0.2.10:8080", beAppEdges)
	}
	beAPI := entityByName(t, sink, "haproxy_backend", "be_api")
	if got := len(edgesFrom(sink, beAPI.IdentityKey)); got != 1 {
		t.Errorf("be_api edges = %d, want 1", got)
	}

	// A listen section carries its own servers on the frontend entity.
	stats := entityByName(t, sink, "haproxy_frontend", "stats")
	if got := len(edgesFrom(sink, stats.IdentityKey)); got != 1 {
		t.Errorf("stats edges = %d, want 1", got)
	}

	// The unix socket target is missing at scan time.
	beSock := entityByName(t, sink, "haproxy_backend", "be_sock")
	if !hasFinding(sink, beSock.IdentityKey, "BROKEN_ROUTE") {
		t.Errorf("findings = %+v, want BROKEN_ROUTE for be_sock", sink.findings)
	}

	// Every evidence row points back at its config line.
	if len(sink.evidence) != 6 {
		t.Errorf("evidence count = %d, want 6", len(sink.evidence))
	}
	for _, ev := range sink.evidence {
		if ev.Channel != "haproxy" || ev.RawRef == "" {
			t.Errorf("evidence = %+v, want haproxy channel with raw_ref", ev)
		}
	}
}

func TestCollectUnresolvedAndMissingListener(t *testing.T) {
	root := writeTree(t, "haproxy.cfg", `
frontend fe
    bind :80
    default_backend be

backend be
    server s1 $BACKEND
    server s2 127.0.0.1:9999
`)
	index := &fakeIndex{rows: []collector.ListenerRow{
		{IdentityKey: listenerKey("tcp", "0.0.0.0", 8080, 99), Name: "0.0.0.0:8080"},
	}}
	sink := collect(t, root, index)

	if !hasBlind(sink, "haproxy_target_unresolved") {
		t.Fatalf("blinds = %+v, want haproxy_target_unresolved", sink.blinds)
	}
	be := entityByName(t, sink, "haproxy_backend", "be")
	if !hasFinding(sink, be.IdentityKey, "BROKEN_ROUTE") {
		t.Errorf("findings = %+v, want BROKEN_ROUTE for port 9999", sink.findings)
	}
}

func TestCollectConfigErrorKeepsValidSections(t *testing.T) {
	root := writeTree(t, "haproxy.cfg", `
frontend
backend be
    server s1
frontend fe
    bind :80
`)
	sink := collect(t, root, nil)

	if !hasBlind(sink, "haproxy_config_parse_error") {
		t.Fatalf("blinds = %+v, want haproxy_config_parse_error", sink.blinds)
	}
	// The valid frontend still contributes inventory.
	if got := countKind(sink, "haproxy_frontend"); got != 1 {
		t.Errorf("haproxy_frontend count = %d, want 1 (the valid one)", got)
	}
	// The nameless section produced no entity.
	for _, e := range sink.entities {
		if e.Kind == "haproxy_frontend" && e.Name == "" {
			t.Errorf("nameless frontend entity: %+v", e)
		}
	}
}

func TestCollectNotInstalledReturnsNil(t *testing.T) {
	if _, err := os.Stat(haproxy.DefaultRoot); err == nil {
		t.Skip("haproxy installed on this machine: default root exists")
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

	root := writeTree(t, "haproxy.cfg", `
frontend fe
    bind :80
    default_backend be

backend be
    server s1 127.0.0.1:8080
    server s2 $BACKEND
    server s3 192.0.2.1:8080
`)
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
	c.root = root
	if err := c.Collect(ctx, sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
}
