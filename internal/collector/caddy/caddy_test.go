package caddy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"archaeologist/internal/collector"
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

type fakeIndex struct {
	rows []collector.ListenerRow
	err  error
}

func (f *fakeIndex) ListenerRows() ([]collector.ListenerRow, error) { return f.rows, f.err }

func listenerKey(proto, addr string, port int, inode int) string {
	return fmt.Sprintf("listener|%s|%s|%d|%d", proto, addr, port, inode)
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "Caddyfile")
}

func collect(t *testing.T, root string, index Index) *recSink {
	t.Helper()
	c := New(nil, index)
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

func routeByName(t *testing.T, sink *recSink, name string) collector.Entity {
	t.Helper()
	for _, e := range sink.entities {
		if e.Kind == "caddy_route" && e.Name == name {
			return e
		}
	}
	t.Fatalf("no caddy_route named %q (have %d routes)", name, countKind(sink, "caddy_route"))
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
	root := writeTree(t, map[string]string{
		"Caddyfile": `
example.com {
	reverse_proxy localhost:8080
	handle /api/* {
		reverse_proxy @api http://127.0.0.1:9000
	}
	handle {
		reverse_proxy {
			to unix//run/app.sock
			to 127.0.0.1:9001
		}
	}
}
static.example.test {
	respond "ok" 200
	reverse_proxy /img/ https://cdn.example.net
}
`,
	})
	index := &fakeIndex{rows: []collector.ListenerRow{
		{IdentityKey: listenerKey("tcp", "0.0.0.0", 8080, 99), Name: "0.0.0.0:8080"},
		{IdentityKey: listenerKey("tcp", "0.0.0.0", 9000, 100), Name: "0.0.0.0:9000"},
		{IdentityKey: listenerKey("tcp", "0.0.0.0", 9001, 101), Name: "0.0.0.0:9001"},
	}}
	sink := collect(t, root, index)

	if got := countKind(sink, "caddy_route"); got != 4 {
		t.Errorf("caddy_route count = %d, want 4", got)
	}

	plain := routeByName(t, sink, "example.com")
	if len(edgesFrom(sink, plain.IdentityKey)) != 1 {
		t.Errorf("plain edges = %d, want 1", len(edgesFrom(sink, plain.IdentityKey)))
	}

	var unixRoute collector.Entity
	for _, e := range sink.entities {
		if e.Kind == "caddy_route" && strings.Contains(e.Attributes["targets"], "unix//run/app.sock") {
			unixRoute = e
		}
	}
	if unixRoute.IdentityKey == "" {
		t.Fatal("unix route missing")
	}
	// unix socket exists? /run/app.sock likely missing → BROKEN_ROUTE
	if !hasFinding(sink, unixRoute.IdentityKey, "BROKEN_ROUTE") {
		// If the socket happens to exist, that's fine; otherwise fail.
		if _, err := os.Stat("/run/app.sock"); os.IsNotExist(err) {
			t.Error("expected BROKEN_ROUTE for missing unix socket")
		}
	}

	cdn := routeByName(t, sink, "static.example.test")
	if cdn.Attributes["targets"] != "https://cdn.example.net" {
		t.Errorf("cdn targets = %q", cdn.Attributes["targets"])
	}
	// The external destination becomes a shared graph entity.
	cdnEdges := edgesFrom(sink, cdn.IdentityKey)
	if len(cdnEdges) != 1 || cdnEdges[0].Kind != "proxies_to" {
		t.Fatalf("cdn edges = %+v, want one proxies_to to the destination", cdnEdges)
	}
	if cdnEdges[0].DstIdentityKey != "external_host|cdn.example.net" {
		t.Errorf("cdn dst = %q, want external_host|cdn.example.net", cdnEdges[0].DstIdentityKey)
	}
}

func TestCollectUnresolvedAndMissingListener(t *testing.T) {
	root := writeTree(t, map[string]string{
		"Caddyfile": `example.com {
	reverse_proxy http://$BACKEND/
	reverse_proxy 127.0.0.1:9999
}
`,
	})
	index := &fakeIndex{rows: []collector.ListenerRow{
		{IdentityKey: listenerKey("tcp", "0.0.0.0", 8080, 99), Name: "0.0.0.0:8080"},
	}}
	sink := collect(t, root, index)

	if !hasBlind(sink, "caddy_target_unresolved") {
		t.Fatalf("blinds = %+v, want caddy_target_unresolved", sink.blinds)
	}
	// The second route targets a port with no listener → BROKEN_ROUTE.
	var broken bool
	for _, f := range sink.findings {
		if f.Kind == "BROKEN_ROUTE" {
			broken = true
		}
	}
	if !broken {
		t.Errorf("findings = %+v, want BROKEN_ROUTE", sink.findings)
	}
}

func TestCollectImportUnreadable(t *testing.T) {
	root := writeTree(t, map[string]string{
		"Caddyfile": "import missing/*.caddy\n",
	})
	sink := collect(t, root, nil)

	if !hasBlind(sink, "caddy_import_unreadable") {
		t.Errorf("blinds = %+v, want caddy_import_unreadable", sink.blinds)
	}
}

func TestCollectSyntaxError(t *testing.T) {
	root := writeTree(t, map[string]string{
		"Caddyfile": "example.com {\n\treverse_proxy localhost:8080\n",
	})
	sink := collect(t, root, nil)

	if !hasBlind(sink, "caddy_config_parse_error") {
		t.Errorf("blinds = %+v, want caddy_config_parse_error", sink.blinds)
	}
}

func TestCollectNotInstalledReturnsNil(t *testing.T) {
	c := New(nil, nil)
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

	root := writeTree(t, map[string]string{
		"Caddyfile": `example.com {
	reverse_proxy localhost:8080
	reverse_proxy 127.0.0.1:9999
}
`,
	})
	// seed listener entity for the edge
	if err := sink.UpsertEntity(collector.Entity{
		Kind: "listener", Name: "0.0.0.0:8080", IdentityKey: listenerKey("tcp", "0.0.0.0", 8080, 1),
	}); err != nil {
		t.Fatal(err)
	}
	c := New(nil, &fakeIndex{rows: []collector.ListenerRow{
		{IdentityKey: listenerKey("tcp", "0.0.0.0", 8080, 1), Name: "0.0.0.0:8080"},
	}})
	c.root = root
	if err := c.Collect(ctx, sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
}
