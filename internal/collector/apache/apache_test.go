package apache

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"archaeologist/internal/apache"
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

// fakeIndex serves a fixed listener snapshot.
type fakeIndex struct {
	rows []collector.ListenerRow
	err  error
}

func (f *fakeIndex) ListenerRows() ([]collector.ListenerRow, error) { return f.rows, f.err }

func listenerKey(proto, addr string, port int, inode int) string {
	return fmt.Sprintf("listener|%s|%s|%d|%d", proto, addr, port, inode)
}

// writeTree writes a config tree under a temp dir and returns the
// main configuration path.
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
	return filepath.Join(dir, "apache2.conf")
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
	root := writeTree(t, map[string]string{
		"apache2.conf": `
<VirtualHost *:80>
    ServerName www.example.test
    ProxyPass "/api" "http://127.0.0.1:8080"
    ProxyPass /ext https://192.0.2.10:9443
    ProxyPass /sock unix:/run/app.sock|http://localhost/sock
</VirtualHost>
`,
	})
	index := &fakeIndex{rows: []collector.ListenerRow{
		{IdentityKey: listenerKey("tcp", "0.0.0.0", 8080, 99), Name: "0.0.0.0:8080"},
	}}
	sink := collect(t, root, index)

	if got := countKind(sink, "apache_route"); got != 3 {
		t.Fatalf("apache_route count = %d, want 3", got)
	}
	if len(sink.blinds) != 0 {
		t.Errorf("blinds = %+v, want none", sink.blinds)
	}

	api := entityByName(t, sink, "apache_route", "/api")
	if api.Attributes["server_name"] != "www.example.test" ||
		api.Attributes["vhost"] != "*:80" {
		t.Errorf("api attrs = %v", api.Attributes)
	}
	if got := len(edgesFrom(sink, api.IdentityKey)); got != 1 {
		t.Errorf("api edges = %d, want 1", got)
	}

	// The external target only shows up as scope, never as an edge.
	ext := entityByName(t, sink, "apache_route", "/ext")
	if got := len(edgesFrom(sink, ext.IdentityKey)); got != 0 {
		t.Errorf("ext edges = %d, want 0", got)
	}
	if ext.Attributes["target"] != "https://192.0.2.10:9443" {
		t.Errorf("ext target attr = %q", ext.Attributes["target"])
	}

	// The unix socket target is missing at scan time.
	sock := entityByName(t, sink, "apache_route", "/sock")
	if !hasFinding(sink, sock.IdentityKey, "BROKEN_ROUTE") {
		t.Errorf("findings = %+v, want BROKEN_ROUTE for /sock", sink.findings)
	}

	// Every evidence row points back at its config line.
	if len(sink.evidence) != 3 {
		t.Errorf("evidence count = %d, want 3", len(sink.evidence))
	}
	for _, ev := range sink.evidence {
		if ev.Channel != "apache" || ev.RawRef == "" {
			t.Errorf("evidence = %+v, want apache channel with raw_ref", ev)
		}
	}
}

func TestCollectUnresolvedAndMissingListener(t *testing.T) {
	root := writeTree(t, map[string]string{
		"apache2.conf": `
<VirtualHost *:80>
    ProxyPass /dyn http://$BACKEND:8080
    ProxyPass /gone http://127.0.0.1:9999
</VirtualHost>
`,
	})
	index := &fakeIndex{rows: []collector.ListenerRow{
		{IdentityKey: listenerKey("tcp", "0.0.0.0", 8080, 99), Name: "0.0.0.0:8080"},
	}}
	sink := collect(t, root, index)

	if !hasBlind(sink, "apache_target_unresolved") {
		t.Fatalf("blinds = %+v, want apache_target_unresolved", sink.blinds)
	}
	gone := entityByName(t, sink, "apache_route", "/gone")
	if !hasFinding(sink, gone.IdentityKey, "BROKEN_ROUTE") {
		t.Errorf("findings = %+v, want BROKEN_ROUTE for port 9999", sink.findings)
	}
}

func TestCollectIncludeAndParseErrors(t *testing.T) {
	root := writeTree(t, map[string]string{
		"apache2.conf": `
Include missing/*.conf
<VirtualHost *:80>
    ProxyPass /broken
    ProxyPass /ok http://127.0.0.1:8080
</VirtualHost>
`,
	})
	sink := collect(t, root, nil)

	if !hasBlind(sink, "apache_include_unreadable") {
		t.Errorf("blinds = %+v, want apache_include_unreadable", sink.blinds)
	}
	if !hasBlind(sink, "apache_config_parse_error") {
		t.Errorf("blinds = %+v, want apache_config_parse_error", sink.blinds)
	}
	// The valid route still contributes inventory.
	if got := countKind(sink, "apache_route"); got != 1 {
		t.Errorf("apache_route count = %d, want 1 (the valid one)", got)
	}
}

func TestCollectNotInstalledReturnsNil(t *testing.T) {
	if _, err := os.Stat(apache.DefaultRoot); err == nil {
		t.Skip("apache installed on this machine: default root exists")
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

	root := writeTree(t, map[string]string{
		"apache2.conf": `
<VirtualHost *:80>
    ProxyPass /api http://127.0.0.1:8080
    ProxyPass /dyn http://$BACKEND
    ProxyPass /ext https://192.0.2.10:9443
</VirtualHost>
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
	c.root = root
	if err := c.Collect(ctx, sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
}
