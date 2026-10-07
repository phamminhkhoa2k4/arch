package nginx

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"archaeologist/internal/collector"
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
		return fmt.Errorf("finding for unknown entity %q", f.EntityIdentityKey)
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
// root path.
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
	return filepath.Join(dir, "nginx.conf")
}

func collect(t *testing.T, root string, index Index) *recSink {
	t.Helper()
	c := New(nil, index)
	c.root = root
	sink := newRecSink()
	// The listener collector runs before nginx in the real pipeline:
	// seed its entities so edges have endpoints.
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

// routeByName finds an nginx_route entity by its location name.
func routeByName(t *testing.T, sink *recSink, name string) collector.Entity {
	t.Helper()
	for _, e := range sink.entities {
		if e.Kind == "nginx_route" && e.Name == name {
			return e
		}
	}
	t.Fatalf("no nginx_route named %q (have %d routes)", name, countKind(sink, "nginx_route"))
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

func TestCollectRoutesEdgesAndScope(t *testing.T) {
	root := writeTree(t, map[string]string{
		"nginx.conf": `http { include conf.d/*.conf; }`,
		"conf.d/lab.conf": `
server {
    listen 8080;
    server_name _;
    location /web/ { proxy_pass http://127.0.0.1:8081/; }
    location /local/ { proxy_pass http://localhost:8080/; }
    location /var/ {
        set $lab_backend 127.0.0.1:8082;
        proxy_pass http://$lab_backend/;
    }
}
`,
		"conf.d/site.conf": `
upstream pool {
    server 127.0.0.1:9001;
    server 127.0.0.1:9002;
}
server {
    listen 8080;
    location /api/ { proxy_pass http://pool/; }
    location /ext/ { proxy_pass https://example.com/; }
    location /static/ { root /var/www; }
}
`,
	})
	index := &fakeIndex{rows: []collector.ListenerRow{
		{IdentityKey: listenerKey("tcp", "0.0.0.0", 8080, 99), Name: "0.0.0.0:8080"},
		{IdentityKey: listenerKey("tcp", "0.0.0.0", 8081, 100), Name: "0.0.0.0:8081"},
		{IdentityKey: listenerKey("tcp6", "::", 8081, 101), Name: "[::]:8081"},
		{IdentityKey: listenerKey("tcp", "127.0.0.1", 9001, 102), Name: "127.0.0.1:9001"},
		{IdentityKey: listenerKey("tcp", "127.0.0.1", 9002, 103), Name: "127.0.0.1:9002"},
	}}
	sink := collect(t, root, index)

	if got := countKind(sink, "nginx_route"); got != 6 {
		t.Errorf("nginx_route count = %d, want 6", got)
	}
	if got := countKind(sink, "nginx_upstream"); got != 1 {
		t.Errorf("nginx_upstream count = %d, want 1", got)
	}

	// /web/ matches the listener snapshot on both address families.
	web := routeByName(t, sink, "/web/")
	if web.Attributes["target_kind"] != "local" || web.Attributes["target_port"] != "8081" {
		t.Errorf("/web/ attrs target = %s/%s, want local/8081",
			web.Attributes["target_kind"], web.Attributes["target_port"])
	}
	webEdges := edgesFrom(sink, web.IdentityKey)
	if len(webEdges) != 2 {
		t.Errorf("/web/ edges = %d, want 2 (tcp + tcp6 listeners)", len(webEdges))
	}
	for _, e := range webEdges {
		if e.Kind != "proxies_to" || e.Strength != collector.StrengthDeterministic {
			t.Errorf("/web/ edge = %+v, want deterministic proxies_to", e)
		}
	}

	// proxy_pass http://localhost:8080 against a known listener: the
	// AC example, deterministic edge.
	local := routeByName(t, sink, "/local/")
	localEdges := edgesFrom(sink, local.IdentityKey)
	if len(localEdges) != 1 || localEdges[0].DstIdentityKey != listenerKey("tcp", "0.0.0.0", 8080, 99) {
		t.Errorf("/local/ edges = %+v, want one to the 8080 listener", localEdges)
	}

	// /var/ is a blind spot: the variable decides the target.
	trap := routeByName(t, sink, "/var/")
	if len(edgesFrom(sink, trap.IdentityKey)) != 0 {
		t.Error("/var/ must not have edges")
	}
	if len(sink.blinds) != 1 || sink.blinds[0].Reason != "nginx_target_unresolved" {
		t.Fatalf("blinds = %+v, want one nginx_target_unresolved", sink.blinds)
	}
	if sink.blinds[0].EntityIdentityKey != trap.IdentityKey {
		t.Errorf("blind spot entity = %q, want %q", sink.blinds[0].EntityIdentityKey, trap.IdentityKey)
	}
	if !strings.Contains(trap.Attributes["set_directives"], "$lab_backend") {
		t.Errorf("set_directives = %q, want the $lab_backend assignment", trap.Attributes["set_directives"])
	}

	// /api/ chains to the upstream entity.
	api := routeByName(t, sink, "/api/")
	apiEdges := edgesFrom(sink, api.IdentityKey)
	if len(apiEdges) != 1 || apiEdges[0].Kind != "proxies_to" {
		t.Fatalf("/api/ edges = %+v, want one proxies_to to the upstream", apiEdges)
	}
	upKey := "nginx_upstream|pool"
	if apiEdges[0].DstIdentityKey != upKey {
		t.Errorf("/api/ dst = %q, want %q", apiEdges[0].DstIdentityKey, upKey)
	}
	if api.Attributes["target_upstream"] != "pool" {
		t.Errorf("/api/ target_upstream = %q, want pool", api.Attributes["target_upstream"])
	}

	// External host: scope in attrs, nothing else claimed.
	ext := routeByName(t, sink, "/ext/")
	if ext.Attributes["upstream_scope"] != "external" {
		t.Errorf("/ext/ upstream_scope = %q, want external", ext.Attributes["upstream_scope"])
	}
	if len(edgesFrom(sink, ext.IdentityKey)) != 0 {
		t.Error("/ext/ must not have edges")
	}

	// Static location: entity only.
	st := routeByName(t, sink, "/static/")
	if _, ok := st.Attributes["target"]; ok {
		t.Errorf("/static/ has target attrs: %v", st.Attributes)
	}
	if len(edgesFrom(sink, st.IdentityKey)) != 0 {
		t.Error("/static/ must not have edges")
	}

	// Upstream members: every server with a listener gets an edge,
	// not just the first one.
	upEdges := edgesFrom(sink, upKey)
	if len(upEdges) != 2 {
		t.Fatalf("upstream edges = %d, want one per member, got %+v", len(upEdges), upEdges)
	}
	wantUpDst := map[string]bool{
		listenerKey("tcp", "127.0.0.1", 9001, 102): true,
		listenerKey("tcp", "127.0.0.1", 9002, 103): true,
	}
	for _, e := range upEdges {
		if !wantUpDst[e.DstIdentityKey] {
			t.Errorf("unexpected upstream edge dst %q", e.DstIdentityKey)
		}
	}

	// No broken routes, no unresolved blind spots besides the trap.
	if len(sink.findings) != 0 {
		t.Errorf("findings = %+v, want none", sink.findings)
	}
	if len(sink.blinds) != 1 {
		t.Errorf("blind spots = %d, want 1", len(sink.blinds))
	}

	// Every route has evidence pointing at its config line.
	for _, e := range sink.evidence {
		if strings.HasPrefix(e.EntityIdentityKey, "nginx_route|") {
			if !strings.Contains(e.RawRef, ".conf:") {
				t.Errorf("route evidence raw_ref = %q, want file:line", e.RawRef)
			}
		}
	}
}

func TestCollectBrokenRoute(t *testing.T) {
	sockOK := filepath.Join(t.TempDir(), "app.sock")
	if err := os.WriteFile(sockOK, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	root := writeTree(t, map[string]string{
		"nginx.conf": fmt.Sprintf(`
http {
    server {
        listen 80;
        location /dead/ { proxy_pass http://127.0.0.1:9999/; }
        location /sock-missing/ { proxy_pass http://unix:/run/no/such.sock:/; }
        location /sock-ok/ { proxy_pass http://unix:%s:/; }
    }
}
`, sockOK),
	})
	index := &fakeIndex{rows: []collector.ListenerRow{
		{IdentityKey: listenerKey("tcp", "0.0.0.0", 8080, 1), Name: "0.0.0.0:8080"},
	}}
	sink := collect(t, root, index)

	if len(sink.findings) != 2 {
		t.Fatalf("findings = %+v, want 2 BROKEN_ROUTE", sink.findings)
	}
	for _, f := range sink.findings {
		if f.Kind != "BROKEN_ROUTE" || f.Severity != "warn" {
			t.Errorf("finding = %+v, want warn BROKEN_ROUTE", f)
		}
	}

	dead := routeByName(t, sink, "/dead/")
	if !hasFinding(sink, dead.IdentityKey, "BROKEN_ROUTE") {
		t.Error("/dead/ must have a BROKEN_ROUTE finding")
	}
	missing := routeByName(t, sink, "/sock-missing/")
	if !hasFinding(sink, missing.IdentityKey, "BROKEN_ROUTE") {
		t.Error("/sock-missing/ must have a BROKEN_ROUTE finding")
	}
	okSock := routeByName(t, sink, "/sock-ok/")
	if hasFinding(sink, okSock.IdentityKey, "BROKEN_ROUTE") {
		t.Error("/sock-ok/ must not have a finding")
	}
}

func TestCollectWithoutIndexSkipsAbsenceClaims(t *testing.T) {
	root := writeTree(t, map[string]string{
		"nginx.conf": `
http {
    server {
        listen 80;
        location /dead/ { proxy_pass http://127.0.0.1:9999/; }
    }
}
`,
	})
	sink := collect(t, root, nil)
	if len(sink.findings) != 0 {
		t.Errorf("findings = %+v, want none without an index", sink.findings)
	}
	r := routeByName(t, sink, "/dead/")
	if len(edgesFrom(sink, r.IdentityKey)) != 0 {
		t.Error("no index means no edges")
	}
	if countKind(sink, "nginx_route") != 1 {
		t.Errorf("entities missing: %d routes", countKind(sink, "nginx_route"))
	}
}

func TestCollectSyntaxErrorBecomesBlindSpot(t *testing.T) {
	root := writeTree(t, map[string]string{
		"nginx.conf": `
http {
    include broken.conf;
    server {
        listen 8080;
        location /ok/ { proxy_pass http://127.0.0.1:8081; }
    }
}
`,
		"broken.conf": "server {\n    listen 80;\n",
	})
	sink := collect(t, root, nil)

	if len(sink.blinds) != 1 || sink.blinds[0].Reason != "nginx_config_parse_error" {
		t.Fatalf("blinds = %+v, want one nginx_config_parse_error", sink.blinds)
	}
	d := sink.blinds[0].Detail
	if !strings.HasSuffix(d["file"], "broken.conf") || d["line"] == "" {
		t.Errorf("parse error detail = %v, want broken.conf with a line", d)
	}
	if countKind(sink, "nginx_route") != 1 {
		t.Errorf("intact routes must still be collected, got %d", countKind(sink, "nginx_route"))
	}
}

func TestCollectMissingRootFails(t *testing.T) {
	c := New(nil, nil)
	c.root = filepath.Join(t.TempDir(), "absent.conf")
	if err := c.Collect(context.Background(), newRecSink()); err == nil {
		t.Fatal("want error for missing root")
	}
}

func TestCollectIndexErrorFails(t *testing.T) {
	root := writeTree(t, map[string]string{
		"nginx.conf": "http { server { listen 80; location /a/ { proxy_pass http://127.0.0.1:1; } } }",
	})
	c := New(nil, &fakeIndex{err: fmt.Errorf("db down")})
	c.root = root
	if err := c.Collect(context.Background(), newRecSink()); err == nil {
		t.Fatal("want error when the index fails")
	}
}

func TestCollectTwiceStableFingerprint(t *testing.T) {
	root := writeTree(t, map[string]string{
		"nginx.conf": "http { server { listen 8080; location /web/ { proxy_pass http://127.0.0.1:8081; } } }",
	})
	idx := &fakeIndex{rows: []collector.ListenerRow{
		{IdentityKey: listenerKey("tcp", "0.0.0.0", 8081, 7), Name: "0.0.0.0:8081"},
	}}
	first := collect(t, root, idx)
	second := collect(t, root, idx)

	a := routeByName(t, first, "/web/")
	b := routeByName(t, second, "/web/")
	if a.IdentityKey != b.IdentityKey {
		t.Errorf("identity drift: %q vs %q", a.IdentityKey, b.IdentityKey)
	}
	if a.Fingerprint == "" || a.Fingerprint != b.Fingerprint {
		t.Errorf("fingerprint drift: %q vs %q", a.Fingerprint, b.Fingerprint)
	}
}

func hasFinding(sink *recSink, entityKey, kind string) bool {
	for _, f := range sink.findings {
		if f.EntityIdentityKey == entityKey && f.Kind == kind {
			return true
		}
	}
	return false
}

// compile-time interface checks
var (
	_ collector.Sink = (*recSink)(nil)
	_ Index          = (*fakeIndex)(nil)
)
