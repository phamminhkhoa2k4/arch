package accesslog

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"archaeologist/internal/collector"
)

// recSink records everything the collector emits.
type recSink struct {
	entities map[string]collector.Entity
	evidence []collector.Evidence
	blinds   []collector.BlindSpot
	findings []collector.Finding
}

func newRecSink() *recSink { return &recSink{entities: map[string]collector.Entity{}} }

func (r *recSink) UpsertEntity(e collector.Entity) error {
	r.entities[e.IdentityKey] = e
	return nil
}
func (r *recSink) UpsertEdge(e collector.Edge) error { return nil }
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

// memLogFS is an in-memory accesslog.FS.
type memLogFS struct {
	files map[string]string
	dirs  map[string][]string
}

func newMemLogFS() *memLogFS {
	return &memLogFS{files: map[string]string{}, dirs: map[string][]string{}}
}

func (f *memLogFS) Open(name string) (io.ReadCloser, error) {
	content, ok := f.files[name]
	if !ok {
		return nil, &logPathError{path: name}
	}
	return io.NopCloser(strings.NewReader(content)), nil
}

func (f *memLogFS) ReadDir(name string) ([]string, error) {
	names, ok := f.dirs[name]
	if !ok {
		return nil, &logPathError{path: name}
	}
	return names, nil
}

type logPathError struct{ path string }

func (e *logPathError) Error() string { return "open " + e.path + ": no such file" }

func (e *logPathError) Is(target error) bool {
	return target.Error() == "file does not exist"
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

const httpTree = `
events { worker_connections 1024; }
http {
    include conf.d/*.conf;
}
`

const labConf = `
access_log /var/log/nginx/lab_access.log;
server {
    listen 8080;
    server_name _;
    location /web/ { proxy_pass http://127.0.0.1:8081/; }
    location /web/app/ { proxy_pass http://127.0.0.1:8081/app/; }
    location /pool/ { proxy_pass http://127.0.0.1:8082/; }
}
`

func logLine(ts, uri string) string {
	return fmt.Sprintf(`192.0.2.1 - - [%s] "GET %s HTTP/1.1" 200 5 "-" "t"`, ts, uri)
}

const labLog = "/var/log/nginx/lab_access.log"

func collectWith(t *testing.T, root string, fsys *memLogFS) *recSink {
	t.Helper()
	c := New(nil, fsys)
	c.root = root
	sink := newRecSink()
	if err := c.Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return sink
}

// Matched traffic becomes in_use evidence with last_request_at
// and a file:line raw_ref; unmatched URIs and unparsable lines are
// handled (blind), never dropped silently.
func TestCollectRouteEvidence(t *testing.T) {
	root := writeTree(t, map[string]string{
		"nginx.conf":      httpTree,
		"conf.d/lab.conf": labConf,
	})
	fsys := newMemLogFS()
	fsys.files[labLog] = strings.Join([]string{
		logLine("06/Oct/2026:10:00:00 +0000", "/web/a"),
		logLine("06/Oct/2026:10:02:00 +0000", "/pool/x"),
		logLine("06/Oct/2026:10:05:00 +0000", "/web/b?q=1"),
		"totally custom format line",
		logLine("06/Oct/2026:10:07:00 +0000", "/nowhere"),
	}, "\n")
	fsys.dirs["/var/log/nginx"] = []string{"lab_access.log"}

	sink := collectWith(t, root, fsys)

	var webEvidence []collector.Evidence
	var poolEvidence []collector.Evidence
	for _, e := range sink.evidence {
		if e.Channel != "nginx_access_log" {
			continue
		}
		switch {
		case strings.HasSuffix(e.EntityIdentityKey, "#/web/"):
			webEvidence = append(webEvidence, e)
		case strings.HasSuffix(e.EntityIdentityKey, "#/web/app/"):
			t.Errorf("no /web/app/ traffic expected: %+v", e)
		case strings.HasSuffix(e.EntityIdentityKey, "#/pool/"):
			poolEvidence = append(poolEvidence, e)
		default:
			t.Errorf("unexpected route evidence: %+v", e)
		}
	}
	if len(webEvidence) != 1 {
		t.Fatalf("web evidence = %+v, want 1", webEvidence)
	}
	we := webEvidence[0]
	if we.Polarity != collector.PolarityInUse ||
		we.Strength != collector.StrengthDeterministic ||
		we.ObservedAt == "" {
		t.Errorf("web evidence = %+v", we)
	}
	if we.Value["count"] != "2" || we.Value["log_path"] != labLog {
		t.Errorf("web value = %+v", we.Value)
	}
	if we.Value["last_request_at"] != "2026-10-06T10:05:00Z" {
		t.Errorf("last_request_at = %q", we.Value["last_request_at"])
	}
	if we.RawRef != labLog+":3" {
		t.Errorf("raw_ref = %q, want line 3", we.RawRef)
	}
	if len(poolEvidence) != 1 || poolEvidence[0].Value["count"] != "1" {
		t.Errorf("pool evidence = %+v", poolEvidence)
	}

	if len(sink.blinds) != 1 || sink.blinds[0].Reason != "log_parse_error" ||
		sink.blinds[0].Channel != "log" ||
		sink.blinds[0].Detail["unparsed"] != "1" || sink.blinds[0].Detail["total"] != "5" {
		t.Errorf("blinds = %+v, want one log_parse_error", sink.blinds)
	}
}

// A fully custom format parses nothing: unparseable blind instead of
// silently missing evidence.
func TestCollectCustomFormatBlind(t *testing.T) {
	root := writeTree(t, map[string]string{
		"nginx.conf":      httpTree,
		"conf.d/lab.conf": labConf,
	})
	fsys := newMemLogFS()
	fsys.files[labLog] = `{"ts":"2026-10-06T10:00:00Z","uri":"/web/","status":200}
{"ts":"2026-10-06T10:01:00Z","uri":"/pool/","status":200}`
	fsys.dirs["/var/log/nginx"] = []string{"lab_access.log"}

	sink := collectWith(t, root, fsys)

	if len(sink.evidence) != 0 {
		t.Errorf("evidence = %+v, want none", sink.evidence)
	}
	if len(sink.blinds) != 1 || sink.blinds[0].Reason != "log_format_unparseable" ||
		sink.blinds[0].Detail["log_path"] != labLog {
		t.Errorf("blinds = %+v, want one log_format_unparseable", sink.blinds)
	}
}

// Rotation of at most seven days attaches a
// log_retention_short blind spot to every route; longer windows and
// no rotation stay silent.
func TestCollectRetentionShortBlind(t *testing.T) {
	root := writeTree(t, map[string]string{
		"nginx.conf":      httpTree,
		"conf.d/lab.conf": labConf,
	})
	fsys := newMemLogFS()
	fsys.files[labLog] = logLine("06/Oct/2026:10:00:00 +0000", "/web/a")
	fsys.dirs["/var/log/nginx"] = []string{"lab_access.log", "lab_access.log.1", "lab_access.log.7.gz"}

	sink := collectWith(t, root, fsys)
	if len(sink.blinds) != 3 {
		t.Fatalf("blinds = %+v, want 3 (one per route)", sink.blinds)
	}
	seen := map[string]bool{}
	for _, b := range sink.blinds {
		if b.Reason != "log_retention_short" || b.Channel != "log" ||
			b.Detail["retention_days"] != "7" || b.Detail["log_path"] != labLog {
			t.Errorf("blind = %+v", b)
		}
		seen[b.EntityIdentityKey] = true
	}
	if len(seen) != 3 {
		t.Errorf("routes covered = %v, want 3", seen)
	}

	// A long window qualifies nothing.
	fsys.dirs["/var/log/nginx"] = []string{"lab_access.log", "lab_access.log.30"}
	if sink := collectWith(t, root, fsys); len(sink.blinds) != 0 {
		t.Errorf("30-day retention blinds = %+v, want none", sink.blinds)
	}

	// No rotation at all: nothing to claim.
	fsys.dirs["/var/log/nginx"] = []string{"lab_access.log"}
	if sink := collectWith(t, root, fsys); len(sink.blinds) != 0 {
		t.Errorf("no-rotation blinds = %+v, want none", sink.blinds)
	}
}

// A declared log that nginx has not written yet is silent.
func TestCollectMissingLogSilent(t *testing.T) {
	root := writeTree(t, map[string]string{
		"nginx.conf":      httpTree,
		"conf.d/lab.conf": labConf,
	})
	sink := collectWith(t, root, newMemLogFS())
	if len(sink.evidence) != 0 || len(sink.blinds) != 0 {
		t.Errorf("evidence=%v blinds=%v, want none", sink.evidence, sink.blinds)
	}
}

// Without any access_log directive the built-in default path is used.
func TestCollectFallsBackToDefaultPath(t *testing.T) {
	root := writeTree(t, map[string]string{
		"nginx.conf": httpTree,
		"conf.d/lab.conf": `
server {
    listen 8080;
    server_name _;
    location /web/ { proxy_pass http://127.0.0.1:8081/; }
}
`,
	})
	fsys := newMemLogFS()
	fsys.files["/var/log/nginx/access.log"] = logLine("06/Oct/2026:11:00:00 +0000", "/web/z")
	fsys.dirs["/var/log/nginx"] = []string{"access.log"}

	sink := collectWith(t, root, fsys)
	if len(sink.evidence) != 1 {
		t.Fatalf("evidence = %+v, want 1", sink.evidence)
	}
	if sink.evidence[0].RawRef != "/var/log/nginx/access.log:1" {
		t.Errorf("raw_ref = %q", sink.evidence[0].RawRef)
	}
}

// The longest matching prefix wins: /web/app/ takes /web/app/x.
func TestCollectLongestPrefixWins(t *testing.T) {
	root := writeTree(t, map[string]string{
		"nginx.conf":      httpTree,
		"conf.d/lab.conf": labConf,
	})
	fsys := newMemLogFS()
	fsys.files[labLog] = logLine("06/Oct/2026:10:00:00 +0000", "/web/app/deep")
	fsys.dirs["/var/log/nginx"] = []string{"lab_access.log"}

	sink := collectWith(t, root, fsys)
	for _, e := range sink.evidence {
		switch {
		case strings.HasSuffix(e.EntityIdentityKey, "#/web/app/"):
			if e.Value["count"] != "1" {
				t.Errorf("/web/app/ value = %+v", e.Value)
			}
		case strings.HasSuffix(e.EntityIdentityKey, "#/web/"):
			t.Errorf("shorter prefix must not match: %+v", e)
		}
	}
}

// An unreadable configuration fails the collector (the run loop turns
// it into a collector-level blind spot).
func TestCollectMissingRootFails(t *testing.T) {
	c := New(nil, newMemLogFS())
	c.root = filepath.Join(t.TempDir(), "absent.conf")
	if err := c.Collect(context.Background(), newRecSink()); err == nil {
		t.Fatal("want error for missing root")
	}
}
