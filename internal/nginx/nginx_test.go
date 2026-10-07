package nginx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTree writes a config tree under a temp dir and returns the
// path of the root file.
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

const labTree = `
events { worker_connections 1024; }
http {
    include conf.d/*.conf;
    include sites-enabled/*;
}
`

func TestLoadFollowsNestedIncludes(t *testing.T) {
	root := writeTree(t, map[string]string{
		"nginx.conf": labTree,
		"conf.d/lab.conf": `
server {
    listen 8080;
    listen [::]:8080;
    server_name _;
    location /web/ {
        proxy_pass http://127.0.0.1:8081/;
    }
    location /var/ {
        set $lab_backend 127.0.0.1:8082;
        proxy_pass http://$lab_backend/;
    }
}
`,
		"sites-enabled/default": `
server {
    location / {
        root /var/www/html;
    }
    listen 80 default_server;
    server_name _;
}
`,
	})

	cfg, err := NewLoader().Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", cfg.Errors)
	}
	if len(cfg.Routes) != 3 {
		t.Fatalf("got %d routes, want 3", len(cfg.Routes))
	}

	byLoc := map[string]Route{}
	for _, r := range cfg.Routes {
		byLoc[r.Location] = r
	}

	web := byLoc["/web/"]
	if web.Target == nil || web.Target.Kind != TargetLocal {
		t.Fatalf("/web/ target = %+v, want local", web.Target)
	}
	if web.Target.Host != "127.0.0.1" || web.Target.Port != 8081 {
		t.Errorf("/web/ target host:port = %s:%d, want 127.0.0.1:8081", web.Target.Host, web.Target.Port)
	}
	if got, want := strings.Join(web.Listen, ","), "8080,[::]:8080"; got != want {
		t.Errorf("/web/ listen = %q, want %q", got, want)
	}
	if got, want := strings.Join(web.ServerName, " "), "_"; got != want {
		t.Errorf("/web/ server_name = %q, want %q", got, want)
	}
	if !strings.HasSuffix(web.File, "lab.conf") {
		t.Errorf("/web/ file = %q, want lab.conf", web.File)
	}
	if web.Line <= 0 || web.TargetLine <= 0 {
		t.Errorf("/web/ lines = %d/%d, want both > 0", web.Line, web.TargetLine)
	}

	trap := byLoc["/var/"]
	if trap.Target == nil || trap.Target.Kind != TargetUnresolved {
		t.Fatalf("/var/ target = %+v, want unresolved", trap.Target)
	}
	if len(trap.SetVars) != 1 || !strings.Contains(trap.SetVars[0], "$lab_backend") {
		t.Errorf("/var/ set vars = %v, want one $lab_backend assignment", trap.SetVars)
	}

	static := byLoc["/"]
	if static.Target != nil {
		t.Errorf("/ target = %+v, want none", static.Target)
	}
	// listen/server_name after the location must still be collected.
	if got, want := strings.Join(static.Listen, " "), "80 default_server"; got != want {
		t.Errorf("/ listen = %q, want %q", got, want)
	}
}

func TestLoadUpstreamAndHostTarget(t *testing.T) {
	root := writeTree(t, map[string]string{
		"nginx.conf": `
http {
    upstream backend {
        server 127.0.0.1:9001;
        server 127.0.0.1:9002 weight=5 backup;
    }
    server {
        listen 8080;
        location /a/ {
            proxy_pass http://backend/;
        }
    }
}
`,
	})

	cfg, err := NewLoader().Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Upstreams) != 1 {
		t.Fatalf("got %d upstreams, want 1", len(cfg.Upstreams))
	}
	u := cfg.Upstreams[0]
	if u.Name != "backend" {
		t.Errorf("upstream name = %q, want backend", u.Name)
	}
	if got, want := strings.Join(u.Servers, " "), "127.0.0.1:9001 127.0.0.1:9002"; got != want {
		t.Errorf("upstream servers = %q, want %q", got, want)
	}
	if u.Line <= 0 || !strings.HasSuffix(u.File, "nginx.conf") {
		t.Errorf("upstream position = %s:%d, want nginx.conf:>0", u.File, u.Line)
	}
	if u.Key() != "nginx_upstream|backend" {
		t.Errorf("upstream key = %q", u.Key())
	}

	if len(cfg.Routes) != 1 {
		t.Fatalf("got %d routes, want 1", len(cfg.Routes))
	}
	r := cfg.Routes[0]
	if r.Target == nil || r.Target.Kind != TargetHost || r.Target.Host != "backend" {
		t.Fatalf("/a/ target = %+v, want host backend", r.Target)
	}
}

func TestLoadDeepIncludeInsideServer(t *testing.T) {
	root := writeTree(t, map[string]string{
		"nginx.conf": `
http {
    server {
        listen 9000;
        include snippets/loc.conf;
    }
}
`,
		"snippets/loc.conf": `
location /deep/ {
    proxy_pass http://127.0.0.1:9001;
}
`,
	})

	cfg, err := NewLoader().Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Routes) != 1 {
		t.Fatalf("got %d routes, want 1", len(cfg.Routes))
	}
	r := cfg.Routes[0]
	if r.Location != "/deep/" || len(r.Listen) != 1 || r.Listen[0] != "9000" {
		t.Errorf("route = %+v, want /deep/ on listen 9000", r)
	}
	if !strings.HasSuffix(r.File, "loc.conf") {
		t.Errorf("route file = %q, want loc.conf", r.File)
	}
}

func TestLoadSyntaxErrorReportsFileLine(t *testing.T) {
	root := writeTree(t, map[string]string{
		"nginx.conf": `
http {
    include broken.conf;
    server {
        listen 8080;
        location /ok/ { proxy_pass http://127.0.0.1:1; }
    }
}
`,
		"broken.conf": `
server {
    listen 80;
`,
	})

	cfg, err := NewLoader().Load(root)
	if err != nil {
		t.Fatalf("Load must not fail on syntax error: %v", err)
	}
	if len(cfg.Errors) == 0 {
		t.Fatal("want syntax error, got none")
	}
	fe := cfg.Errors[0]
	if !strings.HasSuffix(fe.File, "broken.conf") {
		t.Errorf("error file = %q, want broken.conf", fe.File)
	}
	if fe.Line <= 0 {
		t.Errorf("error line = %d, want > 0", fe.Line)
	}
	if fe.Err == nil {
		t.Error("error value is nil")
	}
	// The intact part of the tree still yields its routes.
	if len(cfg.Routes) != 1 || cfg.Routes[0].Location != "/ok/" {
		t.Errorf("routes = %+v, want the intact /ok/ route", cfg.Routes)
	}
}

func TestLoadMissingRootFails(t *testing.T) {
	if _, err := NewLoader().Load(filepath.Join(t.TempDir(), "nope.conf")); err == nil {
		t.Fatal("want error for missing root, got nil")
	}
}

func TestLoadDoesNotWalkSameFileTwice(t *testing.T) {
	root := writeTree(t, map[string]string{
		"nginx.conf": `
http {
    include snippet.conf;
    include snippet.conf;
}
`,
		"snippet.conf": `
server {
    listen 8080;
    location /x/ { proxy_pass http://127.0.0.1:1; }
}
`,
	})

	cfg, err := NewLoader().Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Routes) != 1 {
		t.Fatalf("got %d routes, want 1 (double include must not duplicate)", len(cfg.Routes))
	}
}

func TestFingerprintStableAndDrifts(t *testing.T) {
	files := map[string]string{
		"nginx.conf": `
http {
    server {
        listen 8080;
        location /web/ { proxy_pass http://127.0.0.1:8081/; }
    }
}
`,
	}
	root := writeTree(t, files)

	first, err := NewLoader().Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	second, err := NewLoader().Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if first.Routes[0].Fingerprint() != second.Routes[0].Fingerprint() {
		t.Error("fingerprint must be stable across loads")
	}
	if first.Routes[0].Key() != second.Routes[0].Key() {
		t.Error("key must be stable across loads")
	}

	// Change the target: fingerprint must drift, key must not.
	files["nginx.conf"] = strings.Replace(
		files["nginx.conf"], "127.0.0.1:8081", "127.0.0.1:8082", 1)
	if err := os.WriteFile(root, []byte(files["nginx.conf"]), 0o644); err != nil {
		t.Fatal(err)
	}
	third, err := NewLoader().Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if third.Routes[0].Fingerprint() == first.Routes[0].Fingerprint() {
		t.Error("fingerprint must change when the target changes")
	}
	if third.Routes[0].Key() != first.Routes[0].Key() {
		t.Error("key must not change when the target changes")
	}
}

func TestRouteKeyFormat(t *testing.T) {
	r := Route{
		File:       "/etc/nginx/conf.d/app.conf",
		Listen:     []string{"8080", "[::]:8080"},
		ServerName: []string{"example.com", "www.example.com"},
		Location:   "/web/",
	}
	want := "nginx_route|/etc/nginx/conf.d/app.conf#8080,[::]:8080#example.com www.example.com#/web/"
	if got := r.Key(); got != want {
		t.Errorf("Key() = %q, want %q", got, want)
	}
	if got, want := r.RawRef(), "/etc/nginx/conf.d/app.conf:0"; got != want {
		t.Errorf("RawRef() = %q, want %q", got, want)
	}
}

func TestParseTarget(t *testing.T) {
	cases := []struct {
		raw    string
		kind   TargetKind
		host   string
		port   int
		socket string
	}{
		{"http://127.0.0.1:8081/", TargetLocal, "127.0.0.1", 8081, ""},
		{"http://localhost/", TargetLocal, "localhost", 80, ""},
		{"https://example.com:8443/path", TargetHost, "example.com", 8443, ""},
		{"http://backend/", TargetHost, "backend", 80, ""},
		{"http://$lab_backend/", TargetUnresolved, "", 0, ""},
		{"unix:/run/app.sock:/uri", TargetUnix, "", 0, "/run/app.sock"},
		{"unix:/run/php.sock", TargetUnix, "", 0, "/run/php.sock"},
		{"http://unix:/run/x.sock:/api", TargetUnix, "", 0, "/run/x.sock"},
		{"127.0.0.1:9000", TargetLocal, "127.0.0.1", 9000, ""},
		{"[::1]:8080", TargetLocal, "::1", 8080, ""},
		{"[::1]", TargetLocal, "::1", 0, ""},
		{"127.0.0.1", TargetLocal, "127.0.0.1", 0, ""},
		{"example.com", TargetHost, "example.com", 0, ""},
		{"", TargetUnresolved, "", 0, ""},
		// A variable beyond the authority is a URI part: the host
		// stays static and matchable.
		{"http://127.0.0.1:8081$request_uri", TargetLocal, "127.0.0.1", 8081, ""},
		{"http://backend$request_uri", TargetHost, "backend", 80, ""},
		{"http://127.0.0.1:8081/path$uri", TargetLocal, "127.0.0.1", 8081, ""},
		// A variable inside or before the authority is the target.
		{"$scheme://backend/", TargetUnresolved, "", 0, ""},
		{"127.0.0.1:8081$var", TargetUnresolved, "", 0, ""},
		{"$backend:8080", TargetUnresolved, "", 0, ""},
		{"http://", TargetUnresolved, "", 0, ""},
		{"http://unix:/run/$u.sock:/", TargetUnresolved, "", 0, ""},
	}
	for _, tc := range cases {
		got := ParseTarget(tc.raw)
		if got.Kind != tc.kind || got.Host != tc.host || got.Port != tc.port || got.Socket != tc.socket {
			t.Errorf("ParseTarget(%q) = kind=%s host=%q port=%d socket=%q, want kind=%s host=%q port=%d socket=%q",
				tc.raw, got.Kind, got.Host, got.Port, got.Socket,
				tc.kind, tc.host, tc.port, tc.socket)
		}
		if got.Raw != tc.raw {
			t.Errorf("ParseTarget(%q).Raw = %q", tc.raw, got.Raw)
		}
	}
}

// Load records every access_log directive with file, line, path and
// named format; the argument "off" is skipped.
func TestLoadRecordsAccessLogs(t *testing.T) {
	root := writeTree(t, map[string]string{
		"nginx.conf": `
events { worker_connections 1024; }
http {
    access_log /var/log/nginx/access.log main;
    include conf.d/*.conf;
}
`,
		"conf.d/lab.conf": `
access_log off;
server {
    listen 8080;
    access_log /var/log/nginx/lab_access.log;
    location /web/ { proxy_pass http://127.0.0.1:8081/; }
}
`,
	})
	cfg, err := NewLoader().Load(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.AccessLogs) != 2 {
		t.Fatalf("got %d access logs, want 2: %+v", len(cfg.AccessLogs), cfg.AccessLogs)
	}
	byPath := map[string]AccessLog{}
	for _, al := range cfg.AccessLogs {
		byPath[al.Path] = al
	}
	main, ok := byPath["/var/log/nginx/access.log"]
	if !ok || main.Format != "main" || main.Line == 0 || main.File == "" {
		t.Errorf("main access log = %+v", main)
	}
	lab, ok := byPath["/var/log/nginx/lab_access.log"]
	if !ok || lab.Format != "" {
		t.Errorf("lab access log = %+v", lab)
	}
}
