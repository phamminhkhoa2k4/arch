package traefik

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTree writes a config tree under a temp dir and returns the
// path of the static entry point together with the directory, so
// tests can point the file provider at a subdirectory of it.
func writeTree(t *testing.T, files map[string]string) (root, dir string) {
	t.Helper()
	dir = t.TempDir()
	writeFiles(t, dir, files)
	return filepath.Join(dir, "traefik.yml"), dir
}

// writeFiles writes a name→content map under dir, creating parent
// directories as needed.
func writeFiles(t *testing.T, dir string, files map[string]string) {
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

func TestLoadCollectsRoutersAndServices(t *testing.T) {
	dir := t.TempDir()
	dyn := filepath.Join(dir, "dynamic")
	files := map[string]string{
		"traefik.yml": `
providers:
  file:
    directory: ` + dyn + `
  docker: {}
entryPoints:
  web:
    address: ":80"
`,
		"dynamic/http.yml": `
http:
  routers:
    api:
      rule: "Host(` + "`api.example.test`" + `)"
      service: api-svc
      entryPoints:
        - web
      middlewares:
        - auth
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
		"dynamic/tcp.yml": `
tcp:
  routers:
    db:
      service: db-svc
      entryPoints:
        - dbep
  services:
    db-svc:
      loadBalancer:
        servers:
          - address: "127.0.0.1:5432"
`,
	}
	writeFiles(t, dir, files)
	root := filepath.Join(dir, "traefik.yml")

	cfg, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Errors) != 0 || len(cfg.Unreadable) != 0 || len(cfg.Unsupported) != 0 {
		t.Fatalf("problems = %+v / %+v / %+v, want none", cfg.Errors, cfg.Unreadable, cfg.Unsupported)
	}
	// The docker provider is declared: its labels are not inventoried.
	if strings.Join(cfg.Providers, ",") != "docker" {
		t.Errorf("providers = %v, want [docker]", cfg.Providers)
	}

	if len(cfg.Routers) != 3 {
		t.Fatalf("routers = %+v, want 3", cfg.Routers)
	}
	api := cfg.Routers[0]
	if api.Protocol != "http" || api.Name != "api" || api.Service != "api-svc" {
		t.Errorf("router = %+v, want http api → api-svc", api)
	}
	if !strings.Contains(api.Rule, "api.example.test") {
		t.Errorf("rule = %q", api.Rule)
	}
	if len(api.EntryPoints) != 1 || api.EntryPoints[0] != "web" {
		t.Errorf("entryPoints = %v", api.EntryPoints)
	}
	if len(api.Middlewares) != 1 || api.Middlewares[0] != "auth" {
		t.Errorf("middlewares = %v", api.Middlewares)
	}
	if api.Line <= 0 || !strings.Contains(api.RawRef(), ".yml:") {
		t.Errorf("raw ref = %q, want file:line", api.RawRef())
	}
	tcpRouter := cfg.Routers[2]
	if tcpRouter.Protocol != "tcp" || tcpRouter.Name != "db" || tcpRouter.Rule != "" {
		t.Errorf("tcp router = %+v", tcpRouter)
	}

	if len(cfg.Services) != 3 {
		t.Fatalf("services = %+v, want 3", cfg.Services)
	}
	apiSvc := cfg.Services[0]
	if apiSvc.Kind != "loadBalancer" || len(apiSvc.Servers) != 2 {
		t.Errorf("api-svc = %+v, want loadBalancer with 2 servers", apiSvc)
	}
	if apiSvc.Servers[0].Target != "http://127.0.0.1:8080" {
		t.Errorf("server 1 = %q", apiSvc.Servers[0].Target)
	}
	weighted := cfg.Services[1]
	if weighted.Kind != "weighted" || strings.Join(weighted.Refs, ",") != "api-svc" {
		t.Errorf("weighted-svc = %+v, want ref to api-svc", weighted)
	}
	if cfg.Services[2].Protocol != "tcp" || cfg.Services[2].Servers[0].Target != "127.0.0.1:5432" {
		t.Errorf("db-svc = %+v", cfg.Services[2])
	}
}

func TestLoadRecordsProviderAndFileProblems(t *testing.T) {
	dir := t.TempDir()
	dyn := filepath.Join(dir, "missing") // never created
	files := map[string]string{
		"traefik.yml": `
providers:
  file:
    directory: ` + dyn + `
  docker: {}
  consul: {}
`,
	}
	writeFiles(t, dir, files)
	cfg, err := Load(filepath.Join(dir, "traefik.yml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Providers are sorted for deterministic blind-spot output.
	if strings.Join(cfg.Providers, ",") != "consul,docker" {
		t.Errorf("providers = %v, want consul,docker", cfg.Providers)
	}
	if len(cfg.Unreadable) != 1 {
		t.Errorf("unreadable = %+v, want the missing directory", cfg.Unreadable)
	}
}

func TestLoadRecordsBadDynamicFileAndKeepsGoodOnes(t *testing.T) {
	dir := t.TempDir()
	dyn := filepath.Join(dir, "conf")
	files := map[string]string{
		"traefik.yml": `
providers:
  file:
    directory: ` + dyn + `
`,
		"conf/bad.yml":  "http: [\n",
		"conf/old.toml": "[http.routers.x]\n",
		"conf/good.yml": `
http:
  routers:
    ok:
      rule: "Host(` + "`ok.example.test`" + `)"
      service: ok-svc
  services:
    ok-svc:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8080"
`,
	}
	writeFiles(t, dir, files)
	cfg, err := Load(filepath.Join(dir, "traefik.yml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Errors) != 1 {
		t.Errorf("errors = %+v, want 1 (bad.yml)", cfg.Errors)
	}
	if len(cfg.Unsupported) != 1 || !strings.Contains(cfg.Unsupported[0].File, "old.toml") {
		t.Errorf("unsupported = %+v, want old.toml", cfg.Unsupported)
	}
	// The good file still contributes inventory.
	if len(cfg.Routers) != 1 || cfg.Routers[0].Name != "ok" {
		t.Errorf("routers = %+v, want the good one kept", cfg.Routers)
	}
}

func TestLoadRecordsStaticSyntaxError(t *testing.T) {
	root, _ := writeTree(t, map[string]string{
		"traefik.yml": "providers: [\n",
	})
	cfg, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Errors) != 1 {
		t.Fatalf("errors = %+v, want 1", cfg.Errors)
	}
	if len(cfg.Routers) != 0 || len(cfg.Services) != 0 {
		t.Errorf("inventory from a broken static config: %+v", cfg)
	}
}

func TestParseURLClassifies(t *testing.T) {
	cases := []struct {
		raw  string
		want TargetKind
	}{
		{"", TargetUnresolved},
		{"$URL", TargetUnresolved},
		{"{env.BACKEND}", TargetUnresolved},
		{"127.0.0.1:8080", TargetUnresolved}, // no scheme: not a server URL
		{"ftp://example.test/x", TargetUnresolved},
		{"http://127.0.0.1:8080", TargetLocal},
		{"h2c://localhost:8081", TargetLocal},
		{"http://:8080", TargetLocal},
		{"http://[::1]:9000", TargetLocal},
		{"https://example.test", TargetHost},
		{"http://192.0.2.10:8443", TargetHost},
		{"unix:///run/app.sock", TargetUnix},
	}
	for _, tc := range cases {
		got := ParseURL(tc.raw)
		if got.Kind != tc.want {
			t.Errorf("ParseURL(%q).Kind = %q, want %q", tc.raw, got.Kind, tc.want)
		}
	}
	// The raw value is always preserved for evidence.
	if ParseURL("$URL").Raw != "$URL" {
		t.Error("Raw must keep the configured value")
	}
	// A local URL with a port is matchable against listeners.
	local := ParseURL("http://127.0.0.1:8080")
	if local.Host != "127.0.0.1" || local.Port != 8080 || local.Scheme != "http" {
		t.Errorf("local = %+v, want http127.0.0.1:8080", local)
	}
	// A URL without a port keeps0: the standard port is never guessed.
	if ParseURL("https://example.test").Port != 0 {
		t.Error("port must stay 0 when absent")
	}
	// The unix socket keeps its path.
	sock := ParseURL("unix:///run/app.sock")
	if sock.Socket != "/run/app.sock" {
		t.Errorf("socket = %q", sock.Socket)
	}
}

func TestParseAddressClassifies(t *testing.T) {
	cases := []struct {
		raw  string
		want TargetKind
	}{
		{"", TargetUnresolved},
		{"$ADDR", TargetUnresolved},
		{"/run/db.sock", TargetUnix},
		{"127.0.0.1:5432", TargetLocal},
		{"[::1]:5432", TargetLocal},
		{"192.0.2.1:5432", TargetHost},
		{"example.test:5432", TargetHost},
		{"192.0.2.1", TargetHost}, // no port: never guessed
	}
	for _, tc := range cases {
		got := ParseAddress(tc.raw)
		if got.Kind != tc.want {
			t.Errorf("ParseAddress(%q).Kind = %q, want %q", tc.raw, got.Kind, tc.want)
		}
	}
}

func TestKeysAndFingerprintsStableAcrossLoads(t *testing.T) {
	dir := t.TempDir()
	dyn := filepath.Join(dir, "conf")
	files := map[string]string{
		"traefik.yml": "providers:\n  file:\n    directory: " + dyn + "\n",
		"conf/dyn.yml": `
http:
  routers:
    api:
      rule: "Host(` + "`api.example.test`" + `)"
      service: api-svc
  services:
    api-svc:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8080"
`,
	}
	writeFiles(t, dir, files)
	root := filepath.Join(dir, "traefik.yml")

	a, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if a.Routers[0].Key() != b.Routers[0].Key() ||
		a.Routers[0].Fingerprint() != b.Routers[0].Fingerprint() {
		t.Error("router identity changed between identical loads")
	}
	if a.Services[0].Key() != b.Services[0].Key() ||
		a.Services[0].Fingerprint() != b.Services[0].Fingerprint() {
		t.Error("service identity changed between identical loads")
	}
	if a.Routers[0].Key() != "traefik_router|http#api" {
		t.Errorf("router key = %q", a.Routers[0].Key())
	}
	if a.Services[0].Key() != "traefik_service|http#api-svc" {
		t.Errorf("service key = %q", a.Services[0].Key())
	}

	// Changing the rule changes the fingerprint but not the key.
	files["conf/dyn.yml"] = strings.Replace(
		files["conf/dyn.yml"], "api.example.test", "api2.example.test", 1)
	if err := os.WriteFile(filepath.Join(dir, "conf", "dyn.yml"),
		[]byte(files["conf/dyn.yml"]), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Routers[0].Key() != a.Routers[0].Key() {
		t.Errorf("key = %q, want stable across edits", changed.Routers[0].Key())
	}
	if changed.Routers[0].Fingerprint() == a.Routers[0].Fingerprint() {
		t.Error("fingerprint must change when the rule changes")
	}
}
