package apache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTree writes a config tree under a temp dir and returns the
// path of the main configuration.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	writeFilesAt(t, dir, files)
	return filepath.Join(dir, "apache2.conf")
}

// writeFilesAt writes a name→content map under dir, creating parent
// directories as needed. Tests that embed the directory into the
// config text (ServerRoot, absolute includes) use it directly so the
// tree never points at the host's own configuration.
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

// routeByPath finds the single route matching a source path.
func routeByPath(t *testing.T, cfg *Config, path string) *Route {
	t.Helper()
	for i := range cfg.Routes {
		if cfg.Routes[i].Path == path {
			return &cfg.Routes[i]
		}
	}
	t.Fatalf("no route for path %q (have %d routes)", path, len(cfg.Routes))
	return nil
}

func TestLoadExtractsRoutes(t *testing.T) {
	// ServerRoot points at the fixture tree itself: the include then
	// resolves against the temp dir, never against a real Apache
	// installation that a CI runner may happen to have.
	dir := t.TempDir()
	writeFilesAt(t, dir, map[string]string{
		"apache2.conf": `
ServerRoot "` + dir + `"
Listen 80

# Relative include: resolved against ServerRoot, like Apache does.
IncludeOptional sites-enabled/*.conf

<VirtualHost *:80>
    ProxyPass "/api" "http://127.0.0.1:8080" retry=0
    ProxyPass /app http://192.0.2.10:9000
    ProxyPass "/my app" http://127.0.0.1:9001
    ProxyPass /legacy !
    ServerName www.example.test
</VirtualHost>

ProxyPass /global http://127.0.0.1:9090
`,
		"sites-enabled/000-default.conf": `
<VirtualHost *:443>
    ServerName secure.example.test
    <Location /sock>
        ProxyPass unix:/run/app.sock|http://localhost/sock
    </Location>
</VirtualHost>
`,
	})
	root := filepath.Join(dir, "apache2.conf")

	cfg, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Errors) != 0 || len(cfg.Unreadable) != 0 {
		t.Fatalf("problems = %+v / %+v, want none", cfg.Errors, cfg.Unreadable)
	}
	if len(cfg.Routes) != 5 {
		t.Fatalf("routes = %d, want 5 (the exclusion never becomes one)", len(cfg.Routes))
	}

	api := routeByPath(t, cfg, "/api")
	if api.VHost != "*:80" || api.ServerName != "www.example.test" {
		t.Errorf("api vhost = %q server = %q", api.VHost, api.ServerName)
	}
	if api.Target != "http://127.0.0.1:8080" {
		t.Errorf("api target = %q", api.Target)
	}
	if api.Line <= 0 || !strings.Contains(api.RawRef(), ":") {
		t.Errorf("raw ref = %q, want file:line", api.RawRef())
	}
	// ServerName declared after the proxy lines still lands on them.
	if api.ServerName == "" {
		t.Error("late ServerName must resolve onto earlier routes")
	}
	// Quoted paths keep their spaces.
	myApp := routeByPath(t, cfg, "/my app")
	if myApp.Target != "http://127.0.0.1:9001" {
		t.Errorf("my app target = %q", myApp.Target)
	}
	// Ordinals are per vhost+path.
	if api.Ord != 1 {
		t.Errorf("api ord = %d, want 1", api.Ord)
	}

	// A Location-scoped ProxyPass takes its path from the section
	// and keeps the unix socket target raw.
	sock := routeByPath(t, cfg, "/sock")
	if sock.VHost != "*:443" || sock.ServerName != "secure.example.test" {
		t.Errorf("sock vhost = %q server = %q", sock.VHost, sock.ServerName)
	}
	if sock.Target != "unix:/run/app.sock|http://localhost/sock" {
		t.Errorf("sock target = %q", sock.Target)
	}

	// A global route outside any vhost has no vhost identity.
	global := routeByPath(t, cfg, "/global")
	if global.VHost != "" || global.ServerName != "" {
		t.Errorf("global = %+v, want no vhost", global)
	}
}

func TestLoadRecordsErrorsAndUnreadable(t *testing.T) {
	root := writeTree(t, map[string]string{
		"apache2.conf": `
Include missing/*.conf

<VirtualHost *:80>
    ServerName a.example.test
    ProxyPass /broken
    ProxyPass /ok http://127.0.0.1:8080
</VirtualHost>
</IfModule>
<Directory /var/www>
`,
	})

	cfg, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Unreadable) != 1 || !strings.Contains(cfg.Unreadable[0].Err.Error(), "matched no file") {
		t.Errorf("unreadable = %+v, want the missing include", cfg.Unreadable)
	}
	// ProxyPass without a target, the unmatched close tag and the
	// section left open at EOF.
	if len(cfg.Errors) != 3 {
		t.Fatalf("errors = %+v, want 3", cfg.Errors)
	}
	msgs := make([]string, 0, len(cfg.Errors))
	for _, e := range cfg.Errors {
		msgs = append(msgs, e.Err.Error())
	}
	joined := strings.Join(msgs, "\n")
	for _, want := range []string{"needs a path and a target", "does not match", "never closed"} {
		if !strings.Contains(joined, want) {
			t.Errorf("errors lack %q:\n%s", want, joined)
		}
	}
	// The valid route still contributes inventory.
	if len(cfg.Routes) != 1 || cfg.Routes[0].Path != "/ok" {
		t.Errorf("routes = %+v, want the valid one kept", cfg.Routes)
	}
}

// A relative include resolves against ServerRoot first, like Apache
// does: when ServerRoot points at its own tree (as the fixed fixture
// does), a host installation with the same relative layout must not
// be pulled in. This pins the include-resolution order that made a
// host-dependent fixture lose its own site on machines where
// ServerRoot existed with matching files.
func TestLoadIncludeResolvesAgainstServerRootFirst(t *testing.T) {
	host := t.TempDir() // stands in for a system ServerRoot with a live site
	writeFilesAt(t, host, map[string]string{
		"sites-enabled/000-default.conf": "<VirtualHost *:80>\nDocumentRoot /var/www\n</VirtualHost>\n",
	})
	dir := t.TempDir()
	writeFilesAt(t, dir, map[string]string{
		"apache2.conf": `
ServerRoot "` + host + `"
IncludeOptional sites-enabled/*.conf
ProxyPass /global http://127.0.0.1:9090
`,
		"sites-enabled/000-default.conf": `
<VirtualHost *:443>
    <Location /sock>
        ProxyPass unix:/run/app.sock|http://localhost/sock
    </Location>
</VirtualHost>
`,
	})

	cfg, err := Load(filepath.Join(dir, "apache2.conf"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Only /global: the include followed ServerRoot into the host
	// tree, so the fixture's own site contributed nothing. A test
	// that needs both must point ServerRoot at its own tree.
	if len(cfg.Routes) != 1 || cfg.Routes[0].Path != "/global" {
		t.Fatalf("routes = %+v, want only /global (ServerRoot tree wins)", cfg.Routes)
	}
}

func TestLoadIncludeCycleTerminates(t *testing.T) {
	root := writeTree(t, map[string]string{
		"apache2.conf": `
Include other.conf
ProxyPass /a http://127.0.0.1:8080
`,
		"other.conf": `
Include apache2.conf
ProxyPass /b http://127.0.0.1:8081
`,
	})

	cfg, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Errors) != 0 {
		t.Errorf("errors = %+v, want none", cfg.Errors)
	}
	if len(cfg.Routes) != 2 {
		t.Errorf("routes = %d, want 2 (each file once)", len(cfg.Routes))
	}
}

func TestParseTargetClassifies(t *testing.T) {
	cases := []struct {
		raw  string
		want TargetKind
	}{
		{"", TargetUnresolved},
		{"$BACKEND", TargetUnresolved},
		{"${ENV}/path", TargetUnresolved},
		{"127.0.0.1:8080", TargetUnresolved}, // no scheme
		{"balancer://cluster", TargetUnresolved},
		{"http://127.0.0.1:8080", TargetLocal},
		{"https://localhost:8443", TargetLocal},
		{"ajp://127.0.0.1:8009", TargetLocal},
		{"http://:8080", TargetLocal},
		{"http://[::1]:9000", TargetLocal},
		{"https://example.test", TargetHost},
		{"http://192.0.2.10:9000", TargetHost},
		{"unix:/run/app.sock|http://localhost/sock", TargetUnix},
		{"unix:/run/app.sock", TargetUnresolved}, // socket form needs the URL
	}
	for _, tc := range cases {
		got := ParseTarget(tc.raw)
		if got.Kind != tc.want {
			t.Errorf("ParseTarget(%q).Kind = %q, want %q", tc.raw, got.Kind, tc.want)
		}
	}
	// The raw value is always preserved for evidence.
	if ParseTarget("$BACKEND").Raw != "$BACKEND" {
		t.Error("Raw must keep the configured value")
	}
	// A local target with a port is matchable against listeners.
	local := ParseTarget("http://127.0.0.1:8080")
	if local.Host != "127.0.0.1" || local.Port != 8080 || local.Scheme != "http" {
		t.Errorf("local = %+v, want http 127.0.0.1:8080", local)
	}
	// A URL without a port keeps 0: the standard port is never guessed.
	if ParseTarget("https://example.test").Port != 0 {
		t.Error("port must stay 0 when absent")
	}
	// The unix socket keeps its path.
	sock := ParseTarget("unix:/run/app.sock|http://localhost/sock")
	if sock.Socket != "/run/app.sock" {
		t.Errorf("socket = %q", sock.Socket)
	}
}

func TestKeysAndFingerprintsStableAcrossLoads(t *testing.T) {
	src := `
<VirtualHost *:80>
    ServerName a.example.test
    ProxyPass /api http://127.0.0.1:8080
</VirtualHost>
`
	root := writeTree(t, map[string]string{"apache2.conf": src})

	a, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if a.Routes[0].Key() != b.Routes[0].Key() ||
		a.Routes[0].Fingerprint() != b.Routes[0].Fingerprint() {
		t.Error("route identity changed between identical loads")
	}
	if !strings.HasPrefix(a.Routes[0].Key(), "apache_route|") {
		t.Errorf("key = %q", a.Routes[0].Key())
	}

	// Changing the target changes the fingerprint but not the key.
	if err := os.WriteFile(root, []byte(strings.Replace(
		src, "127.0.0.1:8080", "127.0.0.1:8081", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Routes[0].Key() != a.Routes[0].Key() {
		t.Errorf("key = %q, want stable across edits", changed.Routes[0].Key())
	}
	if changed.Routes[0].Fingerprint() == a.Routes[0].Fingerprint() {
		t.Error("fingerprint must change when the target changes")
	}
}
