package caddy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTree writes a Caddyfile tree under a temp dir and returns the
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
	return filepath.Join(dir, "Caddyfile")
}

// A real-shaped tree: global options, imported site files, inline
// reverse_proxy arguments, block form with a to subdirective, matchers
// that must not be mistaken for upstreams, and a unix socket target.
func TestLoadExtractsRoutes(t *testing.T) {
	root := writeTree(t, map[string]string{
		"Caddyfile": `
{
	admin off
}
import sites/*.caddy
import extra.caddy
`,
		"sites/app.caddy": `example.com {
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
`,
		"extra.caddy": `static.example.test {
	respond "ok" 200
	reverse_proxy /img/ https://cdn.example.net
}
`,
	})

	cfg, err := NewLoader().Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Errors) != 0 || len(cfg.Unreadable) != 0 {
		t.Fatalf("unexpected problems: errors=%v unreadable=%v", cfg.Errors, cfg.Unreadable)
	}
	if len(cfg.Routes) != 4 {
		t.Fatalf("routes = %d, want 4: %+v", len(cfg.Routes), cfg.Routes)
	}

	byName := map[string]Route{}
	for _, r := range cfg.Routes {
		byName[r.Site+"|"+r.Location] = r
	}

	// Top-level proxy inside the site block: no location, one target.
	var plain *Route
	for i := range cfg.Routes {
		if len(cfg.Routes[i].Targets) == 1 && cfg.Routes[i].Targets[0].Raw == "localhost:8080" {
			plain = &cfg.Routes[i]
		}
	}
	if plain == nil {
		t.Fatalf("plain route missing: %+v", cfg.Routes)
	}
	if plain.Location != "" {
		t.Errorf("plain location = %q, want empty", plain.Location)
	}
	if plain.Targets[0].Kind != TargetLocal ||
		plain.Targets[0].Host != "localhost" || plain.Targets[0].Port != 8080 {
		t.Errorf("plain target = %+v, want local localhost:8080", plain.Targets)
	}
	if plain.Line <= 0 || !strings.HasSuffix(plain.File, "app.caddy") {
		t.Errorf("plain ref = %s:%d, want app.caddy line", plain.File, plain.Line)
	}
	if plain.Fingerprint() == "" || plain.Key() == "" {
		t.Errorf("route must have key and fingerprint: %+v", plain)
	}

	// Matcher argument dropped, upstream kept, scheme parsed.
	var api *Route
	for i := range cfg.Routes {
		if len(cfg.Routes[i].Targets) == 1 && cfg.Routes[i].Targets[0].Raw == "http://127.0.0.1:9000" {
			api = &cfg.Routes[i]
		}
	}
	if api == nil {
		t.Fatalf("api route missing: %+v", cfg.Routes)
	}
	if api.Location != "handle /api/*" {
		t.Errorf("api location = %q, want handle /api/*", api.Location)
	}
	if len(api.Targets) != 1 || api.Targets[0].Kind != TargetLocal || api.Targets[0].Port != 9000 {
		t.Errorf("api targets = %+v, want one local :9000", api.Targets)
	}

	// Block form: matcher-free first line empty, two to upstreams
	// including a unix socket.
	var block *Route
	for i := range cfg.Routes {
		if len(cfg.Routes[i].Targets) == 2 {
			block = &cfg.Routes[i]
		}
	}
	if block == nil {
		t.Fatalf("block route missing: %+v", cfg.Routes)
	}
	if block.Location != "handle" {
		t.Errorf("block location = %q, want handle", block.Location)
	}
	if block.Targets[0].Kind != TargetUnix || block.Targets[0].Socket != "/run/app.sock" {
		t.Errorf("block target 0 = %+v, want unix /run/app.sock", block.Targets[0])
	}
	if block.Targets[1].Kind != TargetLocal || block.Targets[1].Port != 9001 {
		t.Errorf("block target 1 = %+v, want local :9001", block.Targets[1])
	}

	// The imported file's route with a path matcher and a CDN host.
	var cdn *Route
	for i := range cfg.Routes {
		if len(cfg.Routes[i].Targets) == 1 && cfg.Routes[i].Targets[0].Raw == "https://cdn.example.net" {
			cdn = &cfg.Routes[i]
		}
	}
	if cdn == nil {
		t.Fatalf("cdn route missing: %+v", cfg.Routes)
	}
	if cdn.Site != "static.example.test" {
		t.Errorf("cdn site = %q, want static.example.test", cdn.Site)
	}
	if cdn.Targets[0].Kind != TargetHost || cdn.Targets[0].Scheme != "https" {
		t.Errorf("cdn target = %+v, want https host", cdn.Targets[0])
	}
}

// Placeholders and environment references decide their address at
// runtime: they stay unresolved so the collector reports the blind
// spot instead of guessing.
func TestParseTargetRefusesGuesses(t *testing.T) {
	cases := map[string]TargetKind{
		"":                         TargetUnresolved,
		"{env.BACKEND_ADDR}":       TargetUnresolved,
		"{$BACKEND}":               TargetUnresolved,
		"http://{$HOST}:8080":      TargetUnresolved,
		"not a host":               TargetUnresolved,
		"localhost:8080":           TargetLocal,
		"127.0.0.1:9000":           TargetLocal,
		"10.0.0.5:80":              TargetHost,
		"backend.internal":         TargetHost,
		"http://example.com":       TargetHost,
		"https://example.com:8443": TargetHost,
		"unix//run/app.sock":       TargetUnix,
		"unix:/run/app.sock":       TargetUnix,
		"/run/app.sock":            TargetUnix,
		":8080":                    TargetLocal,
	}
	for in, want := range cases {
		got := ParseTarget(in)
		if got.Kind != want {
			t.Errorf("ParseTarget(%q).Kind = %q, want %q", in, got.Kind, want)
		}
		if got.Raw != in {
			t.Errorf("ParseTarget(%q).Raw = %q, want the configured value", in, got.Raw)
		}
	}
}

// A syntax error in one file keeps the routes already collected from
// the files that parsed, and is reported with file and line.
func TestLoadRecordsSyntaxError(t *testing.T) {
	root := writeTree(t, map[string]string{
		"Caddyfile": `example.com {
	reverse_proxy localhost:8080
}
broken.test {
	reverse_proxy {
	to :9000
`,
	})

	cfg, err := NewLoader().Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Errors) == 0 {
		t.Fatal("want a syntax error")
	}
	if !strings.Contains(cfg.Errors[0].File, "Caddyfile") || cfg.Errors[0].Line <= 0 {
		t.Errorf("error = %+v, want Caddyfile with a line", cfg.Errors[0])
	}
}

// An import that matches no file is an unreadable target: the scan
// reports it as a blind spot input rather than silently losing the
// sites it would have contributed.
func TestLoadRecordsUnreadableImport(t *testing.T) {
	root := writeTree(t, map[string]string{
		"Caddyfile": "import missing/*.caddy\n",
	})

	cfg, err := NewLoader().Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Unreadable) != 1 || !strings.Contains(cfg.Unreadable[0].File, "Caddyfile") {
		t.Errorf("unreadable = %+v, want the import site", cfg.Unreadable)
	}
}

// Import cycles terminate: the second visit of a file is skipped.
func TestLoadImportCycleTerminates(t *testing.T) {
	root := writeTree(t, map[string]string{
		"Caddyfile":     "import sites/a.caddy\n",
		"sites/a.caddy": "example.com {\n\treverse_proxy localhost:8080\n}\nimport b.caddy\n",
		"sites/b.caddy": "import a.caddy\n",
	})

	cfg, err := NewLoader().Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Routes) != 1 {
		t.Errorf("routes = %d, want 1 (cycle visited once)", len(cfg.Routes))
	}
}

// The same directive in the same site+location keeps its order number
// stable across loads, so identities survive a rescan.
func TestRouteKeyStableAcrossLoads(t *testing.T) {
	files := map[string]string{
		"Caddyfile": `example.com {
	reverse_proxy localhost:8080
	reverse_proxy localhost:8081
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
	if len(first.Routes) != 2 || len(second.Routes) != 2 {
		t.Fatalf("routes = %d/%d, want 2/2", len(first.Routes), len(second.Routes))
	}
	for i := range first.Routes {
		if first.Routes[i].Key() != second.Routes[i].Key() {
			t.Errorf("key %d = %q, want %q", i,
				second.Routes[i].Key(), first.Routes[i].Key())
		}
	}
	if first.Routes[0].Key() == first.Routes[1].Key() {
		t.Errorf("two routes share key %q", first.Routes[0].Key())
	}
	if first.Routes[0].Ord != 1 || first.Routes[1].Ord != 2 {
		t.Errorf("ord = %d/%d, want 1/2", first.Routes[0].Ord, first.Routes[1].Ord)
	}
}
