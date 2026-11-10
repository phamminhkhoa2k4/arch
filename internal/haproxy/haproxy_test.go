package haproxy

import (
	"strings"
	"testing"
)

const sampleConfig = `
global
    log /dev/log local0
    maxconn 4096

defaults
    mode http
    timeout connect 5s

frontend fe_http
    bind :80
    bind :443 ssl
    default_backend be_app
    use_backend be_api if { hdr(host) -i api.example.test }

backend be_app
    server app1 127.0.0.1:8080 check
    server app2 192.0.2.10:8080 backup

listen stats
    bind 127.0.0.1:8404
    server st1 127.0.0.1:8404
`

func TestParseSections(t *testing.T) {
	cfg := Parse("haproxy.cfg", sampleConfig)
	if len(cfg.Errors) != 0 {
		t.Fatalf("errors = %+v, want none", cfg.Errors)
	}
	if len(cfg.Frontends) != 2 {
		t.Fatalf("frontends = %d, want 2", len(cfg.Frontends))
	}
	if len(cfg.Backends) != 1 {
		t.Fatalf("backends = %d, want 1", len(cfg.Backends))
	}

	fe := cfg.Frontends[0]
	if fe.Name != "fe_http" || fe.File != "haproxy.cfg" || fe.Line <= 0 {
		t.Errorf("frontend = %+v, want fe_http at a line", fe)
	}
	if strings.Join(fe.Binds, ",") != ":80,:443" {
		t.Errorf("binds = %v, want [:80 :443]", fe.Binds)
	}
	if fe.DefaultBackend != "be_app" {
		t.Errorf("default_backend = %q, want be_app", fe.DefaultBackend)
	}
	// The conditional after "if" must not leak into the name.
	if strings.Join(fe.UseBackends, ",") != "be_api" {
		t.Errorf("use_backends = %v, want [be_api]", fe.UseBackends)
	}
	if len(fe.Servers) != 0 {
		t.Errorf("frontend servers = %v, want none", fe.Servers)
	}

	be := cfg.Backends[0]
	if be.Name != "be_app" {
		t.Errorf("backend = %+v, want be_app", be)
	}
	if len(be.Servers) != 2 {
		t.Fatalf("servers = %+v, want 2", be.Servers)
	}
	if be.Servers[0].Name != "app1" || be.Servers[0].Addr != "127.0.0.1:8080" {
		t.Errorf("server 1 = %+v", be.Servers[0])
	}
	if be.Servers[0].Line <= 0 {
		t.Errorf("server line = %d, want > 0", be.Servers[0].Line)
	}

	// A listen section is a frontend that carries its own servers.
	listen := cfg.Frontends[1]
	if listen.Name != "stats" || len(listen.Binds) != 1 || len(listen.Servers) != 1 {
		t.Errorf("listen = %+v, want bind and one server", listen)
	}

	if be.Key() != "haproxy_backend|be_app" {
		t.Errorf("backend key = %q", be.Key())
	}
	if !strings.Contains(fe.RawRef(), ":") || strings.HasSuffix(fe.RawRef(), ":") {
		t.Errorf("raw ref = %q, want file:line", fe.RawRef())
	}
	if fe.Fingerprint() == "" || be.Fingerprint() == "" {
		t.Error("sections must have fingerprints")
	}
}

func TestParseSkipsCommentsAndJoinsContinuations(t *testing.T) {
	src := `
# full-line comment
frontend fe
    bind :80 \
        name fe_http
    server s1 127.0.0.1:8080   # trailing comment
`
	cfg := Parse("haproxy.cfg", src)
	if len(cfg.Errors) != 0 {
		t.Fatalf("errors = %+v, want none", cfg.Errors)
	}
	fe := cfg.Frontends[0]
	if strings.Join(fe.Binds, ",") != ":80" {
		t.Errorf("binds = %v, want [:80] (continuation joined, name option dropped)", fe.Binds)
	}
	if len(fe.Servers) != 1 || fe.Servers[0].Addr != "127.0.0.1:8080" {
		t.Errorf("servers = %+v, want one with the address before the comment", fe.Servers)
	}
	// The logical line starts at the physical line of the bind.
	if fe.Line <= 0 {
		t.Errorf("section line = %d", fe.Line)
	}
}

func TestParseRecordsErrors(t *testing.T) {
	src := `
frontend
backend be
    server s1
frontend fe
    default_backend
`
	cfg := Parse("haproxy.cfg", src)
	if len(cfg.Errors) != 3 {
		t.Fatalf("errors = %+v, want 3", cfg.Errors)
	}
	msgs := make([]string, 0, len(cfg.Errors))
	for _, e := range cfg.Errors {
		msgs = append(msgs, e.Err.Error())
	}
	joined := strings.Join(msgs, "\n")
	for _, want := range []string{"section without a name", "without an address", "default_backend without a name"} {
		if !strings.Contains(joined, want) {
			t.Errorf("errors lack %q:\n%s", want, joined)
		}
	}
	// The valid backend still contributes inventory.
	if len(cfg.Backends) != 1 || cfg.Backends[0].Name != "be" {
		t.Errorf("backends = %+v, want the valid one kept", cfg.Backends)
	}
}

func TestParseTargetRefusesGuesses(t *testing.T) {
	cases := []struct {
		raw  string
		want TargetKind
	}{
		{"", TargetUnresolved},
		{"$BACKEND", TargetUnresolved},
		{"{env.PORT}", TargetUnresolved},
		{"http://example.test:80", TargetUnresolved},
		{"/run/app.sock", TargetUnix},
		{"127.0.0.1:8080", TargetLocal},
		{"localhost:80", TargetLocal},
		{"[::1]:80", TargetLocal},
		{"0.0.0.0:80", TargetLocal},
		{":8080", TargetLocal},
		{"192.0.2.1:8080", TargetHost},
		{"example.test:80", TargetHost},
		{"192.0.2.1", TargetHost}, // no port: never guessed
		{"2001:db8::1", TargetHost},
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
	local := ParseTarget("127.0.0.1:8080")
	if local.Host != "127.0.0.1" || local.Port != 8080 {
		t.Errorf("local = %+v, want host and port", local)
	}
	// A unix target keeps its path.
	sock := ParseTarget("/run/app.sock")
	if sock.Socket != "/run/app.sock" {
		t.Errorf("socket = %q", sock.Socket)
	}
}

func TestKeysAndFingerprintsStableAcrossParses(t *testing.T) {
	a := Parse("haproxy.cfg", sampleConfig)
	b := Parse("haproxy.cfg", sampleConfig)
	for i := range a.Frontends {
		if a.Frontends[i].Key() != b.Frontends[i].Key() {
			t.Errorf("frontend key changed: %q vs %q",
				a.Frontends[i].Key(), b.Frontends[i].Key())
		}
		if a.Frontends[i].Fingerprint() != b.Frontends[i].Fingerprint() {
			t.Error("frontend fingerprint changed between identical parses")
		}
	}
	if a.Backends[0].Key() != b.Backends[0].Key() {
		t.Error("backend key changed between identical parses")
	}

	// Changing one server address changes the fingerprint but not the
	// key: same entity, different shape.
	changed := Parse("haproxy.cfg", strings.Replace(
		sampleConfig, "192.0.2.10:8080", "192.0.2.11:8080", 1))
	if changed.Backends[0].Key() != a.Backends[0].Key() {
		t.Errorf("key = %q, want stable across edits", changed.Backends[0].Key())
	}
	if changed.Backends[0].Fingerprint() == a.Backends[0].Fingerprint() {
		t.Error("fingerprint must change when a server address changes")
	}
}
