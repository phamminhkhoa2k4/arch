package cli

import (
	"bytes"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The product's only HTTP client lives in the docker client; the web
// UI server is the only HTTP server (local listen, no client calls).
// Nothing else in internal/ may import net/http (test fakes excluded).
// net/rpc is banned everywhere. net.Dial calls are limited to the two
// documented sites: the doctor's unix-socket probe and the docker
// client's socket dialer.
func TestImportBoundary(t *testing.T) {
	root := filepath.Join("..", "..", "internal")
	httpPkg := regexp.MustCompile(`"net/http"`)
	rpcPkg := regexp.MustCompile(`"net/rpc"`)
	dialCall := regexp.MustCompile(`net\.Dial\(`)
	allowedHTTPPrefix := []string{
		filepath.Join(root, "docker", "client.go"),
		filepath.Join(root, "webui") + string(filepath.Separator),
	}
	allowedDial := map[string]bool{
		filepath.Join(root, "docker", "client.go"): true,
		filepath.Join(root, "cli", "doctor.go"):    true,
	}
	httpAllowed := func(path string) bool {
		for _, p := range allowedHTTPPrefix {
			if strings.HasPrefix(path, p) {
				return true
			}
		}
		return false
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if rpcPkg.Match(src) {
			t.Errorf("%s: net/rpc is banned (DGRAM-free IPC boundary)", path)
		}
		if httpPkg.Match(src) && !httpAllowed(path) {
			t.Errorf("%s: net/http import outside docker client + webui", path)
		}
		if dialCall.Match(src) && !allowedDial[path] {
			t.Errorf("%s: net.Dial call outside doctor/docker-client allowlist", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal: %v", err)
	}
}

// With every proxy variable aimed at a dead local port, the four
// offline commands must still succeed on a copied fixture — proof the
// scan path has no HTTP egress.
func TestAirGapCommandsNoEgress(t *testing.T) {
	for _, v := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
		"http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(v, "http://127.0.0.1:9")
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")

	db := copyFixtureDB(t)
	rules := filepath.Join("..", "..", "lab", "rules.lab.yaml")
	inv := filepath.Join(t.TempDir(), "inv.json")

	steps := []struct {
		name string
		args []string
	}{
		{"scan", []string{"scan", "--db", db}},
		{"explain", []string{"explain", "--db", db, "nginx.service"}},
		{"delete-check", []string{"delete-check", "--db", db, "nginx.service"}},
		{"plan", []string{"plan", "--db", db, "--inventory", inv, "--rules-file", rules, "nginx.service"}},
		{"report-json", []string{"report", "--db", db, "--format", "json"}},
		{"report-md", []string{"report", "--db", db, "--format", "md"}},
		{"report-html", []string{"report", "--db", db, "-o", filepath.Join(t.TempDir(), "r.html")}},
	}
	for _, step := range steps {
		root := rootCmd()
		addCommands(root)
		buf := new(bytes.Buffer)
		root.SetOut(buf)
		root.SetErr(buf)
		root.SetArgs(step.args)
		if err := root.Execute(); err != nil {
			// Attention exit codes are expected verdict outcomes, not
			// network failures; network errors would surface as dial
			// errors in the output.
			if strings.Contains(buf.String(), "dial") || strings.Contains(err.Error(), "dial") {
				t.Fatalf("%s: network dial under air-gap: %v\n%s", step.name, err, buf.String())
			}
			continue
		}
		if strings.Contains(buf.String(), "dial tcp") {
			t.Errorf("%s: dial leaked under air-gap:\n%s", step.name, buf.String())
		}
	}
	if _, err := http.Get("http://127.0.0.1:9"); err == nil {
		t.Error("control: dead port unexpectedly reachable")
	}
}
