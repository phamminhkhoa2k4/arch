package docker

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
)

// recordingRT records every request that reaches the wire and serves a
// canned JSON response per path.
type recordingRT struct {
	mu       sync.Mutex
	requests []string // "METHOD path?query"
	handler  func(req *http.Request) (*http.Response, error)
}

func (r *recordingRT) RoundTrip(req *http.Request) (*http.Response, error) {
	line := req.Method + " " + req.URL.RequestURI()
	r.mu.Lock()
	r.requests = append(r.requests, line)
	r.mu.Unlock()
	return r.handler(req)
}

func (r *recordingRT) lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]string(nil), r.requests...)
	sort.Strings(out)
	return out
}

func okJSON(v any) func(*http.Request) (*http.Response, error) {
	return func(req *http.Request) (*http.Response, error) {
		b, _ := json.Marshal(v)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       nopCloser{strings.NewReader(string(b))},
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Request:    req,
		}, nil
	}
}

type nopCloser struct{ *strings.Reader }

func (nopCloser) Close() error { return nil }

const testContainerID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// The complete set of endpoints a full inventory scan may touch: list
// (+ inspect per container), images, volumes, networks — all GET.
// Anything else must never reach the wire.
func TestWhitelistAllowsOnlyReadOnlyEndpoints(t *testing.T) {
	canned := map[string]func(*http.Request) (*http.Response, error){
		"/containers/json":                         okJSON([]map[string]any{{"Id": testContainerID, "Names": []string{"/lab-web"}, "Image": "nginx", "ImageID": "sha256:1", "State": "running"}}),
		"/containers/" + testContainerID + "/json": okJSON(map[string]any{"Id": testContainerID, "HostConfig": map[string]any{"NetworkMode": "bridge", "RestartPolicy": map[string]any{"Name": "always"}}}),
		"/images/json":                             okJSON([]map[string]any{{"Id": "sha256:2", "RepoTags": []string{"ubuntu:24.04"}, "Size": 119}}),
		"/volumes":                                 okJSON(map[string]any{"Volumes": []map[string]any{{"Name": "v1", "Driver": "local"}}}),
		"/networks":                                okJSON([]map[string]any{{"Id": "n1", "Name": "bridge", "Driver": "bridge"}}),
	}
	rt := &recordingRT{handler: func(req *http.Request) (*http.Response, error) {
		h, ok := canned[req.URL.Path]
		if !ok {
			return nil, fmt.Errorf("unexpected request reached the wire: %s %s", req.Method, req.URL.Path)
		}
		return h(req)
	}}
	c := NewClientWithHTTP(&http.Client{Transport: rt})

	if _, err := c.Containers(); err != nil {
		t.Fatalf("containers: %v", err)
	}
	if _, err := c.Images(); err != nil {
		t.Fatalf("images: %v", err)
	}
	if _, err := c.Volumes(); err != nil {
		t.Fatalf("volumes: %v", err)
	}
	if _, err := c.Networks(); err != nil {
		t.Fatalf("networks: %v", err)
	}

	want := []string{
		"GET /containers/" + testContainerID + "/json",
		"GET /containers/json?all=true",
		"GET /images/json",
		"GET /networks",
		"GET /volumes",
	}
	got := rt.lines()
	if len(got) != len(want) {
		t.Fatalf("wire requests = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("request[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// Any path outside the whitelist (write endpoints included) is
// rejected before it can reach the transport.
func TestNonWhitelistedEndpointsNeverHitTheWire(t *testing.T) {
	rt := &recordingRT{handler: func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("wire called: %s %s", req.Method, req.URL.Path)
	}}
	c := NewClientWithHTTP(&http.Client{Transport: rt})

	deny := []struct {
		method string
		path   string
	}{
		{"POST", "/containers/create"},         // write
		{"POST", "/containers/x/start"},        // write
		{"DELETE", "/containers/x"},            // write
		{"POST", "/images/create"},             // write
		{"POST", "/volumes/create"},            // write
		{"GET", "/containers/x/restart"},       // GET but not read-only
		{"GET", "/containers/x/exec"},          // GET but not read-only
		{"GET", "/info"},                       // outside inventory
		{"GET", "/containers/json/../x/start"}, // traversal attempt
	}
	for _, d := range deny {
		if allowed(d.method, d.path) {
			t.Errorf("allowed(%s %s) = true, want false", d.method, d.path)
		}
	}
	if lines := rt.lines(); len(lines) != 0 {
		t.Errorf("transport was called: %v", lines)
	}

	// The guard sits inside get(): a denied path errors out locally.
	err := c.get("/containers/x/restart", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "whitelist") {
		t.Errorf("get(restart) err = %v, want whitelist error", err)
	}
	if lines := rt.lines(); len(lines) != 0 {
		t.Errorf("denied get reached the wire: %v", lines)
	}
}

// A real unix socket server: the client dials, decodes, and surfaces
// HTTP errors from the engine.
func TestClientOverUnixSocket(t *testing.T) {
	sock := t.TempDir() + "/docker.sock"
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/containers/json":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"Id": testContainerID, "Names": []string{"/x"}, "Image": "alpine",
					"ImageID": "sha256:a", "State": "exited", "Labels": map[string]string{"a": "b"}},
			})
		case r.Method == "GET" && r.URL.Path == "/containers/"+testContainerID+"/json":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Id": testContainerID, "Created": "2026-10-01T00:00:00Z",
				"State": map[string]any{"Status": "exited", "StartedAt": "2026-10-01T00:00:01Z"},
				"HostConfig": map[string]any{"NetworkMode": "bridge",
					"RestartPolicy": map[string]any{"Name": "no"}},
				"Mounts": []map[string]any{{"Type": "volume", "Name": "v1"}},
				"NetworkSettings": map[string]any{"Networks": map[string]any{
					"lab_default": map[string]any{"IPAddress": "172.18.0.2"}}},
			})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	})}
	defer func() { _ = srv.Close() }()
	go func() { _ = srv.Serve(ln) }()

	c := NewClient(sock)
	got, err := c.Containers()
	if err != nil {
		t.Fatalf("containers over socket: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d containers", len(got))
	}
	ct := got[0]
	if ct.Name() != "x" || ct.State != "exited" || ct.RestartPol != "no" ||
		ct.NetworkMode != "bridge" || ct.CreatedAt != "2026-10-01T00:00:00Z" {
		t.Errorf("merged container = %+v", ct)
	}
	if len(ct.Volumes) != 1 || ct.Volumes[0] != "v1" {
		t.Errorf("volumes = %v", ct.Volumes)
	}
	if len(ct.Networks) != 1 || ct.Networks[0] != "lab_default" {
		t.Errorf("networks = %v", ct.Networks)
	}
}

// HTTP-level failures surface as errors (the collector turns them
// into one blind spot).
func TestEngineErrorSurfaces(t *testing.T) {
	rt := &recordingRT{handler: func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       nopCloser{strings.NewReader("boom")},
			Request:    req,
		}, nil
	}}
	c := NewClientWithHTTP(&http.Client{Transport: rt})
	_, err := c.Images()
	if err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Errorf("err = %v, want status 500", err)
	}
}

// Socket unreachable (no daemon) errors out — never panics.
func TestSocketUnreachable(t *testing.T) {
	c := NewClient(t.TempDir() + "/missing.sock")
	_, err := c.Containers()
	if err == nil {
		t.Fatal("want error for missing socket")
	}
	if !strings.Contains(err.Error(), "list containers") {
		t.Errorf("err = %v", err)
	}
}
