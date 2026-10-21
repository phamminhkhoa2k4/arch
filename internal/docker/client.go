// Package docker is a read-only Docker Engine API client over the unix
// socket. Every request must match an explicit endpoint whitelist —
// there is no code path that can send a write operation, and the guard
// rejects anything outside the whitelist before it reaches the wire.
package docker

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultSocket is the standard Docker engine socket path.
const DefaultSocket = "/var/run/docker.sock"

// API is the surface the collector consumes. Implementations: the real
// socket client and fakes in tests.
type API interface {
	// Containers returns every container (running and stopped) with
	// inspect facts merged in.
	Containers() ([]Container, error)
	Images() ([]Image, error)
	Volumes() ([]Volume, error)
	Networks() ([]Network, error)
	// ContainerLogs returns the timestamp of the container's most
	// recent log line (tty tells the client which stream framing to
	// expect). ok=false means the container has no log output.
	ContainerLogs(id string, tty bool) (time.Time, bool, error)
}

// Client calls the Docker Engine API over a unix socket.
type Client struct {
	hc   *http.Client
	base string
}

// NewClient returns a client that dials the given unix socket.
func NewClient(socket string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}
	return &Client{
		hc:   &http.Client{Transport: tr, Timeout: 15 * time.Second},
		base: "http://docker.engine",
	}
}

// NewClientWithHTTP wraps an injected client (tests: recording
// transports). The whitelist guard still applies to every request.
func NewClientWithHTTP(hc *http.Client) *Client {
	return &Client{hc: hc, base: "http://docker.engine"}
}

// whitelist is the complete set of read-only endpoints this tool may
// call for an inventory scan. Anything else is rejected before it is
// sent.
var whitelist = map[string]bool{
	"GET /containers/json": true,
	"GET /images/json":     true,
	"GET /networks":        true,
	"GET /volumes":         true,
}

// inspectRE matches the per-container inspect path (short or full id).
var inspectRE = regexp.MustCompile(`^/containers/[0-9a-f]{12,64}/json$`)

// logsRE matches the per-container log path (short or full id).
var logsRE = regexp.MustCompile(`^/containers/[0-9a-f]{12,64}/logs$`)

// allowed reports whether method+path is inside the read-only
// whitelist. Only GET exists in the table; every other method fails.
func allowed(method, path string) bool {
	if method != http.MethodGet {
		return false
	}
	if whitelist["GET "+path] {
		return true
	}
	return inspectRE.MatchString(path) || logsRE.MatchString(path)
}

// get performs a whitelisted GET and decodes the JSON body into out.
func (c *Client) get(path string, query url.Values, out any) error {
	if !allowed(http.MethodGet, path) {
		return fmt.Errorf("endpoint not in read-only whitelist: GET %s", path)
	}
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("GET %s: status %d: %s", path, resp.StatusCode, string(body))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// getRaw performs a whitelisted GET and returns the response body,
// capped at limit bytes (log tails and other small reads).
func (c *Client) getRaw(path string, query url.Values, limit int64) ([]byte, error) {
	if !allowed(http.MethodGet, path) {
		return nil, fmt.Errorf("endpoint not in read-only whitelist: GET %s", path)
	}
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("GET %s: status %d: %s", path, resp.StatusCode, string(body))
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// Containers lists every container (all=true so stopped ones count)
// and enriches each with inspect facts (restart policy, mounts,
// networks, timestamps). Inspects run in a small pool; result order
// stays the list order.
func (c *Client) Containers() ([]Container, error) {
	var list []Container
	if err := c.get("/containers/json", url.Values{"all": {"true"}}, &list); err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}
	if len(list) == 0 {
		return list, nil
	}
	const workers = 8
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	errs := make([]error, len(list))
	for i := range list {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ins, err := c.inspect(list[i].ID)
			if err != nil {
				errs[i] = err
				return
			}
			list[i].applyInspect(ins)
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, fmt.Errorf("inspect container: %w", err)
		}
	}
	return list, nil
}

func (c *Client) inspect(id string) (*ContainerInspect, error) {
	var ins ContainerInspect
	if err := c.get("/containers/"+id+"/json", nil, &ins); err != nil {
		return nil, err
	}
	return &ins, nil
}

// ContainerLogs fetches the tail of a container's log with timestamps
// (tail=1, timestamps=1) and reports the newest entry. ok=false means
// no log line with a parseable timestamp was found.
func (c *Client) ContainerLogs(id string, tty bool) (time.Time, bool, error) {
	path := "/containers/" + id + "/logs"
	body, err := c.getRaw(path, url.Values{
		"stdout": {"1"}, "stderr": {"1"}, "tail": {"1"}, "timestamps": {"1"},
	}, 1<<20)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("container logs: %w", err)
	}
	var latest time.Time
	for _, line := range logLines(body, tty) {
		ts, ok := parseLogTimestamp(line)
		if ok && ts.After(latest) {
			latest = ts
		}
	}
	if latest.IsZero() {
		return time.Time{}, false, nil
	}
	return latest, true, nil
}

// logLines splits a /logs response into payload lines. Non-TTY
// containers use the Docker multiplexed stream framing (8-byte header
// + payload); TTY containers return the raw byte stream.
func logLines(body []byte, tty bool) []string {
	if !tty && framed(body) {
		var out []string
		for len(body) >= 8 {
			n := binary.BigEndian.Uint32(body[4:8])
			if uint64(n) > uint64(len(body)-8) {
				break
			}
			out = append(out, string(body[8:8+n]))
			body = body[8+n:]
		}
		return out
	}
	return strings.Split(string(body), "\n")
}

// framed reports whether body starts with a Docker stream frame
// header: stream type 0-2, three zero bytes, big-endian payload size.
func framed(body []byte) bool {
	if len(body) < 8 {
		return false
	}
	if body[0] > 2 || body[1] != 0 || body[2] != 0 || body[3] != 0 {
		return false
	}
	return uint64(binary.BigEndian.Uint32(body[4:8])) <= uint64(len(body)-8)
}

// parseLogTimestamp reads the RFC3339Nano prefix docker prepends to
// every line when t=1.
func parseLogTimestamp(line string) (time.Time, bool) {
	sp := strings.IndexByte(line, ' ')
	if sp <= 0 {
		return time.Time{}, false
	}
	ts, err := time.Parse(time.RFC3339Nano, line[:sp])
	if err != nil {
		return time.Time{}, false
	}
	return ts, true
}

// Images lists images with size.
func (c *Client) Images() ([]Image, error) {
	var out []Image
	if err := c.get("/images/json", nil, &out); err != nil {
		return nil, fmt.Errorf("list images: %w", err)
	}
	return out, nil
}

// Volumes lists volumes.
func (c *Client) Volumes() ([]Volume, error) {
	var out struct {
		Volumes []Volume `json:"Volumes"`
	}
	if err := c.get("/volumes", nil, &out); err != nil {
		return nil, fmt.Errorf("list volumes: %w", err)
	}
	return out.Volumes, nil
}

// Networks lists networks.
func (c *Client) Networks() ([]Network, error) {
	var out []Network
	if err := c.get("/networks", nil, &out); err != nil {
		return nil, fmt.Errorf("list networks: %w", err)
	}
	return out, nil
}

// Port is one published or private port of a container.
type Port struct {
	IP          string `json:"IP"`
	PrivatePort uint16 `json:"PrivatePort"`
	PublicPort  uint16 `json:"PublicPort"`
	Type        string `json:"Type"`
}

// Container is the merged list+inspect view of one container.
type Container struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	ImageID string            `json:"ImageID"`
	Created int64             `json:"Created"`
	State   string            `json:"State"`
	Status  string            `json:"Status"`
	Labels  map[string]string `json:"Labels"`
	Ports   []Port            `json:"Ports"`
	// from inspect
	CreatedAt   string   `json:"-"`
	StartedAt   string   `json:"-"`
	NetworkMode string   `json:"-"`
	RestartPol  string   `json:"-"`
	TTY         bool     `json:"-"`
	LogDriver   string   `json:"-"`
	Networks    []string `json:"-"`
	Volumes     []string `json:"-"` // mounted volume names, sorted
}

// Name returns the primary container name without the leading slash.
func (c *Container) Name() string {
	if len(c.Names) == 0 {
		return c.ID
	}
	return c.Names[0][1:]
}

// ContainerInspect is the subset of /containers/{id}/json we read.
type ContainerInspect struct {
	ID      string `json:"Id"`
	Name    string `json:"Name"`
	Created string `json:"Created"`
	State   *struct {
		Status    string `json:"Status"`
		Running   bool   `json:"Running"`
		StartedAt string `json:"StartedAt"`
	} `json:"State"`
	HostConfig *struct {
		NetworkMode   string `json:"NetworkMode"`
		RestartPolicy *struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
		LogConfig *struct {
			Type string `json:"Type"`
		} `json:"LogConfig"`
	} `json:"HostConfig"`
	Config *struct {
		Tty bool `json:"Tty"`
	} `json:"Config"`
	Mounts []struct {
		Type   string `json:"Type"`
		Name   string `json:"Name"`
		Source string `json:"Source"`
	} `json:"Mounts"`
	NetworkSettings *struct {
		Networks map[string]struct {
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

// applyInspect folds per-container inspect facts into the list row.
func (c *Container) applyInspect(ins *ContainerInspect) {
	c.CreatedAt = ins.Created
	if ins.State != nil {
		c.StartedAt = ins.State.StartedAt
	}
	if ins.HostConfig != nil {
		c.NetworkMode = ins.HostConfig.NetworkMode
		if ins.HostConfig.RestartPolicy != nil {
			c.RestartPol = ins.HostConfig.RestartPolicy.Name
		}
		if ins.HostConfig.LogConfig != nil {
			c.LogDriver = ins.HostConfig.LogConfig.Type
		}
	}
	if ins.Config != nil {
		c.TTY = ins.Config.Tty
	}
	for _, m := range ins.Mounts {
		if m.Type == "volume" && m.Name != "" {
			c.Volumes = append(c.Volumes, m.Name)
		}
	}
	sort.Strings(c.Volumes)
	if ins.NetworkSettings != nil {
		for name := range ins.NetworkSettings.Networks {
			c.Networks = append(c.Networks, name)
		}
	}
	sort.Strings(c.Networks)
}

// Image is one entry of /images/json.
type Image struct {
	ID    string            `json:"Id"`
	Tags  []string          `json:"RepoTags"`
	Size  int64             `json:"Size"`
	Label map[string]string `json:"Labels"`
}

// Volume is one entry of the /volumes payload.
type Volume struct {
	Name      string            `json:"Name"`
	Driver    string            `json:"Driver"`
	Labels    map[string]string `json:"Labels"`
	CreatedAt string            `json:"CreatedAt"`
}

// Network is one entry of /networks.
type Network struct {
	ID     string            `json:"Id"`
	Name   string            `json:"Name"`
	Driver string            `json:"Driver"`
	Scope  string            `json:"Scope"`
	Labels map[string]string `json:"Labels"`
}
