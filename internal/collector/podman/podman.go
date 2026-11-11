// Package podman collects the Podman runtime inventory through its
// Docker-compatible API socket: containers, images, volumes and
// networks, plus the published-port and process edges that tie them
// to the listener and process snapshots. Compose mapping is
// deliberately absent — this collector never assumes the Docker
// compose labels apply to podman containers.
package podman

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"archaeologist/internal/collector"
	"archaeologist/internal/collector/listener"
	"archaeologist/internal/docker"
)

// Index supplies snapshots gathered by earlier collectors; nil skips
// the edges that need them (manages, published-port listens_on).
type Index interface {
	ProcessRowsByContainer() (map[string][]collector.ProcessRow, error)
	ListenerRows() ([]collector.ListenerRow, error)
}

// Collector turns the Podman API inventory into entities, findings,
// evidence and container-graph edges.
type Collector struct {
	sockets []string // candidate API sockets, first existing wins
	dial    func(socket string) docker.API
	index   Index

	once sync.Once
	sock string // chosen socket; "" when podman is not installed
	api  docker.API
	snap snapshot
}

// snapshot is the raw read-only inventory fetched before Collect.
// Each endpoint keeps its own error so one failed read becomes a
// blind spot while the endpoints that succeeded still contribute
// inventory.
type snapshot struct {
	containers    []docker.Container
	images        []docker.Image
	volumes       []docker.Volume
	networks      []docker.Network
	containersErr error
	imagesErr     error
	volumesErr    error
	networksErr   error
}

// New creates a podman collector. index may be nil (no process or
// published-port edges).
func New(index Index) *Collector {
	return &Collector{
		sockets: Sockets(),
		dial:    func(socket string) docker.API { return docker.NewClient(socket) },
		index:   index,
	}
}

// Sockets returns the standard Podman API socket locations in
// preference order: the rootful socket first, then the rootless
// socket of the invoking user.
func Sockets() []string {
	out := []string{"/run/podman/podman.sock", "/var/run/podman/podman.sock"}
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		out = append(out, filepath.Join(dir, "podman", "podman.sock"))
	}
	return out
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return "podman" }

// Version implements collector.Collector.
func (c *Collector) Version() string { return "1.0.0" }

// Prefetch picks the socket and reads the four inventory endpoints
// concurrently while earlier collectors run. Only reads happen here;
// Collect still turns the snapshot into entities and edges in one
// ordered pass.
func (c *Collector) Prefetch(ctx context.Context) {
	c.once.Do(c.read)
}

func (c *Collector) ensure() { c.once.Do(c.read) }

// read picks the first existing socket and fetches the snapshot. No
// socket at all means podman is not installed: nothing to read and
// nothing to be blind about.
func (c *Collector) read() {
	c.sock = firstExisting(c.sockets)
	if c.sock == "" {
		return
	}
	c.api = c.dial(c.sock)
	var s snapshot
	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); s.containers, s.containersErr = c.api.Containers() }()
	go func() { defer wg.Done(); s.images, s.imagesErr = c.api.Images() }()
	go func() { defer wg.Done(); s.volumes, s.volumesErr = c.api.Volumes() }()
	go func() { defer wg.Done(); s.networks, s.networksErr = c.api.Networks() }()
	wg.Wait()
	c.snap = s
}

// firstExisting returns the first path that exists, or "".
func firstExisting(paths []string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// Collect writes the snapshot as entities, findings, evidence and
// edges. A socket that exists but cannot be read is a blind spot
// with the failing endpoint named — never a silent gap and never a
// guess built on partial inventory.
func (c *Collector) Collect(ctx context.Context, sink collector.Sink) error {
	c.ensure()
	if c.sock == "" {
		return nil // not installed: no blind spot
	}

	refs := map[string]bool{}
	emitEvidence := func(ev collector.Evidence) error {
		if refs[ev.Ref] {
			return nil
		}
		refs[ev.Ref] = true
		return sink.AddEvidence(ev)
	}
	apiBlind := func(endpoint string, err error) error {
		return sink.AddBlindSpot(collector.BlindSpot{
			Channel: "podman",
			Reason:  "podman_api_unreadable",
			Detail: map[string]string{
				"endpoint": endpoint,
				"socket":   c.sock,
				"error":    err.Error(),
			},
		})
	}

	containersOK := c.snap.containersErr == nil
	if !containersOK {
		if err := apiBlind("containers", c.snap.containersErr); err != nil {
			return err
		}
	} else if err := c.collectContainers(sink, c.snap.containers, emitEvidence); err != nil {
		return err
	}
	if c.snap.imagesErr != nil {
		if err := apiBlind("images", c.snap.imagesErr); err != nil {
			return err
		}
	} else if err := c.collectImages(sink, c.snap.images, c.snap.containers, containersOK, emitEvidence); err != nil {
		return err
	}
	if c.snap.volumesErr != nil {
		if err := apiBlind("volumes", c.snap.volumesErr); err != nil {
			return err
		}
	} else if err := c.collectVolumes(sink, c.snap.volumes, c.snap.containers, containersOK, emitEvidence); err != nil {
		return err
	}
	if c.snap.networksErr != nil {
		if err := apiBlind("networks", c.snap.networksErr); err != nil {
			return err
		}
	} else if err := c.collectNetworks(sink, c.snap.networks, emitEvidence); err != nil {
		return err
	}
	if containersOK {
		if err := c.collectPublishedPorts(sink, c.snap.containers, emitEvidence); err != nil {
			return err
		}
		if err := c.collectOwnership(sink, c.snap.containers, refs); err != nil {
			return err
		}
	}
	return nil
}

// containerStateRef is the evidence reference shared by the state
// evidence and the manages edges of one container.
func containerStateRef(id string) string { return "podman-container-state:" + id }

func (c *Collector) collectContainers(
	sink collector.Sink,
	containers []docker.Container,
	emit func(collector.Evidence) error,
) error {
	for i := range containers {
		ct := &containers[i]
		key := "podman_container|" + ct.ID
		polarity := collector.PolarityNeutral
		if ct.State == "running" {
			polarity = collector.PolarityInUse
		}
		attrs := containerAttrs(*ct)
		lastLog, logOK, logBlind, logErr := c.containerLogTime(key, ct)
		if logOK {
			attrs["last_log_at"] = lastLog.UTC().Format(time.RFC3339)
		}
		if err := sink.UpsertEntity(collector.Entity{
			Kind:        "podman_container",
			Name:        containerName(*ct),
			IdentityKey: key,
			Fingerprint: containerFingerprint(*ct),
			Attributes:  attrs,
		}); err != nil {
			return err
		}
		if err := emit(collector.Evidence{
			EntityIdentityKey: key,
			Polarity:          polarity,
			Channel:           "podman",
			Strength:          collector.StrengthDeterministic,
			ObservedAt:        nowRFC3339(),
			RawRef:            "podman:/containers/json",
			Ref:               containerStateRef(ct.ID),
			Value: map[string]string{
				"id":    ct.ID,
				"state": ct.State,
				"image": ct.Image,
			},
		}); err != nil {
			return err
		}
		if ct.CreatedAt != "" {
			if err := emit(collector.Evidence{
				EntityIdentityKey: key,
				Polarity:          collector.PolarityNeutral,
				Channel:           "podman_created",
				Strength:          collector.StrengthDeterministic,
				ObservedAt:        nowRFC3339(),
				RawRef:            "podman:/containers/" + ct.ID + "/json",
				Ref:               "podman-container-created:" + ct.ID,
				Value: map[string]string{
					"last_deploy_at": ct.CreatedAt,
					"created_at":     ct.CreatedAt,
					"started_at":     ct.StartedAt,
				},
			}); err != nil {
				return err
			}
		}
		if logOK {
			if err := emit(collector.Evidence{
				EntityIdentityKey: key,
				Polarity:          collector.PolarityInUse,
				Channel:           "podman_log",
				Strength:          collector.StrengthDeterministic,
				ObservedAt:        nowRFC3339(),
				RawRef:            "podman:/containers/" + ct.ID + "/logs?tail=1",
				Ref:               "podman-container-log:" + ct.ID,
				Value: map[string]string{
					"last_log_at": lastLog.UTC().Format(time.RFC3339),
				},
			}); err != nil {
				return err
			}
		}
		if logBlind != nil {
			if err := sink.AddBlindSpot(*logBlind); err != nil {
				return err
			}
		}
		if logErr != nil {
			if err := sink.AddBlindSpot(collector.BlindSpot{
				EntityIdentityKey: key,
				Channel:           "podman",
				Reason:            "podman_log_unreadable",
				Detail:            map[string]string{"error": logErr.Error()},
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// containerLogTime reads the newest log timestamp of one container.
// Podman's default k8s-file driver and journald expose readable
// logs; the none driver proves absence instead of hiding it. Any
// other driver is reported without touching the API.
func (c *Collector) containerLogTime(
	key string,
	ct *docker.Container,
) (time.Time, bool, *collector.BlindSpot, error) {
	switch ct.LogDriver {
	case "", "json-file", "k8s-file", "journald":
	case "none":
		return time.Time{}, false, nil, nil
	default:
		return time.Time{}, false, &collector.BlindSpot{
			EntityIdentityKey: key,
			Channel:           "podman",
			Reason:            "log_driver_unsupported",
			Detail:            map[string]string{"driver": ct.LogDriver},
		}, nil
	}
	ts, ok, err := c.api.ContainerLogs(ct.ID, ct.TTY)
	if err != nil {
		return time.Time{}, false, nil, err
	}
	return ts, ok, nil, nil
}

// containerName returns the primary container name without the
// leading slash, whichever shape the compatible API reported.
func containerName(ct docker.Container) string {
	if len(ct.Names) == 0 {
		return ct.ID
	}
	return strings.TrimPrefix(ct.Names[0], "/")
}

// portLines renders published ports canonically; the engine can list
// the same port once per bind address, so lines are deduplicated
// before they reach attributes or fingerprints.
func portLines(ct docker.Container) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range ct.Ports {
		var line string
		if p.PublicPort > 0 {
			line = fmt.Sprintf("%d:%d/%s", p.PublicPort, p.PrivatePort, p.Type)
		} else {
			line = fmt.Sprintf("%d/%s", p.PrivatePort, p.Type)
		}
		if seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}
	sort.Strings(out)
	return out
}

// containerFingerprint hashes the stable shape of a container so a
// config change between scans shows up as a fingerprint diff.
func containerFingerprint(ct docker.Container) string {
	parts := []string{
		ct.ID,
		ct.Image,
		ct.ImageID,
		ct.NetworkMode,
		ct.RestartPol,
		strings.Join(portLines(ct), ","),
		strings.Join(ct.Networks, ","),
		strings.Join(ct.Volumes, ","),
	}
	return fingerprintOf(parts...)
}

func containerAttrs(ct docker.Container) map[string]string {
	return map[string]string{
		"image":          ct.Image,
		"image_id":       ct.ImageID,
		"state":          ct.State,
		"status":         ct.Status,
		"created_at":     ct.CreatedAt,
		"started_at":     ct.StartedAt,
		"restart_policy": ct.RestartPol,
		"network_mode":   ct.NetworkMode,
		"ports":          strings.Join(portLines(ct), ", "),
		"networks":       strings.Join(ct.Networks, ", "),
		"volumes":        strings.Join(ct.Volumes, ", "),
	}
}

// usageRefs indexes which images and volumes the container
// inventory references.
func usageRefs(containers []docker.Container) (images, volumes map[string]bool) {
	images, volumes = map[string]bool{}, map[string]bool{}
	for _, ct := range containers {
		if ct.ImageID != "" {
			images[ct.ImageID] = true
		}
		if ct.Image != "" {
			images[ct.Image] = true
		}
		for _, v := range ct.Volumes {
			volumes[v] = true
		}
	}
	return images, volumes
}

// collectImages writes image entities with their list evidence and
// UNUSED_IMAGE findings. containersKnown=false (the container
// endpoint failed) still yields the inventory but never claims an
// image is unused — absence cannot be asserted without the read.
func (c *Collector) collectImages(
	sink collector.Sink,
	images []docker.Image,
	containers []docker.Container,
	containersOK bool,
	emit func(collector.Evidence) error,
) error {
	var refImages map[string]bool
	if containersOK {
		refImages, _ = usageRefs(containers)
	}
	for i := range images {
		img := &images[i]
		key := "podman_image|" + img.ID
		used := false
		if refImages != nil {
			used = refImages[img.ID]
			for _, tag := range img.Tags {
				if refImages[tag] {
					used = true
				}
			}
		}
		polarity := collector.PolarityNeutral
		if used {
			polarity = collector.PolarityInUse
		}
		ref := "podman-image-list:" + img.ID
		attrs := map[string]string{
			"id":          img.ID,
			"tags":        strings.Join(img.Tags, ", "),
			"size":        fmt.Sprintf("%d", img.Size),
			"repo_source": img.Label["org.opencontainers.image.source"],
		}
		if attrs["repo_source"] == "" {
			attrs["repo_source"] = "unknown"
		}
		if err := sink.UpsertEntity(collector.Entity{
			Kind:        "podman_image",
			Name:        displayName(img.Tags, img.ID),
			IdentityKey: key,
			Fingerprint: img.ID,
			Attributes:  attrs,
		}); err != nil {
			return err
		}
		value := map[string]string{
			"id":   img.ID,
			"size": fmt.Sprintf("%d", img.Size),
		}
		if refImages != nil {
			value["used"] = boolStr(used)
		}
		if err := emit(collector.Evidence{
			EntityIdentityKey: key,
			Polarity:          polarity,
			Channel:           "podman",
			Strength:          collector.StrengthDeterministic,
			ObservedAt:        nowRFC3339(),
			RawRef:            "podman:/images/json",
			Ref:               ref,
			Value:             value,
		}); err != nil {
			return err
		}
		if refImages != nil && !used {
			if err := sink.AddFinding(collector.Finding{
				EntityIdentityKey: key,
				Kind:              "UNUSED_IMAGE",
				Severity:          "warn",
				Detail: map[string]string{
					"image":      displayName(img.Tags, img.ID),
					"image_id":   img.ID,
					"size_bytes": fmt.Sprintf("%d", img.Size),
					"warning":    "no container references this image; check before deleting",
				},
				EvidenceRef: ref,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// collectVolumes writes volume entities with their list evidence and
// UNUSED_VOLUME findings. As with images, usage claims require the
// container read.
func (c *Collector) collectVolumes(
	sink collector.Sink,
	volumes []docker.Volume,
	containers []docker.Container,
	containersOK bool,
	emit func(collector.Evidence) error,
) error {
	var refVolumes map[string]bool
	if containersOK {
		_, refVolumes = usageRefs(containers)
	}
	for i := range volumes {
		vol := &volumes[i]
		key := "podman_volume|" + vol.Name
		used := refVolumes != nil && refVolumes[vol.Name]
		polarity := collector.PolarityNeutral
		if used {
			polarity = collector.PolarityInUse
		}
		ref := "podman-volume-list:" + vol.Name
		if err := sink.UpsertEntity(collector.Entity{
			Kind:        "podman_volume",
			Name:        vol.Name,
			IdentityKey: key,
			Fingerprint: fingerprintOf(vol.Name, vol.Driver, vol.CreatedAt),
			Attributes: map[string]string{
				"name":       vol.Name,
				"driver":     vol.Driver,
				"created_at": vol.CreatedAt,
			},
		}); err != nil {
			return err
		}
		value := map[string]string{"name": vol.Name}
		if refVolumes != nil {
			value["used"] = boolStr(used)
		}
		if err := emit(collector.Evidence{
			EntityIdentityKey: key,
			Polarity:          polarity,
			Channel:           "podman",
			Strength:          collector.StrengthDeterministic,
			ObservedAt:        nowRFC3339(),
			RawRef:            "podman:/volumes",
			Ref:               ref,
			Value:             value,
		}); err != nil {
			return err
		}
		if refVolumes != nil && !used {
			if err := sink.AddFinding(collector.Finding{
				EntityIdentityKey: key,
				Kind:              "UNUSED_VOLUME",
				Severity:          "warn",
				Detail: map[string]string{
					"name":    vol.Name,
					"driver":  vol.Driver,
					"warning": "volume may still contain important data; do not delete without checking",
				},
				EvidenceRef: ref,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Collector) collectNetworks(
	sink collector.Sink,
	networks []docker.Network,
	emit func(collector.Evidence) error,
) error {
	for i := range networks {
		nw := &networks[i]
		key := "podman_network|" + nw.Name
		ref := "podman-network-list:" + nw.Name
		if err := sink.UpsertEntity(collector.Entity{
			Kind:        "podman_network",
			Name:        nw.Name,
			IdentityKey: key,
			Fingerprint: fingerprintOf(nw.Name, nw.Driver, nw.ID),
			Attributes: map[string]string{
				"name":   nw.Name,
				"driver": nw.Driver,
				"scope":  nw.Scope,
				"id":     nw.ID,
			},
		}); err != nil {
			return err
		}
		if err := emit(collector.Evidence{
			EntityIdentityKey: key,
			Polarity:          collector.PolarityNeutral,
			Channel:           "podman",
			Strength:          collector.StrengthDeterministic,
			ObservedAt:        nowRFC3339(),
			RawRef:            "podman:/networks",
			Ref:               ref,
			Value: map[string]string{
				"name":   nw.Name,
				"driver": nw.Driver,
			},
		}); err != nil {
			return err
		}
	}
	return nil
}

// collectPublishedPorts matches published container ports against the
// listener snapshot (port + proto, ignoring the bind address).
func (c *Collector) collectPublishedPorts(
	sink collector.Sink,
	containers []docker.Container,
	emit func(collector.Evidence) error,
) error {
	if c.index == nil {
		return nil
	}
	listeners, err := c.index.ListenerRows()
	if err != nil {
		return err
	}
	type pkey struct {
		proto string
		port  int
	}
	byPort := map[pkey][]string{}
	for _, lr := range listeners {
		proto, _, port, _, perr := listener.ParseIdentityKey(lr.IdentityKey)
		if perr != nil {
			continue
		}
		pk := pkey{normProto(proto), port}
		byPort[pk] = append(byPort[pk], lr.IdentityKey)
	}

	for i := range containers {
		ct := &containers[i]
		ctKey := "podman_container|" + ct.ID
		for _, p := range ct.Ports {
			if p.PublicPort == 0 {
				continue // not published: unreachable from outside
			}
			keys := byPort[pkey{normProto(p.Type), int(p.PublicPort)}]
			if len(keys) == 0 {
				continue
			}
			ref := fmt.Sprintf("podman-port-published:%s:%s:%d", ct.ID, p.Type, p.PublicPort)
			if err := emit(collector.Evidence{
				EntityIdentityKey: ctKey,
				Polarity:          collector.PolarityNeutral,
				Channel:           "podman",
				Strength:          collector.StrengthDeterministic,
				ObservedAt:        nowRFC3339(),
				RawRef:            "podman:/containers/json",
				Ref:               ref,
				Value: map[string]string{
					"id":    ct.ID,
					"proto": p.Type,
					"port":  fmt.Sprintf("%d", p.PublicPort),
				},
			}); err != nil {
				return err
			}
			for _, lk := range keys {
				if err := sink.UpsertEdge(collector.Edge{
					SrcIdentityKey: lk,
					DstIdentityKey: ctKey,
					Kind:           "listens_on",
					Strength:       collector.StrengthDeterministic,
					EvidenceRef:    ref,
				}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// collectOwnership links containers to the processes inside them
// through the cgroup container id recorded by the process collector.
func (c *Collector) collectOwnership(
	sink collector.Sink,
	containers []docker.Container,
	refs map[string]bool,
) error {
	if c.index == nil {
		return nil
	}
	byID, err := c.index.ProcessRowsByContainer()
	if err != nil {
		return err
	}
	present := map[string]bool{}
	for _, ct := range containers {
		present[ct.ID] = true
	}
	for id, rows := range byID {
		if !present[id] {
			continue // never assign an owner we cannot prove exists
		}
		ref := containerStateRef(id)
		if !refs[ref] {
			continue // defensive: state evidence must already exist
		}
		ctKey := "podman_container|" + id
		for _, row := range rows {
			if err := sink.UpsertEdge(collector.Edge{
				SrcIdentityKey: ctKey,
				DstIdentityKey: row.IdentityKey,
				Kind:           "manages",
				Strength:       collector.StrengthDeterministic,
				EvidenceRef:    ref,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func displayName(tags []string, id string) string {
	if len(tags) > 0 {
		return tags[0]
	}
	return id
}

func fingerprintOf(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// normProto folds the /proc-style family names (tcp6/udp6) onto the
// engine names (tcp/udp) so published ports match listeners on both
// address families.
func normProto(p string) string {
	return strings.TrimSuffix(p, "6")
}

// compile-time interface checks
var (
	_ collector.Collector  = (*Collector)(nil)
	_ collector.Prefetcher = (*Collector)(nil)
)
