// Package docker collects the Docker runtime inventory: containers,
// images, volumes, networks, their compose mapping and the edges that
// tie them to the listener/process snapshots.
package docker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"archaeologist/internal/collector"
	"archaeologist/internal/collector/listener"
	"archaeologist/internal/compose"
	"archaeologist/internal/docker"
)

// Index supplies snapshots gathered by earlier collectors; nil skips
// the edges that need them (manages, published-port listens_on).
type Index interface {
	ProcessRowsByContainer() (map[string][]collector.ProcessRow, error)
	ListenerRows() ([]collector.ListenerRow, error)
}

// Collector turns the Docker API inventory into entities, findings,
// evidence and container-graph edges.
type Collector struct {
	api    docker.API
	loader *compose.Loader
	index  Index
}

// New creates a docker collector. loader may be nil (no compose
// mapping); index may be nil (no process/port edges).
func New(api docker.API, loader *compose.Loader, index Index) *Collector {
	if loader == nil {
		loader = compose.NewLoader()
	}
	return &Collector{api: api, loader: loader, index: index}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return "docker" }

// Version implements collector.Collector.
func (c *Collector) Version() string { return "1.1.0" }

// Collect reads the whitelisted endpoints once and writes entities,
// findings and edges. Any API failure is returned so the run loop can
// record one collector-level blind spot instead of guessing.
func (c *Collector) Collect(ctx context.Context, sink collector.Sink) error {
	containers, err := c.api.Containers()
	if err != nil {
		return fmt.Errorf("docker containers: %w", err)
	}
	images, err := c.api.Images()
	if err != nil {
		return fmt.Errorf("docker images: %w", err)
	}
	volumes, err := c.api.Volumes()
	if err != nil {
		return fmt.Errorf("docker volumes: %w", err)
	}
	networks, err := c.api.Networks()
	if err != nil {
		return fmt.Errorf("docker networks: %w", err)
	}

	refs := map[string]bool{}
	emitEvidence := func(ev collector.Evidence) error {
		if refs[ev.Ref] {
			return nil
		}
		refs[ev.Ref] = true
		return sink.AddEvidence(ev)
	}

	if err := c.collectContainers(sink, containers, emitEvidence); err != nil {
		return err
	}
	if err := c.collectUnused(sink, images, volumes, containers, emitEvidence); err != nil {
		return err
	}
	if err := c.collectNetworks(sink, networks, emitEvidence); err != nil {
		return err
	}
	if err := c.collectCompose(sink, containers, refs); err != nil {
		return err
	}
	if err := c.collectPublishedPorts(sink, containers, emitEvidence); err != nil {
		return err
	}
	return c.collectOwnership(sink, containers, refs)
}

// containerStateRef is the evidence reference shared by the state
// evidence, belongs_to edges and manages edges of one container.
func containerStateRef(id string) string { return "container-state:" + id }

func (c *Collector) collectContainers(
	sink collector.Sink,
	containers []docker.Container,
	emit func(collector.Evidence) error,
) error {
	for i := range containers {
		ct := &containers[i]
		key := "container|" + ct.ID
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
			Kind:        "container",
			Name:        ct.Name(),
			IdentityKey: key,
			Fingerprint: containerFingerprint(*ct),
			Attributes:  attrs,
		}); err != nil {
			return err
		}
		if err := emit(collector.Evidence{
			EntityIdentityKey: key,
			Polarity:          polarity,
			Channel:           "docker",
			Strength:          collector.StrengthDeterministic,
			ObservedAt:        nowRFC3339(),
			RawRef:            "docker:/containers/json",
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
				Channel:           "docker_created",
				Strength:          collector.StrengthDeterministic,
				ObservedAt:        nowRFC3339(),
				RawRef:            "docker:/containers/" + ct.ID + "/json",
				Ref:               "container-created:" + ct.ID,
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
				Channel:           "docker_log",
				Strength:          collector.StrengthDeterministic,
				ObservedAt:        nowRFC3339(),
				RawRef:            "docker:/containers/" + ct.ID + "/logs?tail=1",
				Ref:               "container-log:" + ct.ID,
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
				Channel:           "docker",
				Reason:            "docker_log_unreadable",
				Detail:            map[string]string{"error": logErr.Error()},
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// containerLogTime reads the newest log timestamp of one container.
// A nil blind means the driver is readable (or unknown, so reading is
// attempted); a non-nil blind reports an unsupported logging driver
// without touching the API. An error means the read itself failed.
func (c *Collector) containerLogTime(
	key string,
	ct *docker.Container,
) (time.Time, bool, *collector.BlindSpot, error) {
	switch ct.LogDriver {
	case "", "json-file", "journald":
	default:
		return time.Time{}, false, &collector.BlindSpot{
			EntityIdentityKey: key,
			Channel:           "docker",
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

// portLines renders published ports canonically; the engine can list
// the same port once per bind address (IPv4 + IPv6), so lines are
// deduplicated before they reach attributes or fingerprints.
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
	attrs := map[string]string{
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
	if p := ct.Labels["com.docker.compose.project"]; p != "" {
		attrs["compose_project"] = p
	}
	if s := ct.Labels["com.docker.compose.service"]; s != "" {
		attrs["compose_service"] = s
	}
	return attrs
}

// collectUnused writes image/volume entities and UNUSED_* findings
// for inventory no container references.
func (c *Collector) collectUnused(
	sink collector.Sink,
	images []docker.Image,
	volumes []docker.Volume,
	containers []docker.Container,
	emit func(collector.Evidence) error,
) error {
	refImages := map[string]bool{}
	refVolumes := map[string]bool{}
	for _, ct := range containers {
		if ct.ImageID != "" {
			refImages[ct.ImageID] = true
		}
		if ct.Image != "" {
			refImages[ct.Image] = true
		}
		for _, v := range ct.Volumes {
			refVolumes[v] = true
		}
	}

	for i := range images {
		img := &images[i]
		key := "image|" + img.ID
		used := refImages[img.ID]
		for _, tag := range img.Tags {
			if refImages[tag] {
				used = true
			}
		}
		polarity := collector.PolarityNeutral
		if used {
			polarity = collector.PolarityInUse
		}
		ref := "image-list:" + img.ID
		if err := sink.UpsertEntity(collector.Entity{
			Kind:        "image",
			Name:        displayName(img.Tags, img.ID),
			IdentityKey: key,
			Fingerprint: img.ID,
			Attributes: map[string]string{
				"id":   img.ID,
				"tags": strings.Join(img.Tags, ", "),
				"size": fmt.Sprintf("%d", img.Size),
			},
		}); err != nil {
			return err
		}
		if err := emit(collector.Evidence{
			EntityIdentityKey: key,
			Polarity:          polarity,
			Channel:           "docker",
			Strength:          collector.StrengthDeterministic,
			ObservedAt:        nowRFC3339(),
			RawRef:            "docker:/images/json",
			Ref:               ref,
			Value: map[string]string{
				"id":   img.ID,
				"used": boolStr(used),
				"size": fmt.Sprintf("%d", img.Size),
			},
		}); err != nil {
			return err
		}
		if !used {
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

	for i := range volumes {
		vol := &volumes[i]
		key := "volume|" + vol.Name
		used := refVolumes[vol.Name]
		polarity := collector.PolarityNeutral
		if used {
			polarity = collector.PolarityInUse
		}
		ref := "volume-list:" + vol.Name
		if err := sink.UpsertEntity(collector.Entity{
			Kind:        "volume",
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
		if err := emit(collector.Evidence{
			EntityIdentityKey: key,
			Polarity:          polarity,
			Channel:           "docker",
			Strength:          collector.StrengthDeterministic,
			ObservedAt:        nowRFC3339(),
			RawRef:            "docker:/volumes",
			Ref:               ref,
			Value: map[string]string{
				"name": vol.Name,
				"used": boolStr(used),
			},
		}); err != nil {
			return err
		}
		if !used {
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
		key := "network|" + nw.Name
		ref := "network-list:" + nw.Name
		if err := sink.UpsertEntity(collector.Entity{
			Kind:        "network",
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
			Channel:           "docker",
			Strength:          collector.StrengthDeterministic,
			ObservedAt:        nowRFC3339(),
			RawRef:            "docker:/networks",
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

// collectCompose maps labeled containers to compose_service entities
// and extracts depends_on edges from the recorded config files.
// A missing or broken file yields a blind spot, never a silent gap.
func (c *Collector) collectCompose(
	sink collector.Sink,
	containers []docker.Container,
	refs map[string]bool,
) error {
	type fileKey struct{ path, project string }
	type loadResult struct {
		file *compose.File
		err  error
	}
	loaded := map[fileKey]loadResult{}
	seenService := map[string]bool{}

	// First pass: create/refresh compose_service entities, link
	// containers (belongs_to) and record per-container blind spots.
	for i := range containers {
		ct := &containers[i]
		project := ct.Labels["com.docker.compose.project"]
		service := ct.Labels["com.docker.compose.service"]
		if project == "" || service == "" {
			continue
		}
		key := "compose_service|" + project + "/" + service
		ctKey := "container|" + ct.ID

		files := splitPaths(ct.Labels["com.docker.compose.project.config_files"])
		var svc *compose.Service
		mergedContent := ""
		for _, path := range files {
			fk := fileKey{path, project}
			lr, cached := loaded[fk]
			if !cached {
				f, lerr := c.loader.Load(path, project)
				lr = loadResult{file: f, err: lerr}
				loaded[fk] = lr // cache the failure too
			}
			// Blind spots are recorded for every container that
			// references the broken file, not just the first one.
			if lr.err != nil {
				reason := "compose_parse_error"
				if compose.IsNotFound(lr.err) {
					reason = "compose_file_not_found"
				}
				if bErr := sink.AddBlindSpot(collector.BlindSpot{
					EntityIdentityKey: ctKey,
					Channel:           "docker",
					Reason:            reason,
					Detail: map[string]string{
						"path": path, "project": project, "service": service,
						"error": lr.err.Error(),
					},
				}); bErr != nil {
					return bErr
				}
			}
			if lr.file == nil {
				continue
			}
			mergedContent += string(lr.file.Content)
			if s := lr.file.Services[service]; s != nil {
				svc = s
			}
		}
		if len(files) == 0 {
			if bErr := sink.AddBlindSpot(collector.BlindSpot{
				EntityIdentityKey: ctKey,
				Channel:           "docker",
				Reason:            "compose_file_not_found",
				Detail: map[string]string{
					"path":    "com.docker.compose.project.config_files label is empty",
					"project": project,
					"service": service,
				},
			}); bErr != nil {
				return bErr
			}
		}

		if !seenService[key] {
			seenService[key] = true
			attrs := map[string]string{
				"project": project,
				"service": service,
			}
			if len(files) > 0 {
				attrs["config_files"] = strings.Join(files, ", ")
			}
			if svc != nil {
				for _, dep := range svc.DependsOn {
					attrs["depends_on"] = joinKeys(attrs["depends_on"], dep)
				}
			}
			fp := fingerprintOf(project, service, mergedContent)
			if mergedContent == "" {
				// Labels prove the service exists even when its file
				// is gone: keep a stable identity, not a guess.
				fp = fingerprintOf(project, service)
			}
			ref := "compose-service:" + key
			if err := sink.UpsertEntity(collector.Entity{
				Kind:        "compose_service",
				Name:        service,
				IdentityKey: key,
				Fingerprint: fp,
				Attributes:  attrs,
			}); err != nil {
				return err
			}
			if !refs[ref] {
				refs[ref] = true
				raw := "docker:/containers/" + ct.ID + "/json"
				if len(files) > 0 {
					raw = files[0]
				}
				if err := sink.AddEvidence(collector.Evidence{
					EntityIdentityKey: key,
					Polarity:          collector.PolarityNeutral,
					Channel:           "docker",
					Strength:          collector.StrengthDeterministic,
					ObservedAt:        nowRFC3339(),
					RawRef:            raw,
					Ref:               ref,
					Value: map[string]string{
						"project": project,
						"service": service,
					},
				}); err != nil {
					return err
				}
			}
		}

		evRef := "container-compose:" + ct.ID
		if !refs[evRef] {
			refs[evRef] = true
			if err := sink.AddEvidence(collector.Evidence{
				EntityIdentityKey: ctKey,
				Polarity:          collector.PolarityNeutral,
				Channel:           "docker",
				Strength:          collector.StrengthDeterministic,
				ObservedAt:        nowRFC3339(),
				RawRef:            "docker:/containers/" + ct.ID + "/json",
				Ref:               evRef,
				Value: map[string]string{
					"project": project,
					"service": service,
				},
			}); err != nil {
				return err
			}
		}
		if err := sink.UpsertEdge(collector.Edge{
			SrcIdentityKey: ctKey,
			DstIdentityKey: key,
			Kind:           "belongs_to",
			Strength:       collector.StrengthDeterministic,
			EvidenceRef:    evRef,
		}); err != nil {
			return err
		}
	}

	// Second pass: depends_on edges between services that both
	// exist in the loaded files and have a container proving them
	// (seenService); a file may list services with no running
	// container and those have no entity to attach evidence to.
	for fk, lr := range loaded {
		f := lr.file
		if f == nil {
			continue
		}
		for svcName, svc := range f.Services {
			src := "compose_service|" + fk.project + "/" + svcName
			if !seenService[src] {
				continue
			}
			for _, dep := range svc.DependsOn {
				if _, ok := f.Services[dep]; !ok {
					continue // dangling name: no edge, no guess
				}
				dst := "compose_service|" + fk.project + "/" + dep
				if !seenService[dst] {
					continue
				}
				ref := fmt.Sprintf("compose-dep:%s:%s:%s", fk.project, svcName, dep)
				if !refs[ref] {
					refs[ref] = true
					if err := sink.AddEvidence(collector.Evidence{
						EntityIdentityKey: src,
						Polarity:          collector.PolarityNeutral,
						Channel:           "docker",
						Strength:          collector.StrengthDeterministic,
						ObservedAt:        nowRFC3339(),
						RawRef:            fk.path + "#" + svcName + ".depends_on",
						Ref:               ref,
						Value: map[string]string{
							"service":    svcName,
							"dependency": dep,
						},
					}); err != nil {
						return err
					}
				}
				if err := sink.UpsertEdge(collector.Edge{
					SrcIdentityKey: src,
					DstIdentityKey: dst,
					Kind:           "depends_on",
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
		ctKey := "container|" + ct.ID
		for _, p := range ct.Ports {
			if p.PublicPort == 0 {
				continue // not published: unreachable from outside
			}
			keys := byPort[pkey{normProto(p.Type), int(p.PublicPort)}]
			if len(keys) == 0 {
				continue
			}
			ref := fmt.Sprintf("port-published:%s:%s:%d", ct.ID, p.Type, p.PublicPort)
			if err := emit(collector.Evidence{
				EntityIdentityKey: ctKey,
				Polarity:          collector.PolarityNeutral,
				Channel:           "docker",
				Strength:          collector.StrengthDeterministic,
				ObservedAt:        nowRFC3339(),
				RawRef:            "docker:/containers/json",
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
		ctKey := "container|" + id
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

func joinKeys(existing, add string) string {
	if existing == "" {
		return add
	}
	for _, p := range strings.Split(existing, ", ") {
		if p == add {
			return existing
		}
	}
	return existing + ", " + add
}

func splitPaths(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
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
var _ collector.Collector = (*Collector)(nil)
