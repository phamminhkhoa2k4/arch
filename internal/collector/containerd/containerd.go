// Package containerd collects containers that live outside the Docker
// namespace by finding their per-task shim processes in /proc. Each
// live shim proves one container exists; the runtime bundle supplies
// its state when the scan may read it, and the unreadable bundle
// becomes a blind spot attached to that container instead of a
// guessed state.
package containerd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"archaeologist/internal/collector"
)

const (
	defaultProcRoot   = "/proc"
	defaultBundleRoot = "/run/containerd/io.containerd.runtime.v2.task"
	shimPrefix        = "containerd-shim"
	// dockerNamespace is the containerd namespace Docker creates its
	// tasks in. Those containers belong to the docker collector's
	// inventory and must not appear twice.
	dockerNamespace = "moby"
)

// Index supplies the process snapshot gathered by earlier collectors;
// nil skips the ownership (manages) edges.
type Index interface {
	ProcessRowsByContainer() (map[string][]collector.ProcessRow, error)
}

// Collector turns live containerd shims into entities, evidence,
// blind spots and ownership edges.
type Collector struct {
	index      Index
	procRoot   string
	bundleRoot string
}

// New creates a containerd collector. index may be nil (no ownership
// edges).
func New(index Index) *Collector {
	return &Collector{
		index:      index,
		procRoot:   defaultProcRoot,
		bundleRoot: defaultBundleRoot,
	}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return "containerd" }

// Version implements collector.Collector.
func (c *Collector) Version() string { return "1.0.0" }

// shim is one live containerd task shim found in /proc.
type shim struct {
	pid       int
	namespace string
	id        string
	binary    string // shim argv[0] basename, e.g. containerd-shim-runc-v2
}

// unparsedShim is a shim process whose namespace/id flags could not
// be read: reported as a blind spot, never dropped silently.
type unparsedShim struct {
	pid     int
	cmdline string
}

// Collect scans /proc for shims and writes one entity per container
// with its evidence, bundle state (or the blind spot for it) and the
// ownership edges its cgroup processes prove.
func (c *Collector) Collect(ctx context.Context, sink collector.Sink) error {
	shims, unparsed, err := scanShims(c.procRoot)
	if err != nil {
		return err
	}
	for _, u := range unparsed {
		if err := sink.AddBlindSpot(collector.BlindSpot{
			Channel: "containerd",
			Reason:  "containerd_shim_unparsed",
			Detail: map[string]string{
				"pid":     strconv.Itoa(u.pid),
				"cmdline": u.cmdline,
			},
		}); err != nil {
			return err
		}
	}

	var byID map[string][]collector.ProcessRow
	if c.index != nil {
		if byID, err = c.index.ProcessRowsByContainer(); err != nil {
			return err
		}
	}

	seen := map[string]bool{}
	for _, s := range shims {
		if err := ctx.Err(); err != nil {
			return err
		}
		key := "containerd_container|" + s.namespace + "/" + s.id
		if seen[key] {
			continue // /proc race: one container never has two shims
		}
		seen[key] = true

		attrs := map[string]string{
			"namespace": s.namespace,
			"id":        s.id,
			"shim":      s.binary,
			"pid":       strconv.Itoa(s.pid),
			"bundle":    filepath.Join(c.bundleRoot, s.namespace, s.id),
		}
		value := map[string]string{
			"namespace": s.namespace,
			"id":        s.id,
			"shim":      s.binary,
		}
		polarity := collector.PolarityNeutral
		bs, stateErr := readBundle(attrs["bundle"])
		if stateErr == nil {
			if bs.status != "" {
				attrs["state"] = bs.status
				value["state"] = bs.status
				if bs.status == "running" {
					polarity = collector.PolarityInUse
				}
			}
			if bs.name != "" {
				// The CRI container-name annotation, when present;
				// the id stays the stable display name otherwise.
				attrs["container_name"] = bs.name
			}
		}

		if err := sink.UpsertEntity(collector.Entity{
			Kind:        "containerd_container",
			Name:        s.id,
			IdentityKey: key,
			Fingerprint: fingerprintOf(s.namespace, s.id, s.binary),
			Attributes:  attrs,
		}); err != nil {
			return err
		}
		ref := "containerd-shim:" + s.namespace + "/" + s.id
		if err := sink.AddEvidence(collector.Evidence{
			EntityIdentityKey: key,
			Polarity:          polarity,
			Channel:           "containerd",
			Strength:          collector.StrengthDeterministic,
			ObservedAt:        nowRFC3339(),
			RawRef:            fmt.Sprintf("/proc/%d/cmdline", s.pid),
			Ref:               ref,
			Value:             value,
		}); err != nil {
			return err
		}
		if stateErr != nil {
			// The shim proves the container exists; the state does not
			// fit in the read, so the entity carries the gap rather
			// than a guessed state.
			if err := sink.AddBlindSpot(collector.BlindSpot{
				EntityIdentityKey: key,
				Channel:           "containerd",
				Reason:            "containerd_bundle_unreadable",
				Detail: map[string]string{
					"bundle": attrs["bundle"],
					"error":  stateErr.Error(),
				},
			}); err != nil {
				return err
			}
		}

		// Ownership: processes whose cgroup carries this exact id.
		for _, row := range byID[s.id] {
			if err := sink.UpsertEdge(collector.Edge{
				SrcIdentityKey: key,
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

// scanShims walks procRoot for live containerd shims. A kernel
// thread, a zombie and an exited process all yield an empty cmdline:
// without argv there is nothing provable about them, so they are
// skipped. The moby namespace is skipped as Docker's own.
func scanShims(procRoot string) ([]shim, []unparsedShim, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("list %s: %w", procRoot, err)
	}
	var shims []shim
	var unparsed []unparsedShim
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // non-pid entries such as "self" or "net"
		}
		raw, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "cmdline"))
		if err != nil {
			continue // the process exited between readdir and read
		}
		if len(raw) == 0 {
			continue // no argv: nothing provable about this process
		}
		args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		binary := path.Base(args[0])
		if !strings.HasPrefix(binary, shimPrefix) {
			continue
		}
		namespace, id, ok := shimFlags(args)
		if !ok {
			unparsed = append(unparsed, unparsedShim{
				pid:     pid,
				cmdline: strings.Join(args, " "),
			})
			continue
		}
		if namespace == dockerNamespace {
			continue // the docker collector owns these containers
		}
		shims = append(shims, shim{pid: pid, namespace: namespace, id: id, binary: binary})
	}
	sort.Slice(shims, func(i, j int) bool {
		if shims[i].namespace != shims[j].namespace {
			return shims[i].namespace < shims[j].namespace
		}
		return shims[i].id < shims[j].id
	})
	return shims, unparsed, nil
}

// shimFlags extracts the namespace and task id a containerd shim
// was started with; ok=false means the process looks like a shim but
// does not carry both flags.
func shimFlags(args []string) (namespace, id string, ok bool) {
	for i := 0; i+1 < len(args); i++ {
		switch args[i] {
		case "-namespace", "--namespace":
			namespace = args[i+1]
		case "-id", "--id":
			id = args[i+1]
		}
	}
	return namespace, id, namespace != "" && id != ""
}

// bundleState is what the runtime bundle proves about one container:
// the status from state.json, plus the CRI container name from
// config.json when that file is readable.
type bundleState struct {
	status string
	name   string
}

// readBundle reads one container's runtime bundle. Any failure of
// state.json (missing bundle, no permission) is returned so the
// caller records a blind spot. config.json only enriches the
// display, so its absence never fails the read.
func readBundle(dir string) (bundleState, error) {
	var b bundleState
	raw, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		return b, err
	}
	var st struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return b, fmt.Errorf("parse state.json: %w", err)
	}
	b.status = st.Status

	cfgRaw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return b, nil
	}
	var cfg struct {
		Annotations map[string]string `json:"annotations"`
	}
	if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
		return b, nil
	}
	b.name = cfg.Annotations["io.kubernetes.cri.container-name"]
	return b, nil
}

// ProbeBundleAccess reports whether every live non-Docker shim's
// bundle state file can be read. A host without such shims passes:
// there is no bundle to read. Used by doctor.
func ProbeBundleAccess() error {
	shims, _, err := scanShims(defaultProcRoot)
	if err != nil {
		return err
	}
	for _, s := range shims {
		if _, err := readBundle(filepath.Join(defaultBundleRoot, s.namespace, s.id)); err != nil {
			return err
		}
	}
	return nil
}

func fingerprintOf(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// compile-time interface check
var _ collector.Collector = (*Collector)(nil)
