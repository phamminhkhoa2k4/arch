package process

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"archaeologist/internal/collector"
)

// fake is an in-memory procfs.Reader.
type fake struct {
	files map[string][]byte
	dirs  map[string][]string
	links map[string]string
	errs  map[string]error
}

func newFake() *fake {
	return &fake{
		files: map[string][]byte{},
		dirs:  map[string][]string{},
		links: map[string]string{},
		errs:  map[string]error{},
	}
}

func (f *fake) ReadDir(p string) ([]string, error) {
	if err, ok := f.errs[p]; ok {
		return nil, err
	}
	if d, ok := f.dirs[p]; ok {
		return d, nil
	}
	return nil, os.ErrNotExist
}

func (f *fake) ReadFile(p string) ([]byte, error) {
	if err, ok := f.errs[p]; ok {
		return nil, err
	}
	if b, ok := f.files[p]; ok {
		return b, nil
	}
	return nil, os.ErrNotExist
}

func (f *fake) Readlink(p string) (string, error) {
	if err, ok := f.errs[p]; ok {
		return "", err
	}
	if t, ok := f.links[p]; ok {
		return t, nil
	}
	return "", os.ErrNotExist
}

// recSink records everything a collector emits.
type recSink struct {
	entities map[string]collector.Entity
	edges    []collector.Edge
	evidence []collector.Evidence
	blinds   []collector.BlindSpot
	findings []collector.Finding
}

func newRecSink() *recSink { return &recSink{entities: map[string]collector.Entity{}} }

func (r *recSink) UpsertEntity(e collector.Entity) error {
	r.entities[e.IdentityKey] = e
	return nil
}
func (r *recSink) UpsertEdge(e collector.Edge) error {
	r.edges = append(r.edges, e)
	return nil
}
func (r *recSink) AddEvidence(e collector.Evidence) error {
	r.evidence = append(r.evidence, e)
	return nil
}
func (r *recSink) AddBlindSpot(b collector.BlindSpot) error {
	r.blinds = append(r.blinds, b)
	return nil
}
func (r *recSink) AddFinding(f collector.Finding) error {
	r.findings = append(r.findings, f)
	return nil
}

// makeStat builds a valid /proc/<pid>/stat with starttime at field 19.
func makeStat(pid int, comm string, ppid int, start uint64) string {
	rest := []string{"S", strconv.Itoa(ppid), "1", "1", "0", "-1"}
	for len(rest) < 19 {
		rest = append(rest, "0")
	}
	rest = append(rest, strconv.FormatUint(start, 10))
	rest = append(rest, "0", "0", "0", "0")
	return fmt.Sprintf("%d (%s) %s", pid, comm, strings.Join(rest, " "))
}

// Readable pid → entity + evidence; denied pid → blind spot;
// vanished pid → silent skip; non-pid names ignored.
func TestCollectEmitsReadableAndBlindsDenied(t *testing.T) {
	f := newFake()
	f.dirs["/proc"] = []string{"100", "101", "102", "self", "net"}

	f.files["/proc/100/stat"] = []byte(makeStat(100, "nginx", 1, 555))
	f.files["/proc/100/cmdline"] = []byte("/usr/sbin/nginx\x00-g\x00daemon;\x00")
	f.files["/proc/100/status"] = []byte("Name:\tnginx\nUid:\t0\t0\t0\t0\n")
	f.files["/proc/100/cgroup"] = []byte("0::/system.slice/nginx.service\n")

	f.errs["/proc/101/stat"] = os.ErrPermission

	// 102 exists in the dir listing but its files raced away.
	f.dirs["/proc/102"] = nil

	sink := newRecSink()
	if err := New(f).Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}

	if len(sink.entities) != 1 {
		t.Fatalf("got %d entities, want 1: %+v", len(sink.entities), keys(sink))
	}
	e := sink.entities["process|100|555"]
	if e.Kind != "process" || e.Name != "nginx" {
		t.Errorf("entity kind/name = %s/%s, want process/nginx", e.Kind, e.Name)
	}
	wantAttrs := map[string]string{
		"pid": "100", "ppid": "1", "uid": "0",
		"cmdline":    "/usr/sbin/nginx -g daemon;",
		"start_time": "555", "cgroup": "/system.slice/nginx.service",
		"unit": "nginx.service", "user": "root",
	}
	for k, want := range wantAttrs {
		if got := e.Attributes[k]; got != want {
			t.Errorf("attr %s = %q, want %q", k, got, want)
		}
	}
	if e.Fingerprint == "" {
		t.Error("fingerprint must not be empty")
	}

	if len(sink.evidence) != 1 {
		t.Fatalf("got %d evidence, want 1", len(sink.evidence))
	}
	ev := sink.evidence[0]
	if ev.RawRef != "/proc/100/stat" || ev.Channel != "procfs" ||
		ev.Polarity != collector.PolarityInUse || ev.Strength != collector.StrengthDeterministic {
		t.Errorf("evidence %+v does not match procfs/in_use/deterministic", ev)
	}

	if len(sink.blinds) != 1 {
		t.Fatalf("got %d blind spots, want 1: %+v", len(sink.blinds), sink.blinds)
	}
	b := sink.blinds[0]
	if b.Channel != "process" || b.Reason != "permission_denied" || b.Detail["pid"] != "101" {
		t.Errorf("blind spot %+v, want process/permission_denied pid=101", b)
	}
}

// The fingerprint is stable across repeated scans.
func TestFingerprintStableAcrossScans(t *testing.T) {
	build := func() *fake {
		f := newFake()
		f.dirs["/proc"] = []string{"100"}
		f.files["/proc/100/stat"] = []byte(makeStat(100, "nginx", 1, 555))
		f.files["/proc/100/cmdline"] = []byte("/usr/sbin/nginx\x00")
		f.files["/proc/100/status"] = []byte("Uid:\t1000\t1000\t1000\t1000\n")
		f.files["/proc/100/cgroup"] = []byte("0::/system.slice/nginx.service\n")
		return f
	}

	s1 := newRecSink()
	if err := New(build()).Collect(context.Background(), s1); err != nil {
		t.Fatalf("first: %v", err)
	}
	s2 := newRecSink()
	if err := New(build()).Collect(context.Background(), s2); err != nil {
		t.Fatalf("second: %v", err)
	}

	a := s1.entities["process|100|555"]
	b := s2.entities["process|100|555"]
	if a.Fingerprint != b.Fingerprint {
		t.Errorf("fingerprint changed across scans: %s vs %s", a.Fingerprint, b.Fingerprint)
	}
}

// Sink failure must abort the walk (it is a bug, not a /proc gap).
func TestSinkErrorPropagates(t *testing.T) {
	f := newFake()
	f.dirs["/proc"] = []string{"100"}
	f.files["/proc/100/stat"] = []byte(makeStat(100, "x", 1, 1))
	f.files["/proc/100/cmdline"] = []byte("x\x00")
	f.files["/proc/100/status"] = []byte("Uid:\t0\t0\t0\t0\n")
	f.files["/proc/100/cgroup"] = []byte("0::/\n")

	sink := &errSink{wantKey: "process|100|1"}
	err := New(f).Collect(context.Background(), sink)
	if err == nil || !strings.Contains(err.Error(), "sink") {
		t.Fatalf("got %v, want sink error", err)
	}
}

type errSink struct{ wantKey string }

func (e *errSink) UpsertEntity(ent collector.Entity) error {
	if ent.IdentityKey == e.wantKey {
		return fmt.Errorf("sink failure")
	}
	return nil
}
func (e *errSink) UpsertEdge(collector.Edge) error      { return nil }
func (e *errSink) AddEvidence(collector.Evidence) error { return nil }
func (e *errSink) AddFinding(collector.Finding) error   { return nil }
func (e *errSink) AddBlindSpot(collector.BlindSpot) error {
	return nil
}

func keys(s *recSink) []string {
	out := make([]string, 0, len(s.entities))
	for k := range s.entities {
		out = append(out, k)
	}
	return out
}

// Environ is captured with credential names/values masked; the raw
// secret must not appear anywhere in the recorded evidence.
func TestCollectRedactsEnviron(t *testing.T) {
	f := newFake()
	f.dirs["/proc"] = []string{"100"}
	f.files["/proc/100/stat"] = []byte(makeStat(100, "app", 1, 7))
	f.files["/proc/100/cmdline"] = []byte("/usr/bin/app\x00")
	f.files["/proc/100/status"] = []byte("Uid:\t1000\t1000\t1000\t1000\n")
	f.files["/proc/100/cgroup"] = []byte("0::/\n")
	f.files["/proc/100/environ"] = []byte(
		"DATABASE_PASSWORD=supersecret123\x00" +
			"API_HOST=https://api.internal.local:8080\x00" +
			"PWD=/opt/app\x00" +
			"RANDOM_BLOB=aGVsbG8td29ybGQtc2VjcmV0LXRva2VuIQ\x00")

	sink := newRecSink()
	if err := New(f).Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	var env *collector.Evidence
	for i := range sink.evidence {
		if sink.evidence[i].Channel == "environ" {
			env = &sink.evidence[i]
		}
	}
	if env == nil {
		t.Fatalf("no environ evidence: %+v", sink.evidence)
	}
	if env.Value["DATABASE_PASSWORD"] != "<redacted>" {
		t.Errorf("DATABASE_PASSWORD = %q, want <redacted>", env.Value["DATABASE_PASSWORD"])
	}
	if env.Value["API_HOST"] != "https://api.internal.local:8080" {
		t.Errorf("API_HOST = %q, want kept", env.Value["API_HOST"])
	}
	if env.Value["PWD"] != "/opt/app" {
		t.Errorf("PWD = %q, want kept", env.Value["PWD"])
	}
	if env.Value["RANDOM_BLOB"] != "<redacted>" {
		t.Errorf("RANDOM_BLOB = %q, want <redacted> (entropy)", env.Value["RANDOM_BLOB"])
	}
	for _, ev := range sink.evidence {
		for _, v := range ev.Value {
			if strings.Contains(v, "supersecret123") {
				t.Fatalf("raw secret leaked in evidence: %+v", ev)
			}
		}
	}
}

// A denied environ file is skipped silently — no crash, no new blind
// spot (the stat denial already reported the pid).
func TestCollectEnvironDeniedSilent(t *testing.T) {
	f := newFake()
	f.dirs["/proc"] = []string{"100"}
	f.files["/proc/100/stat"] = []byte(makeStat(100, "app", 1, 7))
	f.files["/proc/100/cmdline"] = []byte("/usr/bin/app\x00")
	f.files["/proc/100/status"] = []byte("Uid:\t1000\t1000\t1000\t1000\n")
	f.files["/proc/100/cgroup"] = []byte("0::/\n")
	f.errs["/proc/100/environ"] = os.ErrPermission

	sink := newRecSink()
	if err := New(f).Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(sink.blinds) != 0 {
		t.Errorf("environ denial must not add blind spots: %+v", sink.blinds)
	}
	for _, ev := range sink.evidence {
		if ev.Channel == "environ" {
			t.Error("denied environ must not produce evidence")
		}
	}
}
