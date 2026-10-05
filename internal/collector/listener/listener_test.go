package listener

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"archaeologist/internal/collector"
	"archaeologist/internal/procfs"
)

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

type recSink struct {
	entities map[string]collector.Entity
	edges    []collector.Edge
	evidence []collector.Evidence
	blinds   []collector.BlindSpot
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

func tcpHeader() string {
	return "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
}

// row builds a /proc/net/tcp line: local hex, state, uid, inode.
func row(sl int, local, state string, uid, inode int) string {
	return fmt.Sprintf("%4d: %s 00000000:0000 %s 00000000:00000000 00:00000000 00000000 %5d        0 %d 1 0000000000000000 100 0 0 10 0\n",
		sl, local, state, uid, inode)
}

func tcp6Row(sl int, local, state string, uid, inode int) string {
	return fmt.Sprintf("%4d: %s 00000000000000000000000000000000:0000 %s 00000000:00000000 00:00000000 00000000 %5d        0 %d 1 0000000000000000 100 0 0 10 0\n",
		sl, local, state, uid, inode)
}

// labFixture models the lab shape: 0.0.0.0:8080 (mapped), 0.0.0.0:6379
// (unmapped — fd dir denied), :::80 IPv6 (mapped), plus an ESTABLISHED row
// that must be ignored. The owner process entity is pre-seeded to simulate
// the process collector running first (collector order in scan.go).
func labFixture(t *testing.T) (*fake, *recSink) {
	t.Helper()
	f := newFake()
	f.files["/proc/net/tcp"] = []byte(tcpHeader() +
		row(0, "00000000:1F90", "0A", 0, 111) + // 0.0.0.0:8080 LISTEN inode 111
		row(1, "00000000:18EB", "0A", 0, 222) + // 0.0.0.0:6379 LISTEN inode 222
		row(2, "00000000:1F90", "01", 0, 999)) // ESTABLISHED — not a listener
	f.files["/proc/net/tcp6"] = []byte(tcpHeader() +
		tcp6Row(0, "00000000000000000000000000000000:0050", "0A", 0, 333)) // :::80

	f.dirs["/proc"] = []string{"100", "101"}
	f.dirs["/proc/100/fd"] = []string{"3", "4", "5"}
	f.links["/proc/100/fd/3"] = "socket:[111]"
	f.links["/proc/100/fd/4"] = "socket:[333]"
	f.links["/proc/100/fd/5"] = "/dev/null"
	f.errs["/proc/101/fd"] = os.ErrPermission // denied fd dir → counted

	f.files["/proc/100/stat"] = []byte("100 (nginx) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 555 0 0 0 0")

	sink := newRecSink()
	// Simulate collector order: the process collector already emitted the owner.
	owner := collector.Entity{
		Kind: "process", Name: "nginx", IdentityKey: procfs.IdentityKey(100, 555),
		Fingerprint: "fp", Attributes: map[string]string{"pid": "100"},
	}
	if err := sink.UpsertEntity(owner); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	return f, sink
}

// Mapped listeners get a deterministic listens_on edge;
// the IPv6 listener is mapped too; the ESTABLISHED row is ignored.
func TestCollectMapsListenersToPID(t *testing.T) {
	f, sink := labFixture(t)
	if err := New(f).Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}

	for _, key := range []string{
		"listener|tcp|0.0.0.0|8080|111",
		"listener|tcp|0.0.0.0|6379|222",
		"listener|tcp6|::|80|333",
	} {
		if _, ok := sink.entities[key]; !ok {
			t.Errorf("missing entity %s (have %v)", key, entityKeys(sink))
		}
	}
	if len(sink.entities) != 4 { // 3 listeners + seeded owner
		t.Errorf("got %d entities, want 4", len(sink.entities))
	}

	// Exactly two edges: 8080 and :::80 → owner process; 6379 unmapped.
	if len(sink.edges) != 2 {
		t.Fatalf("got %d edges, want 2: %+v", len(sink.edges), sink.edges)
	}
	for _, e := range sink.edges {
		if e.Kind != "listens_on" || e.Strength != collector.StrengthDeterministic {
			t.Errorf("edge %+v, want listens_on/deterministic", e)
		}
		if e.DstIdentityKey != "process|100|555" {
			t.Errorf("edge dst = %s, want process|100|555", e.DstIdentityKey)
		}
	}

	// Unmapped inode → blind spot, no guessed PID.
	if len(sink.blinds) != 1 {
		t.Fatalf("got %d blind spots, want 1: %+v", len(sink.blinds), sink.blinds)
	}
	b := sink.blinds[0]
	if b.Channel != "listener_mapping" || b.Reason != "inode_not_mapped" {
		t.Errorf("blind spot %s/%s, want listener_mapping/inode_not_mapped", b.Channel, b.Reason)
	}
	if b.EntityIdentityKey != "listener|tcp|0.0.0.0|6379|222" {
		t.Errorf("blind spot entity = %q", b.EntityIdentityKey)
	}
	if b.Detail["inode"] != "222" || b.Detail["unreadable_fd_dirs"] != "1" {
		t.Errorf("blind spot detail = %v, want inode=222 unreadable_fd_dirs=1", b.Detail)
	}
}

// Every listener carries evidence with a resolvable ref (schema requires
// evidence_id on edges).
func TestListenerEvidenceRefsResolve(t *testing.T) {
	f, sink := labFixture(t)
	if err := New(f).Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	refs := map[string]bool{}
	for _, ev := range sink.evidence {
		if ev.RawRef == "" || ev.Channel != "procfs_net" ||
			ev.Strength != collector.StrengthDeterministic {
			t.Errorf("evidence incomplete: %+v", ev)
		}
		refs[ev.Ref] = true
	}
	if len(sink.evidence) != 3 {
		t.Fatalf("got %d evidence, want 3", len(sink.evidence))
	}
	for _, e := range sink.edges {
		if !refs[e.EvidenceRef] {
			t.Errorf("edge evidence ref %q not emitted", e.EvidenceRef)
		}
	}
}

// parseSocketInode: only "socket:[N]" targets map; anything else is ignored.
func TestParseSocketInode(t *testing.T) {
	if n, ok := parseSocketInode("socket:[12345]"); !ok || n != 12345 {
		t.Errorf("got %d/%v, want 12345/true", n, ok)
	}
	for _, bad := range []string{"/dev/null", "socket:[abc]", "socket:123", ""} {
		if _, ok := parseSocketInode(bad); ok {
			t.Errorf("%q must not parse", bad)
		}
	}
}

// Regression: SO_REUSEPORT lets two sockets share one addr:port. The old
// port-only identity collided — the duplicate evidence ref aborted the
// collector. Inode in the key keeps both sockets, both owners, both edges.
func TestReusePortTwoSocketsSamePort(t *testing.T) {
	f := newFake()
	f.files["/proc/net/tcp"] = []byte(tcpHeader() +
		row(0, "00000000:1F90", "0A", 0, 111) + // 0.0.0.0:8080 inode 111
		row(1, "00000000:1F90", "0A", 0, 222))  // 0.0.0.0:8080 inode 222
	f.files["/proc/net/tcp6"] = []byte(tcpHeader())

	f.dirs["/proc"] = []string{"100", "101"}
	f.dirs["/proc/100/fd"] = []string{"3"}
	f.dirs["/proc/101/fd"] = []string{"3"}
	f.links["/proc/100/fd/3"] = "socket:[111]"
	f.links["/proc/101/fd/3"] = "socket:[222]"
	f.files["/proc/100/stat"] = []byte("100 (worker-a) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 555 0 0 0 0")
	f.files["/proc/101/stat"] = []byte("101 (worker-b) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 777 0 0 0 0")

	sink := newRecSink()
	for _, e := range []collector.Entity{
		{Kind: "process", Name: "worker-a", IdentityKey: "process|100|555", Fingerprint: "f1"},
		{Kind: "process", Name: "worker-b", IdentityKey: "process|101|777", Fingerprint: "f2"},
	} {
		if err := sink.UpsertEntity(e); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	if err := New(f).Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect must not abort on shared port: %v", err)
	}

	listeners := 0
	for k := range sink.entities {
		if strings.HasPrefix(k, "listener|") {
			listeners++
		}
	}
	if listeners != 2 {
		t.Errorf("got %d listener entities, want 2 (one per inode): %v", listeners, entityKeys(sink))
	}
	if len(sink.edges) != 2 {
		t.Errorf("got %d edges, want 2 (owner per socket): %+v", len(sink.edges), sink.edges)
	}
	if len(sink.evidence) != 2 || len(sink.blinds) != 0 {
		t.Errorf("evidence=%d blinds=%d, want 2/0", len(sink.evidence), len(sink.blinds))
	}
	dsts := map[string]bool{}
	for _, e := range sink.edges {
		dsts[e.DstIdentityKey] = true
	}
	if !dsts["process|100|555"] || !dsts["process|101|777"] {
		t.Errorf("edges must cover both owners, got %v", dsts)
	}
}

func entityKeys(s *recSink) []string {
	out := make([]string, 0, len(s.entities))
	for k := range s.entities {
		out = append(out, k)
	}
	return out
}
