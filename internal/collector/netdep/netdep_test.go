package netdep

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"archaeologist/internal/collector"
	"archaeologist/internal/store"
)

// recSink records output and enforces the same ordering rules as the
// real store: evidence only for known entities with a raw_ref, edges
// only through known endpoints and refs.
type recSink struct {
	entities map[string]collector.Entity
	refs     map[string]bool
	edges    []collector.Edge
	evidence []collector.Evidence
	blinds   []collector.BlindSpot
	findings []collector.Finding
}

func newRecSink() *recSink {
	return &recSink{
		entities: map[string]collector.Entity{},
		refs:     map[string]bool{},
	}
}

func (r *recSink) UpsertEntity(e collector.Entity) error {
	if e.IdentityKey == "" {
		return fmt.Errorf("empty identity key")
	}
	r.entities[e.IdentityKey] = e
	return nil
}

func (r *recSink) AddEvidence(e collector.Evidence) error {
	if _, ok := r.entities[e.EntityIdentityKey]; !ok {
		return fmt.Errorf("evidence for unknown entity %q", e.EntityIdentityKey)
	}
	if e.RawRef == "" {
		return fmt.Errorf("evidence for %q: empty raw_ref", e.EntityIdentityKey)
	}
	if e.Ref != "" {
		if r.refs[e.Ref] {
			return fmt.Errorf("duplicate evidence ref %q", e.Ref)
		}
		r.refs[e.Ref] = true
	}
	r.evidence = append(r.evidence, e)
	return nil
}

func (r *recSink) UpsertEdge(e collector.Edge) error {
	if _, ok := r.entities[e.SrcIdentityKey]; !ok {
		return fmt.Errorf("edge %s: unknown src %q", e.Kind, e.SrcIdentityKey)
	}
	if _, ok := r.entities[e.DstIdentityKey]; !ok {
		return fmt.Errorf("edge %s: unknown dst %q", e.Kind, e.DstIdentityKey)
	}
	if !r.refs[e.EvidenceRef] {
		return fmt.Errorf("edge %s: unknown evidence ref %q", e.Kind, e.EvidenceRef)
	}
	r.edges = append(r.edges, e)
	return nil
}

func (r *recSink) AddBlindSpot(b collector.BlindSpot) error {
	if b.EntityIdentityKey != "" {
		if _, ok := r.entities[b.EntityIdentityKey]; !ok {
			return fmt.Errorf("blind spot for unknown entity %q", b.EntityIdentityKey)
		}
	}
	r.blinds = append(r.blinds, b)
	return nil
}

func (r *recSink) AddFinding(f collector.Finding) error {
	if _, ok := r.entities[f.EntityIdentityKey]; !ok {
		return fmt.Errorf("finding for unknown entity %q", f.EntityIdentityKey)
	}
	r.findings = append(r.findings, f)
	return nil
}

// writeFile writes one fixture file and returns its path.
func writeFile(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// fixturePaths builds a Paths whose platform sources come from a
// readable non-cloud DMI identity, so DNS-only tests stay free of
// platform blind spots.
func fixturePaths(t *testing.T, resolv ...string) *Paths {
	t.Helper()
	dir := t.TempDir()
	dmi := filepath.Join(dir, "dmi")
	writeFile(t, filepath.Join(dmi, "sys_vendor"), "QEMU\n")
	writeFile(t, filepath.Join(dmi, "product_name"), "Standard PC\n")
	return &Paths{
		ResolvConf: resolv,
		DMIDir:     dmi,
		DSIdentify: filepath.Join(dir, "ds-identify.log"),
	}
}

func TestCollectResolvers(t *testing.T) {
	dir := t.TempDir()
	resolv := writeFile(t, filepath.Join(dir, "resolv.conf"),
		"# generated\nnameserver 9.9.9.9\nnameserver 8.8.8.8\nsearch example.test\n")
	c := New(fixturePaths(t, resolv))
	sink := newRecSink()
	if err := c.Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if len(sink.blinds) != 0 {
		t.Errorf("blinds = %+v, want none", sink.blinds)
	}
	if _, ok := sink.entities["dns_resolver|9.9.9.9"]; !ok {
		t.Errorf("entities = %v, want dns_resolver|9.9.9.9", keys(sink))
	}
	if _, ok := sink.entities["dns_resolver|8.8.8.8"]; !ok {
		t.Errorf("entities = %v, want dns_resolver|8.8.8.8", keys(sink))
	}
	// No cloud entity: a QEMU platform is not a cloud platform.
	if countKind(sink, "cloud_provider") != 0 {
		t.Errorf("cloud_provider count = %d, want 0", countKind(sink, "cloud_provider"))
	}

	ev := evidenceFor(t, sink, "dns_resolver|9.9.9.9")
	if ev.Channel != Channel {
		t.Errorf("channel = %q, want %q", ev.Channel, Channel)
	}
	if !strings.Contains(ev.RawRef, "resolv.conf:2") {
		t.Errorf("raw_ref = %q, want resolv.conf:2", ev.RawRef)
	}
	stub := sink.entities["dns_resolver|9.9.9.9"].Attributes["stub"]
	if stub != "false" {
		t.Errorf("stub = %q, want false", stub)
	}
}

func TestCollectStubFallback(t *testing.T) {
	dir := t.TempDir()
	primary := writeFile(t, filepath.Join(dir, "stub.conf"),
		"nameserver 127.0.0.53\n")
	secondary := writeFile(t, filepath.Join(dir, "resolved.conf"),
		"nameserver 8.8.4.4\n")
	c := New(fixturePaths(t, primary, secondary))
	sink := newRecSink()
	if err := c.Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if len(sink.blinds) != 0 {
		t.Errorf("blinds = %+v, want none", sink.blinds)
	}
	if countKind(sink, "dns_resolver") != 2 {
		t.Fatalf("dns_resolver count = %d, want 2", countKind(sink, "dns_resolver"))
	}
	if got := sink.entities["dns_resolver|127.0.0.53"].Attributes["stub"]; got != "true" {
		t.Errorf("stub = %q, want true", got)
	}
	ev := evidenceFor(t, sink, "dns_resolver|8.8.4.4")
	if !strings.Contains(ev.RawRef, "resolved.conf:1") {
		t.Errorf("raw_ref = %q, want resolved.conf:1", ev.RawRef)
	}
}

func TestCollectResolvConfMissingIsBlind(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent", "resolv.conf")
	c := New(fixturePaths(t, missing))
	sink := newRecSink()
	if err := c.Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if countKind(sink, "dns_resolver") != 0 {
		t.Errorf("dns_resolver count = %d, want 0", countKind(sink, "dns_resolver"))
	}
	if len(sink.blinds) != 1 {
		t.Fatalf("blinds = %+v, want one", sink.blinds)
	}
	b := sink.blinds[0]
	if b.Reason != "resolv_conf_unreadable" || b.Channel != Channel {
		t.Errorf("blind = %+v, want netdep/resolv_conf_unreadable", b)
	}
	if b.Detail["file"] != missing {
		t.Errorf("detail file = %q, want %q", b.Detail["file"], missing)
	}
}

func TestCollectCloudFromDMI(t *testing.T) {
	dir := t.TempDir()
	dmi := filepath.Join(dir, "dmi")
	writeFile(t, filepath.Join(dmi, "sys_vendor"), "Amazon\n")
	writeFile(t, filepath.Join(dmi, "product_name"), "EC2 c6i\n")
	resolv := writeFile(t, filepath.Join(dir, "resolv.conf"), "nameserver 10.0.0.2\n")
	c := New(&Paths{
		ResolvConf: []string{resolv},
		DMIDir:     dmi,
		DSIdentify: filepath.Join(dir, "ds-identify.log"),
	})
	sink := newRecSink()
	if err := c.Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if len(sink.blinds) != 0 {
		t.Errorf("blinds = %+v, want none", sink.blinds)
	}
	ent, ok := sink.entities["cloud_provider|aws"]
	if !ok {
		t.Fatalf("entities = %v, want cloud_provider|aws", keys(sink))
	}
	if ent.Name != "aws" || ent.Attributes["source"] != "dmi" {
		t.Errorf("entity = %+v, want name aws from dmi", ent)
	}
	if ent.Attributes["sys_vendor"] != "Amazon" {
		t.Errorf("sys_vendor = %q, want Amazon", ent.Attributes["sys_vendor"])
	}
	ev := evidenceFor(t, sink, "cloud_provider|aws")
	if !strings.HasSuffix(ev.RawRef, "/sys_vendor:1") {
		t.Errorf("raw_ref = %q, want the sys_vendor line", ev.RawRef)
	}
	if ev.Value["provider"] != "aws" {
		t.Errorf("value provider = %q, want aws", ev.Value["provider"])
	}
}

func TestCollectPlatformNeedsBothDMIFacts(t *testing.T) {
	// A Microsoft Surface is Microsoft hardware, not an Azure VM:
	// the product name must confirm what the vendor suggests.
	dir := t.TempDir()
	dmi := filepath.Join(dir, "dmi")
	writeFile(t, filepath.Join(dmi, "sys_vendor"), "Microsoft Corporation\n")
	writeFile(t, filepath.Join(dmi, "product_name"), "Surface Laptop 5\n")
	resolv := writeFile(t, filepath.Join(dir, "resolv.conf"), "nameserver 10.0.0.2\n")
	c := New(&Paths{
		ResolvConf: []string{resolv},
		DMIDir:     dmi,
		DSIdentify: filepath.Join(dir, "ds-identify.log"),
	})
	sink := newRecSink()
	if err := c.Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if countKind(sink, "cloud_provider") != 0 {
		t.Errorf("cloud_provider count = %d, want 0", countKind(sink, "cloud_provider"))
	}
	if len(sink.blinds) != 0 {
		t.Errorf("blinds = %+v, want none (DMI was readable)", sink.blinds)
	}
}

func TestCollectDMIUnavailableIsBlind(t *testing.T) {
	dir := t.TempDir()
	resolv := writeFile(t, filepath.Join(dir, "resolv.conf"), "nameserver 10.0.0.2\n")
	c := New(&Paths{
		ResolvConf: []string{resolv},
		DMIDir:     filepath.Join(dir, "no-dmi"),
		DSIdentify: filepath.Join(dir, "no-ds.log"),
	})
	sink := newRecSink()
	if err := c.Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if countKind(sink, "cloud_provider") != 0 {
		t.Errorf("cloud_provider count = %d, want 0", countKind(sink, "cloud_provider"))
	}
	if len(sink.blinds) != 1 {
		t.Fatalf("blinds = %+v, want one", sink.blinds)
	}
	b := sink.blinds[0]
	if b.Reason != "dmi_unavailable" || b.Channel != Channel {
		t.Errorf("blind = %+v, want netdep/dmi_unavailable", b)
	}
}

func TestCollectCloudInitFallback(t *testing.T) {
	// No DMI (containers often hide it) but cloud-init recorded the
	// datasource: the platform is known, so no blind spot.
	dir := t.TempDir()
	resolv := writeFile(t, filepath.Join(dir, "resolv.conf"), "nameserver 10.0.0.2\n")
	ds := writeFile(t, filepath.Join(dir, "ds-identify.log"),
		"[up 1s] ds-identify\npolicy loaded\nDSLIST=Ec2 NoCloud\n")
	c := New(&Paths{
		ResolvConf: []string{resolv},
		DMIDir:     filepath.Join(dir, "no-dmi"),
		DSIdentify: ds,
	})
	sink := newRecSink()
	if err := c.Collect(context.Background(), sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if len(sink.blinds) != 0 {
		t.Errorf("blinds = %+v, want none (platform found)", sink.blinds)
	}
	ent, ok := sink.entities["cloud_provider|aws"]
	if !ok {
		t.Fatalf("entities = %v, want cloud_provider|aws", keys(sink))
	}
	if ent.Attributes["source"] != "cloud_init" {
		t.Errorf("source = %q, want cloud_init", ent.Attributes["source"])
	}
	ev := evidenceFor(t, sink, "cloud_provider|aws")
	if !strings.Contains(ev.RawRef, "ds-identify.log:3") {
		t.Errorf("raw_ref = %q, want the DSLIST line", ev.RawRef)
	}
}

func TestCollectorIdentity(t *testing.T) {
	c := New(nil)
	if c.Name() != "netdep" {
		t.Errorf("Name = %q, want netdep", c.Name())
	}
	if c.Version() != "1.0.0" {
		t.Errorf("Version = %q, want 1.0.0", c.Version())
	}
}

// TestCollectSchemaAcceptsRows runs the collector against a real
// store sink so every entity, evidence row and blind spot it emits is
// proven against the database constraints.
func TestCollectSchemaAcceptsRows(t *testing.T) {
	dir := t.TempDir()
	resolv := writeFile(t, filepath.Join(dir, "resolv.conf"),
		"nameserver 9.9.9.9\nnameserver 127.0.0.53\n")
	ds := writeFile(t, filepath.Join(dir, "ds-identify.log"), "DSLIST=GCE\n")
	c := New(&Paths{
		ResolvConf: []string{resolv},
		DMIDir:     filepath.Join(dir, "no-dmi"),
		DSIdentify: ds,
	})

	db := filepath.Join(t.TempDir(), "scan.db")
	st, err := store.Open(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	hostID, err := st.InsertHost(ctx, "lab", "linux", "test")
	if err != nil {
		t.Fatal(err)
	}
	scanID, err := st.InsertScan(ctx, hostID, "v", "{}")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Collect(ctx, store.NewScanSink(ctx, st, scanID)); err != nil {
		t.Fatalf("Collect: %v", err)
	}
}

func keys(s *recSink) []string {
	out := make([]string, 0, len(s.entities))
	for k := range s.entities {
		out = append(out, k)
	}
	return out
}

func countKind(s *recSink, kind string) int {
	n := 0
	for _, e := range s.entities {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

// evidenceFor finds the single evidence row of one entity.
func evidenceFor(t *testing.T, s *recSink, entityKey string) collector.Evidence {
	t.Helper()
	for _, e := range s.evidence {
		if e.EntityIdentityKey == entityKey {
			return e
		}
	}
	t.Fatalf("no evidence for %q", entityKey)
	return collector.Evidence{}
}
