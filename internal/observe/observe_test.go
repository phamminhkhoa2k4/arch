package observe

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// fakeSink records upserts and prunes.
type fakeSink struct {
	upserts []upsert
	prunes  []string
	err     error
}

type upsert struct {
	entity     int64
	remote     string
	bucket     string
	lastSeenAt string
}

func (f *fakeSink) UpsertObservation(_ context.Context, entityID int64, remoteKey, bucketStart, lastSeenAt string) error {
	if f.err != nil {
		return f.err
	}
	f.upserts = append(f.upserts, upsert{entityID, remoteKey, bucketStart, lastSeenAt})
	return nil
}

func (f *fakeSink) PruneObservations(_ context.Context, before string) (int64, error) {
	if f.err != nil {
		return 0, f.err
	}
	f.prunes = append(f.prunes, before)
	return 1, nil
}

// fakeReader serves canned proc contents by path.
type fakeReader struct {
	files map[string]string
	errs  map[string]error
}

func (f *fakeReader) ReadFile(path string) ([]byte, error) {
	if err, ok := f.errs[path]; ok {
		return nil, err
	}
	s, ok := f.files[path]
	if !ok {
		return nil, errors.New("no such file: " + path)
	}
	return []byte(s), nil
}

const tcpHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

// tcpRow builds one /proc/net/tcp data line.
func tcpRow(sl int, local, rem, st string, inode int) string {
	return fmt.Sprintf("%4d: %s %s %s 00000000:00000000 00:00000000 00000000     0        0 %d 1 0000000000000000 100 0 0 10 0\n",
		sl, local, rem, st, inode)
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse time %q: %v", s, err)
	}
	return ts
}

func TestSampleEstablishedConnectionWritesBucket(t *testing.T) {
	now := mustTime(t, "2026-10-08T15:37:12Z")
	sink := &fakeSink{}
	r := &fakeReader{files: map[string]string{
		"/proc/net/tcp": tcpHeader +
			tcpRow(0, "0100007F:1F90", "0200000A:C350", "01", 424242) + // 127.0.0.1:8080 ← 10.0.0.2
			tcpRow(1, "0100007F:1F90", "00000000:000000", "0A", 1), // LISTEN — ignored
		"/proc/net/tcp6": tcpHeader,
	}}
	s := New(r, sink, func() time.Time { return now })
	s.SetListeners([]Listener{{ID: 7, Proto: "tcp", Addr: "0.0.0.0", Port: 8080}})

	n, err := s.SampleOnce(context.Background())
	if err != nil {
		t.Fatalf("SampleOnce: %v", err)
	}
	if n != 1 || len(sink.upserts) != 1 {
		t.Fatalf("upserts = %d, want 1", len(sink.upserts))
	}
	got := sink.upserts[0]
	want := upsert{7, "10.0.0.2", "2026-10-08T15:00:00Z", "2026-10-08T15:37:12Z"}
	if got != want {
		t.Errorf("upsert = %+v, want %+v", got, want)
	}
}

func TestExactAddressBeatsWildcard(t *testing.T) {
	now := mustTime(t, "2026-10-08T15:00:00Z")
	sink := &fakeSink{}
	r := &fakeReader{files: map[string]string{
		"/proc/net/tcp":  tcpHeader + tcpRow(0, "0100007F:1F90", "0200000A:C350", "01", 1),
		"/proc/net/tcp6": tcpHeader,
	}}
	s := New(r, sink, func() time.Time { return now })
	s.SetListeners([]Listener{
		{ID: 1, Proto: "tcp", Addr: "0.0.0.0", Port: 8080},
		{ID: 2, Proto: "tcp", Addr: "127.0.0.1", Port: 8080},
	})
	if _, err := s.SampleOnce(context.Background()); err != nil {
		t.Fatalf("SampleOnce: %v", err)
	}
	if len(sink.upserts) != 1 || sink.upserts[0].entity != 2 {
		t.Errorf("upserts = %+v, want only exact entity 2", sink.upserts)
	}
}

func TestUnknownPortIsIgnored(t *testing.T) {
	now := mustTime(t, "2026-10-08T15:00:00Z")
	sink := &fakeSink{}
	r := &fakeReader{files: map[string]string{
		"/proc/net/tcp":  tcpHeader + tcpRow(0, "0100007F:1F90", "0200000A:C350", "01", 1),
		"/proc/net/tcp6": tcpHeader,
	}}
	s := New(r, sink, func() time.Time { return now })
	s.SetListeners([]Listener{{ID: 3, Proto: "tcp", Addr: "0.0.0.0", Port: 9999}})
	n, err := s.SampleOnce(context.Background())
	if err != nil {
		t.Fatalf("SampleOnce: %v", err)
	}
	if n != 0 {
		t.Errorf("n = %d, want 0", n)
	}
}

func TestConntrackSupplementsProc(t *testing.T) {
	now := mustTime(t, "2026-10-08T15:00:00Z")
	sink := &fakeSink{}
	r := &fakeReader{files: map[string]string{
		"/proc/net/tcp":  tcpHeader, // empty table
		"/proc/net/tcp6": tcpHeader,
		"/proc/net/nf_conntrack": "tcp 431999 ESTABLISHED src=198.51.100.7 dst=10.0.0.5 " +
			"sport=44444 dport=9090 src=10.0.0.5 dst=198.51.100.7 sport=9090 dport=44444\n" +
			"tcp 179 src=203.0.113.9 dst=10.0.0.5 sport=111 dport=8080 [UNREPLIED] src=10.0.0.5 dst=203.0.113.9 sport=8080 dport=111\n",
	}}
	s := New(r, sink, func() time.Time { return now })
	s.SetListeners([]Listener{
		{ID: 4, Proto: "tcp", Addr: "0.0.0.0", Port: 9090},
		{ID: 5, Proto: "tcp", Addr: "0.0.0.0", Port: 8080},
	})
	if _, err := s.SampleOnce(context.Background()); err != nil {
		t.Fatalf("SampleOnce: %v", err)
	}
	if len(sink.upserts) != 1 || sink.upserts[0].entity != 4 || sink.upserts[0].remote != "198.51.100.7" {
		t.Errorf("upserts = %+v, want only established entity 4", sink.upserts)
	}
}

func TestMissingConntrackIsSkipped(t *testing.T) {
	now := mustTime(t, "2026-10-08T15:00:00Z")
	sink := &fakeSink{}
	r := &fakeReader{
		files: map[string]string{"/proc/net/tcp": tcpHeader, "/proc/net/tcp6": tcpHeader},
		errs:  map[string]error{"/proc/net/nf_conntrack": errors.New("no such file")},
	}
	s := New(r, sink, func() time.Time { return now })
	s.SetListeners([]Listener{{ID: 1, Proto: "tcp", Addr: "::", Port: 80}})
	if _, err := s.SampleOnce(context.Background()); err != nil {
		t.Fatalf("SampleOnce with missing conntrack: %v", err)
	}
}

func TestPruneRunsOnConfiguredCadence(t *testing.T) {
	now := mustTime(t, "2026-10-08T15:00:00Z")
	sink := &fakeSink{}
	r := &fakeReader{files: map[string]string{"/proc/net/tcp": tcpHeader, "/proc/net/tcp6": tcpHeader}}
	s := New(r, sink, func() time.Time { return now })
	s.SetListeners([]Listener{{ID: 1, Proto: "tcp", Addr: "::", Port: 80}})
	s.PruneEvery(2)

	if _, err := s.SampleOnce(context.Background()); err != nil {
		t.Fatalf("round 1: %v", err)
	}
	if len(sink.prunes) != 0 {
		t.Fatalf("prunes after round 1 = %d, want 0", len(sink.prunes))
	}
	if _, err := s.SampleOnce(context.Background()); err != nil {
		t.Fatalf("round 2: %v", err)
	}
	want := now.Add(-Retention).Format(time.RFC3339)
	if len(sink.prunes) != 1 || sink.prunes[0] != want {
		t.Errorf("prunes = %v, want [%s]", sink.prunes, want)
	}
}

func TestNoListenersMeansNoWork(t *testing.T) {
	r := &fakeReader{files: map[string]string{}} // any read would fail
	s := New(r, &fakeSink{}, nil)
	n, err := s.SampleOnce(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("n=%d err=%v, want 0/nil", n, err)
	}
}

func TestSampleDeduplicatesPairs(t *testing.T) {
	now := mustTime(t, "2026-10-08T15:00:00Z")
	sink := &fakeSink{}
	r := &fakeReader{files: map[string]string{
		// two established sockets from the same remote — one pair.
		"/proc/net/tcp": tcpHeader +
			tcpRow(0, "0100007F:1F90", "0200000A:C350", "01", 1) +
			tcpRow(1, "0100007F:1F90", "0200000A:C350", "01", 2),
		"/proc/net/tcp6": tcpHeader,
	}}
	s := New(r, sink, func() time.Time { return now })
	s.SetListeners([]Listener{{ID: 9, Proto: "tcp", Addr: "0.0.0.0", Port: 8080}})
	n, err := s.SampleOnce(context.Background())
	if err != nil {
		t.Fatalf("SampleOnce: %v", err)
	}
	if n != 1 || len(sink.upserts) != 1 {
		t.Errorf("n=%d upserts=%d, want 1 (same remote de-duplicated per sample)", n, len(sink.upserts))
	}
	if !strings.HasSuffix(sink.upserts[0].bucket, "T15:00:00Z") {
		t.Errorf("bucket = %q, want hourly", sink.upserts[0].bucket)
	}
}

// One IPv4 connection lands on the IPv4 wildcard listener only — the
// dual-stack :: listener must not double-count it.
func TestIPv4SocketMatchesOnlyIPv4Wildcard(t *testing.T) {
	now := mustTime(t, "2026-10-08T15:00:00Z")
	sink := &fakeSink{}
	r := &fakeReader{files: map[string]string{
		// local D4D04D67:0016 = 103.77.208.212:22 (specific address,
		// so only the wildcard branch applies).
		"/proc/net/tcp":  tcpHeader + tcpRow(0, "D4D04D67:0016", "9A68B871:D154", "01", 1),
		"/proc/net/tcp6": tcpHeader,
	}}
	s := New(r, sink, func() time.Time { return now })
	s.SetListeners([]Listener{
		{ID: 1, Proto: "tcp", Addr: "0.0.0.0", Port: 22},
		{ID: 2, Proto: "tcp6", Addr: "::", Port: 22},
	})
	if _, err := s.SampleOnce(context.Background()); err != nil {
		t.Fatalf("SampleOnce: %v", err)
	}
	if len(sink.upserts) != 1 || sink.upserts[0].entity != 1 {
		t.Errorf("upserts = %+v, want only the IPv4 wildcard entity 1", sink.upserts)
	}
}

// A row from the IPv6 table lands on the :: listener only.
func TestIPv6SocketMatchesOnlyIPv6Wildcard(t *testing.T) {
	now := mustTime(t, "2026-10-08T15:00:00Z")
	sink := &fakeSink{}
	r := &fakeReader{files: map[string]string{
		"/proc/net/tcp": tcpHeader,
		"/proc/net/tcp6": tcpHeader + tcpRow(0,
			"00000000000000000000000000000000:0016",
			"00000000000000000000000000000001:1F90", "01", 1),
	}}
	s := New(r, sink, func() time.Time { return now })
	s.SetListeners([]Listener{
		{ID: 1, Proto: "tcp", Addr: "0.0.0.0", Port: 22},
		{ID: 2, Proto: "tcp6", Addr: "::", Port: 22},
	})
	if _, err := s.SampleOnce(context.Background()); err != nil {
		t.Fatalf("SampleOnce: %v", err)
	}
	if len(sink.upserts) != 1 || sink.upserts[0].entity != 2 {
		t.Errorf("upserts = %+v, want only the IPv6 wildcard entity 2", sink.upserts)
	}
}
