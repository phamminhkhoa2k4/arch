// Package observe samples live inbound connections and records them
// as one-hour observation buckets keyed by entity and remote address.
// The verdict engine reads those buckets as positive evidence that a
// listener is still being called.
package observe

import (
	"context"
	"sync"
	"time"
)

// Listener is one bound socket entity the sampler matches against.
type Listener struct {
	ID    int64
	Proto string // "tcp" or "udp"; tcp6 normalises to tcp
	Addr  string // bound address, "0.0.0.0"/"::" = wildcard
	Port  int
}

// Sink records observation buckets. *store.Store implements it.
type Sink interface {
	// UpsertObservation adds one sample hit: count grows by one and
	// last_seen_at moves to seenAt when the bucket already exists.
	UpsertObservation(ctx context.Context, entityID int64, remoteKey, bucketStart, lastSeenAt string) error
	// PruneObservations drops buckets starting before the cut-off and
	// reports how many rows went away.
	PruneObservations(ctx context.Context, before string) (int64, error)
}

// Reader reads proc files; procfs.OSReader implements it.
type Reader interface {
	ReadFile(path string) ([]byte, error)
}

// Retention is how long observation buckets are kept (D2).
const Retention = 45 * 24 * time.Hour

// DefaultPruneEvery is how many sample rounds pass between prunes (D2).
const DefaultPruneEvery = 100

// Sampler takes one sample of established connections per round and
// writes the distinct (entity, remote) hits as buckets.
type Sampler struct {
	reader     Reader
	sink       Sink
	now        func() time.Time
	pruneEvery int

	mu        sync.Mutex
	listeners []Listener
	rounds    int
}

// New builds a sampler; a nil now means time.Now.
func New(r Reader, sink Sink, now func() time.Time) *Sampler {
	if now == nil {
		now = time.Now
	}
	return &Sampler{reader: r, sink: sink, now: now, pruneEvery: DefaultPruneEvery}
}

// SetListeners replaces the match set (the CLI refreshes it against
// the latest scan every few minutes).
func (s *Sampler) SetListeners(ls []Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listeners = append([]Listener(nil), ls...)
}

// PruneEvery overrides the prune cadence (tests).
func (s *Sampler) PruneEvery(n int) {
	s.pruneEvery = n
}

func (s *Sampler) listenerSnapshot() []Listener {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listeners
}

// SampleOnce reads the socket tables, records one hit per distinct
// (listener entity, remote) pair, and prunes on the configured cadence.
// It returns how many buckets were touched.
func (s *Sampler) SampleOnce(ctx context.Context) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	now := s.now().UTC()
	bucket := now.Truncate(time.Hour).Format(time.RFC3339)
	seen := now.Format(time.RFC3339)

	pairs, err := s.collect()
	if err != nil {
		return 0, err
	}
	written := 0
	for _, p := range pairs {
		if err := s.sink.UpsertObservation(ctx, p.entity, p.remote, bucket, seen); err != nil {
			return written, err
		}
		written++
	}

	s.rounds++
	if s.pruneEvery > 0 && s.rounds%s.pruneEvery == 0 {
		before := now.Add(-Retention).Format(time.RFC3339)
		if _, err := s.sink.PruneObservations(ctx, before); err != nil {
			return written, err
		}
	}
	return written, nil
}
