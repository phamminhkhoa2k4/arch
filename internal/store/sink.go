package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"archaeologist/internal/collector"
)

// ScanSink adapts collector output to the schema for one open scan.
// It implements collector.Sink.
//
// Identity keys and evidence refs are resolved through in-memory maps so
// collectors never touch the database directly. Not safe for concurrent
// use: collector.Run executes collectors sequentially.
type ScanSink struct {
	ctx    context.Context
	s      *Store
	scanID int64

	entities map[string]int64 // identity_key → entities.id
	refs     map[string]int64 // evidence.Ref → evidence.id
}

// NewScanSink binds a sink to one scan row.
func NewScanSink(ctx context.Context, s *Store, scanID int64) *ScanSink {
	return &ScanSink{
		ctx:      ctx,
		s:        s,
		scanID:   scanID,
		entities: make(map[string]int64),
		refs:     make(map[string]int64),
	}
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// jsonMap marshals an attribute map as "{}" instead of JSON "null" when
// nil, so downstream readers (report, UI) always see an object.
func jsonMap(m map[string]string) (string, error) {
	if m == nil {
		return "{}", nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// UpsertEntity inserts the entity or refreshes it when the same identity
// key is emitted again within this scan (id stays stable for edges).
func (k *ScanSink) UpsertEntity(e collector.Entity) error {
	if e.IdentityKey == "" {
		return fmt.Errorf("upsert entity: empty identity_key")
	}
	attrs, err := jsonMap(e.Attributes)
	if err != nil {
		return fmt.Errorf("upsert entity %q: marshal attributes: %w", e.IdentityKey, err)
	}
	now := nowRFC3339()
	_, err = k.s.db.ExecContext(k.ctx,
		`INSERT INTO entities (scan_id, kind, name, identity_key, fingerprint, attributes_json, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (scan_id, identity_key) DO UPDATE SET
		   kind = excluded.kind,
		   name = excluded.name,
		   fingerprint = excluded.fingerprint,
		   attributes_json = excluded.attributes_json,
		   updated_at = excluded.updated_at`,
		k.scanID, e.Kind, e.Name, e.IdentityKey, e.Fingerprint, attrs, now, now)
	if err != nil {
		return fmt.Errorf("upsert entity %q: %w", e.IdentityKey, err)
	}

	var id int64
	err = k.s.db.QueryRowContext(k.ctx,
		`SELECT id FROM entities WHERE scan_id = ? AND identity_key = ?`,
		k.scanID, e.IdentityKey).Scan(&id)
	if err != nil {
		return fmt.Errorf("upsert entity %q: reload id: %w", e.IdentityKey, err)
	}
	k.entities[e.IdentityKey] = id
	return nil
}

// AddEvidence records one fact for an entity already known to this sink.
// Non-empty Ref is a collector-local handle edges can reference.
func (k *ScanSink) AddEvidence(e collector.Evidence) error {
	if e.RawRef == "" {
		return fmt.Errorf("evidence for %q: empty raw_ref", e.EntityIdentityKey)
	}
	entityID, ok := k.entities[e.EntityIdentityKey]
	if !ok {
		return fmt.Errorf("evidence for unknown entity %q", e.EntityIdentityKey)
	}
	if e.Ref != "" {
		if _, dup := k.refs[e.Ref]; dup {
			return fmt.Errorf("duplicate evidence ref %q", e.Ref)
		}
	}
	val, err := jsonMap(e.Value)
	if err != nil {
		return fmt.Errorf("evidence for %q: marshal value: %w", e.EntityIdentityKey, err)
	}
	res, err := k.s.db.ExecContext(k.ctx,
		`INSERT INTO evidence (entity_id, polarity, channel, strength, observed_at, raw_ref, value_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		entityID, string(e.Polarity), e.Channel, string(e.Strength),
		e.ObservedAt, e.RawRef, val)
	if err != nil {
		return fmt.Errorf("evidence for %q: %w", e.EntityIdentityKey, err)
	}
	if e.Ref != "" {
		id, err := res.LastInsertId()
		if err != nil {
			return fmt.Errorf("evidence for %q: id: %w", e.EntityIdentityKey, err)
		}
		k.refs[e.Ref] = id
	}
	return nil
}

// UpsertEdge links two entities through evidence registered earlier in this
// scan. Re-emitting the same (src, dst, kind) refreshes the row.
func (k *ScanSink) UpsertEdge(e collector.Edge) error {
	srcID, ok := k.entities[e.SrcIdentityKey]
	if !ok {
		return fmt.Errorf("edge %s: unknown src %q", e.Kind, e.SrcIdentityKey)
	}
	dstID, ok := k.entities[e.DstIdentityKey]
	if !ok {
		return fmt.Errorf("edge %s: unknown dst %q", e.Kind, e.DstIdentityKey)
	}
	evID, ok := k.refs[e.EvidenceRef]
	if !ok {
		return fmt.Errorf("edge %s: unknown evidence ref %q", e.Kind, e.EvidenceRef)
	}
	_, err := k.s.db.ExecContext(k.ctx,
		`INSERT INTO edges (scan_id, src_id, dst_id, kind, strength, evidence_id)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT (scan_id, src_id, dst_id, kind) DO UPDATE SET
		   strength = excluded.strength,
		   evidence_id = excluded.evidence_id`,
		k.scanID, srcID, dstID, e.Kind, string(e.Strength), evID)
	if err != nil {
		return fmt.Errorf("edge %s: %w", e.Kind, err)
	}
	return nil
}

// AddBlindSpot records something the collector could not see, so the gap
// lands in the database instead of being silently dropped.
// EntityIdentityKey may be empty for host-wide gaps; a non-empty key must
// reference an entity already emitted in this scan.
func (k *ScanSink) AddBlindSpot(b collector.BlindSpot) error {
	var entityID int64
	if b.EntityIdentityKey != "" {
		id, ok := k.entities[b.EntityIdentityKey]
		if !ok {
			return fmt.Errorf("blind spot %s/%s: unknown entity %q", b.Channel, b.Reason, b.EntityIdentityKey)
		}
		entityID = id
	}
	detail, err := jsonMap(b.Detail)
	if err != nil {
		return fmt.Errorf("blind spot %s/%s: marshal detail: %w", b.Channel, b.Reason, err)
	}
	var e any
	if b.EntityIdentityKey != "" {
		e = entityID
	}
	_, err = k.s.db.ExecContext(k.ctx,
		`INSERT INTO blind_spots (scan_id, entity_id, channel, reason, detail_json, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		k.scanID, e, b.Channel, b.Reason, detail, nowRFC3339())
	if err != nil {
		return fmt.Errorf("blind spot %s/%s: %w", b.Channel, b.Reason, err)
	}
	return nil
}
