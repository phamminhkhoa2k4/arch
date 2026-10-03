// Package collector defines the extension point for every data source.
//
// Authority: specs.md §5 (Collector framework), US-0.2.
// The core scan loop only knows this interface; adding a source never
// requires touching the core.
package collector

import "context"

// Strength grades how trustworthy a link or piece of evidence is.
// Authority: specs.md §4.1, US-0.1.
type Strength string

const (
	StrengthDeterministic   Strength = "deterministic"
	StrengthStrongHeuristic Strength = "strong_heuristic"
	StrengthWeakHeuristic   Strength = "weak_heuristic"
)

// Polarity is the direction of an evidence signal.
// Authority: specs.md §4.1, US-0.1.
type Polarity string

const (
	PolarityInUse    Polarity = "in_use"
	PolarityNotInUse Polarity = "not_in_use"
	PolarityNeutral  Polarity = "neutral"
)

// Entity is one discovered component (process, unit, container, ...).
type Entity struct {
	Kind        string // e.g. "process", "systemd_unit", "container"
	Name        string
	IdentityKey string // deterministic key used for merging (specs.md §7.1)
	Fingerprint string // stable across scans, used for diffing (US-1.1)
	Attributes  map[string]string
}

// Edge links two entities through a named relationship.
type Edge struct {
	SrcIdentityKey string // identity keys within the same collect run
	DstIdentityKey string
	Kind           string // e.g. "listens_on", "runs_as", "depends_on"
	Strength       Strength
	EvidenceRef    string // collector-local ref matching an Evidence.Ref
}

// Evidence is one traceable fact. RawRef must never be empty (INV-1).
type Evidence struct {
	EntityIdentityKey string
	Polarity          Polarity
	Channel           string
	Strength          Strength
	ObservedAt        string // RFC3339
	RawRef            string // file:line, /proc path, API call
	Value             map[string]string
	Ref               string // collector-local handle edges can point at
}

// BlindSpot records something the collector could not see (INV-4).
type BlindSpot struct {
	EntityIdentityKey string // "" for host-wide gaps
	Channel           string
	Reason            string
	Detail            map[string]string
}

// Sink receives collector output. Errors are returned to the caller so the
// core can decide policy; collectors never write to the database directly.
type Sink interface {
	UpsertEntity(e Entity) error
	UpsertEdge(e Edge) error
	AddEvidence(e Evidence) error
	AddBlindSpot(b BlindSpot) error
}

// Collector is implemented by every data source.
// Authority: specs.md §5, US-0.2.
type Collector interface {
	Name() string
	Version() string // recorded in scans.collector_versions_json
	Collect(ctx context.Context, sink Sink) error
}
