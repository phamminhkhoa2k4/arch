// Package collector defines the extension point for every data source.
//
// The core scan loop only knows this interface; adding a source never
// requires touching the core.
package collector

import "context"

// Strength grades how trustworthy a link or piece of evidence is.
type Strength string

const (
	StrengthDeterministic   Strength = "deterministic"
	StrengthStrongHeuristic Strength = "strong_heuristic"
	StrengthWeakHeuristic   Strength = "weak_heuristic"
)

// Polarity is the direction of an evidence signal.
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
	IdentityKey string // deterministic key used for merging
	Fingerprint string // stable across scans, used for diffing
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

// Evidence is one traceable fact. RawRef must never be empty — every fact
// has to point back at its source.
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

// BlindSpot records something the collector could not see, so blindness is
// reported instead of silently missing.
type BlindSpot struct {
	EntityIdentityKey string // "" for host-wide gaps
	Channel           string
	Reason            string
	Detail            map[string]string
}

// Finding records a noteworthy configuration problem the collector
// observed (a broken state that exists), unlike a BlindSpot which
// records something the collector could not observe.
type Finding struct {
	EntityIdentityKey string
	Kind              string // e.g. "DANGLING_DEPENDS"
	Severity          string // "info" or "warn"
	Detail            map[string]string
	EvidenceRef       string // optional collector-local evidence handle
}

// ProcessRow is one process as seen through its cgroup attributes —
// the input for unit/container ownership edges.
type ProcessRow struct {
	IdentityKey string
	Owner       string // cgroup owner: systemd unit name or container id, "" outside
}

// ListenerRow is one listener recorded in the scan — the input for
// published-port matching (docker).
type ListenerRow struct {
	IdentityKey string
	Name        string // display name, e.g. "0.0.0.0:8081"
}

// UnitRow is one systemd unit recorded in the scan — the input for
// resolving systemctl references found in cron scripts (cron).
type UnitRow struct {
	IdentityKey string
	Name        string // e.g. "lab-batch.service"
}

// ContainerRow is one container recorded in the scan — the input for
// matching bare commands from cron scripts against containers (cron).
type ContainerRow struct {
	IdentityKey string
	Name        string
	Image       string
}

// Sink receives collector output. Errors are returned to the caller so the
// core can decide policy; collectors never write to the database directly.
type Sink interface {
	UpsertEntity(e Entity) error
	UpsertEdge(e Edge) error
	AddEvidence(e Evidence) error
	AddBlindSpot(b BlindSpot) error
	AddFinding(f Finding) error
}

// Collector is implemented by every data source.
type Collector interface {
	Name() string
	Version() string // recorded in scans.collector_versions_json
	Collect(ctx context.Context, sink Sink) error
}
