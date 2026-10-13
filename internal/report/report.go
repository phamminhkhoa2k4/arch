// Package report assembles the exportable view of one scan — the
// numbers, findings, and blind spots — and renders it as JSON,
// Markdown, or a self-contained HTML file. Free text is scrubbed one
// more time on the way out as defense in depth on top of the store
// choke-point.
package report

import (
	"context"
	"time"

	"archaeologist/internal/redact"
	"archaeologist/internal/store"
)

// Report is the full exportable document. JSON tags are snake_case and
// every slice is non-nil so the JSON never emits null.
type Report struct {
	ScanID      int64     `json:"scan_id"`
	Host        string    `json:"host"`
	Status      string    `json:"status"`
	GeneratedAt string    `json:"generated_at"`
	Dashboard   Dashboard `json:"dashboard"`
	Findings    []Finding `json:"findings"`
	BlindSpots  []Blind   `json:"blind_spots"`
}

// Dashboard is the at-a-glance summary block.
type Dashboard struct {
	EntitiesByKind map[string]int `json:"entities_by_kind"`
	Verdict        map[string]int `json:"verdict"`
	BlindSpots     int            `json:"blind_spots"`
	Findings       int            `json:"findings"`
}

// Finding is one row of the findings list, joined with its entity.
type Finding struct {
	Kind       string            `json:"kind"`
	Severity   string            `json:"severity"`
	Detail     map[string]string `json:"detail"`
	EntityKind string            `json:"entity_kind"`
	EntityName string            `json:"entity_name"`
	Identity   string            `json:"identity"`
}

// Blind is one blind spot — host-wide (entity fields empty) or
// entity-scoped. Blind spots are first-class citizens: always shown.
type Blind struct {
	Channel    string            `json:"channel"`
	Reason     string            `json:"reason"`
	Detail     map[string]string `json:"detail"`
	EntityKind string            `json:"entity_kind,omitempty"`
	EntityName string            `json:"entity_name,omitempty"`
}

// Build loads every report section for one scan from the store and
// scrubs free text on the way out.
func Build(ctx context.Context, st *store.Store, scanID int64) (Report, error) {
	host, status, err := st.ScanHostStatus(ctx, scanID)
	if err != nil {
		return Report{}, err
	}
	sum, err := st.ScanSummary(ctx, scanID)
	if err != nil {
		return Report{}, err
	}
	verdict, err := st.VerdictRollup(ctx, scanID)
	if err != nil {
		return Report{}, err
	}
	if verdict == nil {
		verdict = map[string]int{}
	}
	rawFindings, err := st.FindingsInScan(ctx, scanID)
	if err != nil {
		return Report{}, err
	}
	rawBlinds, err := st.BlindSpotsInScan(ctx, scanID)
	if err != nil {
		return Report{}, err
	}

	r := Report{
		ScanID:      scanID,
		Host:        redact.ScrubString(host),
		Status:      status,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Dashboard: Dashboard{
			EntitiesByKind: map[string]int{},
			Verdict:        verdict,
			BlindSpots:     len(rawBlinds),
			Findings:       len(rawFindings),
		},
		Findings:   make([]Finding, 0, len(rawFindings)),
		BlindSpots: make([]Blind, 0, len(rawBlinds)),
	}
	for k, v := range sum.Entities {
		r.Dashboard.EntitiesByKind[k] = v
	}
	for _, f := range rawFindings {
		r.Findings = append(r.Findings, Finding{
			Kind:       f.Kind,
			Severity:   f.Severity,
			Detail:     scrubMap(f.Detail),
			EntityKind: redact.ScrubString(f.EntityKind),
			EntityName: redact.ScrubString(f.EntityName),
			Identity:   redact.ScrubString(f.Identity),
		})
	}
	for _, b := range rawBlinds {
		r.BlindSpots = append(r.BlindSpots, Blind{
			Channel:    b.Channel,
			Reason:     b.Reason,
			Detail:     scrubMap(b.Detail),
			EntityKind: redact.ScrubString(b.EntityKind),
			EntityName: redact.ScrubString(b.EntityName),
		})
	}
	return r, nil
}

// scrubMap runs every value (and key) through the inline scrubber.
func scrubMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[redact.ScrubString(k)] = redact.ScrubString(v)
	}
	return out
}
