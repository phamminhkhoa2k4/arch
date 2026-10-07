// Package systemd implements the systemd collector: list units over
// D-Bus, resolve their ExecStart targets, build dependency edges, and
// attach processes (from the process collector's cgroup attributes) to
// their owning unit.
//
// Blind spots use channel "systemd": D-Bus unreachable, ExecStart that
// cannot be resolved (unknown env var or specifier), and ExecStart
// targets that cannot be read are reported, never guessed.
package systemd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"archaeologist/internal/collector"
	"archaeologist/internal/systemd"
)

// ProcessIndex supplies the process snapshot collected earlier in the
// scan (identity key + cgroup unit), so ownership edges never re-walk
// /proc. Implemented by the scan's sink.
type ProcessIndex interface {
	ProcessRowsByUnit() (map[string][]collector.ProcessRow, error)
}

// Collector reads units from the bus and unit files from disk.
type Collector struct {
	bus     systemd.Bus
	loader  *systemd.Loader
	index   ProcessIndex // nil skips manages edges (version-only use)
	journal systemd.Journal
}

// New returns the systemd collector. index may be nil only when the
// collector is used for name/version registration, not Collect.
// journal may be nil: journald activity is then skipped entirely.
func New(bus systemd.Bus, loader *systemd.Loader, index ProcessIndex, journal systemd.Journal) *Collector {
	return &Collector{bus: bus, loader: loader, index: index, journal: journal}
}

func (c *Collector) Name() string { return "systemd" }

func (c *Collector) Version() string { return "1.1.0" }

// depDirectives are the unit-file directives that build depends_on.
var depDirectives = []string{"Requires", "Wants", "After"}

func (c *Collector) Collect(ctx context.Context, sink collector.Sink) error {
	statuses, err := c.bus.Units()
	if err != nil {
		return fmt.Errorf("read units over D-Bus: %w", err)
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].Name < statuses[j].Name })

	refs := map[string]bool{}
	emitEvidence := func(ref string, e collector.Evidence) error {
		if refs[ref] {
			return nil
		}
		e.Ref = ref
		if err := sink.AddEvidence(e); err != nil {
			return err
		}
		refs[ref] = true
		return nil
	}

	// Pass 1: every unit becomes an entity with its state evidence.
	// Active units also consult the journal for last_log_at (US-6.2);
	// the first read failure yields one host-wide blind spot and the
	// remaining units are skipped instead of hammering a broken source.
	present := map[string]bool{}
	merged := map[string]*systemd.Merged{}
	journalBlindErr := ""
	journalAttempted := 0
	for _, st := range statuses {
		if err := ctx.Err(); err != nil {
			return err
		}
		key := "systemd_unit|" + st.Name
		present[st.Name] = true

		m, loadErr := c.loader.Load(st.Name, st.FragmentPath)
		switch {
		case loadErr == nil:
			merged[st.Name] = m
		case systemd.IsNotFound(loadErr):
			// Transient units legitimately have no unit file.
		default:
			if bErr := sink.AddBlindSpot(collector.BlindSpot{
				EntityIdentityKey: key,
				Channel:           "systemd",
				Reason:            "unit_file_unreadable",
				Detail:            map[string]string{"unit": st.Name, "error": loadErr.Error()},
			}); bErr != nil {
				return bErr
			}
		}

		fingerprint := sha256Hex([]byte(st.Name))
		if m != nil {
			fingerprint = m.Fingerprint()
		}
		attrs := map[string]string{}
		for k, v := range map[string]string{
			"active_state": st.ActiveState,
			"sub_state":    st.SubState,
			"load_state":   st.LoadState,
		} {
			if v != "" {
				attrs[k] = v
			}
		}
		if st.Description != "" {
			attrs["description"] = st.Description
		}
		if st.UnitFileState != "" {
			attrs["unit_file_state"] = st.UnitFileState
		}
		if st.ActiveEnterTimestamp > 0 {
			attrs["active_enter_timestamp"] = strconv.FormatUint(st.ActiveEnterTimestamp, 10)
		}
		if st.FragmentPath != "" {
			attrs["fragment_path"] = st.FragmentPath
		}
		var journalTS time.Time
		var journalCursor string
		journalOK := false
		// Dash-prefixed names ("-.mount", the root mount) are valid
		// units but fail the unit-name guard; skipping them keeps one
		// odd unit from aborting every journal read on the host.
		if c.journal != nil && st.ActiveState == "active" && journalBlindErr == "" &&
			systemd.ValidUnitName(st.Name) {
			journalAttempted++
			ts, cursor, ok, jErr := c.journal.LastLine(ctx, st.Name)
			switch {
			case jErr != nil:
				if ctx.Err() != nil {
					return ctx.Err()
				}
				journalBlindErr = jErr.Error()
			case ok:
				journalOK = true
				journalTS, journalCursor = ts, cursor
				attrs["last_log_at"] = ts.Format(time.RFC3339)
			}
		}
		polarity := collector.PolarityNeutral
		if st.ActiveState == "active" {
			polarity = collector.PolarityInUse
		}
		if err := sink.UpsertEntity(collector.Entity{
			Kind:        "systemd_unit",
			Name:        st.Name,
			IdentityKey: key,
			Fingerprint: fingerprint,
			Attributes:  attrs,
		}); err != nil {
			return err
		}
		// Provenance: runtime facts come from list-units, file-only
		// units (never loaded this scan) from list-unit-files.
		rawRef := "dbus:org.freedesktop.systemd1.Manager.ListUnitFiles"
		if st.Loaded {
			rawRef = "dbus:org.freedesktop.systemd1.Manager.ListUnits"
		}
		value := map[string]string{"file_state": st.UnitFileState}
		if st.Loaded {
			value["active_state"] = st.ActiveState
			value["sub_state"] = st.SubState
		}
		if err := emitEvidence("unit-state:"+st.Name, collector.Evidence{
			EntityIdentityKey: key,
			Polarity:          polarity,
			Channel:           "systemd",
			Strength:          collector.StrengthDeterministic,
			ObservedAt:        nowRFC3339(),
			RawRef:            rawRef,
			Value:             value,
		}); err != nil {
			return err
		}
		if journalOK {
			if err := emitEvidence("unit-journal:"+st.Name, collector.Evidence{
				EntityIdentityKey: key,
				Polarity:          collector.PolarityInUse,
				Channel:           "journald",
				Strength:          collector.StrengthDeterministic,
				ObservedAt:        nowRFC3339(),
				RawRef:            "journalctl -u " + st.Name + " -n 1",
				Value: map[string]string{
					"last_log_at": journalTS.Format(time.RFC3339),
					"cursor":      journalCursor,
				},
			}); err != nil {
				return err
			}
		}
	}
	if journalBlindErr != "" {
		if err := sink.AddBlindSpot(collector.BlindSpot{
			Channel: "journald",
			Reason:  "journald_unreadable",
			Detail: map[string]string{
				"error":           journalBlindErr,
				"units_attempted": strconv.Itoa(journalAttempted),
			},
		}); err != nil {
			return err
		}
	}

	// Pass 2: file-derived facts — ExecStart targets and dependencies.
	for _, st := range statuses {
		if err := ctx.Err(); err != nil {
			return err
		}
		m := merged[st.Name]
		if m == nil {
			continue
		}
		if err := c.emitExecs(sink, st.Name, m, emitEvidence); err != nil {
			return err
		}
		if err := c.emitDeps(sink, st.Name, m, present, emitEvidence); err != nil {
			return err
		}
	}

	// Pass 3: ownership edges from the earlier process snapshot.
	return c.emitManages(sink, present, refs)
}

// emitExecs resolves every ExecStart into a script/binary entity and a
// runs_as edge; unresolvable cases become blind spots.
func (c *Collector) emitExecs(
	sink collector.Sink,
	unit string,
	m *systemd.Merged,
	emitEvidence func(string, collector.Evidence) error,
) error {
	key := "systemd_unit|" + unit
	env := systemd.EnvMap(m.All("Environment"))
	spec := systemd.Specifiers(unit)
	wd, wdOK := workingDirectory(m, env, spec)

	for _, d := range m.Get("ExecStart") {
		blind := func(reason string, detail map[string]string) error {
			if detail == nil {
				detail = map[string]string{}
			}
			detail["unit"] = unit
			detail["line"] = strconv.Itoa(d.Line)
			return sink.AddBlindSpot(collector.BlindSpot{
				EntityIdentityKey: key,
				Channel:           "systemd",
				Reason:            reason,
				Detail:            detail,
			})
		}

		ex, err := systemd.ParseExec(d.Value, d.Line, d.File)
		if err != nil {
			if bErr := blind("exec_start_parse", map[string]string{"error": err.Error()}); bErr != nil {
				return bErr
			}
			continue
		}
		target, ok := systemd.Expand(ex.Path, env, spec)
		if !ok {
			if bErr := blind("exec_start_unresolved", map[string]string{"value": ex.Path}); bErr != nil {
				return bErr
			}
			continue
		}
		if !systemd.IsAbs(target) {
			if !wdOK || wd == "" {
				if bErr := blind("exec_start_relative", map[string]string{"value": target}); bErr != nil {
					return bErr
				}
				continue
			}
			target = systemd.JoinPath(wd, target)
		}
		fullArgs := make([]string, 0, len(ex.Args)+1)
		resolvedOK := true
		for _, a := range ex.Args {
			ra, aOK := systemd.Expand(a, env, spec)
			if !aOK {
				if bErr := blind("exec_start_unresolved", map[string]string{"value": a}); bErr != nil {
					return bErr
				}
				resolvedOK = false
				break
			}
			fullArgs = append(fullArgs, ra)
		}
		if !resolvedOK {
			continue
		}

		content, err := c.loader.ReadFile(target)
		if err != nil {
			reason := "exec_start_unreadable"
			if errors.Is(err, os.ErrNotExist) {
				reason = "exec_start_not_found"
			}
			if bErr := blind(reason, map[string]string{"path": target, "error": err.Error()}); bErr != nil {
				return bErr
			}
			continue
		}
		kind, kindOK := systemd.Classify(content)
		if !kindOK {
			if bErr := blind("exec_start_unknown_kind", map[string]string{"path": target}); bErr != nil {
				return bErr
			}
			continue
		}

		execRef := fmt.Sprintf("unit-exec:%s:%d", unit, d.Line)
		if err := emitEvidence(execRef, collector.Evidence{
			EntityIdentityKey: key,
			Polarity:          collector.PolarityNeutral,
			Channel:           "systemd",
			Strength:          collector.StrengthDeterministic,
			ObservedAt:        nowRFC3339(),
			RawRef:            fmt.Sprintf("%s:%d", d.File, d.Line),
			Value: map[string]string{
				"exec": strings.Join(append([]string{target}, fullArgs...), " "),
			},
		}); err != nil {
			return err
		}

		scriptKey := kind + "|" + target
		if err := sink.UpsertEntity(collector.Entity{
			Kind:        kind,
			Name:        target,
			IdentityKey: scriptKey,
			Fingerprint: sha256Hex(content),
			Attributes: map[string]string{
				"path": target,
				"unit": unit,
			},
		}); err != nil {
			return err
		}
		if err := emitEvidence(fmt.Sprintf("unit-target:%s:%d", unit, d.Line), collector.Evidence{
			EntityIdentityKey: scriptKey,
			Polarity:          collector.PolarityNeutral,
			Channel:           "systemd",
			Strength:          collector.StrengthDeterministic,
			ObservedAt:        nowRFC3339(),
			RawRef:            target,
			Value: map[string]string{
				"kind":   kind,
				"sha256": sha256Hex(content),
				"unit":   unit,
			},
		}); err != nil {
			return err
		}
		if err := sink.UpsertEdge(collector.Edge{
			SrcIdentityKey: key,
			DstIdentityKey: scriptKey,
			Kind:           "runs_as",
			Strength:       collector.StrengthDeterministic,
			EvidenceRef:    execRef,
		}); err != nil {
			return err
		}
	}
	return nil
}

// emitDeps builds depends_on edges for existing targets and a
// DANGLING_DEPENDS finding for declared-but-missing ones.
func (c *Collector) emitDeps(
	sink collector.Sink,
	unit string,
	m *systemd.Merged,
	present map[string]bool,
	emitEvidence func(string, collector.Evidence) error,
) error {
	key := "systemd_unit|" + unit
	found := map[string]bool{}
	for _, dir := range depDirectives {
		for _, d := range m.All(dir) {
			for _, raw := range strings.Fields(d.Value) {
				target := normalizeUnitName(raw)
				if target == "" || target == "-" || target == unit {
					continue
				}
				ref := fmt.Sprintf("unit-dep:%s:%d:%s", unit, d.Line, dir)
				if err := emitEvidence(ref, collector.Evidence{
					EntityIdentityKey: key,
					Polarity:          collector.PolarityNeutral,
					Channel:           "systemd",
					Strength:          collector.StrengthDeterministic,
					ObservedAt:        nowRFC3339(),
					RawRef:            fmt.Sprintf("%s:%d", d.File, d.Line),
					Value:             map[string]string{"directive": dir, "target": target},
				}); err != nil {
					return err
				}
				if present[target] {
					if err := sink.UpsertEdge(collector.Edge{
						SrcIdentityKey: key,
						DstIdentityKey: "systemd_unit|" + target,
						Kind:           "depends_on",
						Strength:       collector.StrengthDeterministic,
						EvidenceRef:    ref,
					}); err != nil {
						return err
					}
					continue
				}
				fk := unit + "|" + target
				if found[fk] {
					continue
				}
				found[fk] = true
				if err := sink.AddFinding(collector.Finding{
					EntityIdentityKey: key,
					Kind:              "DANGLING_DEPENDS",
					Severity:          "warn",
					Detail: map[string]string{
						"directive": dir,
						"missing":   target,
						"file":      d.File,
						"line":      strconv.Itoa(d.Line),
					},
					EvidenceRef: ref,
				}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// emitManages links each unit to the processes whose cgroup names it.
func (c *Collector) emitManages(
	sink collector.Sink,
	present map[string]bool,
	refs map[string]bool,
) error {
	if c.index == nil {
		return nil
	}
	byUnit, err := c.index.ProcessRowsByUnit()
	if err != nil {
		return fmt.Errorf("process snapshot: %w", err)
	}
	names := make([]string, 0, len(byUnit))
	for n := range byUnit {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, unit := range names {
		if !present[unit] {
			// The cgroup names a unit this scan did not list — do not
			// attach processes to a unit we cannot verify.
			continue
		}
		if !refs["unit-state:"+unit] {
			continue // state evidence missing — edge must stay traceable
		}
		for _, row := range byUnit[unit] {
			if err := sink.UpsertEdge(collector.Edge{
				SrcIdentityKey: "systemd_unit|" + unit,
				DstIdentityKey: row.IdentityKey,
				Kind:           "manages",
				Strength:       collector.StrengthDeterministic,
				EvidenceRef:    "unit-state:" + unit,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// workingDirectory resolves the unit's WorkingDirectory directive.
func workingDirectory(m *systemd.Merged, env, spec map[string]string) (string, bool) {
	ds := m.Get("WorkingDirectory")
	if len(ds) == 0 {
		return "", false
	}
	v := ds[len(ds)-1].Value
	v = strings.TrimLeft(v, "-+:!")
	expanded, ok := systemd.Expand(v, env, spec)
	if !ok || !systemd.IsAbs(expanded) {
		return "", false
	}
	return expanded, true
}

// normalizeUnitName applies systemd's default suffix: a dependency
// without a dot is a .service unit.
func normalizeUnitName(name string) string {
	if name == "" || strings.ContainsRune(name, '.') {
		return name
	}
	return name + ".service"
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}
