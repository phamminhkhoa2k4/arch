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
	"sync"
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

	prefetchOnce sync.Once
	pre          prefetched
}

// prefetched is the read-only inventory gathered before Collect. All
// fields are written once by ensurePrefetch and read after it returns.
type prefetched struct {
	statuses   []systemd.UnitStatus
	statusErr  error
	journals   map[string]journalRead
	attempted  int
	blind      string
	journalErr error
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

// unitLoadWorkers bounds concurrent unit-file reads; the emit pass
// stays serial, so only the disk reads overlap.
const unitLoadWorkers = 8

// Prefetch gathers the unit inventory and journal facts while other
// collectors run. It never touches the sink.
func (c *Collector) Prefetch(ctx context.Context) { c.ensurePrefetch(ctx) }

// ensurePrefetch runs the read-only inventory exactly once. Collect
// calls it too, so a directly-driven collector (tests) still works.
func (c *Collector) ensurePrefetch(ctx context.Context) {
	c.prefetchOnce.Do(func() { c.pre = c.gather(ctx) })
}

func (c *Collector) gather(ctx context.Context) prefetched {
	var out prefetched
	sortByName := func(st []systemd.UnitStatus) {
		sort.Slice(st, func(i, j int) bool { return st[i].Name < st[j].Name })
	}

	if sb, ok := c.bus.(systemd.SplitBus); ok {
		loaded, err := sb.LoadedUnits()
		if err != nil {
			out.statusErr = err
			return out
		}
		sortByName(loaded)
		// Journal reads depend only on the loaded list, not on unit
		// files: overlap them with the slower ListUnitFiles call.
		active := activeUnitNames(loaded, c.journal != nil)
		done := make(chan prefetched, 1)
		go func() {
			j, a, b, e := c.readJournals(ctx, active)
			done <- prefetched{journals: j, attempted: a, blind: b, journalErr: e}
		}()
		files, ferr := sb.UnitFiles()
		jr := <-done
		out.journals, out.attempted, out.blind, out.journalErr =
			jr.journals, jr.attempted, jr.blind, jr.journalErr
		if ferr != nil {
			out.statusErr = ferr
			return out
		}
		out.statuses = systemd.MergeUnits(loaded, files)
		return out
	}

	statuses, err := c.bus.Units()
	if err != nil {
		out.statusErr = err
		return out
	}
	sortByName(statuses)
	out.statuses = statuses
	out.journals, out.attempted, out.blind, out.journalErr =
		c.readJournals(ctx, activeUnitNames(statuses, c.journal != nil))
	return out
}

// activeUnitNames lists units worth a journal read: active units whose
// name passes the journalctl argument guard.
func activeUnitNames(statuses []systemd.UnitStatus, hasJournal bool) []string {
	if !hasJournal {
		return nil
	}
	var out []string
	for _, st := range statuses {
		if st.ActiveState == "active" && systemd.ValidUnitName(st.Name) {
			out = append(out, st.Name)
		}
	}
	return out
}

type unitLoad struct {
	merged *systemd.Merged
	err    error
}

// execFactWorkers bounds concurrent target reads; hashing is CPU-bound,
// so a small pool avoids starving the emit loop on low-core hosts.
const execFactWorkers = 4

// execTargetsFromLoads parses every loaded unit once and returns the
// distinct ExecStart targets. Parse failures and unresolved names are
// skipped here: the emit pass re-parses and records their blind spots.
func execTargetsFromLoads(loads map[string]unitLoad) []string {
	seen := map[string]bool{}
	var out []string
	for name, lr := range loads {
		if lr.err != nil || lr.merged == nil {
			continue
		}
		m := lr.merged
		env := systemd.EnvMap(m.All("Environment"))
		spec := systemd.Specifiers(name)
		for _, d := range m.Get("ExecStart") {
			ex, err := systemd.ParseExec(d.Value, d.Line, d.File)
			if err != nil {
				continue
			}
			target, ok := systemd.Expand(ex.Path, env, spec)
			if !ok || target == "" || seen[target] {
				continue
			}
			seen[target] = true
			out = append(out, target)
		}
	}
	return out
}

// readExecFacts reads and fingerprints each target once. A target that
// cannot be read or classified stays out of the map so the emit pass
// can report the precise blind spot.
func (c *Collector) readExecFacts(ctx context.Context, targets []string) map[string]execFact {
	out := make(map[string]execFact, len(targets))
	if len(targets) == 0 {
		return out
	}
	workers := execFactWorkers
	if len(targets) < workers {
		workers = len(targets)
	}
	jobs := make(chan string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				if ctx.Err() != nil {
					return
				}
				content, err := c.loader.ReadFile(target)
				if err != nil {
					continue
				}
				kind, ok := systemd.Classify(content)
				if !ok {
					continue
				}
				fact := execFact{kind: kind, sha: sha256Hex(content)}
				mu.Lock()
				out[target] = fact
				mu.Unlock()
			}
		}()
	}
feed:
	for _, target := range targets {
		select {
		case jobs <- target:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	return out
}

// loadUnitFiles reads every unit file in a small worker pool. The
// result map is fully built before the caller emits, so sink writes
// stay in the existing order.
func (c *Collector) loadUnitFiles(statuses []systemd.UnitStatus) map[string]unitLoad {
	out := make(map[string]unitLoad, len(statuses))
	if len(statuses) == 0 {
		return out
	}
	workers := unitLoadWorkers
	if len(statuses) < workers {
		workers = len(statuses)
	}
	jobs := make(chan systemd.UnitStatus)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for st := range jobs {
				m, err := c.loader.Load(st.Name, st.FragmentPath)
				mu.Lock()
				out[st.Name] = unitLoad{merged: m, err: err}
				mu.Unlock()
			}
		}()
	}
	for _, st := range statuses {
		jobs <- st
	}
	close(jobs)
	wg.Wait()
	return out
}

func (c *Collector) Collect(ctx context.Context, sink collector.Sink) error {
	c.ensurePrefetch(ctx)
	pre := c.pre
	if pre.statusErr != nil {
		return fmt.Errorf("read units over D-Bus: %w", pre.statusErr)
	}
	if pre.journalErr != nil {
		return pre.journalErr
	}
	statuses := pre.statuses
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
	// Active units also consult the journal for last_log_at; the first
	// read failure yields one host-wide blind spot and the remaining
	// units are skipped instead of hammering a broken source.
	present := map[string]bool{}
	merged := map[string]*systemd.Merged{}
	journals, journalAttempted, journalBlindErr := pre.journals, pre.attempted, pre.blind

	// Unit files are independent reads: load them in a bounded pool so
	// the ordered emit pass below never waits on disk. Writes stay
	// serial in this goroutine.
	loads := c.loadUnitFiles(statuses)

	// ExecStart targets are independent files: read and hash them in
	// the background while pass 1 writes unit entities. Pass 2 joins
	// the result before emitting, so sink writes stay serial.
	execDone := make(chan map[string]execFact, 1)
	go func() {
		execDone <- c.readExecFacts(ctx, execTargetsFromLoads(loads))
	}()
	for _, st := range statuses {
		if err := ctx.Err(); err != nil {
			return err
		}
		key := "systemd_unit|" + st.Name
		present[st.Name] = true

		lr := loads[st.Name]
		m, loadErr := lr.merged, lr.err
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
		if jr, ok := journals[st.Name]; ok && jr.ok {
			journalTS, journalCursor = jr.ts, jr.cursor
			journalOK = true
			attrs["last_log_at"] = journalTS.Format(time.RFC3339)
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
	facts := <-execDone
	for _, st := range statuses {
		if err := ctx.Err(); err != nil {
			return err
		}
		m := merged[st.Name]
		if m == nil {
			continue
		}
		if err := c.emitExecs(sink, st.Name, m, emitEvidence, facts); err != nil {
			return err
		}
		if err := c.emitDeps(sink, st.Name, m, present, emitEvidence); err != nil {
			return err
		}
	}

	// Pass 3: ownership edges from the earlier process snapshot.
	return c.emitManages(sink, present, refs)
}

// execFact is the content-derived part of an ExecStart target: its kind
// and fingerprint. Several units commonly share one binary, and hashing
// a large executable is far more expensive than a map lookup.
type execFact struct {
	kind string
	sha  string
}

// emitExecs resolves every ExecStart into a script/binary entity and a
// runs_as edge; unresolvable cases become blind spots.
func (c *Collector) emitExecs(
	sink collector.Sink,
	unit string,
	m *systemd.Merged,
	emitEvidence func(string, collector.Evidence) error,
	facts map[string]execFact,
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
		// Args are expanded against the redacted environment so a
		// ${SECRET} reference never reaches the evidence row; the
		// path above keeps the real values for filesystem lookups.
		envDisplay := systemd.RedactEnvMap(env)
		resolvedOK := true
		for _, a := range ex.Args {
			ra, aOK := systemd.Expand(a, envDisplay, spec)
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

		fact, cached := facts[target]
		if !cached {
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
			fact = execFact{kind: kind, sha: sha256Hex(content)}
			facts[target] = fact
		}
		kind := fact.kind

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
			Fingerprint: fact.sha,
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
				"sha256": fact.sha,
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

// journalRead is one unit's newest journal entry.
type journalRead struct {
	ts     time.Time
	cursor string
	ok     bool
}

// journalWorkers bounds concurrent journalctl calls. journalctl is a
// short-lived process per unit, so a modest pool keeps the scan fast on
// hosts with hundreds of units without spawning them all at once.
const journalWorkers = 16

// readJournals queries the journal for every active unit. The first
// read is sequential so a broken journal still produces exactly one
// blind spot without hammering the source; the rest run in a bounded
// worker pool. Results are keyed by unit and emitted in status order
// by the caller, so the output stays deterministic.
func (c *Collector) readJournals(ctx context.Context, units []string) (map[string]journalRead, int, string, error) {
	out := make(map[string]journalRead, len(units))
	if c.journal == nil || len(units) == 0 {
		return out, 0, "", nil
	}
	ts, cursor, ok, err := c.journal.LastLine(ctx, units[0])
	attempted := 1
	if err != nil {
		if ctx.Err() != nil {
			return out, attempted, "", ctx.Err()
		}
		return out, attempted, err.Error(), nil
	}
	if ok {
		out[units[0]] = journalRead{ts: ts, cursor: cursor, ok: true}
	}
	rest := units[1:]
	if len(rest) == 0 {
		return out, attempted, "", nil
	}

	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan string)
	var mu sync.Mutex
	var firstErr error
	var wg sync.WaitGroup
	for i := 0; i < journalWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for unit := range jobs {
				ts, cursor, ok, err := c.journal.LastLine(workCtx, unit)
				mu.Lock()
				attempted++
				if err != nil {
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					cancel()
					return
				}
				if ok {
					out[unit] = journalRead{ts: ts, cursor: cursor, ok: true}
				}
				mu.Unlock()
			}
		}()
	}
feed:
	for _, unit := range rest {
		select {
		case jobs <- unit:
		case <-workCtx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		if ctx.Err() != nil {
			return out, attempted, "", ctx.Err()
		}
		return out, attempted, firstErr.Error(), nil
	}
	return out, attempted, "", nil
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}
