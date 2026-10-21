// Package cron collects the crontab and systemd timer inventory:
// cron_job and timer entities with their schedules, references to
// scripts, units and containers, scheduled_by edges from units to
// their timers, ORPHAN_CRON findings for jobs whose script is gone,
// and channel "cron" blind spots for anything static analysis refuses
// to guess.
package cron

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"sync"
	"time"

	"archaeologist/internal/collector"
	"archaeologist/internal/cron"
	"archaeologist/internal/systemd"
)

// Index supplies snapshots gathered by earlier collectors; nil skips
// the unit and container edges that depend on them (decision: absence
// cannot be asserted without the snapshot).
type Index interface {
	ContainerRows() ([]collector.ContainerRow, error)
	UnitRows() ([]collector.UnitRow, error)
}

// Collector turns crontab sources and timer units into entities,
// edges, findings and blind spots.
type Collector struct {
	loader   *cron.Loader
	fsys     systemd.FS // script content and timer files
	timerDir string
	index    Index
	seen     map[string]bool // evidence refs emitted this run
	lastRun  LastRun         // nil: no journal/systemd probing
	cronRuns map[string]time.Time
	probed   bool

	prefetchOnce sync.Once
}

// New creates the cron collector. fsys may be nil (reads the real
// filesystem); index may be nil (no unit/container edges, everything
// else still collected).
func New(fsys systemd.FS, index Index) *Collector {
	if fsys == nil {
		fsys = systemd.OSFS{}
	}
	return &Collector{
		loader:   cron.NewLoaderFS(fsys),
		fsys:     fsys,
		timerDir: cron.TimerDir,
		index:    index,
	}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return "cron" }

// SetLastRun enables journal/systemd probing of when each job last
// ran; without it the schedule entities carry no last_run_at attribute.
func (c *Collector) SetLastRun(lr LastRun) { c.lastRun = lr }

// Version implements collector.Collector.
func (c *Collector) Version() string { return "1.0.0" }

// Prefetch warms the cron journal while earlier collectors run. The
// read is external only; Collect still emits in its own order.
func (c *Collector) Prefetch(ctx context.Context) {
	c.prefetchOnce.Do(func() { c.loadCronRuns(ctx) })
}

// loadCronRuns reads the cron journal once per scan; an unreadable
// journal leaves probed=false so last_run_at is absent, never guessed.
func (c *Collector) loadCronRuns(ctx context.Context) {
	c.cronRuns, c.probed = nil, false
	if c.lastRun == nil {
		return
	}
	if runs, err := c.lastRun.CronRuns(ctx); err == nil {
		c.cronRuns, c.probed = runs, true
	}
}

// Collect reads every crontab source once, then every timer unit,
// and writes the corresponding entities and their references.
func (c *Collector) Collect(ctx context.Context, sink collector.Sink) error {
	now := time.Now()
	c.seen = map[string]bool{}

	// One journal read per scan feeds every job's last_run_at.
	c.prefetchOnce.Do(func() { c.loadCronRuns(ctx) })

	cfg := c.loader.Load()
	for _, fe := range cfg.Errors {
		if err := sink.AddBlindSpot(collector.BlindSpot{
			Channel: "cron",
			Reason:  "cron_source_unreadable",
			Detail:  map[string]string{"file": fe.File, "error": fe.Err.Error()},
		}); err != nil {
			return err
		}
	}

	units, containers, err := c.indexRows()
	if err != nil {
		return err
	}

	for i := range cfg.Jobs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.collectJob(sink, &cfg.Jobs[i], now, units, containers); err != nil {
			return err
		}
	}

	timers, terrs := cron.LoadTimers(c.fsys, c.timerDir)
	for _, te := range terrs {
		if err := sink.AddBlindSpot(collector.BlindSpot{
			Channel: "cron",
			Reason:  "cron_source_unreadable",
			Detail:  map[string]string{"file": te.File, "error": te.Err.Error()},
		}); err != nil {
			return err
		}
	}
	for i := range timers {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.collectTimer(ctx, sink, &timers[i], now, units); err != nil {
			return err
		}
	}
	return nil
}

// emit adds evidence once per ref: repeated identical crontab lines
// (or the same script referenced twice by one command) share a fact.
func (c *Collector) emit(sink collector.Sink, ev collector.Evidence) error {
	if c.seen[ev.Ref] {
		return nil
	}
	if err := sink.AddEvidence(ev); err != nil {
		return err
	}
	c.seen[ev.Ref] = true
	return nil
}

// indexRows resolves the snapshot rows; a nil index means no rows.
func (c *Collector) indexRows() ([]collector.UnitRow, []collector.ContainerRow, error) {
	if c.index == nil {
		return nil, nil, nil
	}
	units, err := c.index.UnitRows()
	if err != nil {
		return nil, nil, fmt.Errorf("unit snapshot: %w", err)
	}
	containers, err := c.index.ContainerRows()
	if err != nil {
		return nil, nil, fmt.Errorf("container snapshot: %w", err)
	}
	return units, containers, nil
}

// collectJob writes one cron job: entity, evidence, schedule blind
// spot (when unparsable) and every reference its command makes.
func (c *Collector) collectJob(
	sink collector.Sink,
	job *cron.Job,
	now time.Time,
	units []collector.UnitRow,
	containers []collector.ContainerRow,
) error {
	key := job.Key()
	attrs := map[string]string{
		"file":     job.File,
		"line":     strconv.Itoa(job.Line),
		"user":     job.User,
		"command":  job.Command,
		"schedule": job.Schedule,
	}
	sched := cron.ParseSched(job.Schedule, now)
	if sched.Valid {
		applySchedule(attrs, sched)
	}
	if c.probed {
		// Empty means the probe ran and saw no run in the journal —
		// distinct from "not probed", where the key stays absent.
		attrs["last_run_at"] = ""
		if t, ok := c.cronRuns[job.Command]; ok {
			attrs["last_run_at"] = t.UTC().Format(time.RFC3339)
		}
	}
	if err := sink.UpsertEntity(collector.Entity{
		Kind:        "cron_job",
		Name:        job.Command,
		IdentityKey: key,
		Fingerprint: job.Fingerprint(),
		Attributes:  attrs,
	}); err != nil {
		return err
	}

	jobRef := "cron-job:" + key
	if err := c.emit(sink, collector.Evidence{
		EntityIdentityKey: key,
		Polarity:          collector.PolarityNeutral,
		Channel:           "cron",
		Strength:          collector.StrengthDeterministic,
		ObservedAt:        now.UTC().Format(time.RFC3339),
		RawRef:            fmt.Sprintf("%s:%d", job.File, job.Line),
		Ref:               jobRef,
		Value: map[string]string{
			"file":     job.File,
			"line":     strconv.Itoa(job.Line),
			"user":     job.User,
			"schedule": job.Schedule,
			"command":  job.Command,
		},
	}); err != nil {
		return err
	}
	if !sched.Valid {
		// The schedule exists but the scanner's grammar does not cover
		// it: report the gap instead of emitting empty cadence attrs.
		if err := sink.AddBlindSpot(collector.BlindSpot{
			EntityIdentityKey: key,
			Channel:           "cron",
			Reason:            "cron_schedule_unparsed",
			Detail: map[string]string{
				"schedule": job.Schedule,
				"file":     job.File,
				"line":     strconv.Itoa(job.Line),
			},
		}); err != nil {
			return err
		}
	}

	refs := cron.CommandRefs(job.Command, job.Line)
	return c.traceRefs(sink, jobRef, key, job.File, refs, units, containers)
}

// traceRefs classifies every reference of one command position:
// paths become script entities (or ORPHAN_CRON when gone), systemctl
// units and bare commands become edges against the snapshots, and
// unresolved variables become blind spots. src is always the owning
// cron job.
func (c *Collector) traceRefs(
	sink collector.Sink,
	srcRef, srcKey, srcFile string,
	refs []cron.Ref,
	units []collector.UnitRow,
	containers []collector.ContainerRow,
) error {
	for _, r := range refs {
		switch r.Kind {
		case cron.RefEnv:
			// A variable decides the target — reported, never guessed.
			if err := sink.AddBlindSpot(collector.BlindSpot{
				EntityIdentityKey: srcKey,
				Channel:           "cron",
				Reason:            "cron_env_unresolved",
				Detail: map[string]string{
					"variable": r.Value,
					"file":     srcFile,
					"line":     strconv.Itoa(r.Line),
				},
			}); err != nil {
				return err
			}

		case cron.RefPath:
			if err := c.tracePath(sink, srcRef, srcKey, srcFile, r, units, containers); err != nil {
				return err
			}

		case cron.RefUnit:
			if c.index == nil {
				continue // no snapshot: nothing to match against
			}
			dst := matchUnit(r.Value, units)
			if dst == "" {
				continue // unit outside this scan's inventory
			}
			if err := sink.UpsertEdge(collector.Edge{
				SrcIdentityKey: srcKey,
				DstIdentityKey: dst,
				Kind:           "references",
				Strength:       collector.StrengthDeterministic,
				EvidenceRef:    srcRef,
			}); err != nil {
				return err
			}

		case cron.RefCommand:
			if c.index == nil {
				continue
			}
			dst := matchContainer(r.Value, containers)
			if dst == "" {
				continue
			}
			if err := sink.UpsertEdge(collector.Edge{
				SrcIdentityKey: srcKey,
				DstIdentityKey: dst,
				Kind:           "references",
				Strength:       collector.StrengthStrongHeuristic,
				EvidenceRef:    srcRef,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// tracePath handles one absolute-path reference: missing → ORPHAN_CRON,
// unreadable → blind spot, readable → script entity + references edge
// + one level of nested tracing.
func (c *Collector) tracePath(
	sink collector.Sink,
	srcRef, srcKey, srcFile string,
	r cron.Ref,
	units []collector.UnitRow,
	containers []collector.ContainerRow,
) error {
	content, err := c.fsys.ReadFile(r.Value)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// The schedule still parses (an ORPHAN_CRON is about the
			// target, not the entry): only the script is gone.
			return sink.AddFinding(collector.Finding{
				EntityIdentityKey: srcKey,
				Kind:              "ORPHAN_CRON",
				Severity:          "warn",
				Detail: map[string]string{
					"path":   r.Value,
					"file":   srcFile,
					"line":   strconv.Itoa(r.Line),
					"reason": "script missing at scan time",
				},
				EvidenceRef: srcRef,
			})
		}
		return sink.AddBlindSpot(collector.BlindSpot{
			EntityIdentityKey: srcKey,
			Channel:           "cron",
			Reason:            "cron_script_unreadable",
			Detail: map[string]string{
				"path":  r.Value,
				"error": err.Error(),
				"file":  srcFile,
				"line":  strconv.Itoa(r.Line),
			},
		})
	}

	nested, analyzable := cron.ScriptRefs(content)
	scriptKey := "script|" + r.Value
	if err := sink.UpsertEntity(collector.Entity{
		Kind:        "script",
		Name:        r.Value,
		IdentityKey: scriptKey,
		Fingerprint: sha256Hex(content),
		Attributes: map[string]string{
			"path":       r.Value,
			"analyzable": strconv.FormatBool(analyzable),
		},
	}); err != nil {
		return err
	}
	if err := c.emit(sink, collector.Evidence{
		EntityIdentityKey: scriptKey,
		Polarity:          collector.PolarityNeutral,
		Channel:           "cron",
		Strength:          collector.StrengthDeterministic,
		ObservedAt:        time.Now().UTC().Format(time.RFC3339),
		RawRef:            r.Value,
		Ref:               "cron-script:" + srcKey + ":" + r.Value,
		Value: map[string]string{
			"cron_file": srcFile,
			"cron_line": strconv.Itoa(r.Line),
			"sha256":    sha256Hex(content),
		},
	}); err != nil {
		return err
	}
	if err := sink.UpsertEdge(collector.Edge{
		SrcIdentityKey: srcKey,
		DstIdentityKey: scriptKey,
		Kind:           "references",
		Strength:       collector.StrengthDeterministic,
		EvidenceRef:    srcRef,
	}); err != nil {
		return err
	}
	if !analyzable {
		return sink.AddBlindSpot(collector.BlindSpot{
			EntityIdentityKey: scriptKey,
			Channel:           "cron",
			Reason:            "cron_script_unanalyzable",
			Detail:            map[string]string{"path": r.Value},
		})
	}

	// One level deep: the script body's own references, still traced
	// back to the owning cron job.
	for _, n := range nested {
		traceRef := fmt.Sprintf("cron-script:%s:%s:%d", srcKey, r.Value, n.Line)
		if n.Kind == cron.RefPath || n.Kind == cron.RefUnit || n.Kind == cron.RefCommand {
			// The fact lives on the script line; the evidence subject
			// stays the cron job that reaches it through that line.
			if err := c.emit(sink, collector.Evidence{
				EntityIdentityKey: srcKey,
				Polarity:          collector.PolarityNeutral,
				Channel:           "cron",
				Strength:          collector.StrengthDeterministic,
				ObservedAt:        time.Now().UTC().Format(time.RFC3339),
				RawRef:            fmt.Sprintf("%s:%d", r.Value, n.Line),
				Ref:               traceRef,
				Value: map[string]string{
					"ref_kind":  n.Kind,
					"ref_value": n.Value,
					"script":    r.Value,
				},
			}); err != nil {
				return err
			}
		}
		if err := c.traceRefs(sink, traceRef, srcKey, r.Value, []cron.Ref{n}, units, containers); err != nil {
			return err
		}
	}
	return nil
}

// collectTimer writes one timer entity, its schedule evidence and the
// scheduled_by edge from its target unit.
func (c *Collector) collectTimer(
	ctx context.Context,
	sink collector.Sink,
	t *cron.Timer,
	now time.Time,
	units []collector.UnitRow,
) error {
	key := t.Key()
	attrs := map[string]string{
		"file": t.File,
		"line": strconv.Itoa(t.Line),
	}
	if t.OnCalendar != "" {
		attrs["on_calendar"] = t.OnCalendar
	}
	if t.Unit != "" {
		attrs["unit"] = t.Unit
	}
	if c.lastRun != nil {
		attrs["last_run_at"] = ""
		if ts, ok, err := c.lastRun.TimerTrigger(ctx, t.Name); err == nil && ok {
			attrs["last_run_at"] = ts.UTC().Format(time.RFC3339)
		}
	}
	calendarOK := false
	if t.OnCalendar != "" {
		sched, err := cron.ParseOnCalendar(t.OnCalendar, now)
		if err == nil {
			applySchedule(attrs, sched)
			calendarOK = true
		}
	}
	if err := sink.UpsertEntity(collector.Entity{
		Kind:        "timer",
		Name:        t.Name,
		IdentityKey: key,
		Fingerprint: t.FingerprintOf(),
		Attributes:  attrs,
	}); err != nil {
		return err
	}
	timerRef := "timer:" + t.Name
	if err := c.emit(sink, collector.Evidence{
		EntityIdentityKey: key,
		Polarity:          collector.PolarityNeutral,
		Channel:           "cron",
		Strength:          collector.StrengthDeterministic,
		ObservedAt:        now.UTC().Format(time.RFC3339),
		RawRef:            t.RawRef(),
		Ref:               timerRef,
		Value: map[string]string{
			"file":        t.File,
			"unit":        t.Unit,
			"on_calendar": t.OnCalendar,
		},
	}); err != nil {
		return err
	}
	if !calendarOK {
		// Missing OnCalendar, or an expression outside the supported
		// subset: the cadence is a blind spot, never an empty guess.
		if err := sink.AddBlindSpot(collector.BlindSpot{
			EntityIdentityKey: key,
			Channel:           "cron",
			Reason:            "timer_calendar_unparsed",
			Detail: map[string]string{
				"timer":       t.Name,
				"file":        t.File,
				"on_calendar": t.OnCalendar,
			},
		}); err != nil {
			return err
		}
	}
	if t.Unit == "" || c.index == nil {
		return nil
	}
	dst := matchUnit(t.Unit, units)
	if dst == "" {
		return nil
	}
	return sink.UpsertEdge(collector.Edge{
		SrcIdentityKey: dst,
		DstIdentityKey: key,
		Kind:           "scheduled_by",
		Strength:       collector.StrengthDeterministic,
		EvidenceRef:    timerRef,
	})
}

// applySchedule copies the parsed cadence onto entity attributes.
func applySchedule(attrs map[string]string, s cron.Sched) {
	if s.PeriodDays > 0 {
		attrs["period_days"] = cron.FormatPeriod(s.PeriodDays)
		attrs["window_14d_sufficient"] = strconv.FormatBool(s.Sufficient())
	}
	if !s.Next.IsZero() {
		attrs["next_run_at"] = s.Next.Format(time.RFC3339)
	}
}

// matchUnit resolves a systemctl target against the unit snapshot.
func matchUnit(name string, rows []collector.UnitRow) string {
	if !strings.ContainsRune(name, '.') {
		name += ".service"
	}
	for _, r := range rows {
		if r.Name == name {
			return r.IdentityKey
		}
	}
	return ""
}

// containerAliases map command families onto the image base names
// their containers report.
var containerAliases = map[string]string{
	"redis-cli":    "redis",
	"redis-server": "redis",
	"psql":         "postgres",
	"pg_dump":      "postgres",
	"pg_restore":   "postgres",
	"mysql":        "mysql",
	"mysqldump":    "mysql",
	"mongo":        "mongodb",
	"mongodump":    "mongodb",
}

// matchContainer resolves a bare command against the container
// snapshot through a small alias table or the image base name. The
// match is a strong heuristic, never deterministic: same image name
// does not prove same process.
func matchContainer(cmd string, rows []collector.ContainerRow) string {
	candidates := map[string]bool{cmd: true}
	if i := strings.IndexByte(cmd, '-'); i > 0 {
		candidates[cmd[:i]] = true
	}
	if alias, ok := containerAliases[cmd]; ok {
		candidates[alias] = true
	}
	for _, r := range rows {
		if candidates[r.Name] || candidates[imageBase(r.Image)] {
			return r.IdentityKey
		}
	}
	return ""
}

// imageBase strips registry, tag and digest from an image reference.
func imageBase(image string) string {
	if i := strings.IndexByte(image, '@'); i >= 0 {
		image = image[:i]
	}
	if i := strings.LastIndexByte(image, '/'); i >= 0 {
		image = image[i+1:]
	}
	if i := strings.IndexByte(image, ':'); i >= 0 {
		image = image[:i]
	}
	return image
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// compile-time interface check
var _ collector.Collector = (*Collector)(nil)
