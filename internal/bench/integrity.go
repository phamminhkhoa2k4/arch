package bench

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"archaeologist/internal/store"
)

// IntegrityReport holds the data-integrity and runtime metrics that are
// published but not gated: evidence traceability, latest scan duration,
// and the observe-daemon overhead when a sampler log is available.
type IntegrityReport struct {
	// RawRefOK/RawRefTotal count evidence rows of the latest scan
	// whose raw_ref is non-empty (schema already enforces it — this
	// line proves the constraint survived).
	RawRefOK    int
	RawRefTotal int
	RawRefPct   float64
	// ScanSeconds is the wall time of the latest scan; nil when the
	// scan has no finished_at yet.
	ScanSeconds *int
	// Observe is the human-readable overhead summary, or the
	// "n/a" placeholder when no sampler log is provided.
	Observe string
}

// samplerLine matches the observe-sla sampler log format:
// "<ts> pid=… utime=… stime=… rss_kb=…".
var samplerLine = regexp.MustCompile(
	`pid=(\d+)\s+utime=(\d+)\s+stime=(\d+)\s+rss_kb=(\d+)`)

// clockTicks is the kernel USER_HZ used to convert utime/stime ticks
// into CPU seconds (POSIX default 100).
const clockTicks = 100.0

// MeasureIntegrity reads the three published-but-ungated metrics for
// the latest scan of dbPath. observeLog may be empty — the overhead
// then reports n/a instead of a fabricated number.
func MeasureIntegrity(dbPath, observeLog string) (*IntegrityReport, error) {
	ctx := context.Background()
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	defer func() { _ = st.Close() }()
	scanID, err := st.LatestScanID(ctx)
	if err != nil {
		return nil, fmt.Errorf("db: %w", err)
	}

	rep := &IntegrityReport{Observe: "n/a (cần observe-sla.log)"}
	if err := st.DB().QueryRowContext(ctx,
		`SELECT
		   count(*),
		   sum(CASE WHEN trim(e.raw_ref) <> '' THEN 1 ELSE 0 END)
		 FROM evidence e JOIN entities en ON en.id = e.entity_id
		 WHERE en.scan_id = ?`, scanID).
		Scan(&rep.RawRefTotal, &rep.RawRefOK); err != nil {
		return nil, fmt.Errorf("raw_ref metric: %w", err)
	}
	rep.RawRefPct = percent(rep.RawRefOK, rep.RawRefTotal)

	var started, finished *string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT started_at, finished_at FROM scans WHERE id = ?`, scanID).
		Scan(&started, &finished); err != nil {
		return nil, fmt.Errorf("scan duration: %w", err)
	}
	if started != nil && finished != nil {
		t0, err0 := time.Parse(time.RFC3339, *started)
		t1, err1 := time.Parse(time.RFC3339, *finished)
		if err0 == nil && err1 == nil {
			secs := int(t1.Sub(t0).Seconds())
			rep.ScanSeconds = &secs
		}
	}

	if observeLog != "" {
		summary, err := parseObserveLog(observeLog)
		if err != nil {
			rep.Observe = "n/a (không đọc được observe-sla.log)"
		} else {
			rep.Observe = summary
		}
	}
	return rep, nil
}

// parseObserveLog summarizes a sampler log: sample count, total CPU
// seconds (utime+stime tick delta over wall time at USER_HZ), and the
// maximum resident set size.
func parseObserveLog(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	samples := 0
	maxRSS := 0
	var firstTicks, lastTicks int64
	var firstTS, lastTS time.Time
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		m := samplerLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		utime, _ := strconv.ParseInt(m[2], 10, 64)
		stime, _ := strconv.ParseInt(m[3], 10, 64)
		rss, _ := strconv.Atoi(m[4])
		ticks := utime + stime
		if samples == 0 {
			firstTicks = ticks
			if ts, ok := parseSamplerTS(sc.Text()); ok {
				firstTS = ts
			}
		}
		lastTicks = ticks
		if ts, ok := parseSamplerTS(sc.Text()); ok {
			lastTS = ts
		}
		if rss > maxRSS {
			maxRSS = rss
		}
		samples++
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	if samples < 2 || lastTS.Before(firstTS) {
		return "n/a (cần ≥2 mẫu observe-sla.log)", nil
	}
	wall := lastTS.Sub(firstTS).Seconds()
	cpuPct := float64(lastTicks-firstTicks) / clockTicks / wall * 100.0
	return fmt.Sprintf("CPU %.2f%% · RAM tối đa %d KB (%d mẫu)", cpuPct, maxRSS, samples), nil
}

// parseSamplerTS extracts the leading "<YYYY-MM-DDTHH:MM:SSZ>" or bare
// RFC3339 token of a sampler line.
func parseSamplerTS(line string) (time.Time, bool) {
	field := strings.Fields(line)
	if len(field) == 0 {
		return time.Time{}, false
	}
	ts, err := time.Parse(time.RFC3339, strings.Trim(field[0], "[]<>"))
	return ts, err == nil
}

// Write prints the integrity section; every line is informational and
// never gates the run.
func (r *IntegrityReport) Write(out io.Writer) error {
	if _, err := fmt.Fprintf(out, "Evidence có raw_ref: %d/%d = %.1f%% (mục tiêu 100%%)\n",
		r.RawRefOK, r.RawRefTotal, r.RawRefPct); err != nil {
		return err
	}
	if r.RawRefPct < 100.0 {
		if _, err := fmt.Fprintf(out,
			"::warning title=benchmark::Evidence thiếu raw_ref — vi phạm truy vết\n"); err != nil {
			return err
		}
	}
	if r.ScanSeconds != nil {
		if _, err := fmt.Fprintf(out, "Thời gian scan gần nhất: %ds (informational)\n",
			*r.ScanSeconds); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintln(out, "Thời gian scan gần nhất: n/a (chưa có finished_at)"); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(out, "Overhead observe: %s\n", r.Observe); err != nil {
		return err
	}
	return nil
}
