// Package accesslog collects nginx access-log activity: per-route
// in_use evidence with last_request_at, retention blindness for short
// log windows, and parse-failure blindness for custom log formats.
//
// Blind spots use channel "log": unparsable lines and retention of at
// most seven days are reported, never guessed over.
package accesslog

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"archaeologist/internal/accesslog"
	"archaeologist/internal/collector"
	"archaeologist/internal/nginx"
)

// Collector turns access-log traffic into route evidence.
type Collector struct {
	loader *nginx.Loader
	fsys   accesslog.FS
	root   string // configuration entry point, normally nginx.DefaultRoot
}

// New returns the access-log collector. loader/fs may be nil (real
// defaults).
func New(loader *nginx.Loader, fsys accesslog.FS) *Collector {
	if loader == nil {
		loader = nginx.NewLoader()
	}
	if fsys == nil {
		fsys = accesslog.OSFS{}
	}
	return &Collector{loader: loader, fsys: fsys, root: nginx.DefaultRoot}
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return "accesslog" }

// Version implements collector.Collector.
func (c *Collector) Version() string { return "1.0.0" }

// agg accumulates one route's traffic across the configured logs.
type agg struct {
	latest  time.Time
	rawRef  string
	logPath string
	count   int
}

// Collect loads the nginx configuration, parses every declared access
// log (falling back to the nginx default path) and attaches in_use
// evidence to the routes those logs cover. Route entities are expected
// to exist already: the nginx collector runs earlier in the scan.
func (c *Collector) Collect(ctx context.Context, sink collector.Sink) error {
	cfg, err := c.loader.Load(c.root)
	if err != nil {
		return fmt.Errorf("load nginx config: %w", err)
	}
	paths := logPaths(cfg)
	if len(paths) == 0 {
		paths = []string{accesslog.DefaultPath}
	}

	matched := map[string]*agg{}
	blindKeys := map[string]bool{}
	retentions := map[string]retentionBlind{}

	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return err
		}
		res, err := accesslog.ParseFile(c.fsys, path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			// nginx has not written anything yet: an observable fact,
			// not blindness.
			continue
		case err != nil:
			return fmt.Errorf("read access log %s: %w", path, err)
		}

		for _, e := range res.Entries {
			for _, r := range matchRoutes(cfg.Routes, e.URI) {
				k := r.Key()
				a := matched[k]
				if a == nil {
					a = &agg{}
					matched[k] = a
				}
				a.count++
				if a.latest.IsZero() || e.Time.After(a.latest) {
					a.latest = e.Time
					a.rawRef = fmt.Sprintf("%s:%d", path, e.Line)
					a.logPath = path
				}
			}
		}

		if res.Unparsed > 0 {
			reason := "log_parse_error"
			if res.Unparsed == res.Total {
				reason = "log_format_unparseable"
			}
			key := path + "|" + reason
			if !blindKeys[key] {
				blindKeys[key] = true
				if err := sink.AddBlindSpot(collector.BlindSpot{
					Channel: "log",
					Reason:  reason,
					Detail: map[string]string{
						"log_path": path,
						"unparsed": fmt.Sprintf("%d", res.Unparsed),
						"total":    fmt.Sprintf("%d", res.Total),
					},
				}); err != nil {
					return err
				}
			}
		}

		if days, ok := accesslog.Retention(c.fsys, path); ok && days <= 7 {
			// Attached to every route: the short window qualifies any
			// conclusion (including "no traffic") about covered routes.
			for _, r := range cfg.Routes {
				k := r.Key()
				cur, seen := retentions[k]
				if !seen || days < cur.days {
					retentions[k] = retentionBlind{days: days, logPath: path}
				}
			}
		}
	}

	// One in_use evidence per route that actually saw traffic, in
	// configuration order for deterministic output.
	for i := range cfg.Routes {
		r := &cfg.Routes[i]
		a := matched[r.Key()]
		if a == nil || a.latest.IsZero() {
			continue
		}
		if err := sink.AddEvidence(collector.Evidence{
			EntityIdentityKey: r.Key(),
			Polarity:          collector.PolarityInUse,
			Channel:           "nginx_access_log",
			Strength:          collector.StrengthDeterministic,
			ObservedAt:        time.Now().UTC().Format(time.RFC3339),
			RawRef:            a.rawRef,
			Ref:               "accesslog:" + r.Key(),
			Value: map[string]string{
				"last_request_at": a.latest.UTC().Format(time.RFC3339),
				"count":           fmt.Sprintf("%d", a.count),
				"log_path":        a.logPath,
			},
		}); err != nil {
			return err
		}
	}

	keys := make([]string, 0, len(retentions))
	for k := range retentions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		rb := retentions[k]
		if err := sink.AddBlindSpot(collector.BlindSpot{
			EntityIdentityKey: k,
			Channel:           "log",
			Reason:            "log_retention_short",
			Detail: map[string]string{
				"retention_days": fmt.Sprintf("%d", rb.days),
				"log_path":       rb.logPath,
			},
		}); err != nil {
			return err
		}
	}
	return nil
}

// retentionBlind is the shortest retention seen for one route.
type retentionBlind struct {
	days    int
	logPath string
}

// logPaths deduplicates the paths of every access_log directive in
// configuration order.
func logPaths(cfg *nginx.Config) []string {
	seen := map[string]bool{}
	var out []string
	for _, al := range cfg.AccessLogs {
		if !seen[al.Path] {
			seen[al.Path] = true
			out = append(out, al.Path)
		}
	}
	return out
}

// matchRoutes returns every plain-prefix location covering uri, tied
// on the longest match. Regex/exact modifiers (=, ~, ^~, @) are out of
// scope for the static matcher and never match.
func matchRoutes(routes []nginx.Route, uri string) []*nginx.Route {
	bestLen := -1
	var out []*nginx.Route
	for i := range routes {
		loc := routes[i].Location
		if !strings.HasPrefix(loc, "/") || !strings.HasPrefix(uri, loc) {
			continue
		}
		switch {
		case len(loc) > bestLen:
			bestLen = len(loc)
			out = out[:0]
			out = append(out, &routes[i])
		case len(loc) == bestLen:
			out = append(out, &routes[i])
		}
	}
	return out
}
