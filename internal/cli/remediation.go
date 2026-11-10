package cli

import (
	"fmt"
	"io"

	"archaeologist/internal/store"
	"archaeologist/internal/verdict"
)

// Blind-spot remediation categories: what kind of action clears the
// gap (or whether any action can).
const (
	remedyPermission = "permission" // grant access, then rescan
	remedyResolve    = "resolve"    // supply or fix the missing value, then rescan
	remedyLimitation = "limitation" // nothing to do: the source cannot provide it
	remedyManual     = "manual"     // inspect the target by hand
)

// blindRemedy is the concrete action that clears one blind-spot reason.
type blindRemedy struct {
	Category string
	Advice   string
}

// blindRemedies maps every known blind-spot reason to its remediation.
// Reasons not listed here fall back to a generic manual review, so a
// newer collector still produces actionable output.
var blindRemedies = map[string]blindRemedy{
	// Permission gaps: name the credential or group to add.
	"ci_workflow_unreadable": {remedyPermission,
		"grant read access to the CI workflow file, then rescan"},
	"cron_script_unreadable": {remedyPermission,
		"grant read access to the cron script (often root-owned), then rescan"},
	"cron_source_unreadable": {remedyPermission,
		"run as root (or grant read access) to read /etc/crontab and /etc/cron.*, then rescan"},
	"docker_log_unreadable": {remedyPermission,
		"read container logs as root or with docker group membership, then rescan"},
	"exec_start_unreadable": {remedyPermission,
		"grant read and execute access to the ExecStart binary, then rescan"},
	"journald_unreadable": {remedyPermission,
		"grant journal access: run as root or add the user to the systemd-journal group, then rescan"},
	"mtime_unreadable": {remedyPermission,
		"grant read/search permission on the path so file times can be read, then rescan"},
	"unit_file_unreadable": {remedyPermission,
		"grant read access to the unit file (usually under /etc/systemd/system), then rescan"},

	// Missing values: supply the data the collector could not resolve.
	"compose_file_not_found": {remedyResolve,
		"restore the compose file or label the service with its compose path, then rescan"},
	"cron_env_unresolved": {remedyResolve,
		"define the environment variable in the crontab or /etc/environment, then rescan"},
	"exec_start_not_found": {remedyResolve,
		"install the missing ExecStart binary or correct the path in the unit, then rescan"},
	"exec_start_relative": {remedyResolve,
		"set WorkingDirectory in the unit or use an absolute ExecStart path, then rescan"},
	"exec_start_unresolved": {remedyResolve,
		"define the variable or specifier referenced by ExecStart (Environment=) so it resolves, then rescan"},
	"inode_not_mapped": {remedyResolve,
		"map the listening binary back to a package (dpkg -S or rpm -qf), then rescan"},
	"nginx_config_parse_error": {remedyResolve,
		"fix the nginx config syntax or grant read access to it, then rescan"},
	"nginx_target_unresolved": {remedyResolve,
		"static set/map values resolve automatically; for a runtime-defined variable run nginx -T to read the effective config, then re-check by hand and rescan"},
	"caddy_config_unreadable": {remedyPermission,
		"grant read access to the Caddyfile (usually /etc/caddy/Caddyfile) or run as root, then rescan"},
	"caddy_config_parse_error": {remedyResolve,
		"fix the Caddyfile syntax, then rescan"},
	"caddy_import_unreadable": {remedyPermission,
		"restore the imported file or grant read access to it, then rescan"},
	"caddy_target_unresolved": {remedyResolve,
		"replace the placeholder or environment reference with a concrete upstream, then rescan"},
	"haproxy_config_unreadable": {remedyPermission,
		"grant read access to the HAProxy config (usually /etc/haproxy/haproxy.cfg) or run as root, then rescan"},
	"haproxy_config_parse_error": {remedyResolve,
		"fix the HAProxy config error (syntax or a directive without its arguments), then rescan"},
	"haproxy_target_unresolved": {remedyResolve,
		"replace the placeholder or environment reference with a concrete server address, then rescan"},
	"traefik_config_unreadable": {remedyPermission,
		"grant read access to the Traefik config (usually /etc/traefik/traefik.yml) or run as root, then rescan"},
	"traefik_config_parse_error": {remedyResolve,
		"fix the Traefik YAML syntax, then rescan"},
	"traefik_config_unsupported": {remedyResolve,
		"convert the TOML config to YAML (traefik.yml); Traefik accepts both formats, then rescan"},
	"traefik_provider_unsupported": {remedyLimitation,
		"no action: routing from this provider (labels or API) is not read from files; rely on other channels or expose it through the file provider"},
	"traefik_target_unresolved": {remedyResolve,
		"replace the placeholder with a concrete server URL, then rescan"},
	"apache_config_unreadable": {remedyPermission,
		"grant read access to the Apache config (usually /etc/apache2/apache2.conf) or run as root, then rescan"},
	"apache_config_parse_error": {remedyResolve,
		"fix the Apache config syntax at the reported position, then rescan"},
	"apache_include_unreadable": {remedyPermission,
		"grant read access to the included Apache config file or run as root, then rescan"},
	"apache_target_unresolved": {remedyResolve,
		"replace the placeholder with a concrete backend address, then rescan"},

	// Source limitations: no action can widen the view.
	"log_driver_unsupported": {remedyLimitation,
		"no action: this container log driver exposes no readable logs; rely on other channels"},
	"log_retention_short": {remedyLimitation,
		"no action: log retention is shorter than the observation window; rely on other channels"},

	// Manual inspection: the parser cannot go further on its own.
	"collector_error": {remedyManual,
		"check the collector error detail, fix the cause, and re-run the scan"},
	"cron_schedule_unparsed": {remedyManual,
		"review the cron schedule manually; the parser could not interpret it"},
	"cron_script_unanalyzable": {remedyManual,
		"inspect the cron script manually; its contents could not be analysed"},
	"exec_start_parse": {remedyManual,
		"fix the ExecStart syntax in the unit, then rescan"},
	"exec_start_unknown_kind": {remedyManual,
		"identify the ExecStart target manually (its type is not recognised), then rescan"},
	"parse_error": {remedyManual,
		"inspect the process manually; its identity could not be parsed"},
	"timer_calendar_unparsed": {remedyManual,
		"review the systemd timer OnCalendar line manually"},
}

// remedyFor returns the known remediation for one blind-spot reason,
// falling back to a generic manual review for reasons introduced by
// newer collectors.
func remedyFor(reason string) blindRemedy {
	if r, ok := blindRemedies[reason]; ok {
		return r
	}
	return blindRemedy{Category: remedyManual,
		Advice: "review this blind spot manually; no specific remediation is known"}
}

// windowNextJSON is the observation-window half of the next steps: how
// much longer to observe before the window can support a verdict.
type windowNextJSON struct {
	Ready         bool    `json:"ready"`
	RequiredDays  int     `json:"required_days"`
	DaysRemaining int     `json:"days_remaining"`
	ReadyAt       *string `json:"ready_at"` // earliest date the window can qualify
	Advice        string  `json:"advice"`
}

// nextStepJSON pairs one blind spot with the action that clears it.
type nextStepJSON struct {
	Channel  string `json:"channel"`
	Reason   string `json:"reason"`
	Category string `json:"category"`
	Advice   string `json:"advice"`
}

// nextJSON is the `next` object `explain --format json --next` adds.
type nextJSON struct {
	Window     windowNextJSON `json:"window"`
	BlindSpots []nextStepJSON `json:"blind_spots"`
}

// buildNext computes the remediation view for one component: whether
// the observation window still needs days, plus one next step per
// blind spot.
func buildNext(win verdict.Window, required int, blinds []store.BlindRow) nextJSON {
	if required < 0 {
		required = 0
	}
	remaining := required - win.Days
	if remaining < 0 {
		remaining = 0
	}
	ready := win.Days >= required
	readyAt := windowReadyAt(win.Start, required)

	var advice string
	switch {
	case ready && readyAt != nil:
		advice = fmt.Sprintf("window is sufficient since %s (%d of %d required days)",
			*readyAt, win.Days, required)
	case ready:
		advice = fmt.Sprintf("window is sufficient (%d of %d required days)", win.Days, required)
	case readyAt != nil:
		advice = fmt.Sprintf("observe %d more days — earliest sufficient date %s",
			remaining, *readyAt)
	default:
		advice = fmt.Sprintf("observe %d more days", remaining)
	}

	steps := make([]nextStepJSON, 0, len(blinds))
	for _, b := range blinds {
		r := remedyFor(b.Reason)
		steps = append(steps, nextStepJSON{
			Channel: b.Channel, Reason: b.Reason,
			Category: r.Category, Advice: r.Advice,
		})
	}
	return nextJSON{
		Window: windowNextJSON{
			Ready: ready, RequiredDays: required,
			DaysRemaining: remaining, ReadyAt: readyAt, Advice: advice,
		},
		BlindSpots: steps,
	}
}

// windowReadyAt is the earliest date the window can qualify: the
// window start plus the required days. It is nil when the start
// stamp cannot be parsed.
func windowReadyAt(start string, required int) *string {
	t, err := parseStampLoose(start)
	if err != nil {
		return nil
	}
	s := t.AddDate(0, 0, required).Format("2006-01-02")
	return &s
}

// printNext renders the next-steps section: window advice first, then
// one remediation line per blind spot.
func printNext(w io.Writer, n nextJSON) error {
	if _, err := fmt.Fprintln(w, "Next steps:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  window: %s\n", n.Window.Advice); err != nil {
		return err
	}
	if len(n.BlindSpots) == 0 {
		_, err := fmt.Fprintln(w, "  blind spots: none — nothing to remediate")
		return err
	}
	for _, s := range n.BlindSpots {
		if _, err := fmt.Fprintf(w, "  [%s] %s (%s): %s\n",
			s.Channel, s.Reason, s.Category, s.Advice); err != nil {
			return err
		}
	}
	return nil
}
