package cleanup

import (
	"fmt"
	"strings"
)

// GoneSignal is the stable substring of the "component no longer
// resolves" error the delete-check command reports. The generated
// Verified script greps for it to tell "the component is gone" (a
// pass) apart from "the command could not run" (a failure), because
// both exit with the execution-error code. A test in the CLI package
// keeps resolveComponent's wording in sync with this constant.
const GoneSignal = "no component matches"

// Build turns a cleanup-eligible component into the six-stage plan.
// Every stage carries an action, a gate condition and the confirmer
// who signs it off; the script body holds the exact commands plus a
// "# rollback:" counterpart for each mutating step.
//
// rt pins the environment the scripts assume (database, rules, binary,
// scan) so a plan generated against one database cannot silently
// verify itself against another.
func Build(c Component, rt Runtime) Plan {
	p := Plan{Component: c, Runtime: rt}
	p.VolumeWarnings = volumeWarnings(c)

	ref := c.Ref
	if ref == "" {
		ref = c.Name
	}

	p.Stages = []Stage{
		{
			Name:      "Candidate",
			Action:    fmt.Sprintf("Read this whole plan, run `archaeologist delete-check %s` and confirm the verdict is still orphan with no new blockers.", ref),
			Gate:      "delete-check returns LIKELY_ORPHANED or ORPHANED with an empty blocker list.",
			Confirmer: "Operator confirms after reading (plan confirm <component> Candidate).",
			Script:    candidateScript(ref, rt),
		},
		{
			Name:      "Quarantined",
			Action:    quarantineAction(c),
			Gate:      "After 7 days of quarantine: no new complain/log/call traffic; delete-check still shows no blockers.",
			Confirmer: "Operator cross-checks logs + delete-check, then confirms.",
			Script:    quarantineScript(c),
		},
		{
			Name:      "Observed",
			Action:    "Do nothing more — let the observe daemon watch for 14 days after quarantine.",
			Gate:      "Observation window >= 14 days, no new activity, verdict still orphan.",
			Confirmer: "Re-scan + delete-check (operator).",
			Script:    observedScript(ref, rt),
		},
		{
			Name:      "Archived",
			Action:    archiveAction(c),
			Gate:      "The archive-<timestamp> directory exists with every file; all data volumes have been backed up by hand.",
			Confirmer: "Operator confirms the backup (including volumes) before moving to Removed.",
			Script:    archiveScript(c, p.VolumeWarnings),
		},
		{
			Name:      "Removed",
			Action:    removedAction(c),
			Gate:      "delete-check returns 'component not found' on a fresh scan.",
			Confirmer: "Operator runs delete-check after removal.",
			Script:    removedScript(c),
		},
		{
			Name:      "Verified",
			Action:    "Run a fresh `archaeologist scan` and `delete-check` over the whole area: the component is gone and leaves no side effects (dead routes, broken cron, error logs).",
			Gate:      "A fresh scan no longer contains the entity and no new related findings appear.",
			Confirmer: "Operator + fresh scan results.",
			Script:    verifiedScript(ref, rt),
		},
	}
	return p
}

// ShellQuote renders s as a single-quoted POSIX shell word. Every
// host-derived value in a generated script — and every copy-paste hint
// the CLI prints — goes through this helper, so a name or path cannot
// break out of its quoting context or trigger expansion.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// defaultStr returns s, or fallback when s is empty.
func defaultStr(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

// scriptPreamble pins the tool and database paths a stage script
// assumes. Both are editable at the top of the script, so an operator
// who moved the binary or database fixes the script once instead of
// hunting through every command.
func scriptPreamble(rt Runtime) []string {
	return []string{
		"# Pinned at plan generation — edit here if you moved the binary or database.",
		fmt.Sprintf("ARCHAEOLOGIST=%s", ShellQuote(defaultStr(rt.BinaryPath, "archaeologist"))),
		fmt.Sprintf("DB=%s", ShellQuote(defaultStr(rt.DBPath, "archaeologist.db"))),
	}
}

// deleteCheckCmd renders a delete-check invocation against the pinned
// runtime. It emits --rules-file only when the plan was generated with
// a rules override, so a plan built on the embedded defaults re-checks
// with the same embedded defaults.
func deleteCheckCmd(rt Runtime, ref string) string {
	cmd := fmt.Sprintf("\"$ARCHAEOLOGIST\" delete-check %s --db \"$DB\"", ShellQuote(ref))
	if rt.RulesPath != "" {
		cmd += " --rules-file " + ShellQuote(rt.RulesPath)
	}
	return cmd
}

// volumeWarnings lists every container volume that must be backed up
// by hand before removal; data volumes are never deleted automatically.
func volumeWarnings(c Component) []string {
	if c.Kind != "container" {
		return nil
	}
	raw := strings.TrimSpace(c.Attrs["volumes"])
	if raw == "" {
		return nil
	}
	var out []string
	for _, v := range strings.Split(raw, ",") {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func candidateScript(ref string, rt Runtime) string {
	lines := []string{
		"#!/usr/bin/env bash",
		"set -euo pipefail",
		"",
		"# Candidate — verify the verdict is still safe to act on.",
		"",
	}
	lines = append(lines, scriptPreamble(rt)...)
	lines = append(lines, "",
		deleteCheckCmd(rt, ref),
		"",
		"# rollback: none needed (read-only step)",
	)
	return strings.Join(lines, "\n") + "\n"
}

func observedScript(ref string, rt Runtime) string {
	lines := []string{
		"#!/usr/bin/env bash",
		"set -euo pipefail",
		"",
		"# Observed — wait for the 14-day observation window; this stage runs nothing.",
		"",
	}
	lines = append(lines, scriptPreamble(rt)...)
	lines = append(lines, "",
		fmt.Sprintf("# After 14 days: %s", deleteCheckCmd(rt, ref)),
		"",
		"# rollback: none needed (waiting step)",
	)
	return strings.Join(lines, "\n") + "\n"
}

// verifiedScript re-scans and then distinguishes the three ways the
// final check can end. It never swallows an execution error: an
// unreadable database or a broken binary must fail the stage rather
// than look like a successful removal.
func verifiedScript(ref string, rt Runtime) string {
	lines := []string{
		"#!/usr/bin/env bash",
		"set -euo pipefail",
		"",
		"# Verified — prove the component is gone and nothing else broke.",
		"#",
		"# delete-check exit contract:",
		"#   0 or 1  the component still resolves  -> verification FAILED",
		"#   2       \"" + GoneSignal + "\" -> the component is gone (PASS)",
		"#   2       any other error              -> execution error (FAILED)",
		"",
	}
	lines = append(lines, scriptPreamble(rt)...)
	lines = append(lines, "",
		"\"$ARCHAEOLOGIST\" scan --db \"$DB\"",
		"",
		"rc=0",
		fmt.Sprintf("out=$(%s 2>&1) || rc=$?", deleteCheckCmd(rt, ref)),
		"",
		"if [ \"$rc\" -eq 0 ] || [ \"$rc\" -eq 1 ]; then",
		"  printf '%s\\n' \"$out\" >&2",
		"  echo \"FAILED: "+ref+" still resolves in a fresh scan — this stage is not done.\" >&2",
		"  exit 1",
		"fi",
		"",
		"if ! printf '%s\\n' \"$out\" | grep -q "+ShellQuote(GoneSignal)+"; then",
		"  printf '%s\\n' \"$out\" >&2",
		"  echo \"FAILED: delete-check could not run (exit $rc) — fix the error above and re-run.\" >&2",
		"  exit 1",
		"fi",
		"",
		"echo \"OK: the component no longer resolves in a fresh scan.\"",
		"",
		"# rollback: none — if delete-check still resolves the component,",
		"# return to Removed and inspect the archive for a missed path.",
	)
	return strings.Join(lines, "\n") + "\n"
}

func quarantineAction(c Component) string {
	switch c.Kind {
	case "systemd_unit", "timer":
		return fmt.Sprintf("Stop and prevent start on boot: `systemctl disable --now %s`.", c.Name)
	case "container":
		return fmt.Sprintf("Stop the container, keep image/volumes: `docker stop %s`.", c.Name)
	case "cron_job":
		return fmt.Sprintf("Disable the job: move the cron file to `.disabled` (%s).", attrOr(c.Attrs, "file", "unknown file"))
	case "nginx_route":
		return "Comment out the whole route block in the nginx config (keep the backed-up copy from Archived); reload nginx."
	default:
		return fmt.Sprintf("Quarantine %s using its kind's mechanism — see the script for commands.", c.Kind)
	}
}

func quarantineScript(c Component) string {
	head := []string{
		"#!/usr/bin/env bash",
		"set -euo pipefail",
		"",
		"# Quarantined — stop the component without deleting anything.",
	}
	if ok, reason := nameCheck(c); !ok {
		body := skipLines(c.Kind, c.Name, reason)
		return strings.Join(append(head, append(body, "", "# end quarantine")...), "\n") + "\n"
	}
	var body []string
	switch c.Kind {
	case "systemd_unit", "timer":
		body = []string{
			fmt.Sprintf("systemctl disable --now %s", ShellQuote(c.Name)),
			fmt.Sprintf("# rollback: systemctl enable --now %s", ShellQuote(c.Name)),
		}
	case "container":
		body = []string{
			fmt.Sprintf("docker stop %s", ShellQuote(c.Name)),
			fmt.Sprintf("# rollback: docker start %s", ShellQuote(c.Name)),
		}
	case "cron_job":
		f := attrOr(c.Attrs, "file", "")
		if f == "" {
			body = []string{
				fmt.Sprintf("# unknown cron file for %q — edit crontab manually, then re-run", c.Name),
				"# rollback: restore the crontab backup you made",
			}
		} else {
			body = []string{
				fmt.Sprintf("mv %s %s", ShellQuote(f), ShellQuote(f+".disabled")),
				fmt.Sprintf("# rollback: mv %s %s", ShellQuote(f+".disabled"), ShellQuote(f)),
			}
		}
	case "nginx_route":
		body = []string{
			"# Backup the config first (see the Archived stage), then comment out",
			"# the server/location block for this route and reload:",
			fmt.Sprintf("# sed -i.bak 's|^\\s*location %s|# location %s|' /etc/nginx/sites-enabled/*", c.Name, c.Name),
			"nginx -t && systemctl reload nginx",
			"# rollback: restore the .bak file from the Archived copy and reload",
		}
	default:
		body = []string{
			fmt.Sprintf("# no standard quarantine command for kind %q — see the plan document in this directory", c.Kind),
			"# rollback: reverse whatever manual step you take",
		}
	}
	return strings.Join(append(head, append(body, "", "# end quarantine")...), "\n") + "\n"
}

func archiveAction(c Component) string {
	base := "Run the Archived script to `cp` the current config (unit file / config / compose / image list) into the `archive-<UTC-timestamp>` directory right next to the plan."
	if len(volumeWarnings(c)) > 0 {
		base += " You MUST back up every data volume by hand before continuing — the tool neither deletes nor backs up data for you."
	}
	return base
}

func archiveScript(c Component, warnings []string) string {
	head := []string{
		"#!/usr/bin/env bash",
		"set -euo pipefail",
		"",
		"# Archived — copy every recovery-relevant artifact BEFORE Removed.",
		"",
		`ARCHIVE="archive-$(date -u +%Y%m%dT%H%M%SZ)"`,
		`mkdir -p "$ARCHIVE"`,
		"",
	}
	var body []string
	switch c.Kind {
	case "systemd_unit", "timer":
		// The archive filename concatenates a quoted directory with a
		// quoted literal, so a unit name cannot trigger expansion inside
		// the double-quoted path. When the name is outside the allowlist
		// the file is still archived, just under a stage-named file, so a
		// hostile name never reaches the destination path.
		dest := c.Name
		if ok, _ := validUnitName(c.Name); !ok {
			dest = "unit"
		}
		body = []string{
			fmt.Sprintf("systemctl cat %s > \"$ARCHIVE/\"%s.txt 2>/dev/null || true",
				ShellQuote(c.Name), ShellQuote(dest)),
			fmt.Sprintf("systemctl show %s -p FragmentPath --value | xargs -r -I{} cp {} \"$ARCHIVE/\" 2>/dev/null || true", ShellQuote(c.Name)),
		}
	case "container":
		dest := c.Name
		if ok, _ := validContainerName(c.Name); !ok {
			dest = "container"
		}
		body = []string{
			fmt.Sprintf("docker inspect %s > \"$ARCHIVE/\"%s.json", ShellQuote(c.Name), ShellQuote("inspect-"+dest)),
			fmt.Sprintf("docker inspect %s --format '{{.Config.Image}}' > \"$ARCHIVE/\"%s 2>/dev/null || true",
				ShellQuote(c.Name), ShellQuote("image-"+dest+".txt")),
		}
	case "cron_job":
		f := attrOr(c.Attrs, "file", "")
		if f == "" {
			body = []string{"crontab -l > \"$ARCHIVE/crontab.bak\" 2>/dev/null || true"}
		} else if ok, reason := validCronPath(f); !ok {
			body = []string{
				fmt.Sprintf("# SKIPPED: the cron file path %q is outside the allowed path set.", f),
				fmt.Sprintf("#   Reason: %s", reason),
				"# No copy command is generated. Back the file up by hand before the",
				"# Removed stage — a path that cannot be named safely cannot be archived",
				"# safely either.",
				"# rollback: n/a — this step emits no command",
			}
		} else {
			body = []string{fmt.Sprintf("cp %s \"$ARCHIVE/\"", ShellQuote(f))}
		}
	case "nginx_route":
		body = []string{
			"cp -a /etc/nginx \"$ARCHIVE/nginx/\" 2>/dev/null || cp -a /etc/nginx/sites-enabled \"$ARCHIVE/\"",
		}
	default:
		body = []string{fmt.Sprintf("# no standard archive source for kind %q", c.Kind)}
	}
	warn := []string{"", "# Data volumes are NEVER deleted automatically — confirm your backup first."}
	for _, w := range warnings {
		warn = append(warn,
			fmt.Sprintf("echo 'Volume %s may still hold data — confirm your backup before continuing' >&2", w),
			fmt.Sprintf("# manual backup of %s happens here; no command is generated", w))
	}
	tail := []string{"", "echo \"Archived into $ARCHIVE — confirm before moving to Removed.\""}
	return strings.Join(append(append(head, body...), append(warn, tail...)...), "\n") + "\n"
}

func removedAction(c Component) string {
	switch c.Kind {
	case "container":
		return "Remove the three targets separately: container -> image -> volume (each command has its own rollback; delete a volume only after confirming the backup)."
	case "systemd_unit", "timer":
		if isLocalUnitPath(attrOr(c.Attrs, "fragment_path", "")) {
			return "Delete the unit file + daemon-reload (only after archiving)."
		}
		return "Disable the unit, then remove it through its package manager — the unit file is not locally managed."
	case "cron_job":
		return "Delete the disabled cron file (only after archiving)."
	case "nginx_route":
		return "Permanently delete the commented-out route block from the config (only after archiving)."
	default:
		return fmt.Sprintf("Remove %s using its kind's mechanism — see the script.", c.Kind)
	}
}

// isLocalUnitPath reports whether a systemd fragment path is a unit the
// operator manages by hand. Units shipped by a package live under
// /usr/lib or /lib; deleting those by hand desynchronises the package
// database, so the plan must route them through the package manager.
func isLocalUnitPath(path string) bool {
	return strings.HasPrefix(path, "/etc/systemd/system/")
}

// packageManagerLines renders the guidance for a unit whose file a
// package owns. Deleting it by hand desynchronises the package
// database, so no delete command is emitted at all.
func packageManagerLines() []string {
	return []string{
		"# The unit file is NOT under /etc/systemd/system, so a package owns it.",
		"# Deleting it by hand desynchronises the package database — use the package manager:",
		"#   apt-get remove <package>       # Debian/Ubuntu",
		"#   dnf remove <package>           # Fedora/RHEL",
		"#   pacman -Rns <package>          # Arch",
		"# rollback: reinstall the package to restore the unit file, then enable --now",
	}
}

// noFragmentPathLines renders the guidance for a unit with no recorded
// fragment path. Nothing is safe to name, so the operator is pointed at
// the live system instead of being handed a guessed path.
func noFragmentPathLines() []string {
	return []string{
		"# No fragment path was recorded for this unit, so there is no file this",
		"# stage may name. Read the real path from the archived unit text, or from",
		"# `systemctl show <unit> -p FragmentPath`, then decide by hand.",
		"# rollback: n/a — this step emits no command",
	}
}

func removedScript(c Component) string {
	head := []string{
		"#!/usr/bin/env bash",
		"set -euo pipefail",
		"",
		"# Removed — delete for real. Archive MUST exist before this stage.",
	}
	if ok, reason := nameCheck(c); !ok {
		body := skipLines(c.Kind, c.Name, reason)
		return strings.Join(append(head, append(body, "", "# end removal")...), "\n") + "\n"
	}
	var body []string
	switch c.Kind {
	case "container":
		img := attrOr(c.Attrs, "image", "")
		imgID := attrOr(c.Attrs, "image_id", "")
		vols := volumeWarnings(c)
		body = []string{
			fmt.Sprintf("docker rm %s", ShellQuote(c.Name)),
			"# rollback: no direct command — rebuild from the archived compose/inspect",
			"",
			"# --- image (separate — DO NOT merge with the container step) ---",
		}
		switch {
		case imgID != "":
			// The image ID is a digest-derived immutable reference, so
			// removing it cannot hit a different image that later reused
			// the same tag.
			body = append(body,
				fmt.Sprintf("docker rmi %s", ShellQuote(imgID)),
				"# rollback: docker pull <tag> — the image ID is immutable, so this only",
				"#           restores the same bytes if the registry still serves them.")
		case img != "":
			body = append(body,
				fmt.Sprintf("# image ID unknown; removing by tag %s may hit a re-pulled image.", ShellQuote(img)),
				fmt.Sprintf("docker rmi %s", ShellQuote(img)),
				fmt.Sprintf("# rollback: docker pull %s", ShellQuote(img)))
		default:
			body = append(body, "# image unknown — read archive/image-*.txt and rmi by hand")
		}
		body = append(body, "", "# --- volume (separate; only after your manual backup) ---")
		if len(vols) == 0 {
			body = append(body, "# no named volumes attached")
		}
		for _, v := range vols {
			body = append(body,
				fmt.Sprintf("# Volume %s may still hold data — confirm your backup before uncommenting the next line:", v),
				fmt.Sprintf("# docker volume rm %s", ShellQuote(volumeName(v))),
				"# rollback: none — restore from the backup you confirmed at Archived")
		}
	case "systemd_unit", "timer":
		frag := attrOr(c.Attrs, "fragment_path", "")
		body = []string{
			fmt.Sprintf("systemctl disable --now %s 2>/dev/null || true", ShellQuote(c.Name)),
		}
		switch ok, reason := safePath(frag); {
		case frag == "":
			// No fragment path recorded: nothing to delete, so fall
			// through to the package-manager guidance rather than
			// inventing a path.
			body = append(body, noFragmentPathLines()...)
		case !ok:
			body = append(body,
				fmt.Sprintf("# SKIPPED: the fragment path %q is outside the allowed path set.", frag),
				fmt.Sprintf("#   Reason: %s", reason),
				"# No delete command is generated, so nothing in it can name the wrong",
				"# file. Move or delete the unit file by hand, then run daemon-reload.",
				"# rollback: n/a — this step emits no command",
			)
		case isLocalUnitPath(frag):
			body = append(body,
				fmt.Sprintf("rm -f %s", ShellQuote(frag)),
				"systemctl daemon-reload",
				fmt.Sprintf("# rollback: copy %s.txt from archive/ back to /etc/systemd/system/ then daemon-reload + enable --now", c.Name),
			)
		default:
			body = append(body, packageManagerLines()...)
		}
	case "cron_job":
		f := attrOr(c.Attrs, "file", "")
		if f == "" {
			body = []string{"# remove the crontab entry manually using the archived crontab.bak as reference",
				"# rollback: restore from archive/crontab.bak"}
		} else {
			body = []string{
				fmt.Sprintf("rm -f %s %s 2>/dev/null || true", ShellQuote(f), ShellQuote(f+".disabled")),
				fmt.Sprintf("# rollback: cp %s back from archive/ then re-verify", ShellQuote(f)),
			}
		}
	case "nginx_route":
		body = []string{
			"# Permanently delete the route block from the config (after the archive exists), then:",
			"nginx -t && systemctl reload nginx",
			"# rollback: restore the nginx file from archive/ then reload",
		}
	default:
		body = []string{fmt.Sprintf("# no standard removal command for kind %q", c.Kind)}
	}
	return strings.Join(append(head, append(body, "", "# end removal")...), "\n") + "\n"
}

// attrOr returns attrs[key] or fallback.
func attrOr(attrs map[string]string, key, fallback string) string {
	if v := strings.TrimSpace(attrs[key]); v != "" {
		return v
	}
	return fallback
}

// volumeName extracts the volume name from a docker mount string
// ("data:/var/lib/x" → "data"); anonymous host paths fall back to the
// full string.
func volumeName(mount string) string {
	if i := strings.IndexByte(mount, ':'); i > 0 {
		return mount[:i]
	}
	return mount
}
