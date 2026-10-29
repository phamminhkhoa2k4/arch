package cleanup

import (
	"fmt"
	"strings"
)

// TODO: provide allowlist documentation for sponsor or external contributors.
// package cleanup

// The stage scripts are written for a human to review and run by hand,
// but their commands are machine-generated from host state. A name that
// leaves the character set its subsystem allows is a name that can no
// longer be trusted to sit inside a command: it may steer the command at
// a different target, or escape its quoting context entirely. Rather
// than guess, the builder refuses to place such a name in a command and
// hands the step back to the operator as a manual instruction. The plan
// itself is still generated — the evidence, gates and provenance remain
// useful — only the command is withheld.
//
// Every check here is an allowlist: a name must match, not merely fail
// to be obviously hostile.

// maxNameLen bounds every host-derived name. Systemd and Docker both
// cap names well below this; anything longer is not a real name.
const maxNameLen = 256

// unitNameRune reports whether r is legal in a systemd unit name.
// systemd accepts letters, digits and the punctuation set ":_.\-",
// plus "@" to mark a template instance such as "app@1.service".
func unitNameRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z',
		r >= 'A' && r <= 'Z',
		r >= '0' && r <= '9':
		return true
	case r == ':' || r == '_' || r == '.' || r == '-' || r == '@':
		return true
	}
	return false
}

// validUnitName accepts a systemd unit or timer name. It rejects an
// empty name, an over-long name, a leading dash (which systemd itself
// treats as an option terminator), a path separator, a parent-directory
// reference and any rune outside the unit name alphabet.
func validUnitName(name string) (bool, string) {
	switch {
	case name == "":
		return false, "the name is empty"
	case len(name) > maxNameLen:
		return false, fmt.Sprintf("the name is %d bytes, over the %d byte limit", len(name), maxNameLen)
	case strings.HasPrefix(name, "-"):
		return false, "the name starts with '-', which a command would read as an option"
	case strings.Contains(name, "/"):
		return false, "the name contains '/', which is a path separator rather than a unit name"
	case strings.Contains(name, ".."):
		return false, "the name contains '..', which is a parent-directory reference"
	}
	for _, r := range name {
		if !unitNameRune(r) {
			return false, fmt.Sprintf("the name contains %q, which is outside the systemd unit name alphabet", string(r))
		}
	}
	return true, ""
}

// validContainerName accepts a Docker container name: an alphanumeric
// first character followed by alphanumerics, dots, underscores or
// dashes. Docker itself enforces this set, so a name outside it did not
// come from a real container.
func validContainerName(name string) (bool, string) {
	if name == "" {
		return false, ""
	}
	if strings.HasPrefix(name, "-") {
		return false, fmt.Sprintf("the name starts with '-', which a command would read as an option")
	}
	if len(name) > 255 {
		return false, fmt.Sprintf("the name is %d bytes, over the 255 byte limit", len(name))
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9':
			continue
		case (r == '.' || r == '_' || r == '-') && i > 0:
			continue
		default:
			return false, fmt.Sprintf("the name contains %q, which is outside the Docker container name alphabet", string(r))
		}
	}
	return true, ""
}

// validCronPath accepts the cron file a job lives in. It must be an
// absolute path with no newline and no parent-directory reference —
// the three properties that decide both which file is touched and
// whether the path can be written into a command on one line.
func validCronPath(path string) (bool, string) {
	switch {
	case path == "":
		return false, "the cron file path is empty"
	case !strings.HasPrefix(path, "/"):
		return false, "the path is not absolute, so it would resolve against whatever directory the script runs in"
	case strings.ContainsAny(path, "\n\r"):
		return false, "the path contains a line break, which would end the command early"
	case strings.Contains(path, ".."):
		return false, "the path contains '..', which is a parent-directory reference"
	}
	return true, ""
}

// validRouteLocation accepts an nginx location for automated editing.
// Only plain prefix locations are accepted. Regex ("~"), case-insensitive
// regex ("~="), exact match ("=") and prefixed match ("^~") all change
// how the location line is written, so the generated text edit cannot be
// trusted to match the real block; those routes stay manual.
func validRouteLocation(loc string) (bool, string) {
	switch {
	case loc == "":
		return false, "the location is empty"
	case strings.HasPrefix(loc, "~"):
		return false, "the location is a regular expression, which a text edit cannot match safely"
	case strings.HasPrefix(loc, "="):
		return false, "the location is an exact match, which a prefix edit would not match"
	case strings.HasPrefix(loc, "^~"):
		return false, "the location is a prefixed match, which a prefix edit would not match"
	case !strings.HasPrefix(loc, "/"):
		return false, "the location does not start with '/', so it is not a plain prefix location"
	case strings.ContainsAny(loc, "\n\r"):
		return false, "the location contains a line break"
	}
	return true, ""
}

// safePath accepts a filesystem path that a generated command may name
// directly, such as a systemd fragment path. It must be absolute, on a
// single line, with no parent-directory reference.
func safePath(path string) (bool, string) {
	switch {
	case path == "":
		return false, "the path is empty"
	case !strings.HasPrefix(path, "/"):
		return false, "the path is not absolute"
	case strings.ContainsAny(path, "\n\r"):
		return false, "the path contains a line break, which would end the command early"
	case strings.Contains(path, ".."):
		return false, "the path contains '..', which is a parent-directory reference"
	}
	return true, ""
}

// nameCheck validates the identifier a stage's commands will name, by
// component kind. Cron jobs are identified by their file rather than by
// their name, so that case validates the path.
func nameCheck(c Component) (bool, string) {
	switch c.Kind {
	case "systemd_unit", "timer":
		return validUnitName(c.Name)
	case "container":
		ok, msg := validContainerName(c.Name)
		return ok && msg == "", msg
	case "cron_job":
		return validCronPath(attrOr(c.Attrs, "file", ""))
	case "nginx_route":
		return validRouteLocation(c.Name)
	default:
		// Kinds with no generated mutating command need no allowlist;
		// their scripts are comments from the start.
		return true, ""
	}
}

// skipLines renders the manual-only replacement for a stage whose
// identifier did not pass the allowlist. The plan is still generated and
// the stage keeps its gate and confirmer, but no command is emitted — a
// name outside the allowlist is never placed in a command.
func skipLines(kind, name, reason string) []string {
	return []string{
		fmt.Sprintf("# SKIPPED: the %s identifier %q is outside the allowed character set.", kind, name),
		fmt.Sprintf("#   Reason: %s", reason),
		"# No command is generated for this step, so nothing in it can name the",
		"# wrong target or escape its quoting. Perform this step by hand after",
		"# reading plan.md, then confirm the stage as usual.",
		"# rollback: n/a — this stage emits no command",
	}
}
