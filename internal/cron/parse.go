package cron

import "strings"

// parseLine turns one raw crontab line into a Job. Comments, blanks
// and lines cron itself would reject (environment assignments,
// malformed schedules) are skipped, not reported.
func parseLine(file, digest string, line int, raw string, userField bool, user string) (Job, bool) {
	s := strings.TrimSpace(raw)
	s = strings.TrimSuffix(s, "\r")
	if s == "" || strings.HasPrefix(s, "#") {
		return Job{}, false
	}
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return Job{}, false
	}

	if strings.HasPrefix(fields[0], "@") {
		idx := 1
		if userField {
			if len(fields) < 3 {
				return Job{}, false
			}
			user = fields[1]
			idx = 2
		}
		cmd := strings.Join(fields[idx:], " ")
		if cmd == "" {
			return Job{}, false
		}
		return Job{
			File: file, FileDigest: digest, Line: line,
			User: user, Schedule: fields[0], Command: cmd,
		}, true
	}

	// Five schedule fields are mandatory; a user field follows in
	// /etc/crontab and /etc/cron.d, and the command is the rest.
	minFields := 6
	if userField {
		minFields = 7
	}
	if len(fields) < minFields {
		return Job{}, false
	}
	cmdIdx := 5
	if userField {
		user = fields[5]
		cmdIdx = 6
	}
	return Job{
		File: file, FileDigest: digest, Line: line,
		User: user, Schedule: strings.Join(fields[0:5], " "),
		Command: strings.Join(fields[cmdIdx:], " "),
	}, true
}
