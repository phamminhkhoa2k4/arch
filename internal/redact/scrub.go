package redact

import "regexp"

// Inline credential fragments inside otherwise-legitimate strings
// (cmdlines, cron commands, nginx set directives, systemd exec).
var inline = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`(?i)(--?password[=\s])\S+`), "${1}" + Mask},
	{regexp.MustCompile(`(?i)(--?passwd[=\s])\S+`), "${1}" + Mask},
	{regexp.MustCompile(`(?i)(--?token[=\s])\S+`), "${1}" + Mask},
	{regexp.MustCompile(`(?i)(--?secret[=\s])\S+`), "${1}" + Mask},
	{regexp.MustCompile(`(?i)(password=)[^&\s]+`), "${1}" + Mask},
	{regexp.MustCompile(`(?i)(authorization:\s*bearer\s+)[^\s']+`), "${1}" + Mask},
	// mysql-style attached short flag: "-psecret" (value ≥8, not a
	// lone "-" flag or a negative number).
	{regexp.MustCompile(`(?:^|\s)-p([^\s-]\S{7,})`), " -p" + Mask},
}

// ScrubString replaces inline credential fragments inside s.
func ScrubString(s string) string {
	for _, rule := range inline {
		s = rule.re.ReplaceAllString(s, rule.repl)
	}
	return s
}

// RedactMap is the sink choke-point: a secret-looking key has its
// value replaced outright; every other value is scrubbed for inline
// credential fragments. It does not apply the entropy heuristic —
// that belongs to environment capture only — so timestamps and
// addresses used by the verdict engine survive.
func RedactMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		if IsSecretName(k) {
			out[k] = Mask
			continue
		}
		out[k] = ScrubString(v)
	}
	return out
}

// RedactEnv is the environment-capture path: in addition to the name
// patterns and inline scrubbing, a high-entropy value is masked even
// when its name looks innocuous.
func RedactEnv(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		if IsSecretName(k) || IsHighEntropy(v) {
			out[k] = Mask
			continue
		}
		out[k] = ScrubString(v)
	}
	return out
}
