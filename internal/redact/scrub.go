package redact

import "regexp"

// Shaped credential formats carry no key name to hang a name-based
// rule on — a JWT, a cloud key id, a connection-string password, a
// private key block — so they are matched on structure. They run
// before the inline rules so a private key block is replaced
// atomically instead of in fragments.
var shaped = []struct {
	re   *regexp.Regexp
	repl string
}{
	// Private key blocks: whole block first, then any truncated block
	// (BEGIN with no END) masks to the end of the string.
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`), Mask},
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*`), Mask},
	// JWT: three base64url segments with an "eyJ" header prefix.
	{regexp.MustCompile(`eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}`), Mask},
	// AWS access key id: service prefix plus 16 uppercase alphanumerics.
	{regexp.MustCompile(`\b(?:AKIA|ASIA|AIDA|AROA|AIPA|AGPA|ABIA|ACCA)[0-9A-Z]{16}\b`), Mask},
	// AWS key material assigned by name on a cmdline or config line.
	{regexp.MustCompile(`(?i)(\baws[_-]?(?:access[_-]?key[_-]?id|secret[_-]?access[_-]?key|session[_-]?token)\b[\s:=]+)\S+`), "${1}" + Mask},
	// Google API key.
	{regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), Mask},
	// Azure Storage account key inside a connection string.
	{regexp.MustCompile(`(?i)(accountkey=)[^;\s]+`), "${1}" + Mask},
	// Connection-string password: scheme://user:pass@host. The
	// password part may itself contain "@", so it is taken greedily
	// up to the last separator before the host; a userinfo without a
	// password is left alone.
	{regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)([^/\s:@]*):([^/\s]*)@`), "${1}${2}:" + Mask + "@"},
	// Long token in a URL query string.
	{regexp.MustCompile(`(?i)([?&](?:access_token|id_token|refresh_token|api_key|apikey|token|auth|session|signature|sig|code|key)=)[^&\s#]+`), "${1}" + Mask},
	// Credential values in headers (and -H cmdline fragments); the
	// auth scheme stays in the output so the header remains readable.
	{regexp.MustCompile(`(?i)\b((?:authorization|x-api-key|x-apikey|x-auth-token|x-amz-security-token|x-amz-signature|x-goog-api-key|x-csrf-token|api-key|apikey|auth-token|session-token)\s*[:=]\s*(?:bearer\s+|basic\s+|token\s+)?)[^\s'\"]+`), "${1}" + Mask},
}

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
	{regexp.MustCompile(`(?i)(password=)[^&\s;]+`), "${1}" + Mask},
	{regexp.MustCompile(`(?i)(authorization:\s*bearer\s+)[^\s']+`), "${1}" + Mask},
	// mysql-style attached short flag: "-psecret" (value ≥8, not a
	// lone "-" flag or a negative number).
	{regexp.MustCompile(`(?:^|\s)-p([^\s-]\S{7,})`), " -p" + Mask},
}

// ScrubString replaces credential material inside s: shaped formats
// first, then the inline fragments.
func ScrubString(s string) string {
	for _, rule := range shaped {
		s = rule.re.ReplaceAllString(s, rule.repl)
	}
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
