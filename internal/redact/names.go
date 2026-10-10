// Package redact removes credential material from maps before they
// reach the evidence database. The scan sink runs every attribute,
// evidence value and blind-spot detail through it, so no collector
// can persist a secret by accident.
package redact

import "strings"

// Mask replaces every redacted value.
const Mask = "<redacted>"

// secretParts are substrings (after normalization) that mark a name
// as credential-bearing.
var secretParts = []string{
	"password", "passwd", "token", "secret", "credential",
	"api_key", "apikey", "private_key", "access_key", "auth_key",
	"session_key", "signing_key", "encryption_key", "ssh_key",
	"client_secret", "signature", "bearer",
}

// keepExact are normalized names that must never be redacted even
// though they look related (PWD is the working directory, not a
// password).
var keepExact = map[string]bool{
	"pwd":    true, // POSIX cwd
	"oldpwd": true, // bash previous cwd
}

// IsSecretName reports whether an environment/attribute name looks
// credential-bearing. Names are lowercased with "-" folded to "_";
// a "_pwd" suffix counts, an exact "pwd" does not.
func IsSecretName(name string) bool {
	n := normalize(name)
	if keepExact[n] {
		return false
	}
	if strings.HasSuffix(n, "_pwd") {
		return true
	}
	for _, p := range secretParts {
		if strings.Contains(n, p) {
			return true
		}
	}
	return false
}

func normalize(name string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), "-", "_"))
}
