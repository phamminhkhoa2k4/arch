package systemd

import "fmt"

// elfMagic identifies an ELF binary; shebang identifies a script.
var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

// Classify inspects a file's first bytes: ELF → "binary",
// "#!" → "script". Anything else is unknown — ok=false so the caller
// records a blind spot instead of guessing the kind.
func Classify(content []byte) (kind string, ok bool) {
	if len(content) >= 4 && content[0] == elfMagic[0] &&
		content[1] == elfMagic[1] && content[2] == elfMagic[2] &&
		content[3] == elfMagic[3] {
		return "binary", true
	}
	if len(content) >= 2 && content[0] == '#' && content[1] == '!' {
		return "script", true
	}
	return "", false
}

// errNotFound reports a unit with no base file on disk (transient or
// masked units) — a normal condition, not an error to blind-spot.
type errNotFound struct{ name string }

func (e *errNotFound) Error() string {
	return fmt.Sprintf("unit %s has no unit file", e.name)
}

// IsNotFound reports whether err means "no base file".
func IsNotFound(err error) bool {
	_, ok := err.(*errNotFound)
	return ok
}
