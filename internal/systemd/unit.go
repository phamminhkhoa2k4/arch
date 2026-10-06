package systemd

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// Directive is one `Key=Value` (or `Key+=Value`) line from a unit file.
type Directive struct {
	Section string // enclosing [Unit]/[Service]/[Install]
	Key     string
	Op      string // "=", "+=", or "-="
	Value   string
	Line    int // 1-based line number for raw_ref
	File    string
}

// File is the parsed directives of one unit file, before merging.
type File struct {
	Path string
	Raw  []byte // original content, kept for fingerprints
	Dirs []Directive
}

// listKeys are directives systemd accumulates instead of overriding:
// later files append to earlier values, and every line inside one file
// is kept. Everything else is scalar: the last file that mentions the
// key wins with all of its lines for that key.
var listKeys = map[string]bool{
	"Requires": true, "Wants": true, "After": true, "Before": true,
	"Conflicts": true, "PartOf": true, "BindsTo": true,
	"Requisite": true, "Upholds": true, "PropagatesReloadTo": true,
	"RequiresMountsFor": true, "WantedBy": true, "RequiredBy": true,
	"Also": true, "Alias": true,
	"Environment": true, "EnvironmentFile": true,
	"ExecStartPre": true, "ExecStartPost": true,
	"ExecStop": true, "ExecStopPost": true,
	"ExecReload": true, "ExecCondition": true,
	"OnCalendar": true, "OnBootSec": true, "OnUnitActiveSec": true,
}

// ParseFile parses one unit file body. Full-line comments (#/;) and
// blanks are skipped; other lines must be `Key=Value` inside a section.
func ParseFile(path string, data []byte) (*File, error) {
	f := &File{Path: path, Raw: append([]byte(nil), data...)}
	section := ""
	for i, line := range strings.Split(string(data), "\n") {
		lineNo := i + 1
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section = strings.TrimSpace(t[1 : len(t)-1])
			continue
		}
		key, op, value, ok := splitAssignment(t)
		if !ok {
			continue // not a directive line — tolerated like systemd ignores junk
		}
		f.Dirs = append(f.Dirs, Directive{
			Section: section, Key: key, Op: op,
			Value: value, Line: lineNo, File: path,
		})
	}
	return f, nil
}

// splitAssignment splits "Key=Value", "Key+=Value", "Key-=Value". The
// operator must sit directly before the first "=" so that operators
// inside the value (e.g. "Description=a+=b") stay part of the value.
func splitAssignment(t string) (key, op, value string, ok bool) {
	i := strings.IndexByte(t, '=')
	if i <= 0 {
		return "", "", "", false
	}
	key, op, value = t[:i], "=", t[i+1:]
	if j := len(key) - 1; key[j] == '+' || key[j] == '-' {
		key, op = key[:j], string(key[j])+"="
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return "", "", "", false
	}
	return key, op, strings.TrimSpace(value), true
}

// Merged is the effective configuration of a unit after applying its
// base file and every drop-in, in load order.
type Merged struct {
	Name string // unit name, e.g. nginx.service
	// scalars hold the last file's lines per key; lists concatenate
	// every file in order.
	scalars map[string][]Directive
	lists   map[string][]Directive
	raws    [][]byte // file contents in application order
}

// Merge applies base first, then drop-ins in load order. For scalar
// keys the last file that mentions the key replaces earlier values
// entirely (so a drop-in `ExecStart=` overrides the base); list keys
// append. Subtraction operators ("-=") remove a matching value.
func Merge(name string, files ...*File) *Merged {
	m := &Merged{
		Name:    name,
		scalars: map[string][]Directive{},
		lists:   map[string][]Directive{},
	}
	for _, f := range files {
		if f == nil {
			continue
		}
		m.raws = append(m.raws, f.Raw)
		// Group this file's directives per key so a scalar key with
		// several lines inside one file (e.g. oneshot ExecStart) is
		// kept together and replaced as a unit by the next file.
		perKey := map[string][]Directive{}
		var keys []string
		for _, d := range f.Dirs {
			if _, seen := perKey[d.Key]; !seen {
				keys = append(keys, d.Key)
			}
			perKey[d.Key] = append(perKey[d.Key], d)
		}
		for _, k := range keys {
			lines := perKey[k]
			if listKeys[k] {
				for _, d := range lines {
					m.lists[k] = applyList(m.lists[k], d)
				}
				continue
			}
			m.scalars[k] = nil
			for _, d := range lines {
				m.scalars[k] = applyScalar(m.scalars[k], d)
			}
		}
	}
	return m
}

func applyList(dst []Directive, d Directive) []Directive {
	if d.Op == "-=" {
		return removeValue(dst, d.Value)
	}
	if d.Op == "=" && len(dst) == 0 {
		return append(dst, d)
	}
	if d.Op == "+=" {
		return append(dst, d)
	}
	// "=" on a list key inside a later file: systemd semantics vary per
	// directive; append keeps prior values (documented plan decision).
	return append(dst, d)
}

func applyScalar(dst []Directive, d Directive) []Directive {
	if d.Op == "-=" {
		return removeValue(dst, d.Value)
	}
	// First line of this key in this file replaces anything from
	// earlier files; further lines of the same key in this file append
	// (handles oneshot multi-ExecStart without leaking across files).
	if d.Op == "=" && !scalarStarted(dst, d) {
		return append([]Directive(nil), d)
	}
	return append(dst, d)
}

// scalarStarted reports whether dst already contains a line from the
// same file for this key (used to reset on the first "=" line).
func scalarStarted(dst []Directive, d Directive) bool {
	return len(dst) > 0 && dst[len(dst)-1].File == d.File
}

func removeValue(dst []Directive, v string) []Directive {
	out := dst[:0]
	for _, d := range dst {
		if strings.TrimSpace(d.Value) == v {
			continue
		}
		out = append(out, d)
	}
	return out
}

// Get returns the effective scalar directives for key (all lines of the
// last file that defined it).
func (m *Merged) Get(key string) []Directive { return m.scalars[key] }

// All returns list-type directives for key in merge order.
func (m *Merged) All(key string) []Directive { return m.lists[key] }

// Has reports whether any file defined key.
func (m *Merged) Has(key string) bool {
	return len(m.scalars[key]) > 0 || len(m.lists[key]) > 0
}

// Fingerprint hashes every input file in application order, so the
// value changes when the unit or any drop-in changes.
func (m *Merged) Fingerprint() string {
	h := sha256.New()
	for _, r := range m.raws {
		h.Write(r)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Names returns every distinct key mentioned (sorted) — test helper.
func (m *Merged) Names() []string {
	seen := map[string]bool{}
	for k := range m.scalars {
		seen[k] = true
	}
	for k := range m.lists {
		seen[k] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
