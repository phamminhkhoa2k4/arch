package systemd

import (
	"errors"
	"os"
	"sort"
	"strings"
)

// FS abstracts filesystem access so the loader can run against the real
// disk or a fake in tests.
type FS interface {
	ReadFile(path string) ([]byte, error)
	ReadDir(path string) ([]string, error)
}

// OSFS reads the real filesystem.
type OSFS struct{}

func (OSFS) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

func (OSFS) ReadDir(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}

// LoadPath is systemd's unit load order (lowest priority first).
var LoadPath = []string{
	"/usr/lib/systemd/system",
	"/run/systemd/system",
	"/etc/systemd/system",
}

// Loader resolves a unit's base file plus its drop-ins.
type Loader struct {
	fs   FS
	dirs []string
}

// NewLoader loads units through fs using the standard load path.
func NewLoader(fs FS) *Loader { return &Loader{fs: fs, dirs: LoadPath} }

// LoadDir returns the loader (test helper for a custom load path).
func LoadDir(fs FS, dirs ...string) *Loader { return &Loader{fs: fs, dirs: dirs} }

// ReadFile exposes the loader's filesystem (used to inspect ExecStart
// targets on disk).
func (l *Loader) ReadFile(path string) ([]byte, error) { return l.fs.ReadFile(path) }

// Load merges the base unit file with every applicable drop-in. For an
// instantiated unit (foo@bar.service) the template file (foo@.service)
// is the base when no instance file exists, and template drop-ins are
// merged before instance drop-ins — systemd's load order. fragment
// (from D-Bus) wins as the base path when present; otherwise the load
// path is searched. A missing base file returns an IsNotFound error —
// transient units legitimately have none.
func (l *Loader) Load(name, fragment string) (*Merged, error) {
	tmpl := templateName(name)
	basePath := fragment
	if basePath == "" {
		basePath = l.search(name)
		if basePath == "" && tmpl != "" {
			basePath = l.search(tmpl)
		}
	}
	if basePath == "" {
		return nil, &errNotFound{name: name}
	}
	baseData, err := l.fs.ReadFile(basePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && fragment != "" {
			return nil, &errNotFound{name: name}
		}
		return nil, err
	}
	base, err := ParseFile(basePath, baseData)
	if err != nil {
		return nil, err
	}

	// Drop-ins: template directory first, then the instance's own.
	dropinUnits := []string{name}
	if tmpl != "" && tmpl != name {
		dropinUnits = []string{tmpl, name}
	}
	files := []*File{base}
	for _, unit := range dropinUnits {
		for _, dir := range l.dirs {
			drops, err := l.dropins(dir, unit)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue // unit.d directory absent — normal
				}
				return nil, err
			}
			files = append(files, drops...)
		}
	}
	return Merge(name, files...), nil
}

// search returns the first load-path hit for unit, or "".
func (l *Loader) search(unit string) string {
	for _, d := range l.dirs {
		if _, err := l.fs.ReadFile(d + "/" + unit); err == nil {
			return d + "/" + unit
		}
	}
	return ""
}

// templateName maps foo@bar.service → foo@.service ("" when the unit
// is not an instance or already a template).
func templateName(name string) string {
	i := strings.IndexByte(name, '@')
	if i < 0 {
		return ""
	}
	dot := strings.LastIndexByte(name, '.')
	if dot <= i+1 {
		return ""
	}
	tmpl := name[:i+1] + name[dot:]
	if tmpl == name {
		return ""
	}
	return tmpl
}

// dropins reads `<dir>/<name>.d/*.conf` sorted by name.
func (l *Loader) dropins(dir, name string) ([]*File, error) {
	ddir := dir + "/" + name + ".d"
	entries, err := l.fs.ReadDir(ddir)
	if err != nil {
		return nil, err
	}
	var confs []string
	for _, e := range entries {
		if strings.HasSuffix(e, ".conf") {
			confs = append(confs, e)
		}
	}
	sort.Strings(confs)
	var out []*File
	for _, c := range confs {
		p := ddir + "/" + c
		data, err := l.fs.ReadFile(p)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		f, err := ParseFile(p, data)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}
