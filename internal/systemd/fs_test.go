package systemd

import (
	"os"
	"testing"
)

type fakeFS struct {
	files map[string]string
	dirs  map[string][]string
}

func newFakeFS() *fakeFS {
	return &fakeFS{files: map[string]string{}, dirs: map[string][]string{}}
}

func (f *fakeFS) ReadFile(p string) ([]byte, error) {
	v, ok := f.files[p]
	if !ok {
		return nil, &os.PathError{Op: "open", Path: p, Err: os.ErrNotExist}
	}
	return []byte(v), nil
}

func (f *fakeFS) ReadDir(p string) ([]string, error) {
	v, ok := f.dirs[p]
	if !ok {
		return nil, &os.PathError{Op: "open", Path: p, Err: os.ErrNotExist}
	}
	return v, nil
}

// Base file in the distro dir, drop-in in /etc overrides ExecStart.
func TestLoaderMergesDropInsInLoadOrder(t *testing.T) {
	fs := newFakeFS()
	fs.files["/usr/lib/systemd/system/x.service"] =
		"[Service]\nExecStart=/old/run.sh\nEnvironment=BASE=1\n"
	fs.dirs["/etc/systemd/system/x.service.d"] = []string{"override.conf"}
	fs.files["/etc/systemd/system/x.service.d/override.conf"] =
		"[Service]\nExecStart=/new/run.sh\n"

	m, err := LoadDir(fs, "/usr/lib/systemd/system", "/etc/systemd/system").
		Load("x.service", "")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := m.Get("ExecStart")
	if len(got) != 1 || got[0].Value != "/new/run.sh" {
		t.Errorf("ExecStart = %+v, want /new/run.sh from drop-in", got)
	}
	if len(m.All("Environment")) != 1 {
		t.Error("base Environment must survive")
	}
}

// An explicit fragment path from D-Bus wins as the base file.
func TestLoaderUsesFragmentPath(t *testing.T) {
	fs := newFakeFS()
	fs.files["/run/systemd/transient/y.service"] = "[Service]\nExecStart=/t\n"

	m, err := NewLoader(fs).Load("y.service", "/run/systemd/transient/y.service")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(m.Get("ExecStart")) != 1 {
		t.Error("fragment not loaded")
	}
}

// No base file anywhere → IsNotFound (transient unit, not an error).
func TestLoaderNotFound(t *testing.T) {
	fs := newFakeFS()
	_, err := NewLoader(fs).Load("ghost.service", "")
	if err == nil || !IsNotFound(err) {
		t.Fatalf("err = %v, want IsNotFound", err)
	}

	// Fragment recorded but file since deleted also counts as not found.
	_, err = NewLoader(fs).Load("gone.service", "/lib/systemd/system/gone.service")
	if err == nil || !IsNotFound(err) {
		t.Fatalf("deleted fragment err = %v, want IsNotFound", err)
	}
}

// An instantiated unit loads from its template file, template drop-ins
// first, then instance drop-ins — systemd's merge order.
func TestLoaderInstantiatedUnitUsesTemplate(t *testing.T) {
	fs := newFakeFS()
	fs.files["/usr/lib/systemd/system/work@.service"] =
		"[Service]\nExecStart=/tpl/run.sh\nEnvironment=MODE=tpl\n"
	fs.dirs["/etc/systemd/system/work@.service.d"] = []string{"10-tpl.conf"}
	fs.files["/etc/systemd/system/work@.service.d/10-tpl.conf"] =
		"[Service]\nEnvironment=FROM_TPL=1\n"
	fs.dirs["/etc/systemd/system/work@7.service.d"] = []string{"20-inst.conf"}
	fs.files["/etc/systemd/system/work@7.service.d/20-inst.conf"] =
		"[Service]\nEnvironment=INST=7\nExecStart=/inst/run.sh\n"

	m, err := NewLoader(fs).Load("work@7.service", "")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Instance drop-in overrides the template ExecStart.
	exec := m.Get("ExecStart")
	if len(exec) != 1 || exec[0].Value != "/inst/run.sh" {
		t.Errorf("ExecStart = %+v, want instance override", exec)
	}
	env := m.All("Environment")
	got := map[string]bool{}
	for _, e := range env {
		got[e.Value] = true
	}
	for _, want := range []string{"MODE=tpl", "FROM_TPL=1", "INST=7"} {
		if !got[want] {
			t.Errorf("Environment missing %s: %+v", want, env)
		}
	}
}

// The template itself (work@.service) still loads normally.
func TestLoaderTemplateItself(t *testing.T) {
	fs := newFakeFS()
	fs.files["/usr/lib/systemd/system/work@.service"] = "[Service]\nExecStart=/tpl/run.sh\n"
	m, err := NewLoader(fs).Load("work@.service", "")
	if err != nil {
		t.Fatalf("load template: %v", err)
	}
	if len(m.Get("ExecStart")) != 1 {
		t.Error("template base not loaded")
	}
}
