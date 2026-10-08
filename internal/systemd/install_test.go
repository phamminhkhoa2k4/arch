package systemd

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeWriter records unit writes and removals.
type fakeWriter struct {
	files    map[string][]byte
	writeErr error
	removes  []string
}

func newFakeWriter() *fakeWriter { return &fakeWriter{files: map[string][]byte{}} }

func (f *fakeWriter) WriteUnit(path string, contents []byte) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	f.files[path] = contents
	return nil
}

func (f *fakeWriter) RemoveUnit(path string) error {
	f.removes = append(f.removes, path)
	delete(f.files, path)
	return nil
}

// fakeRunner records systemctl invocations and can fail per verb.
type fakeRunner struct {
	calls  [][]string
	failed map[string]error
}

func (f *fakeRunner) Systemctl(_ context.Context, args ...string) error {
	f.calls = append(f.calls, append([]string(nil), args...))
	if err, ok := f.failed[args[0]]; ok {
		return err
	}
	return nil
}

func joined(calls [][]string) []string {
	out := make([]string, 0, len(calls))
	for _, c := range calls {
		out = append(out, strings.Join(c, " "))
	}
	return out
}

func TestRenderUnitWiresDaemonFlags(t *testing.T) {
	got := string(RenderUnit(ServiceSpec{
		Binary: "/usr/local/bin/archaeologist",
		DBPath: "/var/lib/archaeologist/evidence.db",
	}))
	for _, want := range []string{
		"ExecStart=/usr/local/bin/archaeologist observe --daemon --db /var/lib/archaeologist/evidence.db",
		"StandardOutput=journal",
		"Restart=on-failure",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("unit missing %q:\n%s", want, got)
		}
	}
}

func TestRenderUnitQuotesPathsWithSpaces(t *testing.T) {
	got := string(RenderUnit(ServiceSpec{Binary: "/opt/my tools/arch", DBPath: "/tmp/a b.db"}))
	if !strings.Contains(got, `"/opt/my tools/arch" observe --daemon --db "/tmp/a b.db"`) {
		t.Errorf("paths with spaces must be quoted:\n%s", got)
	}
}

func TestInstallServiceEnablesUnit(t *testing.T) {
	w, r := newFakeWriter(), &fakeRunner{}
	err := NewInstall(w, r).InstallService(context.Background(),
		ServiceSpec{Binary: "/bin/arch", DBPath: "/tmp/x.db"})
	if err != nil {
		t.Fatalf("InstallService: %v", err)
	}
	if _, ok := w.files[UnitPath]; !ok {
		t.Fatalf("unit file not written: %v", w.files)
	}
	got := joined(r.calls)
	want := []string{"daemon-reload", "enable --now " + UnitName}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("systemctl calls = %v, want %v", got, want)
	}
}

func TestInstallServiceWriteFailureRunsNoSystemctl(t *testing.T) {
	w, r := newFakeWriter(), &fakeRunner{}
	w.writeErr = errors.New("disk full")
	err := NewInstall(w, r).InstallService(context.Background(),
		ServiceSpec{Binary: "/bin/arch", DBPath: "/tmp/x.db"})
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("err = %v, want the write failure", err)
	}
	if len(r.calls) != 0 {
		t.Errorf("systemctl calls = %v, want none after a write failure", r.calls)
	}
}

func TestInstallServiceRejectsEmptySpec(t *testing.T) {
	w, r := newFakeWriter(), &fakeRunner{}
	if err := NewInstall(w, r).InstallService(context.Background(), ServiceSpec{}); err == nil {
		t.Fatal("empty spec must be rejected")
	}
	if len(r.calls) != 0 || len(w.files) != 0 {
		t.Errorf("rejected spec must leave no state: calls=%v files=%v", r.calls, w.files)
	}
}

func TestUninstallServiceRemovesUnitAndReloads(t *testing.T) {
	w, r := newFakeWriter(), &fakeRunner{}
	w.files[UnitPath] = []byte("x")
	err := NewInstall(w, r).UninstallService(context.Background())
	if err != nil {
		t.Fatalf("UninstallService: %v", err)
	}
	got := joined(r.calls)
	want := []string{"stop " + UnitName, "disable " + UnitName, "daemon-reload"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("systemctl calls = %v, want %v", got, want)
	}
	if _, ok := w.files[UnitPath]; ok {
		t.Error("unit file must be gone")
	}
}

func TestUninstallServiceIdempotentWhenUnitAlreadyGone(t *testing.T) {
	w, r := newFakeWriter(), &fakeRunner{}
	// Second run: systemctl stop/disable fail (unit not loaded), the
	// file is already absent — everything must still succeed.
	r.failed = map[string]error{
		"stop":    errors.New("Unit not loaded"),
		"disable": errors.New("Unit not loaded"),
	}
	if err := NewInstall(w, r).UninstallService(context.Background()); err != nil {
		t.Fatalf("second uninstall: %v", err)
	}
	if len(w.removes) != 1 {
		t.Errorf("removes = %v, want the file removal attempted once", w.removes)
	}
	if last := joined(r.calls); last[len(last)-1] != "daemon-reload" {
		t.Errorf("calls = %v, want daemon-reload last", last)
	}
}
