package systemd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// UnitName is the daemon unit installed by observe install-service.
const UnitName = "archaeologist-observe.service"

// UnitPath is where that unit file lives.
const UnitPath = "/etc/systemd/system/" + UnitName

// UnitWriter persists or removes the unit file. Implementations must
// treat a missing file on removal as success so uninstall stays
// idempotent.
type UnitWriter interface {
	WriteUnit(path string, contents []byte) error
	RemoveUnit(path string) error
}

// Runner executes systemctl verbs.
type Runner interface {
	Systemctl(ctx context.Context, args ...string) error
}

// ServiceSpec is the daemon wiring baked into the unit file.
type ServiceSpec struct {
	Binary string
	DBPath string
}

// RenderUnit builds the unit file: foreground observe loop run under
// systemd (D1 — no double fork), logs straight to the journal.
func RenderUnit(spec ServiceSpec) []byte {
	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=Archaeologist observation daemon\n")
	b.WriteString("After=network.target\n")
	b.WriteString("\n[Service]\n")
	b.WriteString("Type=simple\n")
	fmt.Fprintf(&b, "ExecStart=%s observe --daemon --db %s\n",
		quoteIfNeeded(spec.Binary), quoteIfNeeded(spec.DBPath))
	b.WriteString("Restart=on-failure\n")
	b.WriteString("RestartSec=5\n")
	b.WriteString("StandardOutput=journal\n")
	b.WriteString("StandardError=journal\n")
	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return []byte(b.String())
}

// quoteIfNeeded wraps a path for systemd's ExecStart grammar.
func quoteIfNeeded(p string) string {
	if strings.ContainsAny(p, " \t") {
		return `"` + p + `"`
	}
	return p
}

// Install creates or removes the observation service through the
// injected writer and runner (fakeable in tests).
type Install struct {
	writer UnitWriter
	runner Runner
}

// NewInstall returns an installer backed by writer and runner.
func NewInstall(w UnitWriter, r Runner) *Install {
	return &Install{writer: w, runner: r}
}

// InstallService writes the unit, reloads systemd and enables it
// now. A write failure stops before any systemctl call: the machine
// keeps its previous state instead of half-installing.
func (i *Install) InstallService(ctx context.Context, spec ServiceSpec) error {
	if spec.Binary == "" || spec.DBPath == "" {
		return fmt.Errorf("cần đường dẫn binary và db để tạo unit")
	}
	if err := i.writer.WriteUnit(UnitPath, RenderUnit(spec)); err != nil {
		return fmt.Errorf("ghi unit %s: %w", UnitPath, err)
	}
	if err := i.runner.Systemctl(ctx, "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	if err := i.runner.Systemctl(ctx, "enable", "--now", UnitName); err != nil {
		return fmt.Errorf("systemctl enable --now: %w", err)
	}
	return nil
}

// UninstallService stops and disables the service, removes the unit
// file and reloads. stop/disable are best-effort so a second run over
// an already removed unit still succeeds; the file removal and the
// reload are hard requirements.
func (i *Install) UninstallService(ctx context.Context) error {
	_ = i.runner.Systemctl(ctx, "stop", UnitName)
	_ = i.runner.Systemctl(ctx, "disable", UnitName)
	if err := i.writer.RemoveUnit(UnitPath); err != nil {
		return fmt.Errorf("xóa unit %s: %w", UnitPath, err)
	}
	if err := i.runner.Systemctl(ctx, "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	return nil
}

// OSUnitWriter writes unit files on the real filesystem.
type OSUnitWriter struct{}

// NewOSUnitWriter returns the filesystem-backed writer.
func NewOSUnitWriter() OSUnitWriter { return OSUnitWriter{} }

// WriteUnit stores the unit at 0644 (systemd's expected mode).
func (OSUnitWriter) WriteUnit(path string, contents []byte) error {
	return os.WriteFile(path, contents, 0o644)
}

// RemoveUnit deletes the unit file; absence counts as success.
func (OSUnitWriter) RemoveUnit(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ExecRunner runs systemctl on the host.
type ExecRunner struct{}

// NewExecRunner returns the systemctl-backed runner.
func NewExecRunner() ExecRunner { return ExecRunner{} }

// Systemctl runs one systemctl invocation with combined output in
// the error message on failure.
func (ExecRunner) Systemctl(ctx context.Context, args ...string) error {
	argv := append([]string{"systemctl"}, args...)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	if msg := strings.TrimSpace(string(out)); msg != "" {
		return fmt.Errorf("%w: %s", err, msg)
	}
	return err
}
