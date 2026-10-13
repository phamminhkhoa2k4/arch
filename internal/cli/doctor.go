package cli

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"

	"archaeologist/internal/procfs"
)

// doctorCheck is one access probe. fail and hint carry the user-facing
// wording; pass is the short line for a successful probe.
type doctorCheck struct {
	pass string
	fail string
	hint string
	run  func() error
}

// realChecks returns the probes against the live system. Every probe is
// read-only (stat / read-dir / connect-and-close), never a write.
func realChecks() []doctorCheck {
	return []doctorCheck{
		{
			pass: "Foreign-user processes (read /proc/<pid>/fd)",
			fail: "Cannot read other users' processes",
			hint: "run with sudo/root — listener → PID mapping fails for other users' processes otherwise",
			run:  checkForeignProcFD,
		},
		{
			pass: "Docker socket",
			fail: "Cannot access the Docker socket",
			hint: "sudo usermod -aG docker $USER then log in again, or run with sudo",
			run:  checkUnixSocket("/var/run/docker.sock"),
		},
		{
			pass: "D-Bus systemd",
			fail: "Cannot access systemd D-Bus",
			hint: "run with sudo — needs access to /run/dbus/system_bus_socket",
			run:  checkUnixSocket("/run/dbus/system_bus_socket"),
		},
		{
			pass: "Nginx configs (/etc/nginx)",
			fail: "Cannot read /etc/nginx",
			hint: "run with sudo or grant read access — the nginx collector needs to list the config",
			run: func() error {
				_, err := os.ReadDir("/etc/nginx")
				return err
			},
		},
		{
			pass: "Systemd journal (journalctl)",
			fail: "Cannot run journalctl",
			hint: "install systemd or add the user to the systemd-journal group",
			run: func() error {
				return exec.Command("journalctl", "-n", "1", "--no-pager").Run()
			},
		},
		{
			pass: "Log paths (/var/log)",
			fail: "Cannot read /var/log",
			hint: "add the user to the adm group (sudo usermod -aG adm $USER) or run with sudo",
			run: func() error {
				_, err := os.ReadDir("/var/log")
				return err
			},
		},
		{
			pass: "Cron paths (/etc/crontab, /etc/cron.d)",
			fail: "Cannot read cron paths (/etc/crontab, /etc/cron.d)",
			hint: "run with sudo — /etc/crontab is usually root-only",
			run: func() error {
				if _, err := os.ReadFile("/etc/crontab"); err != nil {
					return err
				}
				_, err := os.ReadDir("/etc/cron.d")
				return err
			},
		},
	}
}

// errNoForeignPID means the system has no process owned by another user —
// not an access failure: listener mapping can never be blocked by it.
var errNoForeignPID = errors.New("no foreign pid")

// checkForeignProcFD verifies the /proc access a non-root user genuinely
// lacks: the fd directory of a process owned by another user. Reading it
// is what listener→PID mapping needs, so its absence is real blindness
// the scan reports as blind spots. No foreign process at all means
// nothing to be blind about — the probe passes.
func checkForeignProcFD() error {
	target, err := foreignPID()
	if errors.Is(err, errNoForeignPID) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = os.ReadDir(fmt.Sprintf("/proc/%d/fd", target))
	return err
}

// foreignPID finds a pid owned by a uid different from the current user.
func foreignPID() (int, error) {
	me := os.Getuid()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			continue
		}
		uid := procfs.ParseUID(status)
		if uid >= 0 && uid != me {
			return pid, nil
		}
	}
	return 0, errNoForeignPID
}

// checkUnixSocket reports whether path exists and accepts a connection —
// enough to know Docker/D-Bus is usable, without issuing any API call.
func checkUnixSocket(path string) func() error {
	return func() error {
		conn, err := net.Dial("unix", path)
		if err != nil {
			return err
		}
		return conn.Close()
	}
}

// runDoctor prints one line per check plus the final summary line stating
// whether every source is available.
func runDoctor(w io.Writer, checks []doctorCheck) bool {
	_, _ = fmt.Fprintln(w, "Checking source access (read-only):")
	available := true
	for _, c := range checks {
		if err := c.run(); err != nil {
			available = false
			_, _ = fmt.Fprintf(w, "✗ %s\n   Hint: %s\n", c.fail, c.hint)
			continue
		}
		_, _ = fmt.Fprintf(w, "✓ %s\n", c.pass)
	}
	if available {
		_, _ = fmt.Fprintln(w, "✅ All sources available")
	}
	return available
}
