package procfs

import (
	"fmt"
	"strconv"
	"strings"
)

// Stat is the subset of /proc/<pid>/stat the collectors need.
type Stat struct {
	PID        int
	Comm       string // executable name, may contain spaces and parentheses
	State      string
	PPID       int
	StartTicks uint64 // clock ticks after boot — stable while the process lives
}

// fieldStarttime is the index of starttime among the fields following ") ".
// Fields: state(0) ppid(1) pgrp(2) session(3) tty(4) tpgid(5) flags(6) ...
// itrealvalue(18) starttime(19).
const fieldStarttime = 19

// ParseStat parses /proc/<pid>/stat.
//
// comm is delimited by the FIRST '(' and the LAST ')' so names like
// "Web Content" or "a ) b" parse correctly.
func ParseStat(data []byte) (Stat, error) {
	line := strings.TrimSpace(string(data))
	open := strings.IndexByte(line, '(')
	close := strings.LastIndexByte(line, ')')
	if open < 0 || close < 0 || close < open {
		return Stat{}, fmt.Errorf("parse stat: missing comm parentheses in %q", line)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(line[:open]))
	if err != nil {
		return Stat{}, fmt.Errorf("parse stat: pid: %w", err)
	}
	comm := line[open+1 : close]

	rest := strings.Fields(line[close+1:])
	// state ppid ... starttime need at least 20 fields after comm.
	if len(rest) <= fieldStarttime {
		return Stat{}, fmt.Errorf("parse stat: %d fields after comm, want >%d", len(rest), fieldStarttime)
	}
	ppid, err := strconv.Atoi(rest[1])
	if err != nil {
		return Stat{}, fmt.Errorf("parse stat: ppid: %w", err)
	}
	start, err := strconv.ParseUint(rest[fieldStarttime], 10, 64)
	if err != nil {
		return Stat{}, fmt.Errorf("parse stat: starttime: %w", err)
	}
	return Stat{PID: pid, Comm: comm, State: rest[0], PPID: ppid, StartTicks: start}, nil
}

// IdentityKey returns the deterministic identity of a process within a scan
// (pid alone is reused after restart; start_ticks disambiguates). Shared by
// the process and listener collectors so cross-collector edges resolve.
func IdentityKey(pid int, startTicks uint64) string {
	return fmt.Sprintf("process|%d|%d", pid, startTicks)
}
