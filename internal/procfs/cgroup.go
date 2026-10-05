package procfs

import (
	"regexp"
	"strings"
)

// Cgroup is the parsed view of /proc/<pid>/cgroup.
type Cgroup struct {
	Path        string // primary cgroup path (v2 preferred, systemd v1 next)
	Unit        string // systemd unit/scope basename, "" when not derivable
	ContainerID string // 64-hex container id, "" when not present
}

// hex64 matches a container id in any cgroup path layout:
// /docker/<id>, /system.slice/docker-<id>.scope, /kubepods/.../<id>.
// Boundaries exclude substrings of longer hex runs.
var hex64 = regexp.MustCompile(`(?:^|[^0-9a-f])([0-9a-f]{64})(?:[^0-9a-f]|$)`)

// ParseCgroup parses /proc/<pid>/cgroup for both cgroup v1 and v2.
//
// v1 lines: "hier-id:controller-list:path" (e.g. "1:systemd:/system.slice/x.service").
// v2 lines: "0::path". The v2 path wins when both exist (hybrid mode);
// otherwise the systemd controller line is preferred for Unit extraction.
func ParseCgroup(data []byte) Cgroup {
	var (
		v2Path      string
		systemdPath string
		firstPath   string
	)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		path := parts[2]
		if firstPath == "" {
			firstPath = path
		}
		if parts[0] == "0" && parts[1] == "" {
			v2Path = path
		}
		if parts[1] == "systemd" || strings.Contains(parts[1], "name=systemd") {
			systemdPath = path
		}
	}

	// Priority: systemd controller line (unit names live there on v1/hybrid),
	// then v2, then the first readable line.
	path := systemdPath
	if path == "" {
		path = v2Path
	}
	if path == "" {
		path = firstPath
	}

	return Cgroup{
		Path:        path,
		Unit:        unitName(path),
		ContainerID: containerID(path),
	}
}

// unitName returns the last path segment when it looks like a unit
// ("nginx.service", "docker-<id>.scope"); "" for "/" or plain dirs.
func unitName(path string) string {
	path = strings.TrimRight(path, "/")
	if path == "" {
		return ""
	}
	base := path[strings.LastIndexByte(path, '/')+1:]
	if strings.Contains(base, ".") {
		return base
	}
	return ""
}

// containerID extracts a 64-hex container id from a cgroup path, "" if none.
func containerID(path string) string {
	m := hex64.FindStringSubmatch(path)
	if m == nil {
		return ""
	}
	return m[1]
}
