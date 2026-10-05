// Package procfs parses Linux /proc files.
//
// Parsers are pure functions over byte slices so tests never depend on the
// host's /proc; Reader abstracts file access for collectors.
package procfs

import (
	"os"
	"sort"
)

// Reader abstracts filesystem access to /proc.
type Reader interface {
	// ReadDir returns entry names directly under path.
	ReadDir(path string) ([]string, error)
	// ReadFile returns the contents of path.
	ReadFile(path string) ([]byte, error)
	// Readlink returns the link target of path.
	Readlink(path string) (string, error)
}

// OSReader reads the real /proc filesystem.
type OSReader struct{}

func (OSReader) ReadDir(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}

func (OSReader) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (OSReader) Readlink(path string) (string, error) {
	return os.Readlink(path)
}

// IsNotExist reports whether err means the path vanished (process raced
// away during a scan — expected, not an error).
func IsNotExist(err error) bool {
	return os.IsNotExist(err)
}

// IsPermission reports whether err is EACCES/EPERM.
func IsPermission(err error) bool {
	return os.IsPermission(err)
}

// isDigitASCII avoids importing strconv for pid filtering.
func isDigitASCII(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// PIDNames filters ReadDir output of /proc to numeric pid entries.
func PIDNames(names []string) []string {
	var pids []string
	for _, n := range names {
		if isDigitASCII(n) {
			pids = append(pids, n)
		}
	}
	return pids
}
