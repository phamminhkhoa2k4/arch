package procfs

import (
	"strconv"
	"strings"
)

// ParseUID extracts the real uid from /proc/<pid>/status
// ("Uid:\treal\teffective\tsaved\tfs"), returning -1 when absent or
// unparsable so callers never guess a user.
func ParseUID(status []byte) int {
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
		if len(fields) == 0 {
			return -1
		}
		uid, err := strconv.Atoi(fields[0])
		if err != nil {
			return -1
		}
		return uid
	}
	return -1
}
