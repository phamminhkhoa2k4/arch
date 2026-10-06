package listener

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseIdentityKey splits a listener identity key
// (listener|<proto>|<addr>|<port>|<inode>) back into its parts — the
// inverse of the key Collect builds. Other collectors (docker) use it
// instead of re-implementing the format.
func ParseIdentityKey(key string) (proto, addr string, port int, inode uint64, err error) {
	parts := strings.Split(key, "|")
	if len(parts) != 5 || parts[0] != "listener" {
		return "", "", 0, 0, fmt.Errorf("invalid listener identity key %q", key)
	}
	p, err := strconv.ParseUint(parts[3], 10, 32)
	if err != nil {
		return "", "", 0, 0, fmt.Errorf("invalid listener identity key %q: port: %w", key, err)
	}
	in, err := strconv.ParseUint(parts[4], 10, 64)
	if err != nil {
		return "", "", 0, 0, fmt.Errorf("invalid listener identity key %q: inode: %w", key, err)
	}
	return parts[1], parts[2], int(p), in, nil
}
