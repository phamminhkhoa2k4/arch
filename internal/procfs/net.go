package procfs

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Sock is one socket row from /proc/net/tcp or /proc/net/tcp6.
type Sock struct {
	Proto string // "tcp" or "tcp6" — set by the parser caller
	Addr  string // numeric IP (decoded from the hex little-endian form)
	Port  int
	State string // hex state, "0A" = LISTEN
	UID   int
	Inode uint64
	Sl    int // socket line number (field "sl") for raw_ref
}

// IsLISTEN reports whether the socket is a listener (state 0A).
func (s Sock) IsLISTEN() bool { return s.State == "0A" }

// ParseTCPTable parses /proc/net/tcp or /proc/net/tcp6.
//
// Row layout (whitespace-split): sl local rem st tx:rx tr:when retrnsmt uid
// timeout inode ... — inode sits at index 9, uid at 7.
func ParseTCPTable(proto string, data []byte) ([]Sock, error) {
	lines := strings.Split(string(data), "\n")
	var socks []Sock
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "sl") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 10 {
			continue // header artifact / truncated line — not a socket
		}
		sl, err := strconv.Atoi(strings.TrimSuffix(f[0], ":"))
		if err != nil {
			continue
		}
		addr, port, err := decodeAddrPort(f[1], proto == "tcp6")
		if err != nil {
			return nil, fmt.Errorf("%s sl=%d: %w", proto, sl, err)
		}
		uid, err := strconv.Atoi(f[7])
		if err != nil {
			return nil, fmt.Errorf("%s sl=%d uid: %w", proto, sl, err)
		}
		inode, err := strconv.ParseUint(f[9], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s sl=%d inode: %w", proto, sl, err)
		}
		socks = append(socks, Sock{
			Proto: proto, Addr: addr, Port: port, State: f[3],
			UID: uid, Inode: inode, Sl: sl,
		})
	}
	return socks, nil
}

// decodeAddrPort converts "0100007F:1F90" (or a 32-hex IPv6 + port) to a
// numeric address and port. The kernel stores addresses little-endian per
// 32-bit word: 0100007F → 127.0.0.1, word-wise for IPv6.
func decodeAddrPort(field string, ipv6 bool) (string, int, error) {
	i := strings.LastIndexByte(field, ':')
	if i < 0 {
		return "", 0, fmt.Errorf("bad addr:port %q", field)
	}
	hexIP, hexPort := field[:i], field[i+1:]

	port64, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return "", 0, fmt.Errorf("port %q: %w", hexPort, err)
	}

	if !ipv6 {
		if len(hexIP) != 8 {
			return "", 0, fmt.Errorf("ipv4 hex %q: want 8 chars", hexIP)
		}
		b, err := hexBytes(hexIP)
		if err != nil {
			return "", 0, err
		}
		// b[0..3] is one little-endian word → reverse to network order.
		ip := fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
		return ip, int(port64), nil
	}

	if len(hexIP) != 32 {
		return "", 0, fmt.Errorf("ipv6 hex %q: want 32 chars", hexIP)
	}
	b, err := hexBytes(hexIP)
	if err != nil {
		return "", 0, err
	}
	// Four little-endian 32-bit words → network byte order.
	out := make([]byte, 16)
	for w := 0; w < 4; w++ {
		base := w * 4
		out[base+0] = b[base+3]
		out[base+1] = b[base+2]
		out[base+2] = b[base+1]
		out[base+3] = b[base+0]
	}
	return net.IP(out).String(), int(port64), nil
}

func hexBytes(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd hex %q", s)
	}
	out := make([]byte, 0, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		v, err := strconv.ParseUint(s[i:i+2], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("hex %q: %w", s, err)
		}
		out = append(out, byte(v))
	}
	return out, nil
}
