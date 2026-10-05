package procfs

import (
	"strings"
	"testing"
)

// Real /proc/1/stat from an Ubuntu 24.04 host.
const statSystemd = "1 (systemd) S 0 1 1 0 -1 4194560 17194 1563072 13 984 127 105 " +
	"2451 1324 20 0 1 0 449 171622400 3114 18446744073709551615 1 1 0 0 0 0 " +
	"671173123 4096 1260 0 0 0 17 3 0 0 0 0 0 0 0 0 0 0 0 0 0"

func TestParseStat(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    Stat
		wantErr bool
	}{
		{"real systemd row", statSystemd,
			Stat{PID: 1, Comm: "systemd", State: "S", PPID: 0, StartTicks: 449}, false},
		{"comm with spaces", "1234 (Web Content) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 778811 0 0 0 0",
			Stat{PID: 1234, Comm: "Web Content", State: "S", PPID: 1, StartTicks: 778811}, false},
		{"comm with closing paren", "9 (a ) b) R 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 5 0 0 0 0",
			Stat{PID: 9, Comm: "a ) b", State: "R", PPID: 1, StartTicks: 5}, false},
		{"missing parens", "1234 S 0 0 0", Stat{}, true},
		{"too few fields after comm", "1 (x) S 0", Stat{}, true},
		{"non numeric pid", "abc (x) S 0 0 0", Stat{}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseStat([]byte(tc.in))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("got %+v, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestIdentityKeyIncludesStartTicks(t *testing.T) {
	a := IdentityKey(123, 449)
	b := IdentityKey(123, 450)
	if a == b {
		t.Errorf("same pid with different start ticks must differ: %s", a)
	}
	if !strings.HasPrefix(a, "process|123|449") {
		t.Errorf("unexpected key format: %s", a)
	}
}

func TestParseCgroup(t *testing.T) {
	id64 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tests := []struct {
		name string
		in   string
		want Cgroup
	}{
		{"v2 service", "0::/system.slice/nginx.service\n",
			Cgroup{Path: "/system.slice/nginx.service", Unit: "nginx.service"}},
		{"v2 docker scope", "0::/system.slice/docker-" + id64 + ".scope\n",
			Cgroup{Path: "/system.slice/docker-" + id64 + ".scope",
				Unit: "docker-" + id64 + ".scope", ContainerID: id64}},
		{"v1 docker devices line", "11:devices:/docker/" + id64 + "\n",
			Cgroup{Path: "/docker/" + id64, ContainerID: id64}},
		{"hybrid prefers systemd line",
			"1:systemd:/system.slice/ssh.service\n0::/system.slice/ssh.service\n",
			Cgroup{Path: "/system.slice/ssh.service", Unit: "ssh.service"}},
		{"v1 no systemd controller falls to first",
			"3:cpu,cpuacct:/user.slice/user-1000.slice\n4:memory:/user.slice\n",
			Cgroup{Path: "/user.slice/user-1000.slice", Unit: "user-1000.slice"}},
		{"root path has no unit", "0::/\n", Cgroup{Path: "/", Unit: ""}},
		{"empty input", "", Cgroup{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseCgroup([]byte(tc.in))
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestParseUID(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{"typical", "Name:\tsshd\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n", 0},
		{"user process", "Name:\tbash\nUid:\t1000\t1000\t1000\t1000\n", 1000},
		{"missing", "Name:\tsshd\nGid:\t0\t0\t0\t0\n", -1},
		{"empty", "", -1},
		{"unparsable", "Uid:\tnotanumber\t0\t0\t0\n", -1},
		{"no fields", "Uid:\n", -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseUID([]byte(tc.in)); got != tc.want {
				t.Errorf("ParseUID(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseTCPTable(t *testing.T) {
	tcpHeader := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	// Real row: 127.0.0.53:53 LISTEN, uid 101, inode 13403.
	tcpRow := "   0: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 13403 1 0000000000000000 100 0 0 10 5\n"

	socks, err := ParseTCPTable("tcp", []byte(tcpHeader+tcpRow))
	if err != nil {
		t.Fatalf("parse tcp: %v", err)
	}
	if len(socks) != 1 {
		t.Fatalf("got %d socks, want 1", len(socks))
	}
	s := socks[0]
	if s.Addr != "127.0.0.53" || s.Port != 53 || !s.IsLISTEN() || s.UID != 101 || s.Inode != 13403 {
		t.Errorf("got %+v, want 127.0.0.53:53 LISTEN uid=101 inode=13403", s)
	}

	t.Run("ipv6 any-address listener", func(t *testing.T) {
		row := "   0: 00000000000000000000000000000000:1F92 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1546 1 0000000000000000 100 0 0 10 0\n"
		got, err := ParseTCPTable("tcp6", []byte(row))
		if err != nil {
			t.Fatalf("parse tcp6: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d socks, want 1", len(got))
		}
		if got[0].Addr != "::" || got[0].Port != 8082 || !got[0].IsLISTEN() {
			t.Errorf("got %+v, want :::8082 LISTEN", got[0])
		}
	})

	t.Run("ipv6 mapped ipv4 address decodes word-wise", func(t *testing.T) {
		addr, port, err := decodeAddrPort("0000000000000000FFFF00000100007F:1F90", true)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		// net.IP canonicalises v4-mapped to the dotted quad; tcp vs tcp6 in
		// the identity key keeps the two listeners distinct regardless.
		if addr != "127.0.0.1" || port != 8080 {
			t.Errorf("got %s:%d, want 127.0.0.1:8080", addr, port)
		}
	})

	t.Run("established socket is not a listener", func(t *testing.T) {
		row := "   1: 3500007F:0035 3600007F:0035 01 00000000:00000000 00:00000000 00000000   101        0 13404 1 0000000000000000 100 0 0 10 0\n"
		got, err := ParseTCPTable("tcp", []byte(row))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got[0].IsLISTEN() {
			t.Errorf("state 01 must not be a listener: %+v", got[0])
		}
	})
}
