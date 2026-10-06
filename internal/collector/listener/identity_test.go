package listener

import "testing"

func TestParseIdentityKey(t *testing.T) {
	proto, addr, port, inode, err := ParseIdentityKey("listener|tcp|0.0.0.0|8081|987654321")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if proto != "tcp" || addr != "0.0.0.0" || port != 8081 || inode != 987654321 {
		t.Errorf("got %q %q %d %d", proto, addr, port, inode)
	}

	// IPv6 addresses contain ':' but never '|'.
	_, addr6, _, _, err := ParseIdentityKey("listener|tcp6|::|80|42")
	if err != nil || addr6 != "::" {
		t.Errorf("ipv6 addr = %q err=%v", addr6, err)
	}

	// unix sockets share the same shape.
	protoU, _, portU, _, err := ParseIdentityKey("listener|unix|-|0|7")
	if err != nil || protoU != "unix" || portU != 0 {
		t.Errorf("unix parse = %q %d err=%v", protoU, portU, err)
	}
}

func TestParseIdentityKeyRejectsMalformed(t *testing.T) {
	bad := []string{
		"",
		"listener|tcp|0.0.0.0|8081",          // too few fields
		"listener|tcp|0.0.0.0|8081|1|extra",  // too many
		"process|tcp|0.0.0.0|8081|1",         // wrong prefix
		"listener|tcp|0.0.0.0|notaport|1",    // bad port
		"listener|tcp|0.0.0.0|80|notaninode", // bad inode
	}
	for _, k := range bad {
		if _, _, _, _, err := ParseIdentityKey(k); err == nil {
			t.Errorf("ParseIdentityKey(%q) must fail", k)
		}
	}
}
