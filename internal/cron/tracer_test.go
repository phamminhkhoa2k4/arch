package cron

import (
	"testing"
)

func TestCommandHead(t *testing.T) {
	cases := map[string]string{
		"/opt/lab/scripts/backup.sh":   "/opt/lab/scripts/backup.sh",
		"FOO=bar /opt/lab/scripts/x":   "/opt/lab/scripts/x",
		"A=1 B=2 redis-cli -h 127.0.0.1": "redis-cli",
		"$BACKUP_CMD arg":              "$BACKUP_CMD",
		"  spaced/path.sh  ":           "spaced/path.sh",
		"":                             "",
	}
	for in, want := range cases {
		if got := CommandHead(in); got != want {
			t.Errorf("CommandHead(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCommandRefs(t *testing.T) {
	cases := []struct {
		cmd  string
		line int
		kind string
		val  string
		unrs bool
	}{
		{"/opt/lab/scripts/backup.sh arg", 7, RefPath, "/opt/lab/scripts/backup.sh", false},
		{"systemctl start --no-block lab-batch.service", 3, RefUnit, "lab-batch.service", false},
		{"/usr/bin/systemctl is-active ssh.service", 4, RefUnit, "ssh.service", false},
		{"redis-cli -h 127.0.0.1 BGSAVE", 2, RefCommand, "redis-cli", false},
		{"$RUN_ME now", 5, RefEnv, "$RUN_ME", true},
		{"systemctl start $UNIT", 6, RefEnv, "$UNIT", true},
		{"echo done", 1, "", "", false}, // builtin: no ref
		{"for f in /a /b", 1, "", "", false},
		{"VAR=1", 1, "", "", false}, // assignment only: nothing runs
	}
	for _, c := range cases {
		refs := CommandRefs(c.cmd, c.line)
		if c.kind == "" {
			if len(refs) != 0 {
				t.Errorf("%q refs = %+v, want none", c.cmd, refs)
			}
			continue
		}
		if len(refs) != 1 {
			t.Errorf("%q refs = %+v, want exactly 1", c.cmd, refs)
			continue
		}
		r := refs[0]
		if r.Kind != c.kind || r.Value != c.val || r.Line != c.line || r.Unresolved != c.unrs {
			t.Errorf("%q ref = %+v, want kind=%s value=%s unresolved=%v",
				c.cmd, r, c.kind, c.val, c.unrs)
		}
	}
}

func TestCommandRefsMultipleSegments(t *testing.T) {
	refs := CommandRefs("systemctl start a.service && redis-cli ping; true", 1)
	if len(refs) != 2 {
		t.Fatalf("refs = %+v, want 2", refs)
	}
	if refs[0].Kind != RefUnit || refs[1].Kind != RefCommand {
		t.Errorf("refs = %+v", refs)
	}
}

func TestScriptRefs(t *testing.T) {
	content := []byte(`#!/usr/bin/env bash
# comment: systemctl start ignored.service
redis-cli -h 127.0.0.1 BGSAVE >/dev/null 2>&1 || true
systemctl start --no-block lab-batch.service
echo "$(date -Is) backup done" >>/var/log/lab-backup.log
for f in /var/log/x; do
  mv -f "$f" "$f.1"
done
`)
	refs, analyzable := ScriptRefs(content)
	if !analyzable {
		t.Fatal("plain script must be analyzable")
	}
	want := map[string]Ref{}
	for _, r := range refs {
		want[r.Kind+":"+r.Value] = r
	}
	for _, key := range []string{
		"command:redis-cli",
		"unit:lab-batch.service",
	} {
		if _, ok := want[key]; !ok {
			t.Errorf("missing ref %s in %+v", key, refs)
		}
	}
	// Loop variable in argument position must NOT become an env blind spot.
	for _, r := range refs {
		if r.Kind == RefEnv {
			t.Errorf("$f in argument position must not be flagged: %+v", r)
		}
	}
	// comment line mentioning systemctl must not contribute.
	for _, r := range refs {
		if r.Value == "ignored.service" {
			t.Errorf("comment line contributed a ref: %+v", r)
		}
	}
}

func TestScriptRefsUnanalyzable(t *testing.T) {
	if _, ok := ScriptRefs([]byte{0x7f, 'E', 'L', 'F', 0x00, 0x01}); ok {
		t.Error("binary content must be unanalyzable")
	}
	if _, ok := ScriptRefs([]byte{0xff, 0xfe, 0x00}); ok {
		t.Error("non-UTF-8 must be unanalyzable")
	}
	if _, ok := ScriptRefs([]byte("echo ZWNobyB2aWN0aW0K | base64 -d | sh")); ok {
		t.Error("base64 decode pipelines must be unanalyzable")
	}
}

func TestScriptRefsEnvInHead(t *testing.T) {
	refs, ok := ScriptRefs([]byte("$BACKUP_TOOL --full\n"))
	if !ok {
		t.Fatal("text script is analyzable")
	}
	if len(refs) != 1 || !refs[0].Unresolved || refs[0].Kind != RefEnv {
		t.Fatalf("refs = %+v, want one unresolved env ref", refs)
	}
}
