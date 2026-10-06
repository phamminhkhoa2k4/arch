package systemd

import "testing"

func TestParseExecPrefixesAndArgs(t *testing.T) {
	ex, err := ParseExec("-/opt/app/run.sh --flag \"two words\"", 3, "/x")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ex.Prefixes != "-" || ex.Path != "/opt/app/run.sh" {
		t.Errorf("prefix/path = %q / %q", ex.Prefixes, ex.Path)
	}
	if len(ex.Args) != 2 || ex.Args[1] != "two words" {
		t.Errorf("args = %#v", ex.Args)
	}
	if ex.Line != 3 || ex.File != "/x" {
		t.Errorf("location = %d %s", ex.Line, ex.File)
	}
}

func TestParseExecErrors(t *testing.T) {
	for _, bad := range []string{"", "   ", `"/unterminated`} {
		if _, err := ParseExec(bad, 1, "t"); err == nil {
			t.Errorf("%q must fail", bad)
		}
	}
}

func TestSplitArgvQuoting(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{`a b c`, []string{"a", "b", "c"}},
		{`"a b" c`, []string{"a b", "c"}},
		{`'lit eral'`, []string{"lit eral"}},
		{`esc\ ape`, []string{"esc ape"}},
		{`"inner \"q\" x"`, []string{`inner "q" x`}},
		{`  spaced   out  `, []string{"spaced", "out"}},
	}
	for _, tc := range tests {
		got, err := SplitArgv(tc.in)
		if err != nil {
			t.Errorf("SplitArgv(%q): %v", tc.in, err)
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("SplitArgv(%q) = %#v, want %#v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("SplitArgv(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
	for _, bad := range []string{`"unterminated`, `'unterminated`} {
		if _, err := SplitArgv(bad); err == nil {
			t.Errorf("%q must fail", bad)
		}
	}
}

func TestExpandEnvAndSpecifiers(t *testing.T) {
	env := map[string]string{"APP_HOME": "/opt/app", "EMPTY": ""}
	spec := Specifiers("worker@7.service")
	if spec["i"] != "7" || spec["n"] != "worker@7.service" || spec["p"] != "worker" {
		t.Errorf("specifiers = %#v", spec)
	}
	if s := Specifiers("plain.service"); s["i"] != "" || s["p"] != "plain" {
		t.Errorf("plain specifiers = %#v", s)
	}

	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"$APP_HOME/bin/start", "/opt/app/bin/start", true},
		{"${APP_HOME}/bin/start", "/opt/app/bin/start", true},
		{"no vars here", "no vars here", true},
		{"%n", "worker@7.service", true},
		{"%%", "%", true},
		{"$$", "$", true},
		{"$MISSING/x", "", false}, // unknown env → unresolved
		{"%H", "", false},         // unknown specifier → unresolved
		{"$", "", false},          // bare dollar → unresolved
		{"prefix%q", "", false},   // unknown specifier mid-string
	}
	for _, tc := range tests {
		got, ok := Expand(tc.in, env, spec)
		if ok != tc.ok || got != tc.want {
			t.Errorf("Expand(%q) = %q,%v want %q,%v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestEnvMapParsesPairs(t *testing.T) {
	lines := []Directive{
		{Value: `FOO=bar`},
		// Verified against systemd: one quoted word stays one pair,
		// the value keeps its spaces (A="1 B=2"), matching env output.
		{Value: `"A=1 B=2" FOO2=2`},
		{Value: `no-equals`},
		{Value: `FOO3="a b"`},
	}
	env := EnvMap(lines)
	if env["FOO"] != "bar" || env["FOO2"] != "2" || env["A"] != "1 B=2" ||
		env["FOO3"] != "a b" {
		t.Errorf("env = %#v", env)
	}
	if _, ok := env["B"]; ok {
		t.Error("B is not a variable of its own")
	}
	if _, bad := env["no-equals"]; bad {
		t.Error("token without = must not become an entry")
	}
}

func TestClassify(t *testing.T) {
	if k, ok := Classify([]byte{0x7f, 'E', 'L', 'F', 0x02}); !ok || k != "binary" {
		t.Errorf("ELF → %q,%v", k, ok)
	}
	if k, ok := Classify([]byte("#!/bin/sh\necho hi\n")); !ok || k != "script" {
		t.Errorf("shebang → %q,%v", k, ok)
	}
	if _, ok := Classify([]byte("plain text")); ok {
		t.Error("plain text must be unknown, not guessed")
	}
	if _, ok := Classify(nil); ok {
		t.Error("empty file must be unknown")
	}
}
