package systemd

import "testing"

const baseUnit = `[Unit]
Description=Legacy worker
Requires=database.service
Wants=log-shipper.service
After=database.service network.target

[Service]
Type=simple
Environment=APP_HOME=/opt/legacy
ExecStart=/opt/legacy-worker/run.sh --queue high
WorkingDirectory=/opt/legacy-worker
`

func TestParseFileDirectives(t *testing.T) {
	f, err := ParseFile("/etc/systemd/system/x.service", []byte(baseUnit))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.Dirs) != 8 {
		t.Fatalf("got %d directives, want 8: %+v", len(f.Dirs), f.Dirs)
	}
	d := f.Dirs[0]
	if d.Section != "Unit" || d.Key != "Description" || d.Line != 2 {
		t.Errorf("first directive = %+v", d)
	}
	// Comments and blanks are skipped; Service ExecStart is line 10.
	var exec *Directive
	for i := range f.Dirs {
		if f.Dirs[i].Key == "ExecStart" {
			exec = &f.Dirs[i]
		}
	}
	if exec == nil {
		t.Fatal("ExecStart not parsed")
	}
	if exec.Section != "Service" || exec.Line != 10 {
		t.Errorf("ExecStart = %+v", exec)
	}
}

func TestParseFileAppendsAndJunk(t *testing.T) {
	data := "# comment\n\n[Service]\nEnvironment+=FOO=bar\nnot a directive\nEnvironment=BAZ=qux\n"
	f, err := ParseFile("t", []byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.Dirs) != 2 {
		t.Fatalf("got %d directives, want 2 (junk line ignored)", len(f.Dirs))
	}
	if f.Dirs[0].Op != "+=" || f.Dirs[1].Op != "=" {
		t.Errorf("ops = %q / %q", f.Dirs[0].Op, f.Dirs[1].Op)
	}
}

// Operators inside the value must not be mistaken for the assignment
// operator ("Description=a+=b" keeps its value intact).
func TestSplitAssignmentOperatorInValue(t *testing.T) {
	data := "[Unit]\nDescription=a+=b\nDocumentation=https://x\nLimitNOFILE=-\n"
	f, err := ParseFile("t", []byte(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.Dirs) != 3 {
		t.Fatalf("got %d directives, want 3: %+v", len(f.Dirs), f.Dirs)
	}
	if f.Dirs[0].Key != "Description" || f.Dirs[0].Op != "=" || f.Dirs[0].Value != "a+=b" {
		t.Errorf("Description = %+v", f.Dirs[0])
	}
	if f.Dirs[2].Key != "LimitNOFILE" || f.Dirs[2].Value != "-" {
		t.Errorf("LimitNOFILE = %+v", f.Dirs[2])
	}
}

// A drop-in ExecStart replaces the base value; list directives append.
func TestMergeDropInOverrideAndAppend(t *testing.T) {
	base, _ := ParseFile("/lib/systemd/system/x.service", []byte(baseUnit))
	drop, _ := ParseFile("/etc/systemd/system/x.service.d/override.conf",
		[]byte("[Service]\nExecStart=/new/run.sh\nEnvironment=EXTRA=1\nRequires=extra.service\n"))
	m := Merge("x.service", base, drop)

	exec := m.Get("ExecStart")
	if len(exec) != 1 || exec[0].Value != "/new/run.sh" {
		t.Errorf("ExecStart after drop-in = %+v, want only /new/run.sh", exec)
	}
	env := m.All("Environment")
	if len(env) != 2 || env[0].Value != "APP_HOME=/opt/legacy" || env[1].Value != "EXTRA=1" {
		t.Errorf("Environment = %+v, want base then drop-in", env)
	}
	req := m.All("Requires")
	if len(req) != 2 {
		t.Errorf("Requires = %+v, want base + drop-in append", req)
	}
	// Unmentioned keys survive from the base.
	if !m.Has("WorkingDirectory") {
		t.Error("WorkingDirectory lost in merge")
	}
}

// Several ExecStart lines inside ONE file stay together (oneshot).
func TestMergeKeepsSameFileLines(t *testing.T) {
	f, _ := ParseFile("t", []byte("[Service]\nExecStart=/a\nExecStart=/b\n"))
	m := Merge("t.service", f)
	got := m.Get("ExecStart")
	if len(got) != 2 {
		t.Fatalf("ExecStart lines = %+v, want 2", got)
	}
}

func TestMergedFingerprintChangesWithDropIn(t *testing.T) {
	base, _ := ParseFile("t", []byte(baseUnit))
	m1 := Merge("x.service", base)
	m2 := Merge("x.service", base)
	if m1.Fingerprint() != m2.Fingerprint() {
		t.Error("same input must fingerprint equal")
	}
	drop, _ := ParseFile("t2", []byte("[Service]\nExecStart=/other\n"))
	m3 := Merge("x.service", base, drop)
	if m3.Fingerprint() == m1.Fingerprint() {
		t.Error("adding a drop-in must change the fingerprint")
	}
}

func TestScalarSubtractRemovesValue(t *testing.T) {
	base, _ := ParseFile("t", []byte("[Unit]\nRequires=a.service\nRequires=b.service\n"))
	drop, _ := ParseFile("t2", []byte("[Unit]\nRequires-=a.service\n"))
	m := Merge("x.service", base, drop)
	got := m.All("Requires")
	if len(got) != 1 || got[0].Value != "b.service" {
		t.Errorf("Requires after -= : %+v", got)
	}
}
