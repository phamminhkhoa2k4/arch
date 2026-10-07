package accesslog

import (
	"io"
	"strings"
	"testing"
	"time"
)

// memFS is an in-memory FS for tests.
type memFS struct {
	files map[string]string
	dirs  map[string][]string
}

func newMemFS() *memFS {
	return &memFS{files: map[string]string{}, dirs: map[string][]string{}}
}

func (f *memFS) Open(name string) (io.ReadCloser, error) {
	content, ok := f.files[name]
	if !ok {
		return nil, &pathError{name}
	}
	return io.NopCloser(strings.NewReader(content)), nil
}

func (f *memFS) ReadDir(name string) ([]string, error) {
	names, ok := f.dirs[name]
	if !ok {
		return nil, &pathError{name}
	}
	return names, nil
}

type pathError struct{ path string }

func (e *pathError) Error() string { return "open " + e.path + ": no such file" }

func TestParseLineCombined(t *testing.T) {
	e, ok := ParseLine(
		`192.0.2.7 - - [06/Oct/2026:10:11:12 +0000] "GET /web/index.html HTTP/1.1" 200 1234 "http://x/" "curl/8.5"`,
		42)
	if !ok {
		t.Fatal("combined line must parse")
	}
	if e.Method != "GET" || e.URI != "/web/index.html" || e.Status != 200 || e.Line != 42 {
		t.Errorf("entry = %+v", e)
	}
	if e.Time.Year() != 2026 || e.Time.Month() != time.October || e.Time.Day() != 6 {
		t.Errorf("time = %v", e.Time)
	}
	if e.Time.Hour() != 10 || e.Time.Minute() != 11 || e.Time.Second() != 12 {
		t.Errorf("time = %v", e.Time)
	}
}

func TestParseLineRejectsOtherFormats(t *testing.T) {
	cases := []string{
		"", // empty never reaches ParseLine, but must not panic
		`custom format with no structure`,
		`192.0.2.7 - - [06/Oct/2026:10:11:12 +0000] "GET /x HTTP/1.1" 200 12 "r" "a" extra`,
		`192.0.2.7 - - [bad-time] "GET /x HTTP/1.1" 200 12 "r" "a"`,
		`{"time":"2026-10-06T10:11:12Z","method":"GET"}`, // json log_format
	}
	for _, line := range cases {
		if _, ok := ParseLine(line, 1); ok {
			t.Errorf("ParseLine(%q) = true, want false", line)
		}
	}
}

func TestParseFileCountsAndLines(t *testing.T) {
	f := newMemFS()
	f.files["/var/log/nginx/a.log"] = strings.Join([]string{
		`192.0.2.7 - - [06/Oct/2026:10:00:00 +0000] "GET /web/ HTTP/1.1" 200 10 "-" "c"`,
		``,
		`not a log line at all`,
		`192.0.2.7 - - [06/Oct/2026:10:05:00 +0000] "GET /pool/ HTTP/1.1" 502 0 "-" "c"`,
	}, "\n")

	res, err := ParseFile(f, "/var/log/nginx/a.log")
	if err != nil {
		t.Fatalf("parse file: %v", err)
	}
	if res.Total != 3 || res.Unparsed != 1 || len(res.Entries) != 2 {
		t.Fatalf("result = %+v, want 3 total / 1 unparsed / 2 entries", res)
	}
	if res.Entries[0].Line != 1 || res.Entries[1].Line != 4 {
		t.Errorf("line numbers = %d, %d", res.Entries[0].Line, res.Entries[1].Line)
	}
	if res.Entries[1].Status != 502 {
		t.Errorf("status = %d", res.Entries[1].Status)
	}
}

func TestParseFileMissingIsFsError(t *testing.T) {
	_, err := ParseFile(newMemFS(), "/missing.log")
	if err == nil {
		t.Fatal("missing file: want error")
	}
}

func TestRetentionDetectsRotationSuffix(t *testing.T) {
	f := newMemFS()
	f.dirs["/var/log/nginx"] = []string{
		"lab_access.log", "lab_access.log.1", "lab_access.log.2", "lab_access.log.7.gz",
		"other.log", "lab_access.log.bak",
	}
	days, found := Retention(f, "/var/log/nginx/lab_access.log")
	if !found || days != 7 {
		t.Errorf("retention = (%d, %v), want (7, true)", days, found)
	}

	f.dirs["/var/log/nginx"] = []string{"lab_access.log", "unrelated.1"}
	if _, found := Retention(f, "/var/log/nginx/lab_access.log"); found {
		t.Error("no siblings: want found=false")
	}

	if _, found := Retention(newMemFS(), "/var/log/nginx/gone.log"); found {
		t.Error("missing dir: want found=false")
	}
}
