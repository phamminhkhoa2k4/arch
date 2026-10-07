// Package accesslog parses nginx access logs into per-request entries
// and reports rotation retention. It only reads; it never tails or
// writes log files.
package accesslog

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultPath is nginx's built-in access log location, used when the
// configuration declares no access_log directive.
const DefaultPath = "/var/log/nginx/access.log"

// Entry is one parsed access-log line.
type Entry struct {
	Time   time.Time
	Method string
	URI    string
	Status int
	Line   int // 1-based line number in the file
}

// FileResult is one log file's parse outcome. Total counts non-empty
// lines; Unparsed counts the ones that did not match the combined
// format (a custom log_format among them).
type FileResult struct {
	Entries  []Entry
	Total    int
	Unparsed int
}

// FS opens and lists log files. Implementations: OSFS and fakes in
// tests.
type FS interface {
	Open(name string) (io.ReadCloser, error)
	ReadDir(name string) ([]string, error)
}

// OSFS reads the real filesystem.
type OSFS struct{}

func (OSFS) Open(name string) (io.ReadCloser, error) { return os.Open(name) }

func (OSFS) ReadDir(name string) ([]string, error) {
	entries, err := os.ReadDir(name)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}

// combinedRE matches the nginx combined log format:
//
//	remote_addr remote_user [time_local] "method uri proto" status bytes "referer" "agent"
//
// Trailing extras (e.g. x_forwarded_for) are deliberately not matched:
// a different format must surface as a blind spot, not a silent skip.
var combinedRE = regexp.MustCompile(
	`^\S+ \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d{3}) (\d+|-) "[^"]*" "[^"]*"$`)

// timeLayout is the nginx $time_local format.
const timeLayout = "02/Jan/2006:15:04:05 -0700"

// ParseLine parses one combined-format line. lineNo is the 1-based
// position kept for raw_ref tracing.
func ParseLine(line string, lineNo int) (Entry, bool) {
	m := combinedRE.FindStringSubmatch(line)
	if m == nil {
		return Entry{}, false
	}
	t, err := time.Parse(timeLayout, m[1])
	if err != nil {
		return Entry{}, false
	}
	status, err := strconv.Atoi(m[4])
	if err != nil {
		return Entry{}, false
	}
	return Entry{Time: t, Method: m[2], URI: m[3], Status: status, Line: lineNo}, true
}

// ParseFile streams a log file line by line. A missing file is
// returned as the raw fs error so the caller can treat "no file yet"
// differently from a read failure.
func ParseFile(fsys FS, path string) (FileResult, error) {
	rc, err := fsys.Open(path)
	if err != nil {
		return FileResult{}, err
	}
	defer func() { _ = rc.Close() }()

	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var res FileResult
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		res.Total++
		e, ok := ParseLine(line, lineNo)
		if !ok {
			res.Unparsed++
			continue
		}
		res.Entries = append(res.Entries, e)
	}
	if err := sc.Err(); err != nil {
		return res, err
	}
	return res, nil
}

// Retention reports the newest rotation suffix of path: siblings
// named base.N (optionally compressed, e.g. base.1.gz) contribute N;
// the largest N is assumed to be the retention in days under daily
// rotation. found=false means no rotation was detected.
func Retention(fsys FS, path string) (days int, found bool) {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	names, err := fsys.ReadDir(dir)
	if err != nil {
		return 0, false
	}
	for _, name := range names {
		suffix, ok := strings.CutPrefix(name, base+".")
		if !ok || suffix == "" {
			continue
		}
		if i := strings.IndexByte(suffix, '.'); i >= 0 {
			suffix = suffix[:i] // drop compression suffix: base.1.gz → 1
		}
		n, err := strconv.Atoi(suffix)
		if err != nil || n <= 0 {
			continue
		}
		if n > days {
			days = n
		}
		found = true
	}
	return days, found
}
