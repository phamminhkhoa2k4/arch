// Package cron parses crontab sources and systemd timer units into
// the jobs, schedules and script references the scanner needs. It
// only reads files and never executes anything from them.
package cron

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"strings"

	"archaeologist/internal/systemd"
)

// Source paths the scanner reads.
const (
	CrontabPath = "/etc/crontab"
	CronDir     = "/etc/cron.d"
	SpoolDir    = "/var/spool/cron/crontabs"
	SpoolAltDir = "/var/spool/cron"
)

// Job is one parsed crontab entry from any source.
type Job struct {
	File       string // source file of the entry
	FileDigest string // sha256 of that file's content
	Line       int    // 1-based line number
	User       string
	Schedule   string // raw schedule: five fields or a macro
	Command    string
}

// Script returns the command head when the job runs an absolute path.
func (j *Job) Script() string {
	head := CommandHead(j.Command)
	if strings.HasPrefix(head, "/") {
		return head
	}
	return ""
}

// Key is the deterministic identity of the job. Line numbers are
// deliberately absent: inserting a line above must not fork identity.
func (j *Job) Key() string {
	return "cron_job|" + strings.Join([]string{j.File, j.User, j.Command}, "#")
}

// Fingerprint hashes the stable shape of the job so schedule drift
// shows up between scans.
func (j *Job) Fingerprint() string {
	return digestOf(j.FileDigest, j.User, j.Schedule, j.Command)
}

// FileError is one source that could not be read.
type FileError struct {
	File string
	Err  error
}

func (e FileError) Error() string { return e.File + ": " + e.Err.Error() }

// Config is the extracted static view of every crontab source.
type Config struct {
	Jobs   []Job
	Errors []FileError // unreadable sources, never fatal to the caller
}

// Loader reads crontab sources from disk.
type Loader struct {
	fs systemd.FS
}

// NewLoader returns a loader that reads the real filesystem.
func NewLoader() *Loader { return &Loader{fs: systemd.OSFS{}} }

// NewLoaderFS reads through fs, for tests.
func NewLoaderFS(fs systemd.FS) *Loader { return &Loader{fs: fs} }

// Load reads every supported crontab source. A source that is absent
// is normal on a machine without it and is skipped; a source that
// exists but cannot be read comes back in Config.Errors so the caller
// reports it instead of silently missing jobs. Never panics.
func (l *Loader) Load() *Config {
	cfg := &Config{}
	// /etc/crontab: schedule + user + command.
	l.loadSource(cfg, CrontabPath, true, "")
	// /etc/cron.d: same shape; ignore names with "." or trailing "~"
	// (crontab(5) semantics).
	if names, ok := l.readDir(CronDir, cfg); ok {
		for _, n := range names {
			if strings.HasPrefix(n, ".") || strings.Contains(n, ".") || strings.HasSuffix(n, "~") {
				continue
			}
			l.loadSource(cfg, CronDir+"/"+n, true, "")
		}
	}
	// Per-user spools: no user field, the file name is the user.
	for _, dir := range []string{SpoolDir, SpoolAltDir} {
		if names, ok := l.readDir(dir, cfg); ok {
			for _, n := range names {
				if strings.HasPrefix(n, ".") {
					continue
				}
				l.loadSource(cfg, dir+"/"+n, false, n)
			}
		}
	}
	return cfg
}

func (l *Loader) readDir(dir string, cfg *Config) ([]string, bool) {
	names, err := l.fs.ReadDir(dir)
	if err != nil {
		if missing(err) {
			return nil, false
		}
		cfg.Errors = append(cfg.Errors, FileError{File: dir, Err: err})
		return nil, false
	}
	return names, true
}

func (l *Loader) loadSource(cfg *Config, path string, userField bool, user string) {
	data, err := l.fs.ReadFile(path)
	if err != nil {
		// Absent (or a directory standing in for a file, like the
		// crontabs/ subdir under /var/spool/cron) is not a gap.
		if missing(err) || strings.Contains(err.Error(), "is a directory") {
			return
		}
		cfg.Errors = append(cfg.Errors, FileError{File: path, Err: err})
		return
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	for i, raw := range strings.Split(string(data), "\n") {
		if j, ok := parseLine(path, digest, i+1, raw, userField, user); ok {
			cfg.Jobs = append(cfg.Jobs, j)
		}
	}
}

func missing(err error) bool { return errors.Is(err, fs.ErrNotExist) }

// digestOf joins parts into a sha256 hex string.
func digestOf(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
