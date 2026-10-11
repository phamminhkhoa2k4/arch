// Package gitrepo discovers local git repositories next to the
// file-backed components recorded earlier in a scan, reads their most
// recent commit through go-git (no git binary required), and parses
// static CI workflow files to link containers to deploy jobs. Every
// read is bounded by a timeout so a corrupt or huge repository becomes
// a blind spot instead of hanging the scan.
package gitrepo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"

	"archaeologist/internal/collector"
)

// repoTimeout bounds one repository open+log read.
const repoTimeout = 5 * time.Second

// maxParentLevels caps the walk from a file path up to the repository
// root so a deep directory tree cannot stall the scan.
const maxParentLevels = 10

// Index supplies the inputs recorded earlier in the scan. Implemented
// by the scan's sink.
type Index interface {
	PathRows() ([]collector.PathRow, error)
	ContainerRows() ([]collector.ContainerRow, error)
}

// RepoInfo is the small slice of repository state the collector keeps.
type RepoInfo struct {
	Branch        string
	LastCommitAt  string
	LastContributor string
}

// Reader opens a repository directory and returns its summary. The
// default implementation wraps go-git with a timeout; tests may stub
// it.
type Reader interface {
	Read(repoDir string) (RepoInfo, error)
}

// GoGitReader is the production Reader backed by go-git.
type GoGitReader struct {
	Timeout time.Duration
}

// Read opens repoDir and reads the head commit + branch, bounded by
// the configured timeout.
func (g GoGitReader) Read(repoDir string) (RepoInfo, error) {
	timeout := g.Timeout
	if timeout <= 0 {
		timeout = repoTimeout
	}
	type result struct {
		info RepoInfo
		err  error
	}
	ch := make(chan result, 1)
	go func() { info, err := readRepo(repoDir); ch <- result{info, err} }()
	select {
	case r := <-ch:
		return r.info, r.err
	case <-time.After(timeout):
		return RepoInfo{}, fmt.Errorf("git read exceeded %s", timeout)
	}
}

// readRepo performs the actual go-git reads without a timeout wrapper.
func readRepo(repoDir string) (RepoInfo, error) {
	r, err := git.PlainOpen(repoDir)
	if err != nil {
		return RepoInfo{}, err
	}
	info := RepoInfo{}
	if head, err := r.Head(); err == nil {
		info.Branch = head.Name().Short()
	}
	iter, err := r.Log(&git.LogOptions{})
	if err != nil {
		return info, err
	}
	defer iter.Close()
	commit, err := iter.Next()
	if err != nil {
		return info, err
	}
	info.LastCommitAt = commit.Committer.When.UTC().Format(time.RFC3339)
	info.LastContributor = commit.Author.Name
	return info, nil
}

// Collector finds repositories above script/binary paths.
type Collector struct {
	index  Index
	reader Reader
}

// New returns the git repository collector. index may be nil only for
// name/version registration.
func New(index Index) *Collector {
	return &Collector{index: index, reader: GoGitReader{}}
}

// SetReader overrides the repository reader (tests).
func (c *Collector) SetReader(r Reader) { c.reader = r }

// Name implements collector.Collector.
func (c *Collector) Name() string { return "git" }

// Version implements collector.Collector.
func (c *Collector) Version() string { return "1.0.0" }

// Collect walks from every recorded script/binary path up to the
// enclosing repository, emits one repo entity per repository plus a
// belongs_to edge from each file, and parses CI workflows inside each
// discovered repository.
func (c *Collector) Collect(ctx context.Context, sink collector.Sink) error {
	if c.index == nil {
		return errors.New("git collector: no path index")
	}
	rows, err := c.index.PathRows()
	if err != nil {
		return fmt.Errorf("path rows: %w", err)
	}
	seen := map[string]bool{}       // repo dir already processed
	edgeSeen := map[string]bool{}   // src|repo edge already emitted
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		dir := findRepoDir(row.Path)
		if dir == "" || seen[dir] {
			if dir == "" {
				continue
			}
			// Repo already processed: still link this file.
			if err := c.linkFile(sink, row.IdentityKey, dir, edgeSeen); err != nil {
				return err
			}
			continue
		}
		seen[dir] = true
		info, err := c.reader.Read(dir)
		if err != nil {
			reason := "git_repo_unreadable"
			if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "exceeded") {
				reason = "git_repo_timeout"
			}
			if bErr := sink.AddBlindSpot(collector.BlindSpot{
				EntityIdentityKey: row.IdentityKey,
				Channel:           "git",
				Reason:            reason,
				Detail:            map[string]string{"path": dir, "error": err.Error()},
			}); bErr != nil {
				return bErr
			}
			continue
		}
		key := repoKey(dir)
		if err := sink.UpsertEntity(collector.Entity{
			Kind:        "repo",
			Name:        filepath.Base(dir),
			IdentityKey: key,
			Fingerprint: repoFingerprint(dir),
			Attributes: map[string]string{
				"path":             dir,
				"branch":           info.Branch,
				"last_commit_at":   info.LastCommitAt,
				"last_contributor": info.LastContributor,
			},
		}); err != nil {
			return err
		}
		ref := "git-repo:" + dir
		if err := sink.AddEvidence(collector.Evidence{
			EntityIdentityKey: key,
			Polarity:          collector.PolarityNeutral,
			Channel:           "git",
			Strength:          collector.StrengthDeterministic,
			ObservedAt:        time.Now().UTC().Format(time.RFC3339),
			RawRef:            filepath.Join(dir, ".git"),
			Ref:               ref,
			Value: map[string]string{
				"branch":           info.Branch,
				"last_commit_at":   info.LastCommitAt,
				"last_contributor": info.LastContributor,
			},
		}); err != nil {
			return err
		}
		if err := c.linkFile(sink, row.IdentityKey, dir, edgeSeen); err != nil {
			return err
		}
		if err := c.collectCI(ctx, sink, dir); err != nil {
			return err
		}
	}
	return nil
}

// linkFile emits the belongs_to edge from a file-backed entity to its
// repository, once per (file, repo) pair.
func (c *Collector) linkFile(sink collector.Sink, fileKey, dir string, edgeSeen map[string]bool) error {
	pair := fileKey + "|" + dir
	if edgeSeen[pair] {
		return nil
	}
	edgeSeen[pair] = true
	return sink.UpsertEdge(collector.Edge{
		SrcIdentityKey: fileKey,
		DstIdentityKey: repoKey(dir),
		Kind:           "belongs_to",
		Strength:       collector.StrengthDeterministic,
		EvidenceRef:    "git-repo:" + dir,
	})
}

// findRepoDir walks up from path looking for a .git entry, capped at
// maxParentLevels. Returns "" when no repository encloses the file.
func findRepoDir(path string) string {
	dir := filepath.Dir(path)
	for i := 0; i < maxParentLevels; i++ {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
	return ""
}

func repoKey(dir string) string { return "repo|" + dir }

func repoFingerprint(dir string) string {
	h := sha256.Sum256([]byte(dir))
	return hex.EncodeToString(h[:])
}
