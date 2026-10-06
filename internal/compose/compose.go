// Package compose parses docker-compose files into the small subset the
// scanner needs: service names and their depends_on graph. It wraps
// compose-go and never executes anything from the file.
package compose

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"

	"github.com/compose-spec/compose-go/v2/cli"
)

// Service is one compose service and the services it depends on.
type Service struct {
	Name      string
	DependsOn []string // sorted, every condition form reduced to a name
}

// File is the parsed content of one compose file.
type File struct {
	Path     string
	Project  string // project name as resolved by compose-go
	Content  []byte // raw file bytes, kept for fingerprints
	Services map[string]*Service
}

// Fingerprint hashes the raw file content so config drift shows up
// between scans.
func (f *File) Fingerprint() string {
	h := sha256.Sum256(f.Content)
	return hex.EncodeToString(h[:])
}

// notFoundError means the recorded compose path no longer exists —
// the caller records a blind spot, never guesses an alternative file.
type notFoundError struct{ Path string }

func (e *notFoundError) Error() string {
	return fmt.Sprintf("compose file not found at recorded path: %s", e.Path)
}

// IsNotFound reports whether err means "file missing at its path".
func IsNotFound(err error) bool {
	_, ok := err.(*notFoundError)
	return ok
}

// Loader reads compose files from disk.
type Loader struct{}

// NewLoader returns a loader that reads real files.
func NewLoader() *Loader { return &Loader{} }

// Load parses path. projectName, when non-empty, is passed to
// compose-go so files without a top-level name still resolve.
// depends_on entries of every condition form (short syntax and
// long syntax with condition) collapse to service names.
func (l *Loader) Load(path, projectName string) (*File, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &notFoundError{Path: path}
		}
		return nil, fmt.Errorf("read compose file %s: %w", path, err)
	}

	// Consistency checks are skipped on purpose: a file fragment
	// (override file listed in a container's config_files label) may
	// reference services defined in another file of the same project.
	// The static graph is still extracted; dangling names simply
	// produce no edge. Schema validation stays on.
	opts := []cli.ProjectOptionsFn{
		cli.WithoutEnvironmentResolution,
		cli.WithInterpolation(false),
		cli.WithConsistency(false),
	}
	if projectName != "" {
		opts = append(opts, cli.WithName(projectName))
	}
	po, err := cli.NewProjectOptions([]string{path}, opts...)
	if err != nil {
		return nil, fmt.Errorf("compose options for %s: %w", path, err)
	}
	project, err := po.LoadProject(context.Background())
	if err != nil {
		return nil, fmt.Errorf("parse compose file %s: %w", path, err)
	}

	f := &File{
		Path:     path,
		Project:  project.Name,
		Content:  content,
		Services: map[string]*Service{},
	}
	for name, svc := range project.Services {
		deps := map[string]bool{}
		for dep := range svc.DependsOn {
			if dep != name {
				deps[dep] = true
			}
		}
		list := make([]string, 0, len(deps))
		for d := range deps {
			list = append(list, d)
		}
		sort.Strings(list)
		f.Services[name] = &Service{Name: name, DependsOn: list}
	}
	return f, nil
}
