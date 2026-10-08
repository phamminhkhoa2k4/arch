// Package rules loads the verdict rule file. Rules live in YAML so
// operators can tune thresholds without rebuilding; every load either
// succeeds, fails loudly with file:line, or is an error the caller
// must surface. There is no silent fallback to defaults.
package rules

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"go.yaml.in/yaml/v4"
)

//go:embed rules.yaml
var embedded embed.FS

// Thresholds are the numeric gates used by the verdict engine.
type Thresholds struct {
	ObservationWindowDays int `yaml:"observation_window_days"`
	NoDeployDays          int `yaml:"no_deploy_days"`
	NoActivityDays        int `yaml:"no_activity_days"`
}

// StringList accepts either a scalar or a YAML list, so coverage
// accepts `coverage: HIGH` and `coverage: [HIGH, MEDIUM]`.
type StringList []string

// UnmarshalYAML implements yaml.Unmarshaler.
func (l *StringList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var s string
		if err := node.Decode(&s); err != nil {
			return err
		}
		*l = StringList{s}
		return nil
	case yaml.SequenceNode:
		var out []string
		if err := node.Decode(&out); err != nil {
			return err
		}
		*l = out
		return nil
	default:
		return fmt.Errorf("line %d: coverage must be a string or list of strings", node.Line)
	}
}

// Requirement describes when a verdict state is reachable.
type Requirement struct {
	Coverage         StringList `yaml:"coverage"`
	Blockers         string     `yaml:"blockers"`
	WindowSufficient bool       `yaml:"window_sufficient"`
}

// Verdicts maps coverage/no-blocker conditions to states.
type Verdicts struct {
	LikelyOrphanedRequires Requirement `yaml:"likely_orphaned_requires"`
	OrphanedRequires       Requirement `yaml:"orphaned_requires"`
	Fallback               string      `yaml:"fallback"`
}

// Coverage is the Evidence Coverage definition (D2): a ratio band
// per entity kind plus the channel applicability matrix.
type Coverage struct {
	HighRatio   float64             `yaml:"high_ratio"`
	MediumRatio float64             `yaml:"medium_ratio"`
	Channels    map[string][]string `yaml:"channels"`
}

// Rules is the fully parsed rule file.
type Rules struct {
	Thresholds Thresholds `yaml:"thresholds"`
	Verdicts   Verdicts   `yaml:"verdicts"`
	Coverage   Coverage   `yaml:"coverage"`
}

// Load reads path and returns the parsed rules plus the SHA-256 of
// the raw bytes (used to key stored verdicts). An empty path loads
// the embedded defaults.
func Load(path string) (Rules, string, error) {
	var raw []byte
	var err error
	src := path
	if path == "" {
		src = "rules.yaml (embedded)"
		raw, err = embedded.ReadFile("rules.yaml")
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return Rules{}, "", fmt.Errorf("load rules: %w", err)
	}

	var r Rules
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if derr := dec.Decode(&r); derr != nil {
		return Rules{}, "", formatErr(src, derr)
	}
	if err := r.validate(src); err != nil {
		return Rules{}, "", err
	}
	sum := sha256.Sum256(raw)
	return r, hex.EncodeToString(sum[:]), nil
}

// Default returns the embedded rules (path "").
func Default() (Rules, string, error) {
	return Load("")
}

// formatErr rewrites yaml "line N: msg" errors into "path:N: msg",
// preferring the last "line N:" (libyaml nests an outer position in
// front of the actionable one).
func formatErr(src string, err error) error {
	msg := err.Error()
	best := -1
	line := ""
	for i := 0; i+5 <= len(msg); {
		j := strings.Index(msg[i:], "line ")
		if j < 0 {
			break
		}
		i += j + len("line ")
		k := i
		for k < len(msg) && msg[k] >= '0' && msg[k] <= '9' {
			k++
		}
		if k > i && k < len(msg) && msg[k] == ':' {
			best, line = i-5, msg[i:k]
			i = k + 1
			continue
		}
	}
	if best >= 0 {
		rest := msg[best+len("line "+line)+1:]
		return fmt.Errorf("%s:%s: %s", src, line, strings.TrimSpace(rest))
	}
	return fmt.Errorf("%s: %s", src, msg)
}

// validate rejects values the engine cannot interpret, so a bad file
// fails at load instead of silently producing odd verdicts.
func (r Rules) validate(src string) error {
	fatal := func(format string, args ...any) error {
		return fmt.Errorf("%s: %s", src, fmt.Sprintf(format, args...))
	}
	validStates := map[string]bool{
		"ACTIVE": true, "LIKELY_ORPHANED": true, "ORPHANED": true, "UNKNOWN": true,
	}
	if !validStates[r.Verdicts.Fallback] {
		return fatal("verdicts.fallback: unknown state %q", r.Verdicts.Fallback)
	}
	coverLevels := map[string]bool{"HIGH": true, "MEDIUM": true, "LOW": true}
	if err := validateRequirement("likely_orphaned_requires", r.Verdicts.LikelyOrphanedRequires, coverLevels); err != nil {
		return fatal("%s", err)
	}
	if err := validateRequirement("orphaned_requires", r.Verdicts.OrphanedRequires, coverLevels); err != nil {
		return fatal("%s", err)
	}
	if r.Coverage.HighRatio <= 0 || r.Coverage.HighRatio > 1 {
		return fatal("coverage.high_ratio must be in (0, 1], got %v", r.Coverage.HighRatio)
	}
	if r.Coverage.MediumRatio <= 0 || r.Coverage.MediumRatio > r.Coverage.HighRatio {
		return fatal("coverage.medium_ratio must be in (0, high_ratio], got %v", r.Coverage.MediumRatio)
	}
	if len(r.Coverage.Channels) == 0 {
		return fatal("coverage.channels must not be empty")
	}
	for kind, chans := range r.Coverage.Channels {
		if len(chans) == 0 {
			return fatal("coverage.channels[%s] must list at least one channel", kind)
		}
	}
	if r.Thresholds.ObservationWindowDays < 0 || r.Thresholds.NoDeployDays < 0 || r.Thresholds.NoActivityDays < 0 {
		return fatal("thresholds must not be negative")
	}
	return nil
}

func validateRequirement(name string, req Requirement, valid map[string]bool) error {
	for _, c := range req.Coverage {
		if !valid[c] {
			return fmt.Errorf("verdicts.%s.coverage: unknown level %q", name, c)
		}
	}
	if req.Blockers != "" && req.Blockers != "none" {
		return fmt.Errorf("verdicts.%s.blockers: only %q is supported", name, "none")
	}
	return nil
}
