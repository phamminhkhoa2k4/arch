package gitrepo

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.yaml.in/yaml/v4"

	"archaeologist/internal/collector"
)

// workflowFileMax bounds one workflow file read.
const workflowFileMax = 1 << 20 // 1 MiB

// ciJob is one parsed deploy-capable job from a static workflow file.
type ciJob struct {
	Name  string
	Image string
	File  string
}

// collectCI parses static CI workflow files inside a discovered
// repository and links matching containers to their deploy jobs.
// Jenkins is deliberately out of scope: a Jenkinsfile yields nothing.
func (c *Collector) collectCI(ctx context.Context, sink collector.Sink, repoDir string) error {
	containers, err := c.index.ContainerRows()
	if err != nil {
		return fmt.Errorf("container rows: %w", err)
	}
	if len(containers) == 0 {
		return nil
	}
	jobs, err := parseWorkflows(repoDir)
	if err != nil {
		// A malformed workflow is a blind spot on the repo, never a
		// scan failure.
		return sink.AddBlindSpot(collector.BlindSpot{
			Channel: "ci",
			Reason:  "ci_workflow_unreadable",
			Detail:  map[string]string{"repo": repoDir, "error": err.Error()},
		})
	}
	for _, job := range jobs {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, ct := range containers {
			strength, ok := matchContainer(ct, job)
			if !ok {
				continue
			}
			if err := c.emitCIDeploy(sink, repoDir, job, ct, strength); err != nil {
				return err
			}
		}
	}
	return nil
}

// matchContainer grades a container-to-job match: an exact image name
// hit is a strong heuristic; a bare service-name hit is weak.
func matchContainer(ct collector.ContainerRow, job ciJob) (collector.Strength, bool) {
	if job.Image == "" {
		return "", false
	}
	if bareName(ct.Image) == bareName(job.Image) && bareName(ct.Image) != "" {
		return collector.StrengthStrongHeuristic, true
	}
	if job.Image == ct.Name {
		return collector.StrengthWeakHeuristic, true
	}
	return "", false
}

// bareName strips a tag and any registry/repo prefix so
// "registry.example.com/svc/web:1.2" and "web" compare equal.
func bareName(ref string) string {
	if i := strings.IndexByte(ref, ':'); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndexByte(ref, '/'); i >= 0 {
		ref = ref[i+1:]
	}
	return ref
}

// emitCIDeploy upserts the ci_job entity and the deployed_by edge from
// the container.
func (c *Collector) emitCIDeploy(sink collector.Sink, repoDir string, job ciJob,
	ct collector.ContainerRow, strength collector.Strength) error {
	key := fmt.Sprintf("ci_job|%s#%s#%s", repoDir, filepath.Base(job.File), job.Name)
	if err := sink.UpsertEntity(collector.Entity{
		Kind:        "ci_job",
		Name:        job.Name,
		IdentityKey: key,
		Fingerprint: repoFingerprint(key),
		Attributes: map[string]string{
			"repo":  repoDir,
			"file":  job.File,
			"image": job.Image,
		},
	}); err != nil {
		return err
	}
	ref := "ci-job:" + key
	if err := sink.AddEvidence(collector.Evidence{
		EntityIdentityKey: key,
		Polarity:          collector.PolarityNeutral,
		Channel:           "ci",
		Strength:          strength,
		ObservedAt:        time.Now().UTC().Format(time.RFC3339),
		RawRef:            job.File,
		Ref:               ref,
		Value: map[string]string{
			"job":   job.Name,
			"image": job.Image,
		},
	}); err != nil {
		return err
	}
	return sink.UpsertEdge(collector.Edge{
		SrcIdentityKey: ct.IdentityKey,
		DstIdentityKey: key,
		Kind:           "deployed_by",
		Strength:       strength,
		EvidenceRef:    ref,
	})
}

// parseWorkflows reads GitHub Actions and GitLab CI files under repoDir
// and returns every job that names an image. A missing workflow
// directory is not an error; an unreadable or malformed file is.
func parseWorkflows(repoDir string) ([]ciJob, error) {
	var jobs []ciJob
	ghDir := filepath.Join(repoDir, ".github", "workflows")
	if entries, err := os.ReadDir(ghDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
				continue
			}
			file := filepath.Join(ghDir, name)
			parsed, err := parseGitHubWorkflow(file)
			if err != nil {
				return nil, err
			}
			jobs = append(jobs, parsed...)
		}
	}
	glFile := filepath.Join(repoDir, ".gitlab-ci.yml")
	if _, err := os.Stat(glFile); err == nil {
		parsed, err := parseGitLabCI(glFile)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, parsed...)
	}
	return jobs, nil
}

// parseGitHubWorkflow extracts jobs that set container image or a
// docker image in steps (basic parse — matrix/reusable nuances fall
// back to whatever is statically visible).
func parseGitHubWorkflow(file string) ([]ciJob, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	if len(data) > workflowFileMax {
		return nil, fmt.Errorf("workflow too large: %s", file)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	jobs, _ := doc["jobs"].(map[string]any)
	var out []ciJob
	for name, raw := range jobs {
		job, _ := raw.(map[string]any)
		image := firstImageString(job, "container")
		if image == "" {
			if steps, ok := job["steps"].([]any); ok {
				for _, s := range steps {
					step, _ := s.(map[string]any)
					if img := firstImageString(step, "docker"); img != "" {
						image = img
						break
					}
				}
			}
		}
		if image == "" {
			continue
		}
		out = append(out, ciJob{Name: name, Image: image, File: file})
	}
	return out, nil
}

// parseGitLabCI extracts jobs that name an image (top-level or nested
// under image: { name: ... }).
func parseGitLabCI(file string) ([]ciJob, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	if len(data) > workflowFileMax {
		return nil, fmt.Errorf("workflow too large: %s", file)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	reserved := map[string]bool{
		"stages": true, "variables": true, "include": true, "default": true,
		"workflow": true, "image": true, "services": true, "cache": true,
		"before_script": true, "after_script": true, "pages": true,
	}
	var out []ciJob
	for name, raw := range doc {
		if reserved[name] {
			continue
		}
		job, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		image := firstImageString(job, "image")
		if image == "" {
			continue
		}
		out = append(out, ciJob{Name: name, Image: image, File: file})
	}
	return out, nil
}

// firstImageString pulls an image out of a map that may hold either
// "container: name", "image: name" or the nested map form
// "{ image: name }" / "{ name: name }".
func firstImageString(m map[string]any, key string) string {
	switch v := m[key].(type) {
	case string:
		return v
	case map[string]any:
		if s, ok := v["image"].(string); ok {
			return s
		}
		if s, ok := v["name"].(string); ok {
			return s
		}
	}
	return ""
}
