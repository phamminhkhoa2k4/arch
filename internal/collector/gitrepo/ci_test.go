package gitrepo

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"archaeologist/internal/collector"
)

func writeWorkflow(t *testing.T, dir, rel, content string) string {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const ghaWorkflow = `name: ci
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: myapp:latest
    steps:
      - run: echo hi
`

func TestParseGitHubWorkflowExtractsImage(t *testing.T) {
	dir := t.TempDir()
	file := writeWorkflow(t, dir, ".github/workflows/ci.yml", ghaWorkflow)
	jobs, err := parseGitHubWorkflow(file)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(jobs) != 1 || jobs[0].Name != "build" || jobs[0].Image != "myapp:latest" {
		t.Fatalf("unexpected jobs: %+v", jobs)
	}
}

func TestParseGitLabCIExtractsImage(t *testing.T) {
	dir := t.TempDir()
	file := writeWorkflow(t, dir, ".gitlab-ci.yml", "deploy:\n  image: registry.example.com/svc/web\n")
	jobs, err := parseGitLabCI(file)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(jobs) != 1 || jobs[0].Name != "deploy" || jobs[0].Image != "registry.example.com/svc/web" {
		t.Fatalf("unexpected jobs: %+v", jobs)
	}
}

func TestParseMalformedWorkflowError(t *testing.T) {
	dir := t.TempDir()
	file := writeWorkflow(t, dir, ".github/workflows/bad.yml", ":\n\tbad: [")
	if _, err := parseGitHubWorkflow(file); err == nil {
		t.Fatal("want parse error for malformed yaml")
	}
}

func TestMatchContainerGrades(t *testing.T) {
	tests := []struct {
		name      string
		ct        collector.ContainerRow
		job       ciJob
		wantOK    bool
		wantPower collector.Strength
	}{
		{"exact image name", collector.ContainerRow{Image: "myapp:latest"}, ciJob{Image: "myapp"}, true, collector.StrengthStrongHeuristic},
		{"registry suffix both sides", collector.ContainerRow{Image: "x"}, ciJob{Image: "registry.example.com/svc/myapp"}, false, ""},
		{"both bare names match", collector.ContainerRow{Image: "registry.example.com/svc/web:1.0"}, ciJob{Image: "web"}, true, collector.StrengthStrongHeuristic},
		{"tag on both sides", collector.ContainerRow{Image: "myapp:1.2"}, ciJob{Image: "myapp:latest"}, true, collector.StrengthStrongHeuristic},
		{"service name weak", collector.ContainerRow{Name: "web"}, ciJob{Image: "web"}, true, collector.StrengthWeakHeuristic},
		{"no image", collector.ContainerRow{Name: "web"}, ciJob{}, false, ""},
		{"no match", collector.ContainerRow{Image: "other"}, ciJob{Image: "myapp"}, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strength, ok := matchContainer(tt.ct, tt.job)
			if ok != tt.wantOK || strength != tt.wantPower {
				t.Errorf("got (%q,%v) want (%q,%v)", strength, ok, tt.wantPower, tt.wantOK)
			}
		})
	}
}

func TestCollectCILinksContainer(t *testing.T) {
	dir := initTestRepo(t)
	writeWorkflow(t, dir, ".github/workflows/ci.yml", ghaWorkflow)
	script := filepath.Join(dir, "main.go")
	idx := &fakeIndex{
		rows: []collector.PathRow{{IdentityKey: "script|" + script, Path: script}},
		containers: []collector.ContainerRow{
			{IdentityKey: "container|abc123", Name: "web", Image: "myapp:latest"},
		},
	}
	sink := &fakeSink{}
	if err := New(idx).Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	ciJobs := sink.entityByKind("ci_job")
	if len(ciJobs) != 1 || ciJobs[0].Name != "build" {
		t.Fatalf("want 1 ci_job build, got %+v", ciJobs)
	}
	edges := sink.edgeByKind("deployed_by")
	if len(edges) != 1 {
		t.Fatalf("want 1 deployed_by edge, got %d", len(edges))
	}
	if edges[0].SrcIdentityKey != "container|abc123" || edges[0].Strength != collector.StrengthStrongHeuristic {
		t.Errorf("unexpected edge %+v", edges[0])
	}
}

func TestCollectCIWeakServiceNameMatch(t *testing.T) {
	dir := initTestRepo(t)
	writeWorkflow(t, dir, ".gitlab-ci.yml", "deploy:\n  image: web\n")
	script := filepath.Join(dir, "main.go")
	idx := &fakeIndex{
		rows: []collector.PathRow{{IdentityKey: "script|" + script, Path: script}},
		containers: []collector.ContainerRow{
			{IdentityKey: "container|abc123", Name: "web", Image: "unrelated:latest"},
		},
	}
	sink := &fakeSink{}
	if err := New(idx).Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	edges := sink.edgeByKind("deployed_by")
	if len(edges) != 1 || edges[0].Strength != collector.StrengthWeakHeuristic {
		t.Fatalf("want weak deployed_by edge, got %+v", edges)
	}
}

func TestCollectCIJenkinsExcluded(t *testing.T) {
	dir := initTestRepo(t)
	if err := os.WriteFile(filepath.Join(dir, "Jenkinsfile"), []byte("pipeline { agent any }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "main.go")
	idx := &fakeIndex{
		rows: []collector.PathRow{{IdentityKey: "script|" + script, Path: script}},
		containers: []collector.ContainerRow{
			{IdentityKey: "container|abc123", Name: "web", Image: "myapp:latest"},
		},
	}
	sink := &fakeSink{}
	if err := New(idx).Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(sink.entityByKind("ci_job")) != 0 {
		t.Error("Jenkinsfile must not produce ci_job entities")
	}
}

func TestCollectCIMalformedWorkflowBlindSpot(t *testing.T) {
	dir := initTestRepo(t)
	writeWorkflow(t, dir, ".github/workflows/bad.yml", ":\n\tbad: [")
	script := filepath.Join(dir, "main.go")
	idx := &fakeIndex{
		rows: []collector.PathRow{{IdentityKey: "script|" + script, Path: script}},
		containers: []collector.ContainerRow{
			{IdentityKey: "container|abc123", Name: "web", Image: "myapp:latest"},
		},
	}
	sink := &fakeSink{}
	if err := New(idx).Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	found := false
	for _, b := range sink.blinds {
		if b.Reason == "ci_workflow_unreadable" {
			found = true
		}
	}
	if !found {
		t.Errorf("want ci_workflow_unreadable blind, got %+v", sink.blinds)
	}
}
