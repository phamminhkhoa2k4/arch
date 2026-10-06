package compose

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return p
}

const labCompose = `name: lab

services:
  web:
    container_name: lab-web
    image: nginx:1.27-alpine
    ports:
      - "8081:80"
    depends_on:
      - helper

  api:
    container_name: lab-api
    image: nginx:1.27-alpine

  helper:
    container_name: lab-helper
    image: alpine:3.20
`

func TestLoadParsesServicesAndShortDependsOn(t *testing.T) {
	p := write(t, "docker-compose.yml", labCompose)
	f, err := NewLoader().Load(p, "")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if f.Project != "lab" {
		t.Errorf("project = %q, want lab", f.Project)
	}
	if len(f.Services) != 3 {
		t.Fatalf("got %d services, want 3: %v", len(f.Services), f.Services)
	}
	web := f.Services["web"]
	if web == nil || len(web.DependsOn) != 1 || web.DependsOn[0] != "helper" {
		t.Errorf("web.DependsOn = %+v", web)
	}
	if len(f.Services["api"].DependsOn) != 0 {
		t.Errorf("api must have no deps: %+v", f.Services["api"])
	}
}

// Long syntax with condition: service_healthy still produces the edge
// — v0.1 does not distinguish condition types.
func TestLoadLongDependsOnConditionForm(t *testing.T) {
	body := `services:
  web:
    image: nginx
    depends_on:
      db:
        condition: service_healthy
      cache:
        condition: service_started
        restart: true
  db:
    image: postgres
  cache:
    image: redis
`
	f, err := NewLoader().Load(write(t, "compose.yml", body), "proj")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := f.Services["web"].DependsOn
	if len(got) != 2 || got[0] != "cache" || got[1] != "db" {
		t.Errorf("web deps = %v, want [cache db] (sorted)", got)
	}
}

// Environment variables in the file must not fail the parse —
// interpolation is off; we only need the static graph.
func TestLoadWithoutEnvironmentResolution(t *testing.T) {
	body := `services:
  app:
    image: ${MISSING_IMAGE_VAR}
    environment:
      - TOKEN=${ALSO_MISSING}
`
	f, err := NewLoader().Load(write(t, "c.yml", body), "")
	if err != nil {
		t.Fatalf("load with unresolved vars must succeed: %v", err)
	}
	if _, ok := f.Services["app"]; !ok {
		t.Errorf("services = %v", f.Services)
	}
}

// A recorded path that no longer exists → IsNotFound so the caller
// writes "compose file not found at recorded path" as a blind spot.
func TestLoadNotFound(t *testing.T) {
	_, err := NewLoader().Load(filepath.Join(t.TempDir(), "gone.yml"), "")
	if err == nil || !IsNotFound(err) {
		t.Fatalf("err = %v, want IsNotFound", err)
	}
	if !strings.Contains(err.Error(), "compose file not found at recorded path") {
		t.Errorf("message = %q", err.Error())
	}
}

func TestLoadInvalidYAMLError(t *testing.T) {
	_, err := NewLoader().Load(write(t, "bad.yml", "services:\n  x: [\n"), "")
	if err == nil || IsNotFound(err) {
		t.Fatalf("err = %v, want parse error", err)
	}
}

func TestFingerprintChangesWithContent(t *testing.T) {
	a, _ := NewLoader().Load(write(t, "a.yml", labCompose), "")
	b, _ := NewLoader().Load(write(t, "b.yml", labCompose+"  # drift\n"), "")
	same, _ := NewLoader().Load(write(t, "c.yml", labCompose), "")
	if a.Fingerprint() != same.Fingerprint() {
		t.Error("same content must fingerprint equal")
	}
	if a.Fingerprint() == b.Fingerprint() {
		t.Error("changed content must fingerprint differently")
	}
}

// Several config files of one project load independently (the
// collector concatenates their content itself); an override fragment
// referencing base-file services must still parse.
func TestLoadOverrideFragment(t *testing.T) {
	base := write(t, "base.yml", labCompose)
	override := write(t, "override.yml", `services:
  web:
    image: nginx:1.28
    depends_on:
      - helper
      - api
`)
	f1, err := NewLoader().Load(base, "lab")
	if err != nil {
		t.Fatalf("load base: %v", err)
	}
	f2, err := NewLoader().Load(override, "lab")
	if err != nil {
		t.Fatalf("load override fragment must succeed: %v", err)
	}
	if len(f1.Services) != 3 {
		t.Errorf("base services = %d, want 3", len(f1.Services))
	}
	if len(f2.Services["web"].DependsOn) != 2 {
		t.Errorf("override deps = %v, want [api helper]", f2.Services["web"].DependsOn)
	}
}
