package gitrepo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

	"archaeologist/internal/collector"
)

// fakeSink records everything a collector emits.
type fakeSink struct {
	entities []collector.Entity
	edges    []collector.Edge
	evidence []collector.Evidence
	blinds   []collector.BlindSpot
}

func (f *fakeSink) UpsertEntity(e collector.Entity) error {
	f.entities = append(f.entities, e)
	return nil
}
func (f *fakeSink) UpsertEdge(e collector.Edge) error {
	f.edges = append(f.edges, e)
	return nil
}
func (f *fakeSink) AddEvidence(e collector.Evidence) error {
	f.evidence = append(f.evidence, e)
	return nil
}
func (f *fakeSink) AddBlindSpot(b collector.BlindSpot) error {
	f.blinds = append(f.blinds, b)
	return nil
}
func (f *fakeSink) AddFinding(collector.Finding) error { return nil }

func (f *fakeSink) entityByKind(kind string) []collector.Entity {
	var out []collector.Entity
	for _, e := range f.entities {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

func (f *fakeSink) edgeByKind(kind string) []collector.Edge {
	var out []collector.Edge
	for _, e := range f.edges {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// fakeIndex feeds canned path/container rows.
type fakeIndex struct {
	rows       []collector.PathRow
	containers []collector.ContainerRow
	err        error
}

func (f *fakeIndex) PathRows() ([]collector.PathRow, error) { return f.rows, f.err }
func (f *fakeIndex) ContainerRows() ([]collector.ContainerRow, error) {
	return f.containers, f.err
}

// initTestRepo creates a real git repository with one commit.
func initTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	r, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("init repo: %v", err)
	}
	file := filepath.Join(dir, "main.go")
	if err := os.WriteFile(file, []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	w, err := r.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}
	if _, err := w.Add("main.go"); err != nil {
		t.Fatalf("add: %v", err)
	}
	_, err = w.Commit("initial", &git.CommitOptions{
		Author: &object.Signature{Name: "Tester", Email: "t@example.com", When: time.Now()},
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	return dir
}

func TestCollectFindsRepoAndLinksFile(t *testing.T) {
	dir := initTestRepo(t)
	script := filepath.Join(dir, "main.go")
	idx := &fakeIndex{rows: []collector.PathRow{
		{IdentityKey: "script|" + script, Path: script},
	}}
	c := New(idx)
	sink := &fakeSink{}
	if err := c.Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	repos := sink.entityByKind("repo")
	if len(repos) != 1 {
		t.Fatalf("want 1 repo entity, got %d", len(repos))
	}
	if repos[0].Attributes["path"] != dir {
		t.Errorf("repo path = %q, want %q", repos[0].Attributes["path"], dir)
	}
	if repos[0].Attributes["branch"] != "master" && repos[0].Attributes["branch"] != "main" {
		t.Errorf("unexpected branch %q", repos[0].Attributes["branch"])
	}
	if repos[0].Attributes["last_commit_at"] == "" {
		t.Error("missing last_commit_at")
	}
	if repos[0].Attributes["last_contributor"] != "Tester" {
		t.Errorf("last_contributor = %q", repos[0].Attributes["last_contributor"])
	}
	edges := sink.edgeByKind("belongs_to")
	if len(edges) != 1 {
		t.Fatalf("want 1 belongs_to edge, got %d", len(edges))
	}
	if edges[0].SrcIdentityKey != "script|"+script || edges[0].DstIdentityKey != repos[0].IdentityKey {
		t.Errorf("unexpected edge %+v", edges[0])
	}
	if edges[0].Strength != collector.StrengthDeterministic {
		t.Errorf("edge strength = %q", edges[0].Strength)
	}
	if len(sink.evidence) == 0 || sink.evidence[0].Channel != "git" || sink.evidence[0].RawRef == "" {
		t.Errorf("missing git evidence: %+v", sink.evidence)
	}
	if len(sink.blinds) != 0 {
		t.Errorf("unexpected blind spots: %+v", sink.blinds)
	}
}

func TestCollectNoRepoIsSilent(t *testing.T) {
	plain := t.TempDir()
	script := filepath.Join(plain, "run.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	idx := &fakeIndex{rows: []collector.PathRow{
		{IdentityKey: "script|" + script, Path: script},
	}}
	sink := &fakeSink{}
	if err := New(idx).Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(sink.entities) != 0 || len(sink.blinds) != 0 {
		t.Errorf("expected silence, got %d entities %d blinds", len(sink.entities), len(sink.blinds))
	}
}

func TestCollectCorruptRepoBlindSpot(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "run.sh")
	if err := os.WriteFile(script, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	idx := &fakeIndex{rows: []collector.PathRow{
		{IdentityKey: "script|" + script, Path: script},
	}}
	sink := &fakeSink{}
	if err := New(idx).Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(sink.blinds) != 1 || sink.blinds[0].Reason != "git_repo_unreadable" {
		t.Fatalf("want git_repo_unreadable blind, got %+v", sink.blinds)
	}
	if len(sink.entityByKind("repo")) != 0 {
		t.Error("corrupt repo must not emit entity")
	}
}

type timeoutReader struct{}

func (timeoutReader) Read(string) (RepoInfo, error) {
	return RepoInfo{}, errors.New("git read exceeded 5s")
}

func TestCollectTimeoutBlindSpot(t *testing.T) {
	dir := initTestRepo(t)
	script := filepath.Join(dir, "main.go")
	idx := &fakeIndex{rows: []collector.PathRow{
		{IdentityKey: "script|" + script, Path: script},
	}}
	c := New(idx)
	c.SetReader(timeoutReader{})
	sink := &fakeSink{}
	if err := c.Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(sink.blinds) != 1 || sink.blinds[0].Reason != "git_repo_timeout" {
		t.Fatalf("want git_repo_timeout blind, got %+v", sink.blinds)
	}
}

func TestCollectDedupesSharedRepo(t *testing.T) {
	dir := initTestRepo(t)
	a := filepath.Join(dir, "a.sh")
	b := filepath.Join(dir, "sub", "b.sh")
	if err := os.MkdirAll(filepath.Dir(b), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	idx := &fakeIndex{rows: []collector.PathRow{
		{IdentityKey: "script|" + a, Path: a},
		{IdentityKey: "script|" + b, Path: b},
	}}
	sink := &fakeSink{}
	if err := New(idx).Collect(context.Background(), sink); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(sink.entityByKind("repo")) != 1 {
		t.Errorf("want 1 repo entity, got %d", len(sink.entityByKind("repo")))
	}
	if len(sink.edgeByKind("belongs_to")) != 2 {
		t.Errorf("want 2 belongs_to edges, got %d", len(sink.edgeByKind("belongs_to")))
	}
}
