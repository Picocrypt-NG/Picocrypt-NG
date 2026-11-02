package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func contextFixture(t *testing.T) string {
	t.Helper()
	repo, _ := recordCountFixture(t, "package pcv3\n")
	for relative, source := range map[string]string{"src/go.sum": "", "src/internal/util/unselected.go": "package util\n"} {
		path := filepath.Join(repo, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return repo
}

func TestSourceContextRejectsNewBindingAfterActualPayloadLoad(t *testing.T) {
	repo, cache := payloadFixture(t, currentPayload(t), "")
	if err := os.WriteFile(filepath.Join(repo, "src/go.sum"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	context, err := captureSourceContext(repo)
	if err != nil {
		t.Fatal(err)
	}
	before, err := loadPayloadFixture(t, repo, cache)
	if err != nil {
		t.Fatal(err)
	}
	late := filepath.Join(repo, "src/internal/pcv3operation/internal/pcv3/late.go")
	if err = os.WriteFile(late, []byte("package pcv3\nvar false = true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	unchanged := true
	for path, snapshot := range before.Snapshots {
		current, err := os.ReadFile(filepath.Join(repo, path))
		if err != nil {
			t.Fatal(err)
		}
		unchanged = unchanged && bytes.Equal(snapshot, current)
	}
	if !unchanged {
		t.Fatal("witness unexpectedly modified a selected source file")
	}
	_, freshErr := loadPayloadFixture(t, repo, cache)
	if freshErr == nil || !strings.Contains(freshErr.Error(), "unreviewed payload binding \"false\"") {
		t.Fatalf("fresh load did not identify the new actual false binding: %v", freshErr)
	}
	_, contextErr := checkSourceContext(repo, context)
	if contextErr == nil {
		t.Fatal("new source file changed the actual false binding but source-context guard accepted it")
	}
	t.Logf("old selected finalcheck unchanged=%t; freshloader=%v; contextguard=%v", unchanged, freshErr, contextErr)
}

func TestSourceContextRejectsInventoryContentAndModuleDrift(t *testing.T) {
	for _, kind := range []string{"addition", "existing unselected source", "deletion", "module", "checksums"} {
		t.Run(kind, func(t *testing.T) {
			repo := contextFixture(t)
			before, err := captureSourceContext(repo)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(repo, "src/internal/util/unselected.go")
			switch kind {
			case "addition":
				path = filepath.Join(repo, "src/internal/pcv3operation/internal/pcv3/late.go")
				err = os.WriteFile(path, []byte("package pcv3\nvar false = true\n"), 0644)
			case "existing unselected source":
				err = os.WriteFile(path, []byte("package util\nvar true = false\n"), 0644)
			case "deletion":
				err = os.Remove(path)
			case "module":
				err = os.WriteFile(filepath.Join(repo, "src/go.mod"), []byte("module Picocrypt-NG\n\ngo 1.27.2\n"), 0644)
			case "checksums":
				err = os.WriteFile(filepath.Join(repo, "src/go.sum"), []byte("changed checksum input\n"), 0644)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = checkSourceContext(repo, before); err == nil {
				t.Fatal("source-context drift was accepted")
			}
		})
	}
}

func TestSourceContextScopeIsOwnNonTestGoAndModuleInputs(t *testing.T) {
	repo := contextFixture(t)
	before, err := captureSourceContext(repo)
	if err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{"src/internal/util/new_test.go", "src/internal/util/data.txt", "verification/extra.go"} {
		path := filepath.Join(repo, relative)
		if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, []byte("outside the production-Go context scope\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	after, err := checkSourceContext(repo, before)
	if err != nil {
		t.Fatal(err)
	}
	if after.SHA256 != before.SHA256 {
		t.Fatal("reported context scope includes unrelated inputs")
	}
}

func TestSourceContextRejectsNewNestedModuleBoundary(t *testing.T) {
	repo, cache := payloadFixture(t, currentPayload(t), "")
	if err := os.WriteFile(filepath.Join(repo, "src/go.sum"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	before, err := captureSourceContext(repo)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repo, "src/internal/pcv3operation/internal/pcv3/go.mod")
	if err = os.WriteFile(path, []byte("module detached\n\ngo 1.27.3\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, freshErr := loadPayloadFixture(t, repo, cache); freshErr == nil {
		t.Fatal("nested module fixture did not alter actual package resolution")
	}
	if _, err = checkSourceContext(repo, before); err == nil {
		t.Fatal("new module boundary changed package resolution but source-context guard accepted it")
	}
}
