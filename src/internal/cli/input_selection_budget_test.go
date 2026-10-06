package cli

import (
	"Picocrypt-NG/internal/fileops"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestEncryptDiscoveryBudgetRefusalReturnsNoPartialSelection(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "original")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, paths := range [][]string{{path}, {root}} {
		budget := fileops.NewZIPResourceBudget()
		if err := budget.Reserve(budget.LimitBytes() - 64); err != nil {
			t.Fatal(err)
		}
		inputs, err := resolveEncryptInputsWithBudget(context.Background(), paths, nil, false, budget)
		if !errors.Is(err, fileops.ErrZIPMetadataLimit) {
			t.Fatalf("resolve %v = %v; want resource refusal", paths, err)
		}
		if len(inputs.inputFiles) != 0 || len(inputs.selections) != 0 {
			t.Fatal("resource refusal returned partial encryption selection")
		}
	}
	body, err := os.ReadFile(path)
	if err != nil || string(body) != "original" {
		t.Fatalf("source changed: %q, %v", body, err)
	}
}

func TestEncryptDiscoveryPreservesLexicalSelectionDeduplicationAndSymlinkPolicy(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"z.txt", "a.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(root, "b-link")
	if err := os.Symlink(filepath.Join(root, "z.txt"), link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	for _, follow := range []bool{false, true} {
		inputs, err := resolveEncryptInputs([]string{root}, []string{filepath.Join(root, "*.txt")}, follow)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{filepath.Join(root, "a.txt"), filepath.Join(root, "z.txt")}
		if follow {
			want = []string{filepath.Join(root, "a.txt"), link, filepath.Join(root, "z.txt")}
		}
		if !reflect.DeepEqual(inputs.inputFiles, want) {
			t.Fatalf("follow=%v paths=%v want=%v", follow, inputs.inputFiles, want)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	inputs, err := resolveEncryptInputsWithBudget(ctx, []string{root}, nil, false, fileops.NewZIPResourceBudget())
	if !errors.Is(err, context.Canceled) || len(inputs.inputFiles) != 0 {
		t.Fatalf("cancelled discovery=%v paths=%v", err, inputs.inputFiles)
	}
}

func TestSplitOutputDiscoveryBudgetRefusalPreservesOccupiedChunks(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "output.pcv")
	chunk := output + ".0"
	if err := os.WriteFile(chunk, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	budget := fileops.NewZIPResourceBudget()
	if err := budget.Reserve(budget.LimitBytes() - 64); err != nil {
		t.Fatal(err)
	}
	artifacts, err := existingSplitOutputArtifactsWithBudget(output, budget)
	if !errors.Is(err, fileops.ErrZIPMetadataLimit) || len(artifacts) != 0 {
		t.Fatalf("split-output discovery=%v artifacts=%v; want early refusal", err, artifacts)
	}
	body, err := os.ReadFile(chunk)
	if err != nil || string(body) != "foreign" {
		t.Fatalf("occupied chunk changed: %q, %v", body, err)
	}
}
