package ui

import (
	"Picocrypt-NG/internal/fileops"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestScanFoldersRefusesResourceBudgetBeforeEmittingFiles(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "original")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	budget := fileops.NewZIPResourceBudget()
	if err := budget.Reserve(budget.LimitBytes() - 64); err != nil {
		t.Fatal(err)
	}
	emitted := false
	err := scanFoldersWithBudget(context.Background(), []string{root}, budget, func(context.Context, []scannedFile) error { emitted = true; return nil })
	if !errors.Is(err, fileops.ErrZIPMetadataLimit) || emitted {
		t.Fatalf("scan = %v, emitted=%v; budget refusal must precede selection copies", err, emitted)
	}
	body, err := os.ReadFile(path)
	if err != nil || string(body) != "original" {
		t.Fatalf("source changed: %q, %v", body, err)
	}
}

func TestDeletionDiscoveryBudgetRefusalRetainsOriginalAndOccupiedOutput(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "original")
	occupied := filepath.Join(root, "occupied.pcv")
	for _, path := range []string{original, occupied} {
		if err := os.WriteFile(path, []byte("unchanged"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	budget := fileops.NewZIPResourceBudget()
	if err := budget.Reserve(budget.LimitBytes() - 64); err != nil {
		t.Fatal(err)
	}
	manifest, err := captureOperationDeletionManifestWithBudget(context.Background(), operationInput{mode: "encrypt", inputFiles: []string{original}, onlyFolders: []string{root}, outputFile: occupied, delete: true}, budget)
	if !errors.Is(err, fileops.ErrZIPMetadataLimit) || manifest != nil {
		t.Fatalf("manifest=%v err=%v; want refusal without deletion authority", manifest, err)
	}
	for _, path := range []string{original, occupied} {
		body, err := os.ReadFile(path)
		if err != nil || string(body) != "unchanged" {
			t.Fatalf("discovery changed %s: %q, %v", path, body, err)
		}
	}
}

func TestZIPWriterSharesDeletionDiscoveryBudgetAndKeepsSourcesOnRefusal(t *testing.T) {
	root := t.TempDir()
	paths := []string{filepath.Join(root, "a"), filepath.Join(root, "b")}
	foreign := filepath.Join(root, "foreign.pcv")
	for _, path := range append(paths, foreign) {
		if err := os.WriteFile(path, []byte("unchanged"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	budget := fileops.NewZIPResourceBudget()
	baseline := budget.LimitBytes() - (5 << 20)
	if err := budget.Reserve(baseline); err != nil {
		t.Fatal(err)
	}
	input := operationInput{mode: "encrypt", inputFiles: paths, onlyFiles: paths, outputFile: filepath.Join(root, "output.pcv"), password: []byte("public test password"), delete: true, zipBudget: budget}
	result := (&App{}).runCapturedOperation(context.Background(), executeVolumeOperation, nil, input)
	if !errors.Is(result.err, fileops.ErrZIPMetadataLimit) || result.completed {
		t.Fatalf("ZIP operation used a new budget after deletion discovery: %+v", result)
	}
	for _, path := range append(paths, foreign) {
		body, err := os.ReadFile(path)
		if err != nil || string(body) != "unchanged" {
			t.Fatalf("refused operation changed %s: %q %v", path, body, err)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"a": true, "b": true, "foreign.pcv": true}
	for _, entry := range entries {
		if !want[entry.Name()] {
			t.Fatalf("refusal left output/staging residue: %s", entry.Name())
		}
	}
	if len(entries) != len(want) {
		t.Fatal("refusal removed a protected source")
	}
	if budget.CurrentBytes() != baseline {
		t.Fatalf("shared operation budget retained %d bytes", budget.CurrentBytes()-baseline)
	}
}
