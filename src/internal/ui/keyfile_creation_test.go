package ui

import (
	"Picocrypt-NG/internal/keyfile"
	"Picocrypt-NG/internal/secret"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestGeneratedKeyfileCanBeReadByOwnerWithoutReplacingExistingKey(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "generated.bin")
	if err := writeGeneratedKeyfile(t.Context(), target); err != nil {
		t.Fatalf("create keyfile: %v", err)
	}
	original, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.SecureZero(original)
	if len(original) != 32 {
		t.Fatalf("keyfile size = %d, want 32", len(original))
	}
	processed, err := keyfile.Process([]string{target}, false, nil)
	if err != nil {
		t.Fatalf("read generated keyfile through keyfile processor: %v", err)
	}
	defer secret.SecureZeroMultiple(processed.Key, processed.Hash)
	if err := writeGeneratedKeyfile(t.Context(), target); err == nil {
		t.Fatal("keyfile generation replaced an existing credential")
	}
	current, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.SecureZero(current)
	if !bytes.Equal(current, original) {
		t.Fatal("existing credential changed")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(target) {
		t.Fatalf("unexpected staging residue: %v", err)
	}
}

func TestCancelledKeyfileGenerationLeavesNoOutput(t *testing.T) {
	parent := t.TempDir()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := writeGeneratedKeyfile(ctx, filepath.Join(parent, "generated.bin")); err == nil {
		t.Fatal("cancelled keyfile generation reported success")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("cancelled generation left %d entries: %v", len(entries), err)
	}
}
