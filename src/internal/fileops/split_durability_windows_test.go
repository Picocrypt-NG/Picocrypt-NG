//go:build windows

package fileops

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSplitRequiredNativeDirectorySyncRefusesUnconfirmedDurability(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "ciphertext.pcv")
	payload := bytes.Repeat([]byte("ciphertext survives unsupported directory flush"), 100)
	if err := os.WriteFile(input, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	chunks, err := Split(SplitOptions{
		InputPath: input, ChunkSize: 1, Unit: SplitUnitKiB, RequireDirectorySync: true,
	})
	if err == nil || len(chunks) != 0 {
		t.Fatalf("unconfirmed native Windows directory flush accepted: chunks=%v err=%v", chunks, err)
	}
	entries, readErr := os.ReadDir(directory)
	if readErr != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(input) {
		t.Fatalf("failed split left partial chunks: %v, %v", entries, readErr)
	}
	got, readErr := os.ReadFile(input)
	if readErr != nil || !bytes.Equal(got, payload) {
		t.Fatalf("failed split changed complete ciphertext: %v", readErr)
	}
}
