//go:build windows

package fileops

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestSplitRequiredNativeDirectorySyncHonorsFilesystemContract(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "ciphertext.pcv")
	payload := make([]byte, 3072)
	for index := range payload {
		payload[index] = byte(index)
	}
	if err := os.WriteFile(input, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	chunks, err := Split(SplitOptions{
		InputPath: input, ChunkSize: 1, Unit: SplitUnitKiB, RequireDirectorySync: true,
	})
	if nativeFileopsDirectorySyncSupported(t, directory) {
		if err != nil || len(chunks) != 3 {
			t.Fatalf("native durable split = %v/%v; want three complete chunks", chunks, err)
		}
		for index := range 3 {
			chunk := fmt.Sprintf("%s.%d", input, index)
			if info, err := os.Lstat(chunk); err != nil || !info.Mode().IsRegular() {
				t.Fatalf("native chunk %d is not a regular file: %v", index, err)
			}
		}
		recombined := filepath.Join(directory, "recombined.pcv")
		if err := Recombine(RecombineOptions{InputBase: input, OutputPath: recombined}); err != nil {
			t.Fatalf("recombine durable native chunks: %v", err)
		}
		got, err := os.ReadFile(recombined)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("durable native chunks changed ciphertext: %v", err)
		}
	} else {
		if !errors.Is(err, errors.ErrUnsupported) || len(chunks) != 0 {
			t.Fatalf("unsupported native split = %v/%v; want unsupported and no chunks", chunks, err)
		}
		entries, readErr := os.ReadDir(directory)
		if readErr != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(input) {
			t.Fatalf("failed split left partial chunks: %v, %v", entries, readErr)
		}
	}
	got, readErr := os.ReadFile(input)
	if readErr != nil || !bytes.Equal(got, payload) {
		t.Fatalf("native split changed complete input ciphertext: %v", readErr)
	}
}
