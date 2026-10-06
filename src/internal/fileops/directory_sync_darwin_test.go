//go:build darwin

package fileops

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDarwinUnsupportedFullSyncRefusesSplitAndArchiveDurability(t *testing.T) {
	for _, failure := range []error{unix.ENOTSUP, unix.EINVAL, unix.EIO} {
		t.Run(failure.Error(), func(t *testing.T) {
			native := darwinFullSync
			darwinFullSync = func(uintptr) error { return failure }
			t.Cleanup(func() { darwinFullSync = native })
			directory := t.TempDir()
			input := filepath.Join(directory, "complete.pcv")
			payload := bytes.Repeat([]byte("ciphertext"), 300)
			if err := os.WriteFile(input, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			chunks, err := Split(SplitOptions{InputPath: input, ChunkSize: 1, Unit: SplitUnitKiB, RequireDirectorySync: true})
			if !errors.Is(err, failure) || len(chunks) != 0 {
				t.Fatalf("unsupported split barrier returned %v/%v; want failure and no completed set", chunks, err)
			}
			requireUnpackFileBytes(t, input, payload)
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 1 || entries[0].Name() != "complete.pcv" {
				t.Fatalf("failed split must leave only complete container: %v/%v", entries, err)
			}

			archive := filepath.Join(directory, "archive.zip")
			createStoredZipForUnpackStagingTest(t, archive, "nested/payload.txt", payload)
			output := filepath.Join(directory, "out")
			if err := os.Mkdir(output, 0o700); err != nil {
				t.Fatal(err)
			}
			result := UnpackWithResult(UnpackOptions{ZipPath: archive, ExtractDir: output})
			requireUnpackState(t, result, UnpackStatePublishedDurabilityUncertain)
			if !errors.Is(result, failure) {
				t.Fatalf("archive lost directory barrier failure: %v", result)
			}
			requireUnpackFileBytes(t, filepath.Join(output, "nested", "payload.txt"), payload)
			requireNoUnpackStages(t, output)
		})
	}
}

func TestDarwinDirectoryFullSyncRetriesInterruptionThenRequiresNativeSuccess(t *testing.T) {
	native := darwinFullSync
	interrupted := false
	darwinFullSync = func(fd uintptr) error {
		if !interrupted {
			interrupted = true
			return unix.EINTR
		}
		return native(fd)
	}
	t.Cleanup(func() { darwinFullSync = native })
	parent, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if err := SyncDirectory(parent); err != nil {
		t.Fatalf("required native directory full-sync failed: %v", err)
	}
}
