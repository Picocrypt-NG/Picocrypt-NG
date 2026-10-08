package pcv3publication

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteRetainedKeepsOriginalDescriptorAndUncertainPublishedOutput(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(map[bool]string{false: "durable", true: "uncertain"}[uncertain], func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, "ciphertext")
			operations, _ := realRenameOperations(t, directory)
			operations.openRetained = func(*os.Root, string) (*os.File, error) {
				t.Fatal("write custody reopened output")
				return nil, errors.New("reopen")
			}
			if uncertain {
				operations.syncDirectory = func(*os.File) error { return errors.New("sync") }
			}
			stage, err := createWithOperations(target, nil, PolicyNoReplace, operations)
			if err != nil {
				t.Fatal(err)
			}
			original := stage.File()
			if _, err := original.Write([]byte("ciphertext")); err != nil {
				t.Fatal(err)
			}
			result, held := stage.PublishWriteRetained(context.Background())
			want := StatePublishedDurable
			if uncertain {
				want = StatePublishedDurabilityUncertain
			}
			if result.State() != want || held == nil || held.file != original {
				t.Fatalf("state=%v held=%v", result, held)
			}
			if err := stage.Cleanup(); err != nil {
				t.Fatal(err)
			}
			if _, err := original.Stat(); err != nil {
				t.Fatalf("held descriptor closed: %v", err)
			}
			if err := held.Close(); err != nil {
				t.Fatal(err)
			}
			if data, err := os.ReadFile(target); err != nil || string(data) != "ciphertext" {
				t.Fatalf("published output lost: %q %v", data, err)
			}
		})
	}
}
