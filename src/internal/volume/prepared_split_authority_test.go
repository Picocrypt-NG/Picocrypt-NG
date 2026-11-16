package volume

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Invalid synthetic legacy bytes make any KDF call a failure: changed sources
// must be refused during preparation/recombination, before parsing plaintext.
func TestPreparedSplitAuthorityCannotBeDiscardedByCallerManifest(t *testing.T) {
	for _, manifest := range []string{"omitted", "prepared", "replacement"} {
		for _, change := range []string{"identity", "size", "symlink", "directory", "added", "removed"} {
			t.Run(manifest+"/"+change, func(t *testing.T) {
				base, _ := writeExpectedInputChunks(t, bytes.Repeat([]byte("L"), 128))
				prepared, err := PrepareDecryptInput(base+".0", true)
				if err != nil {
					t.Fatal(err)
				}
				defer prepared.Close()
				tail := base + ".1"
				switch change {
				case "identity", "symlink", "directory", "removed":
					if err := os.Rename(tail, tail+".selected"); err != nil {
						t.Fatal(err)
					}
					if change == "identity" {
						if err := os.WriteFile(tail, bytes.Repeat([]byte("R"), 64), 0o600); err != nil {
							t.Fatal(err)
						}
					}
					if change == "symlink" {
						if err := os.Symlink(tail+".selected", tail); err != nil {
							t.Skipf("symlinks unavailable: %v", err)
						}
					}
					if change == "directory" {
						if err := os.Mkdir(tail, 0o700); err != nil {
							t.Fatal(err)
						}
					}
				case "size":
					if err := os.Truncate(tail, 65); err != nil {
						t.Fatal(err)
					}
				case "added":
					if err := os.WriteFile(base+".2", []byte("late"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				req := &DecryptRequest{InputFile: base + ".0", OutputFile: base + ".plaintext", Password: []byte("test"), Recombine: true, RSCodecs: newRSCodecsT(t)}
				if manifest == "prepared" {
					req.RecombineExpectedInputs = prepared.inputInfos
				}
				if manifest == "replacement" {
					req.RecombineExpectedInputs = append([]os.FileInfo(nil), prepared.inputInfos...)
					if current, statErr := os.Stat(tail); statErr == nil {
						req.RecombineExpectedInputs[1] = current
					}
				}
				calls := 0
				old := deriveVolumeKey
				deriveVolumeKey = func([]byte, []byte, bool) ([]byte, error) { calls++; return nil, errors.New("unexpected KDF") }
				defer func() { deriveVolumeKey = old }()
				err = DecryptPrepared(context.Background(), req, prepared)
				if err == nil || calls != 0 || !strings.Contains(err.Error(), "chunk") {
					t.Fatalf("changed prepared input was not refused at chunk boundary: KDF=%d err=%v", calls, err)
				}
				for _, path := range []string{base, req.OutputFile} {
					if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("changed input left output %q: %v", path, err)
					}
				}
				assertNoPicocryptStages(t, filepath.Dir(base))
				assertFileBytes(t, base+".0", bytes.Repeat([]byte("L"), 64))
			})
		}
	}
}
