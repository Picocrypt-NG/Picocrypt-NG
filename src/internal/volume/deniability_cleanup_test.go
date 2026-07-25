package volume

import (
	"Picocrypt-NG/internal/encoding"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestRemoveDeniabilityRemovesTempOnVerificationFailure locks the cleanup
// invariant: when RemoveDeniability decrypts a deniability wrapper whose inner
// payload is not a valid volume, it must remove its random staging file
// rather than leaving the recovered inner plaintext on disk. Cleanup is plain
// os.Remove (no shredding — overwrite-before-unlink was dropped as useless on
// flash/CoW filesystems); the only invariant is that the temp is gone.
func TestRemoveDeniabilityRemovesTempOnVerificationFailure(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	tmpDir := t.TempDir()
	wrappedPath := filepath.Join(tmpDir, "wrapped-invalid-inner.pcv")
	innerPlaintext := bytes.Repeat([]byte("invalid inner volume plaintext; "), 4)
	if err := os.WriteFile(wrappedPath, innerPlaintext, 0o600); err != nil {
		t.Fatalf("write invalid inner volume: %v", err)
	}

	const password = "deniability-cleanup-password"
	if err := AddDeniability(wrappedPath, []byte(password), nil); err != nil {
		t.Fatalf("AddDeniability failed: %v", err)
	}

	before, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("read directory before RemoveDeniability: %v", err)
	}

	decryptedStage, err := RemoveDeniability(wrappedPath, []byte(password), nil, rs)
	if err == nil {
		decryptedStage.Cleanup()
		t.Fatalf("RemoveDeniability succeeded for invalid inner volume, returned %q", decryptedStage.Path())
	}
	after, readErr := os.ReadDir(tmpDir)
	if readErr != nil {
		t.Fatalf("read directory after RemoveDeniability: %v", readErr)
	}
	if len(after) != len(before) {
		t.Fatalf("RemoveDeniability leaked a staging file: before=%v after=%v", before, after)
	}
}
