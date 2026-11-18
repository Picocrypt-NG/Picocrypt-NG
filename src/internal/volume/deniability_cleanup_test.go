package volume

import (
	"Picocrypt-NG/internal/encoding"
	perrors "Picocrypt-NG/internal/errors"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type cancelAfterDeniabilityReporter struct {
	GoldenTestReporter
	wasDisabled bool
	canCancel   bool
}

func (r *cancelAfterDeniabilityReporter) SetCanCancel(canCancel bool) {
	r.wasDisabled = r.wasDisabled || !canCancel
	r.canCancel = canCancel
}

func (r *cancelAfterDeniabilityReporter) Update() {
	if r.wasDisabled && r.canCancel {
		r.cancelled = true
	}
}

func TestLegacyDeniabilityReporterCancellationPreventsPublication(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	output := filepath.Join(dir, "output.pcv")
	plaintext := []byte("legacy deniability cancellation")
	if err := os.WriteFile(input, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}

	reporter := &cancelAfterDeniabilityReporter{}
	err := Encrypt(t.Context(), &EncryptRequest{
		InputFile: input, OutputFile: output, Password: []byte("test"),
		Deniability: true, Reporter: reporter, RSCodecs: newRSCodecsT(t),
	})
	if !reporter.IsCancelled() || !errors.Is(err, perrors.ErrCancelled) {
		t.Fatalf("reporter cancelled = %t, Encrypt error = %v; want reporter cancellation", reporter.IsCancelled(), err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(input) {
		t.Fatalf("cancelled encryption left an output or staging file: %v", entries)
	}
	got, err := os.ReadFile(input)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("cancelled encryption changed its input: %v", err)
	}
}

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
