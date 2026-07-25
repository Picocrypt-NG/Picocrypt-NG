package volume

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	perrors "Picocrypt-NG/internal/errors"
)

// assertCancelled fails unless err is a cancellation error (reporter-driven
// ErrCancelled or context.Canceled, through any %w wrapping) and the final output
// file was never produced. Encodes the cancellation contract: an aborted operation
// must surface a cancellation error and leave no partial volume behind.
func assertCancelled(t *testing.T, op string, err error, outputPath string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s must fail when cancelled, not complete", op)
	}
	if !errors.Is(err, perrors.ErrCancelled) && !errors.Is(err, context.Canceled) {
		t.Fatalf("%s cancellation error = %v; want errors.Is(ErrCancelled) or errors.Is(context.Canceled)", op, err)
	}
	if _, statErr := os.Stat(outputPath); !os.IsNotExist(statErr) {
		t.Errorf("cancelled %s left an output file at %s (stat err = %v)", op, outputPath, statErr)
	}
}

// =============================================================================
// Tests for VerifyFirst mode (decryptVerifyMACFirst)
// Addresses PCC-004 security audit recommendation
// =============================================================================

// TestVerifyFirstModeWithReedSolomon tests VerifyFirst mode with RS enabled
func TestVerifyFirstModeWithReedSolomon(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("VerifyFirst + Reed-Solomon test data for enhanced verification.")
	inputPath := filepath.Join(tmpDir, "verify_first_rs.txt")
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "verify_first_rs.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "verify_first_rs_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with Reed-Solomon
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    []byte("verify_first_rs_password"),
		ReedSolomon: true,
		Reporter:    reporter,
		RSCodecs:    rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt with VerifyFirst mode
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     []byte("verify_first_rs_password"),
		VerifyFirst:  true,
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt with VerifyFirst + RS failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch (VerifyFirst + RS)")
	}

	t.Log("VerifyFirst mode with Reed-Solomon: SUCCESS")
}

// TestVerifyFirstModeParanoid tests VerifyFirst mode with paranoid settings
func TestVerifyFirstModeParanoid(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("VerifyFirst + Paranoid mode test data with maximum security.")
	inputPath := filepath.Join(tmpDir, "verify_first_paranoid.txt")
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "verify_first_paranoid.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "verify_first_paranoid_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with paranoid mode
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   []byte("verify_first_paranoid_password"),
		Paranoid:   true,
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt with VerifyFirst mode
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     []byte("verify_first_paranoid_password"),
		VerifyFirst:  true,
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt with VerifyFirst + Paranoid failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch (VerifyFirst + Paranoid)")
	}

	t.Log("VerifyFirst mode with Paranoid: SUCCESS")
}

// TestVerifyFirstModeWithKeyfiles tests VerifyFirst mode with keyfiles
func TestVerifyFirstModeWithKeyfiles(t *testing.T) {
	restore := useProductionTestKDF()
	defer restore()

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	testdata := findTestdata(t)
	encryptedPath := filepath.Join(testdata, "pico_test_v2_keyfile_single.txt.pcv")
	keyfilePath := filepath.Join(testdata, "keyfile_alpha.bin")
	decryptedPath := filepath.Join(tmpDir, "verify_first_kf_dec.txt")

	reporter := &GoldenTestReporter{}

	// Read a frozen pre-2.19 volume; the current writer must remain disabled.
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     []byte(goldenPassword),
		Keyfiles:     []string{keyfilePath},
		VerifyFirst:  true,
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt with VerifyFirst + Keyfile failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != expectedContent {
		t.Errorf("Content mismatch (VerifyFirst + Keyfile)")
	}

	t.Log("VerifyFirst mode with keyfiles: SUCCESS")
}

// TestVerifyFirstModeCorruptedData tests VerifyFirst with corrupted data
func TestVerifyFirstModeCorruptedData(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("VerifyFirst corruption detection test data - integrity check.")
	inputPath := filepath.Join(tmpDir, "verify_first_corrupt.txt")
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "verify_first_corrupt.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "verify_first_corrupt_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   []byte("verify_first_corrupt_password"),
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Corrupt the payload
	data, err := os.ReadFile(encryptedPath)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}

	// Corrupt bytes in the payload area (after header)
	corruptOffset := header.BaseHeaderSize + 10
	if corruptOffset < len(data) {
		data[corruptOffset] ^= 0xFF
		data[corruptOffset+1] ^= 0xFF
	}

	if err := os.WriteFile(encryptedPath, data, 0o644); err != nil {
		t.Fatalf("Failed to write corrupted file: %v", err)
	}

	// Decrypt with VerifyFirst - should detect corruption before decryption
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     []byte("verify_first_corrupt_password"),
		VerifyFirst:  true,
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	err = Decrypt(context.Background(), decReq)
	if err == nil {
		t.Error("Expected VerifyFirst to detect corruption, but decryption succeeded")
	} else {
		t.Logf("VerifyFirst correctly detected corruption: %v", err)
	}

	// Verify output file was not created (corruption detected early)
	if _, err := os.Stat(decryptedPath); !os.IsNotExist(err) {
		t.Error("Output file should not exist after VerifyFirst detects corruption")
	}

	t.Log("VerifyFirst corruption detection: SUCCESS")
}

// TestVerifyFirstModeForceDecrypt tests VerifyFirst with ForceDecrypt on corrupted data
func TestVerifyFirstModeForceDecrypt(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := bytes.Repeat([]byte("VerifyFirst + ForceDecrypt payload. "), 32)
	inputPath := filepath.Join(tmpDir, "verify_force.txt")
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	encryptedPath := filepath.Join(tmpDir, "verify_force.txt.pcv")
	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   []byte("verify_force_password"),
		Reporter:   &GoldenTestReporter{},
		RSCodecs:   rsCodecs,
	}); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Corrupt one ciphertext byte so the MAC fails.
	data, err := os.ReadFile(encryptedPath)
	if err != nil {
		t.Fatalf("read encrypted: %v", err)
	}
	corruptOffset := header.BaseHeaderSize + 10
	if corruptOffset >= len(data)-64 {
		t.Fatalf("encrypted file too small (%d bytes)", len(data))
	}
	data[corruptOffset] ^= 0xFF
	if err := os.WriteFile(encryptedPath, data, 0o644); err != nil {
		t.Fatalf("write corrupted: %v", err)
	}

	// VerifyFirst WITHOUT ForceDecrypt: the pre-decryption MAC pass must reject and
	// leave no output.
	rejectedPath := filepath.Join(tmpDir, "verify_rejected.txt")
	if err := Decrypt(context.Background(), &DecryptRequest{
		InputFile:   encryptedPath,
		OutputFile:  rejectedPath,
		Password:    []byte("verify_force_password"),
		VerifyFirst: true,
		Reporter:    &GoldenTestReporter{},
		RSCodecs:    rsCodecs,
	}); err == nil {
		t.Fatal("VerifyFirst decrypt of corrupted data must fail without ForceDecrypt")
	}
	if _, statErr := os.Stat(rejectedPath); !os.IsNotExist(statErr) {
		t.Error("rejected VerifyFirst decrypt must not leave an output file")
	}

	// VerifyFirst WITH ForceDecrypt: forces through the MAC failure and keeps output.
	var kept bool
	keptPath := filepath.Join(tmpDir, "verify_force_dec.txt")
	if err := Decrypt(context.Background(), &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   keptPath,
		Password:     []byte("verify_force_password"),
		VerifyFirst:  true,
		ForceDecrypt: true,
		Kept:         &kept,
		Reporter:     &GoldenTestReporter{},
		RSCodecs:     rsCodecs,
	}); err != nil {
		t.Fatalf("VerifyFirst + ForceDecrypt must force through, got: %v", err)
	}
	if !kept {
		t.Error("VerifyFirst + ForceDecrypt over a MAC failure must set kept=true")
	}
	if _, statErr := os.Stat(keptPath); statErr != nil {
		t.Errorf("VerifyFirst + ForceDecrypt must produce an output file: %v", statErr)
	}
}

// TestVerifyFirstAllOptions tests VerifyFirst with all options enabled
func TestVerifyFirstParanoidReedSolomon(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("VerifyFirst with Paranoid mode and Reed-Solomon.")
	inputPath := filepath.Join(tmpDir, "verify_all.txt")
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "verify_all.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "verify_all_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with every currently supported compatible option.
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    []byte("verify_all_password"),
		Paranoid:    true,
		ReedSolomon: true,
		Reporter:    reporter,
		RSCodecs:    rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt with VerifyFirst
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     []byte("verify_all_password"),
		VerifyFirst:  true,
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt with VerifyFirst + Paranoid + Reed-Solomon failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch (VerifyFirst + Paranoid + Reed-Solomon)")
	}

	t.Log("VerifyFirst mode with Paranoid + Reed-Solomon: SUCCESS")
}

// =============================================================================
// Tests for TempZipReader (context.go)
// =============================================================================

// TestTempZipReaderNoTempZip tests TempZipReader when no temp zip is in use
func TestTempZipReaderNoTempZip(t *testing.T) {
	ctx := &OperationContext{
		TempZipInUse: false,
		TempCiphers:  nil,
	}

	testData := []byte("test data for reader")
	reader := bytes.NewReader(testData)

	wrapped := ctx.TempZipReader(reader)

	// When TempZipInUse is false, should return the same reader
	if wrapped != reader {
		t.Error("TempZipReader should return original reader when TempZipInUse is false")
	}
}

// =============================================================================
// Tests for error paths and edge cases
// =============================================================================

// TestDecryptWrongKeyfileMissingRequirement tests decryption when keyfile is required but not provided
func TestDecryptWrongKeyfileMissingRequirement(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()
	encryptedPath := filepath.Join(findTestdata(t), "pico_test_v2_keyfile_single.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "kf_required_dec.txt")

	reporter := &GoldenTestReporter{}

	// A frozen pre-2.19 volume must still demand its keyfile.
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     []byte(goldenPassword),
		Keyfiles:     nil, // No keyfile provided!
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	err = Decrypt(context.Background(), decReq)
	if err == nil {
		t.Fatal("Decrypt should fail when required keyfile is not provided")
	}
	// The keyfile-required gate must surface a typed ValidationError on the
	// "keyfiles" field (decrypt.go), not a generic/wrong error. Dropping the gate or
	// returning a different error type would let a keyfile-protected volume be
	// attempted without keyfiles.
	var ve *perrors.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("Decrypt error = %v, want *perrors.ValidationError", err)
	}
	if ve.Field != "keyfiles" {
		t.Errorf("ValidationError.Field = %q, want %q", ve.Field, "keyfiles")
	}
}

// TestDecryptCancellation tests that cancellation during decrypt is handled
func TestDecryptCancellation(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Multi-chunk plaintext (>1 MiB): the reporter cancels after the first progress
	// tick, so a single-chunk file would finish before the next IsCancelled check.
	plaintext := make([]byte, 3*1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}
	inputPath := filepath.Join(tmpDir, "cancel_test.bin")
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "cancel_test.bin.pcv")
	decryptedPath := filepath.Join(tmpDir, "cancel_dec.bin")

	// Encrypt normally.
	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   []byte("cancel_password"),
		Reporter:   &GoldenTestReporter{},
		RSCodecs:   rsCodecs,
	}); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt while the reporter signals cancellation mid-stream.
	err = Decrypt(context.Background(), &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     []byte("cancel_password"),
		ForceDecrypt: false,
		Reporter:     &CancellableReporter{cancelAfter: 0},
		RSCodecs:     rsCodecs,
	})
	assertCancelled(t, "Decrypt", err, decryptedPath)
}

// CancellableReporter is a test reporter that triggers cancellation
type CancellableReporter struct {
	progressCalls int
	cancelAfter   int
}

func (r *CancellableReporter) SetStatus(text string)                     {}
func (r *CancellableReporter) SetProgress(fraction float32, info string) { r.progressCalls++ }
func (r *CancellableReporter) SetCanCancel(can bool)                     {}
func (r *CancellableReporter) Update()                                   {}
func (r *CancellableReporter) IsCancelled() bool {
	return r.progressCalls > r.cancelAfter
}

// TestEncryptCommentsTooLong tests that comments exceeding max length are rejected
func TestEncryptCommentsTooLong(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	inputPath := filepath.Join(tmpDir, "long_comments.txt")
	if err := os.WriteFile(inputPath, []byte("test"), 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "long_comments.txt.pcv")

	// Create comments that exceed MaxCommentLen
	longComments := strings.Repeat("X", header.MaxCommentLen+1)

	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   []byte("long_comments_password"),
		Comments:   longComments,
		Reporter:   &GoldenTestReporter{},
		RSCodecs:   rsCodecs,
	}

	err = Encrypt(context.Background(), encReq)
	if err == nil {
		t.Error("Encrypt should fail when comments exceed max length")
	} else {
		t.Logf("Expected error (comments too long): %v", err)
	}
}

// TestDecryptNonExistentFile tests decryption of a non-existent file
func TestDecryptNonExistentFile(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	decReq := &DecryptRequest{
		InputFile:    filepath.Join(tmpDir, "nonexistent.pcv"),
		OutputFile:   filepath.Join(tmpDir, "output.txt"),
		Password:     []byte("password"),
		ForceDecrypt: false,
		Reporter:     &GoldenTestReporter{},
		RSCodecs:     rsCodecs,
	}

	err = Decrypt(context.Background(), decReq)
	if err == nil {
		t.Fatal("Decrypt should fail for non-existent file")
	}
	// The not-found cause must propagate (via %w wrapping) so callers can match it;
	// a %v wrap or a swallowed error would break errors.Is here.
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Decrypt error = %v, want it to wrap os.ErrNotExist", err)
	}
}

// TestEncryptNonExistentFile tests encryption of a non-existent file
func TestEncryptNonExistentFile(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	encReq := &EncryptRequest{
		InputFile:  filepath.Join(tmpDir, "nonexistent.txt"),
		OutputFile: filepath.Join(tmpDir, "output.pcv"),
		Password:   []byte("password"),
		Reporter:   &GoldenTestReporter{},
		RSCodecs:   rsCodecs,
	}

	err = Encrypt(context.Background(), encReq)
	if err == nil {
		t.Fatal("Encrypt should fail for non-existent input file")
	}
	// The not-found cause must propagate (via %w wrapping) so callers can match it;
	// a %v wrap or a swallowed error would break errors.Is here.
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Encrypt error = %v, want it to wrap os.ErrNotExist", err)
	}
}

// =============================================================================
// Tests for deniability edge cases
// =============================================================================

// TestDeniabilityRoundTripWithVerifyFirst tests deniability + verify first combination
func TestDeniabilityRoundTripWithVerifyFirst(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("Deniability + VerifyFirst combination test")
	inputPath := filepath.Join(tmpDir, "deny_verify.txt")
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "deny_verify.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "deny_verify_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with deniability
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    []byte("deny_verify_password"),
		Deniability: true,
		Reporter:    reporter,
		RSCodecs:    rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify deniability is detected
	if !IsDeniable(encryptedPath, rsCodecs) {
		t.Error("File should be detected as deniable")
	}

	// Decrypt with deniability + VerifyFirst
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     []byte("deny_verify_password"),
		Deniability:  true,
		VerifyFirst:  true, // Use two-pass verification
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt with deniability + VerifyFirst failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch (deniability + VerifyFirst)")
	}

	t.Log("Deniability + VerifyFirst: SUCCESS")
}

// TestIsDeniableNonExistentFile tests IsDeniable with a non-existent file
func TestIsDeniableNonExistentFile(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	result := IsDeniable("/nonexistent/path/file.pcv", rsCodecs)
	if result {
		t.Error("IsDeniable should return false for non-existent file")
	}
}

// TestIsDeniableNormalFile tests IsDeniable with a non-deniable file
func TestIsDeniableNormalFile(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create and encrypt without deniability
	plaintext := []byte("Normal file test")
	inputPath := filepath.Join(tmpDir, "normal.txt")
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "normal.txt.pcv")

	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    []byte("normal_password"),
		Deniability: false, // No deniability
		Reporter:    &GoldenTestReporter{},
		RSCodecs:    rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Check that it's not detected as deniable
	if IsDeniable(encryptedPath, rsCodecs) {
		t.Error("Normal file should not be detected as deniable")
	}
}

// TestIsDeniableCorruptedNotDeniable proves the QUAL-02 fix: a truncated/corrupt
// REGULAR volume must NOT be misclassified as deniable. The old IsDeniable returned
// true on any short read (deniability.go:343) or RS5-decode failure (:348), so a
// truncated regular volume was mis-routed as deniable. The fix is a length pre-guard:
// a genuine deniable volume always wraps a COMPLETE regular volume, so its size is at
// least salt(16) + nonce(24) + header.BaseHeaderSize; anything shorter cannot be
// deniable. Over-correction is guarded by the existing reliably-green true-positive
// tests (TestGoldenDeniabilityDetection, TestRoundTripDeniability) which run in the
// same close gate; we do not rebuild a deniable fixture here because IsDeniable's
// positive path is input-dependent (the random leading bytes occasionally RS5-decode
// to a version-like string) — that property is pre-existing and frozen by 05-03's
// guardrail (positive path unchanged; only negative rejections added).
func TestIsDeniableCorruptedNotDeniable(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Build a genuine regular (non-deniable) volume to corrupt.
	plaintext := bytes.Repeat([]byte("Corruption test plaintext."), 256)
	inputPath := filepath.Join(tmpDir, "regular.txt")
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	regularPath := filepath.Join(tmpDir, "regular.pcv")
	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  regularPath,
		Password:    []byte("regular_password"),
		Deniability: false,
		Reporter:    &GoldenTestReporter{},
		RSCodecs:    rsCodecs,
	}); err != nil {
		t.Fatalf("encrypt regular: %v", err)
	}
	full, err := os.ReadFile(regularPath)
	if err != nil {
		t.Fatalf("read regular volume: %v", err)
	}
	minDeniable := 16 + 24 + header.BaseHeaderSize
	if len(full) < minDeniable {
		t.Fatalf("regular volume size = %d; need >= deniable minimum %d to exercise full-size corrupt path", len(full), minDeniable)
	}

	// Variant (a): truncate below 15 bytes — old code hits the io.ReadFull error
	// branch (:343) and returns true. New code rejects via the length pre-guard.
	shortPath := filepath.Join(tmpDir, "short.pcv")
	if err := os.WriteFile(shortPath, full[:10], 0o644); err != nil {
		t.Fatalf("write short volume: %v", err)
	}
	if IsDeniable(shortPath, rsCodecs) {
		t.Error("truncated regular volume (10 bytes) misclassified as deniable (QUAL-02)")
	}

	// Variant (b): a short file (< deniable minimum) with a zeroed leading version
	// field — old code decodes the all-zero RS5 word to a non-version string and
	// returns !MatchVersion == true. New code rejects via the length pre-guard.
	if len(full) < 200 {
		t.Fatalf("regular volume unexpectedly shorter than 200 bytes: %d", len(full))
	}
	garbage := make([]byte, 200)
	copy(garbage, full[:200])
	for i := range 15 {
		garbage[i] = 0
	}
	garbagePath := filepath.Join(tmpDir, "garbage.pcv")
	if err := os.WriteFile(garbagePath, garbage, 0o644); err != nil {
		t.Fatalf("write garbage volume: %v", err)
	}
	if IsDeniable(garbagePath, rsCodecs) {
		t.Error("short corrupt regular volume (200 bytes) misclassified as deniable (QUAL-02)")
	}

	// Variant (c): a file exactly one byte below the deniable minimum must be rejected
	// by the length guard (boundary check).
	belowMin := make([]byte, minDeniable-1)
	copy(belowMin, full[:min(len(full), minDeniable-1)])
	belowMinPath := filepath.Join(tmpDir, "belowmin.pcv")
	if err := os.WriteFile(belowMinPath, belowMin, 0o644); err != nil {
		t.Fatalf("write below-min volume: %v", err)
	}
	if IsDeniable(belowMinPath, rsCodecs) {
		t.Errorf("file one byte below deniable minimum (%d) misclassified as deniable (QUAL-02)", minDeniable)
	}

	// Variant (d): a full-size regular volume with an unrepairable RS5 version
	// field decode error must still be treated as corrupted/non-deniable, not
	// routed into deniability handling. The length pre-guard alone cannot catch
	// this case because the file is large enough to look like a possible
	// deniability wrapper.
	fullSizeCorrupt := append([]byte(nil), full...)
	copy(fullSizeCorrupt[:header.VersionEncSize], corruptRS5Block(t, rsCodecs))
	fullSizeCorruptPath := filepath.Join(tmpDir, "full-size-corrupt-version.pcv")
	if err := os.WriteFile(fullSizeCorruptPath, fullSizeCorrupt, 0o644); err != nil {
		t.Fatalf("write full-size corrupt volume: %v", err)
	}
	if IsDeniable(fullSizeCorruptPath, rsCodecs) {
		t.Error("full-size regular volume with corrupted version field misclassified as deniable (QUAL-02)")
	}

	// Variant (e): a full-size regular volume whose damaged version field still
	// RS-decodes to a non-version string must also be treated as corrupted/
	// non-deniable when the following header fields are regular. This covers
	// the sibling branch to the decode-error case above.
	fullSizeNonVersion := append([]byte(nil), full...)
	copy(fullSizeNonVersion[:header.VersionEncSize], validNonVersionRS5Block(t, rsCodecs))
	fullSizeNonVersionPath := filepath.Join(tmpDir, "full-size-non-version.pcv")
	if err := os.WriteFile(fullSizeNonVersionPath, fullSizeNonVersion, 0o644); err != nil {
		t.Fatalf("write full-size non-version volume: %v", err)
	}
	if IsDeniable(fullSizeNonVersionPath, rsCodecs) {
		t.Error("full-size regular volume with non-version decoded version field misclassified as deniable (QUAL-02)")
	}

	// Over-correction guard: the existing reliably-green TestGoldenDeniabilityDetection
	// and TestRoundTripDeniability assert that genuine deniable volumes (size >= the
	// deniable minimum) are still detected as deniable after this guard lands.
}

func validNonVersionRS5Block(t *testing.T, rsCodecs *encoding.RSCodecs) []byte {
	t.Helper()

	block, err := encoding.Encode(rsCodecs.RS5, []byte("abcde"))
	if err != nil {
		t.Fatalf("encode non-version RS5 block: %v", err)
	}
	return block
}

func corruptRS5Block(t *testing.T, rsCodecs *encoding.RSCodecs) []byte {
	t.Helper()

	for seed := uint32(1); seed < 10000; seed++ {
		candidate := make([]byte, header.VersionEncSize)
		x := seed
		for i := range candidate {
			x = x*1664525 + 1013904223
			candidate[i] = byte(x >> 24)
		}
		if _, err := encoding.Decode(rsCodecs.RS5, candidate, false); err != nil {
			return candidate
		}
	}

	t.Fatal("could not construct a deterministic RS5 decode-error block")
	return nil
}

// =============================================================================
// Tests for operation context
// =============================================================================

// TestOperationContextClose tests that Close() handles nil values gracefully
func TestOperationContextClose(t *testing.T) {
	// Test nil context
	var nilCtx *OperationContext
	nilCtx.Close() // Should not panic

	// Test empty context
	emptyCtx := &OperationContext{}
	emptyCtx.Close() // Should not panic

	// Test context with nil slices
	ctx := &OperationContext{
		Key:         nil,
		KeyfileKey:  nil,
		KeyfileHash: nil,
		CipherSuite: nil,
		Header:      nil,
		TempCiphers: nil,
	}
	ctx.Close() // Should not panic
}

// TestOperationContextUpdateProgressNilReporter tests progress updates with nil reporter
func TestOperationContextUpdateProgressNilReporter(t *testing.T) {
	ctx := &OperationContext{
		Reporter: nil,
	}

	// These should not panic with nil reporter
	ctx.UpdateProgress(0.5, "50%")
	ctx.SetStatus("Processing...")

	if ctx.IsCancelled() {
		t.Error("IsCancelled should return false with nil reporter")
	}
}

func TestEncryptWithNilReporter(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "plain.txt")
	if err := os.WriteFile(inputPath, []byte("plaintext"), 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	req := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: filepath.Join(tmpDir, "plain.txt.pcv"),
		Password:   []byte("pw"),
		Reporter:   nil,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), req); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
}

func TestDecryptWithNilReporter(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "plain.txt")
	encryptedPath := filepath.Join(tmpDir, "plain.txt.pcv")
	outputPath := filepath.Join(tmpDir, "plain.out")

	if err := os.WriteFile(inputPath, []byte("plaintext"), 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   []byte("pw"),
		Reporter:   &GoldenTestReporter{},
		RSCodecs:   rsCodecs,
	}
	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decReq := &DecryptRequest{
		InputFile:  encryptedPath,
		OutputFile: outputPath,
		Password:   []byte("pw"),
		Reporter:   nil,
		RSCodecs:   rsCodecs,
	}
	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
}

// TestEncryptCancellation tests that encryption can be cancelled
func TestEncryptCancellation(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Multi-chunk plaintext so the reporter's cancel is observed before completion.
	plaintext := make([]byte, 3*1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}
	inputPath := filepath.Join(tmpDir, "cancel_enc_test.bin")
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "cancel_enc_test.bin.pcv")

	err = Encrypt(context.Background(), &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   []byte("cancel_password"),
		Reporter:   &CancellableReporter{cancelAfter: 0},
		RSCodecs:   rsCodecs,
	})
	assertCancelled(t, "Encrypt", err, encryptedPath)
}

// TestEncryptContextCancellation tests that encryption respects context cancellation.
// This tests the standard Go context.Context pattern for cancellation.
func TestEncryptContextCancellation(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create test file
	plaintext := make([]byte, 50*1024) // 50 KiB
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}
	inputPath := filepath.Join(tmpDir, "ctx_cancel_enc.bin")
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "ctx_cancel_enc.bin.pcv")

	// Create a pre-cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   []byte("ctx_cancel_password"),
		Reporter:   &GoldenTestReporter{},
		RSCodecs:   rsCodecs,
	}

	err = Encrypt(ctx, encReq)
	assertCancelled(t, "Encrypt", err, encryptedPath)
}

// TestDecryptContextCancellation tests that decryption respects context cancellation.
// This tests the standard Go context.Context pattern for cancellation.
func TestDecryptContextCancellation(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create test file
	plaintext := make([]byte, 50*1024) // 50 KiB
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}
	inputPath := filepath.Join(tmpDir, "ctx_cancel_dec.bin")
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "ctx_cancel_dec.bin.pcv")
	decryptedPath := filepath.Join(tmpDir, "ctx_cancel_dec_out.bin")

	// First encrypt normally
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   []byte("ctx_cancel_password"),
		Reporter:   &GoldenTestReporter{},
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Create a pre-cancelled context for decryption
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	decReq := &DecryptRequest{
		InputFile:  encryptedPath,
		OutputFile: decryptedPath,
		Password:   []byte("ctx_cancel_password"),
		Reporter:   &GoldenTestReporter{},
		RSCodecs:   rsCodecs,
	}

	err = Decrypt(ctx, decReq)
	assertCancelled(t, "Decrypt", err, decryptedPath)
}
