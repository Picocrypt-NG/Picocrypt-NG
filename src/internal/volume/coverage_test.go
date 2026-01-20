package volume

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
)

// =============================================================================
// Tests for VerifyFirst mode (decryptVerifyMACFirst)
// Addresses PCC-004 security audit recommendation
// =============================================================================

// TestVerifyFirstModeBasic tests the two-pass verification mode
func TestVerifyFirstModeBasic(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create test file
	plaintext := []byte("VerifyFirst mode test data - this should be verified before decryption.")
	inputPath := filepath.Join(tmpDir, "verify_first_test.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "verify_first_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "verify_first_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "verify_first_password",
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt with VerifyFirst mode enabled
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "verify_first_password",
		VerifyFirst:  true, // Enable two-pass verification
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt with VerifyFirst failed: %v", err)
	}

	// Verify content
	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch.\nExpected: %q\nGot: %q", plaintext, decrypted)
	}

	t.Log("VerifyFirst mode basic: SUCCESS")
}

// TestVerifyFirstModeWithReedSolomon tests VerifyFirst mode with RS enabled
func TestVerifyFirstModeWithReedSolomon(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("VerifyFirst + Reed-Solomon test data for enhanced verification.")
	inputPath := filepath.Join(tmpDir, "verify_first_rs.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "verify_first_rs.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "verify_first_rs_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with Reed-Solomon
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    "verify_first_rs_password",
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
		Password:     "verify_first_rs_password",
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
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "verify_first_paranoid.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "verify_first_paranoid_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with paranoid mode
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "verify_first_paranoid_password",
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
		Password:     "verify_first_paranoid_password",
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
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("VerifyFirst + Keyfiles test data.")
	inputPath := filepath.Join(tmpDir, "verify_first_kf.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create keyfile
	keyfilePath := filepath.Join(tmpDir, "verify_first.key")
	if err := os.WriteFile(keyfilePath, []byte("verify first keyfile content"), 0644); err != nil {
		t.Fatalf("Failed to write keyfile: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "verify_first_kf.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "verify_first_kf_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with keyfile
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "verify_first_kf_password",
		Keyfiles:   []string{keyfilePath},
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt with VerifyFirst mode + keyfile
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "verify_first_kf_password",
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

	if string(decrypted) != string(plaintext) {
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
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "verify_first_corrupt.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "verify_first_corrupt_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "verify_first_corrupt_password",
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

	if err := os.WriteFile(encryptedPath, data, 0644); err != nil {
		t.Fatalf("Failed to write corrupted file: %v", err)
	}

	// Decrypt with VerifyFirst - should detect corruption before decryption
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "verify_first_corrupt_password",
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

	plaintext := []byte("VerifyFirst + ForceDecrypt test data.")
	inputPath := filepath.Join(tmpDir, "verify_force.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "verify_force.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "verify_force_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "verify_force_password",
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

	corruptOffset := header.BaseHeaderSize + 10
	if corruptOffset < len(data) {
		data[corruptOffset] ^= 0xFF
	}

	if err := os.WriteFile(encryptedPath, data, 0644); err != nil {
		t.Fatalf("Failed to write corrupted file: %v", err)
	}

	// Decrypt with VerifyFirst + ForceDecrypt - should continue despite MAC failure
	var kept bool
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "verify_force_password",
		VerifyFirst:  true,
		ForceDecrypt: true, // Force through MAC failure
		Kept:         &kept,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	err = Decrypt(context.Background(), decReq)
	// ForceDecrypt may succeed or fail depending on corruption severity
	if err != nil {
		t.Logf("VerifyFirst + ForceDecrypt error (may be expected): %v", err)
	} else {
		t.Log("VerifyFirst + ForceDecrypt succeeded (forced through MAC failure)")
	}
}

// TestVerifyFirstAllOptions tests VerifyFirst with all options enabled
func TestVerifyFirstAllOptions(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("VerifyFirst with ALL options: paranoid + RS + keyfile.")
	inputPath := filepath.Join(tmpDir, "verify_all.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	keyfilePath := filepath.Join(tmpDir, "verify_all.key")
	if err := os.WriteFile(keyfilePath, []byte("all options keyfile"), 0644); err != nil {
		t.Fatalf("Failed to write keyfile: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "verify_all.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "verify_all_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with all options
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    "verify_all_password",
		Paranoid:    true,
		ReedSolomon: true,
		Keyfiles:    []string{keyfilePath},
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
		Password:     "verify_all_password",
		Keyfiles:     []string{keyfilePath},
		VerifyFirst:  true,
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt with VerifyFirst + all options failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch (VerifyFirst + all options)")
	}

	t.Log("VerifyFirst mode with all options: SUCCESS")
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

	plaintext := []byte("Keyfile required test data")
	inputPath := filepath.Join(tmpDir, "kf_required.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	keyfilePath := filepath.Join(tmpDir, "required.key")
	if err := os.WriteFile(keyfilePath, []byte("keyfile content"), 0644); err != nil {
		t.Fatalf("Failed to write keyfile: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "kf_required.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "kf_required_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with keyfile
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "kf_required_password",
		Keyfiles:   []string{keyfilePath},
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Try to decrypt WITHOUT keyfile (should fail)
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "kf_required_password",
		Keyfiles:     nil, // No keyfile provided!
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	err = Decrypt(context.Background(), decReq)
	if err == nil {
		t.Error("Decrypt should fail when required keyfile is not provided")
	} else {
		t.Logf("Expected error (missing keyfile): %v", err)
	}
}

// TestDecryptCancellation tests that cancellation during decrypt is handled
func TestDecryptCancellation(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create a larger test file to have time for cancellation
	plaintext := make([]byte, 100*1024) // 100 KiB
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}
	inputPath := filepath.Join(tmpDir, "cancel_test.bin")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "cancel_test.bin.pcv")
	decryptedPath := filepath.Join(tmpDir, "cancel_dec.bin")

	// Use a reporter that will signal cancellation
	reporter := &CancellableReporter{cancelAfter: 1}

	// Encrypt normally
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "cancel_password",
		Reporter:   &GoldenTestReporter{},
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt with cancellation
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "cancel_password",
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	err = Decrypt(context.Background(), decReq)
	if err == nil {
		t.Log("Decrypt completed before cancellation was triggered")
	} else if strings.Contains(err.Error(), "cancelled") {
		t.Log("Decrypt correctly handled cancellation")
	} else {
		t.Logf("Decrypt error: %v", err)
	}
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
	if err := os.WriteFile(inputPath, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "long_comments.txt.pcv")

	// Create comments that exceed MaxCommentLen
	longComments := strings.Repeat("X", header.MaxCommentLen+1)

	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "long_comments_password",
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
		Password:     "password",
		ForceDecrypt: false,
		Reporter:     &GoldenTestReporter{},
		RSCodecs:     rsCodecs,
	}

	err = Decrypt(context.Background(), decReq)
	if err == nil {
		t.Error("Decrypt should fail for non-existent file")
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
		Password:   "password",
		Reporter:   &GoldenTestReporter{},
		RSCodecs:   rsCodecs,
	}

	err = Encrypt(context.Background(), encReq)
	if err == nil {
		t.Error("Encrypt should fail for non-existent input file")
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
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "deny_verify.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "deny_verify_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with deniability
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    "deny_verify_password",
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
		Password:     "deny_verify_password",
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
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "normal.txt.pcv")

	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    "normal_password",
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

// TestEncryptCancellation tests that encryption can be cancelled
func TestEncryptCancellation(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create larger test file
	plaintext := make([]byte, 100*1024) // 100 KiB
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}
	inputPath := filepath.Join(tmpDir, "cancel_enc_test.bin")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "cancel_enc_test.bin.pcv")

	// Use reporter that cancels immediately
	reporter := &CancellableReporter{cancelAfter: 0}

	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "cancel_password",
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	err = Encrypt(context.Background(), encReq)
	if err == nil {
		t.Log("Encrypt completed before cancellation")
	} else if strings.Contains(err.Error(), "cancelled") {
		t.Log("Encrypt correctly handled cancellation")
	} else {
		t.Logf("Encrypt error: %v", err)
	}
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
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "ctx_cancel_enc.bin.pcv")

	// Create a pre-cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "ctx_cancel_password",
		Reporter:   &GoldenTestReporter{},
		RSCodecs:   rsCodecs,
	}

	err = Encrypt(ctx, encReq)
	if err == nil {
		t.Log("Encrypt completed before context cancellation was detected")
	} else if errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "cancelled") {
		t.Log("Encrypt correctly handled context cancellation")
	} else {
		t.Logf("Encrypt error: %v", err)
	}
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
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "ctx_cancel_dec.bin.pcv")
	decryptedPath := filepath.Join(tmpDir, "ctx_cancel_dec_out.bin")

	// First encrypt normally
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "ctx_cancel_password",
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
		Password:   "ctx_cancel_password",
		Reporter:   &GoldenTestReporter{},
		RSCodecs:   rsCodecs,
	}

	err = Decrypt(ctx, decReq)
	if err == nil {
		t.Log("Decrypt completed before context cancellation was detected")
	} else if errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "cancelled") {
		t.Log("Decrypt correctly handled context cancellation")
	} else {
		t.Logf("Decrypt error: %v", err)
	}
}

// TestRoundTripLargeFile tests encryption/decryption with a larger file to hit rekey code paths
func TestRoundTripLargeFile(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large file test in short mode")
	}

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create 1 MiB test file
	plaintext := make([]byte, 1024*1024)
	for i := range plaintext {
		plaintext[i] = byte((i * 7) % 256)
	}
	inputPath := filepath.Join(tmpDir, "large_test.bin")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "large_test.bin.pcv")
	decryptedPath := filepath.Join(tmpDir, "large_decrypted.bin")

	reporter := &GoldenTestReporter{}

	// Encrypt
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "large_file_password",
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "large_file_password",
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if len(decrypted) != len(plaintext) {
		t.Errorf("Length mismatch. Expected: %d, Got: %d", len(plaintext), len(decrypted))
	}

	for i := range plaintext {
		if decrypted[i] != plaintext[i] {
			t.Errorf("Content mismatch at byte %d", i)
			break
		}
	}

	t.Log("Large file round-trip: SUCCESS")
}

// TestRoundTripRSLargeFile tests RS decoding with a larger file (exercises FastDecode code path)
func TestRoundTripRSLargeFile(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large RS file test in short mode")
	}

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create 512 KiB file - large enough to exercise RS128 blocks and fast decode path
	plaintext := make([]byte, 512*1024)
	for i := range plaintext {
		plaintext[i] = byte((i * 11) % 256)
	}
	inputPath := filepath.Join(tmpDir, "rs_large.bin")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "rs_large.bin.pcv")
	decryptedPath := filepath.Join(tmpDir, "rs_large_dec.bin")

	reporter := &GoldenTestReporter{}

	// Encrypt with Reed-Solomon
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    "rs_large_password",
		ReedSolomon: true,
		Reporter:    reporter,
		RSCodecs:    rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt (will use fast decode path automatically)
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "rs_large_password",
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if len(decrypted) != len(plaintext) {
		t.Errorf("Length mismatch. Expected: %d, Got: %d", len(plaintext), len(decrypted))
	}

	for i := range plaintext {
		if decrypted[i] != plaintext[i] {
			t.Errorf("Content mismatch at byte %d", i)
			break
		}
	}

	t.Log("RS Large file round-trip: SUCCESS")
}
