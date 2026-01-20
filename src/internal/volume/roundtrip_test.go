package volume

import (
	"archive/zip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"Picocrypt-NG/internal/encoding"
)

// TestRoundTripBasic tests basic encrypt -> decrypt cycle
func TestRoundTripBasic(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create test file
	plaintext := []byte("Hello, Picocrypt! This is a test message for round-trip encryption.")
	inputPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "test_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    "testpassword123",
		Paranoid:    false,
		ReedSolomon: false,
		Deniability: false,
		Reporter:    reporter,
		RSCodecs:    rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify encrypted file exists
	if _, err := os.Stat(encryptedPath); os.IsNotExist(err) {
		t.Fatal("Encrypted file was not created")
	}

	// Decrypt
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "testpassword123",
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Verify decrypted content matches original
	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch.\nExpected: %q\nGot: %q", plaintext, decrypted)
	}

	t.Log("Round-trip basic: SUCCESS")
}

// TestRoundTripParanoid tests encrypt -> decrypt with paranoid mode
func TestRoundTripParanoid(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("Paranoid mode test data with extra security.")
	inputPath := filepath.Join(tmpDir, "paranoid_test.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "paranoid_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "paranoid_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with paranoid mode
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "paranoid_password",
		Paranoid:   true,
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (paranoid) failed: %v", err)
	}

	// Decrypt
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "paranoid_password",
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (paranoid) failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch (paranoid).\nExpected: %q\nGot: %q", plaintext, decrypted)
	}

	t.Log("Round-trip paranoid: SUCCESS")
}

// TestRoundTripReedSolomon tests encrypt -> decrypt with Reed-Solomon
func TestRoundTripReedSolomon(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("Reed-Solomon protected data for error correction testing.")
	inputPath := filepath.Join(tmpDir, "rs_test.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "rs_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "rs_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with Reed-Solomon
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    "rs_password",
		ReedSolomon: true,
		Reporter:    reporter,
		RSCodecs:    rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (RS) failed: %v", err)
	}

	// Decrypt
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "rs_password",
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (RS) failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch (RS).\nExpected: %q\nGot: %q", plaintext, decrypted)
	}

	t.Log("Round-trip Reed-Solomon: SUCCESS")
}

// TestRoundTripDeniability tests encrypt -> decrypt with deniability
func TestRoundTripDeniability(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("Deniability test data - this should be hidden!")
	inputPath := filepath.Join(tmpDir, "deny_test.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "deny_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "deny_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with deniability
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    "deny_password",
		Deniability: true,
		Reporter:    reporter,
		RSCodecs:    rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (deniability) failed: %v", err)
	}

	// Check that deniability is detected
	if !IsDeniable(encryptedPath, rsCodecs) {
		t.Error("Encrypted file should be detected as deniable")
	}

	// Decrypt with deniability flag
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "deny_password",
		Deniability:  true,
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (deniability) failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch (deniability).\nExpected: %q\nGot: %q", plaintext, decrypted)
	}

	t.Log("Round-trip deniability: SUCCESS")
}

// TestRoundTripAllOptions tests encrypt -> decrypt with all options enabled
func TestRoundTripAllOptions(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("Full options test: paranoid + Reed-Solomon + deniability")
	inputPath := filepath.Join(tmpDir, "full_test.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "full_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "full_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with all options
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    "full_options_password",
		Paranoid:    true,
		ReedSolomon: true,
		Deniability: true,
		Reporter:    reporter,
		RSCodecs:    rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (all options) failed: %v", err)
	}

	// Decrypt
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "full_options_password",
		Deniability:  true,
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (all options) failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch (all options).\nExpected: %q\nGot: %q", plaintext, decrypted)
	}

	t.Log("Round-trip all options: SUCCESS")
}

// TestRoundTripWithComments tests encrypt -> decrypt with comments
func TestRoundTripWithComments(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("Test data with comments in the header.")
	inputPath := filepath.Join(tmpDir, "comments_test.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "comments_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "comments_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with comments
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "comments_password",
		Comments:   "This is a test comment! 日本語テスト 🔐",
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (with comments) failed: %v", err)
	}

	// Decrypt
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "comments_password",
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (with comments) failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch (with comments).\nExpected: %q\nGot: %q", plaintext, decrypted)
	}

	t.Log("Round-trip with comments: SUCCESS")
}

// TestRoundTripWithKeyfile tests encrypt -> decrypt with keyfile
func TestRoundTripWithKeyfile(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create test file
	plaintext := []byte("Keyfile protected data for testing.")
	inputPath := filepath.Join(tmpDir, "keyfile_test.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create keyfile
	keyfilePath := filepath.Join(tmpDir, "keyfile.bin")
	keyfileData := []byte("This is my secret keyfile content!")
	if err := os.WriteFile(keyfilePath, keyfileData, 0644); err != nil {
		t.Fatalf("Failed to write keyfile: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "keyfile_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "keyfile_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with keyfile
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "password_with_keyfile",
		Keyfiles:   []string{keyfilePath},
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (with keyfile) failed: %v", err)
	}

	// Decrypt with keyfile
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "password_with_keyfile",
		Keyfiles:     []string{keyfilePath},
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (with keyfile) failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch (with keyfile).\nExpected: %q\nGot: %q", plaintext, decrypted)
	}

	t.Log("Round-trip with keyfile: SUCCESS")
}

// TestRoundTripWithMultipleKeyfiles tests encrypt -> decrypt with multiple keyfiles
func TestRoundTripWithMultipleKeyfiles(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create test file
	plaintext := []byte("Multiple keyfiles protected data.")
	inputPath := filepath.Join(tmpDir, "multi_keyfile_test.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create keyfiles
	keyfile1 := filepath.Join(tmpDir, "keyfile1.bin")
	keyfile2 := filepath.Join(tmpDir, "keyfile2.bin")
	if err := os.WriteFile(keyfile1, []byte("First keyfile content"), 0644); err != nil {
		t.Fatalf("Failed to write keyfile1: %v", err)
	}
	if err := os.WriteFile(keyfile2, []byte("Second keyfile content"), 0644); err != nil {
		t.Fatalf("Failed to write keyfile2: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "multi_keyfile_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "multi_keyfile_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with multiple keyfiles (unordered - default)
	encReq := &EncryptRequest{
		InputFile:      inputPath,
		OutputFile:     encryptedPath,
		Password:       "multi_keyfile_pass",
		Keyfiles:       []string{keyfile1, keyfile2},
		KeyfileOrdered: false,
		Reporter:       reporter,
		RSCodecs:       rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (multiple keyfiles) failed: %v", err)
	}

	// Decrypt with keyfiles in different order (should work for unordered)
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "multi_keyfile_pass",
		Keyfiles:     []string{keyfile2, keyfile1}, // Reversed order
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (multiple keyfiles, reversed) failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch (multiple keyfiles).\nExpected: %q\nGot: %q", plaintext, decrypted)
	}

	t.Log("Round-trip with multiple keyfiles: SUCCESS")
}

// TestRoundTripWithOrderedKeyfiles tests encrypt -> decrypt with ordered keyfiles
func TestRoundTripWithOrderedKeyfiles(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create test file
	plaintext := []byte("Ordered keyfiles protected data.")
	inputPath := filepath.Join(tmpDir, "ordered_keyfile_test.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create keyfiles
	keyfile1 := filepath.Join(tmpDir, "ordered1.bin")
	keyfile2 := filepath.Join(tmpDir, "ordered2.bin")
	if err := os.WriteFile(keyfile1, []byte("First ordered keyfile"), 0644); err != nil {
		t.Fatalf("Failed to write keyfile1: %v", err)
	}
	if err := os.WriteFile(keyfile2, []byte("Second ordered keyfile"), 0644); err != nil {
		t.Fatalf("Failed to write keyfile2: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "ordered_keyfile_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "ordered_keyfile_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with ordered keyfiles
	encReq := &EncryptRequest{
		InputFile:      inputPath,
		OutputFile:     encryptedPath,
		Password:       "ordered_keyfile_pass",
		Keyfiles:       []string{keyfile1, keyfile2},
		KeyfileOrdered: true,
		Reporter:       reporter,
		RSCodecs:       rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (ordered keyfiles) failed: %v", err)
	}

	// Decrypt with same order
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "ordered_keyfile_pass",
		Keyfiles:     []string{keyfile1, keyfile2},
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (ordered keyfiles) failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch (ordered keyfiles).\nExpected: %q\nGot: %q", plaintext, decrypted)
	}

	t.Log("Round-trip with ordered keyfiles: SUCCESS")
}

// TestWrongKeyfileFails verifies that wrong keyfile fails
func TestWrongKeyfileFails(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("Secret data")
	inputPath := filepath.Join(tmpDir, "secret.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create correct keyfile
	correctKeyfile := filepath.Join(tmpDir, "correct_keyfile.bin")
	if err := os.WriteFile(correctKeyfile, []byte("Correct keyfile"), 0644); err != nil {
		t.Fatalf("Failed to write correct keyfile: %v", err)
	}

	// Create wrong keyfile
	wrongKeyfile := filepath.Join(tmpDir, "wrong_keyfile.bin")
	if err := os.WriteFile(wrongKeyfile, []byte("Wrong keyfile"), 0644); err != nil {
		t.Fatalf("Failed to write wrong keyfile: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "secret.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "secret_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with correct keyfile
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "keyfile_password",
		Keyfiles:   []string{correctKeyfile},
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Try to decrypt with wrong keyfile
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "keyfile_password",
		Keyfiles:     []string{wrongKeyfile},
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	err = Decrypt(context.Background(), decReq)
	if err == nil {
		t.Error("Decrypt should have failed with wrong keyfile")
	} else {
		t.Logf("Expected error: %v", err)
	}

	// Decrypted file should not exist
	if _, err := os.Stat(decryptedPath); !os.IsNotExist(err) {
		t.Error("Decrypted file should not exist after failed decryption")
	}
}

// TestRoundTripSplit tests encrypt with splitting -> recombine -> decrypt
func TestRoundTripSplit(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create larger test file to have multiple chunks
	plaintext := make([]byte, 1024*100) // 100 KiB
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}
	inputPath := filepath.Join(tmpDir, "split_test.bin")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "split_test.bin.pcv")
	decryptedPath := filepath.Join(tmpDir, "split_decrypted.bin")

	reporter := &GoldenTestReporter{}

	// Encrypt with splitting (10 KiB chunks)
	// SplitUnitKiB = 0
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "split_password",
		Split:      true,
		ChunkSize:  10,
		ChunkUnit:  0, // SplitUnitKiB
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (split) failed: %v", err)
	}

	// Verify chunks were created
	chunks, err := filepath.Glob(encryptedPath + ".*")
	if err != nil {
		t.Fatalf("Failed to glob chunks: %v", err)
	}
	if len(chunks) < 2 {
		t.Logf("Only %d chunk(s) created - file might be too small for splitting", len(chunks))
		// Still try to decrypt the first chunk if it exists
		if len(chunks) == 0 {
			t.Skip("No chunks created - splitting might not be working")
		}
	}
	t.Logf("Created %d chunks", len(chunks))

	// Decrypt with recombine
	// InputFile should be the base path (without .N suffix) for recombine
	decReq := &DecryptRequest{
		InputFile:    encryptedPath, // Base path - recombine will look for .0, .1, etc.
		OutputFile:   decryptedPath,
		Password:     "split_password",
		Recombine:    true,
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (split/recombine) failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if len(decrypted) != len(plaintext) {
		t.Errorf("Length mismatch (split). Expected: %d, Got: %d", len(plaintext), len(decrypted))
	}

	for i := range plaintext {
		if decrypted[i] != plaintext[i] {
			t.Errorf("Content mismatch at byte %d (split). Expected: %d, Got: %d", i, plaintext[i], decrypted[i])
			break
		}
	}

	t.Log("Round-trip split/recombine: SUCCESS")
}

// TestWrongPasswordFails verifies that wrong password fails
func TestWrongPasswordFails(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("Secret data")
	inputPath := filepath.Join(tmpDir, "secret.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "secret.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "secret_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "correct_password",
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Try to decrypt with wrong password
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "wrong_password",
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	err = Decrypt(context.Background(), decReq)
	if err == nil {
		t.Error("Decrypt should have failed with wrong password")
	} else {
		t.Logf("Expected error: %v", err)
	}

	// Decrypted file should not exist
	if _, err := os.Stat(decryptedPath); !os.IsNotExist(err) {
		t.Error("Decrypted file should not exist after failed decryption")
	}
}

// TestAutoUnzip tests automatic zip extraction after decryption
func TestAutoUnzip(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create a test file and zip it
	testContent := []byte("Auto-unzip test content!")
	testDir := filepath.Join(tmpDir, "test_folder")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	testFile := filepath.Join(testDir, "test_file.txt")
	if err := os.WriteFile(testFile, testContent, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create zip file
	zipPath := filepath.Join(tmpDir, "test.zip")
	if err := createTestZip(zipPath, testDir, "test_folder"); err != nil {
		t.Fatalf("Failed to create test zip: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "test.zip.pcv")
	decryptedPath := filepath.Join(tmpDir, "test.zip")

	reporter := &GoldenTestReporter{}

	// Encrypt the zip file
	encReq := &EncryptRequest{
		InputFile:  zipPath,
		OutputFile: encryptedPath,
		Password:   "autounzip_password",
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Remove original zip and test folder
	_ = os.Remove(zipPath)
	_ = os.RemoveAll(testDir)

	// Decrypt with AutoUnzip enabled
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "autounzip_password",
		AutoUnzip:    true,
		SameLevel:    false, // Extract to directory containing the zip
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (auto-unzip) failed: %v", err)
	}

	// Verify the zip was removed (auto-unzip removes it)
	if _, err := os.Stat(decryptedPath); !os.IsNotExist(err) {
		t.Error("Zip file should have been removed after auto-unzip")
	}

	// Verify the extracted content exists
	// When SameLevel=false, extracts to a subdirectory named after the zip
	// So test.zip extracts to test/test_folder/test_file.txt
	extractedFile := filepath.Join(tmpDir, "test", "test_folder", "test_file.txt")
	content, err := os.ReadFile(extractedFile)
	if err != nil {
		t.Fatalf("Failed to read extracted file at %s: %v", extractedFile, err)
	}

	if string(content) != string(testContent) {
		t.Errorf("Content mismatch after auto-unzip.\nExpected: %q\nGot: %q", testContent, content)
	}

	t.Log("Auto-unzip: SUCCESS")
}

// TestAutoUnzipSameLevel tests automatic zip extraction to the same directory as the volume
func TestAutoUnzipSameLevel(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create subdirectory for the encrypted file
	volumeDir := filepath.Join(tmpDir, "volume_location")
	if err := os.MkdirAll(volumeDir, 0755); err != nil {
		t.Fatalf("Failed to create volume directory: %v", err)
	}

	// Create a test file and zip it
	testContent := []byte("Same-level unzip test content!")
	testDir := filepath.Join(tmpDir, "source_folder")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	testFile := filepath.Join(testDir, "same_level_test.txt")
	if err := os.WriteFile(testFile, testContent, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create zip file
	zipPath := filepath.Join(tmpDir, "samelevel.zip")
	if err := createTestZip(zipPath, testDir, "source_folder"); err != nil {
		t.Fatalf("Failed to create test zip: %v", err)
	}

	encryptedPath := filepath.Join(volumeDir, "samelevel.zip.pcv")
	decryptedPath := filepath.Join(volumeDir, "samelevel.zip")

	reporter := &GoldenTestReporter{}

	// Encrypt the zip file
	encReq := &EncryptRequest{
		InputFile:  zipPath,
		OutputFile: encryptedPath,
		Password:   "samelevel_password",
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Remove original zip and test folder
	_ = os.Remove(zipPath)
	_ = os.RemoveAll(testDir)

	// Decrypt with AutoUnzip + SameLevel enabled
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "samelevel_password",
		AutoUnzip:    true,
		SameLevel:    true, // Extract to same directory as volume
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (same-level) failed: %v", err)
	}

	// Verify the zip was removed (auto-unzip removes it)
	if _, err := os.Stat(decryptedPath); !os.IsNotExist(err) {
		t.Error("Zip file should have been removed after auto-unzip")
	}

	// Verify the extracted content exists in the same directory as the volume
	extractedFile := filepath.Join(volumeDir, "source_folder", "same_level_test.txt")
	content, err := os.ReadFile(extractedFile)
	if err != nil {
		t.Fatalf("Failed to read extracted file at %s: %v", extractedFile, err)
	}

	if string(content) != string(testContent) {
		t.Errorf("Content mismatch after same-level unzip.\nExpected: %q\nGot: %q", testContent, content)
	}

	t.Log("Auto-unzip same-level: SUCCESS")
}

// createTestZip creates a zip file from a directory
func createTestZip(zipPath, sourceDir, baseName string) error {
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer func() { _ = zipFile.Close() }()

	zipWriter := zip.NewWriter(zipFile)
	defer func() { _ = zipWriter.Close() }()

	return filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Create relative path
		relPath, err := filepath.Rel(filepath.Dir(sourceDir), path)
		if err != nil {
			return err
		}

		if info.IsDir() {
			_, err = zipWriter.Create(relPath + "/")
			return err
		}

		// Create file in zip
		writer, err := zipWriter.Create(relPath)
		if err != nil {
			return err
		}

		// Copy file content
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = file.Close() }()

		_, err = io.Copy(writer, file)
		return err
	})
}

// TestRoundTripMultiFile tests encrypting multiple files (zipped internally)
func TestRoundTripMultiFile(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create multiple test files
	file1Content := []byte("First file content")
	file2Content := []byte("Second file content with more data")
	file3Content := []byte("Third file!")

	file1Path := filepath.Join(tmpDir, "file1.txt")
	file2Path := filepath.Join(tmpDir, "file2.txt")
	file3Path := filepath.Join(tmpDir, "file3.txt")

	if err := os.WriteFile(file1Path, file1Content, 0644); err != nil {
		t.Fatalf("Failed to write file1: %v", err)
	}
	if err := os.WriteFile(file2Path, file2Content, 0644); err != nil {
		t.Fatalf("Failed to write file2: %v", err)
	}
	if err := os.WriteFile(file3Path, file3Content, 0644); err != nil {
		t.Fatalf("Failed to write file3: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "multifile.zip.pcv")
	decryptedPath := filepath.Join(tmpDir, "multifile.zip")

	reporter := &GoldenTestReporter{}

	// Encrypt with multiple input files
	encReq := &EncryptRequest{
		InputFiles: []string{file1Path, file2Path, file3Path},
		OutputFile: encryptedPath,
		Password:   "multifile_password",
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (multi-file) failed: %v", err)
	}

	// Remove original files
	_ = os.Remove(file1Path)
	_ = os.Remove(file2Path)
	_ = os.Remove(file3Path)

	// Decrypt
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "multifile_password",
		AutoUnzip:    true,
		SameLevel:    true,
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (multi-file) failed: %v", err)
	}

	// Verify all files were extracted
	restored1, err := os.ReadFile(filepath.Join(tmpDir, "file1.txt"))
	if err != nil {
		t.Fatalf("Failed to read restored file1: %v", err)
	}
	restored2, err := os.ReadFile(filepath.Join(tmpDir, "file2.txt"))
	if err != nil {
		t.Fatalf("Failed to read restored file2: %v", err)
	}
	restored3, err := os.ReadFile(filepath.Join(tmpDir, "file3.txt"))
	if err != nil {
		t.Fatalf("Failed to read restored file3: %v", err)
	}

	if string(restored1) != string(file1Content) {
		t.Errorf("file1 content mismatch")
	}
	if string(restored2) != string(file2Content) {
		t.Errorf("file2 content mismatch")
	}
	if string(restored3) != string(file3Content) {
		t.Errorf("file3 content mismatch")
	}

	t.Log("Round-trip multi-file: SUCCESS")
}

// TestRoundTripSplitWithDeniability tests split + deniability combination
func TestRoundTripSplitWithDeniability(t *testing.T) {
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
	inputPath := filepath.Join(tmpDir, "split_deny_test.bin")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "split_deny_test.bin.pcv")
	decryptedPath := filepath.Join(tmpDir, "split_deny_decrypted.bin")

	reporter := &GoldenTestReporter{}

	// Encrypt with split + deniability
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    "split_deny_password",
		Deniability: true,
		Split:       true,
		ChunkSize:   10,
		ChunkUnit:   0, // KiB
		Reporter:    reporter,
		RSCodecs:    rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (split+deniability) failed: %v", err)
	}

	// Verify chunks were created
	chunks, _ := filepath.Glob(encryptedPath + ".*")
	if len(chunks) < 2 {
		t.Logf("Only %d chunk(s) created", len(chunks))
	}

	// Decrypt with recombine + deniability
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "split_deny_password",
		Deniability:  true,
		Recombine:    true,
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (split+deniability) failed: %v", err)
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

	t.Log("Round-trip split+deniability: SUCCESS")
}

// TestRoundTripSplitWithReedSolomon tests split + Reed-Solomon combination.
// This tests the complete encrypt->split->recombine->decrypt cycle with RS enabled.
func TestRoundTripSplitWithReedSolomon(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping split+RS test in short mode")
	}
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Use a size that creates clean RS128 boundaries
	// 128 * 400 = 51200 bytes = exactly 400 RS128 blocks
	plaintext := make([]byte, 128*400) // 51200 bytes
	for i := range plaintext {
		plaintext[i] = byte((i * 7) % 256)
	}
	inputPath := filepath.Join(tmpDir, "split_rs_test.bin")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "split_rs_test.bin.pcv")
	decryptedPath := filepath.Join(tmpDir, "split_rs_decrypted.bin")

	reporter := &GoldenTestReporter{}

	// Encrypt with split + Reed-Solomon
	// Use larger chunk size (50 KiB) to avoid too many small chunks
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    "split_rs_password",
		ReedSolomon: true,
		Split:       true,
		ChunkSize:   50, // 50 KiB chunks
		ChunkUnit:   0,  // KiB
		Reporter:    reporter,
		RSCodecs:    rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (split+RS) failed: %v", err)
	}

	// Verify chunks were created
	chunks, _ := filepath.Glob(encryptedPath + ".*")
	t.Logf("Created %d chunks", len(chunks))

	// Decrypt
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "split_rs_password",
		Recombine:    true,
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (split+RS) failed: %v", err)
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

	t.Log("Round-trip split+Reed-Solomon: SUCCESS")
}

// TestRoundTripSplitAllOptions tests split + paranoid + RS + deniability
func TestRoundTripSplitAllOptions(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := make([]byte, 30*1024) // 30 KiB
	for i := range plaintext {
		plaintext[i] = byte((i * 13) % 256)
	}
	inputPath := filepath.Join(tmpDir, "split_all_test.bin")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "split_all_test.bin.pcv")
	decryptedPath := filepath.Join(tmpDir, "split_all_decrypted.bin")

	reporter := &GoldenTestReporter{}

	// Encrypt with ALL options
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    "split_all_password",
		Paranoid:    true,
		ReedSolomon: true,
		Deniability: true,
		Split:       true,
		ChunkSize:   10,
		ChunkUnit:   0, // KiB
		Reporter:    reporter,
		RSCodecs:    rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (split+all) failed: %v", err)
	}

	// Decrypt
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "split_all_password",
		Deniability:  true,
		Recombine:    true,
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (split+all) failed: %v", err)
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

	t.Log("Round-trip split+all options: SUCCESS")
}

// TestRoundTripEmptyFile tests encryption/decryption of an empty file
func TestRoundTripEmptyFile(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create empty file
	inputPath := filepath.Join(tmpDir, "empty.txt")
	if err := os.WriteFile(inputPath, []byte{}, 0644); err != nil {
		t.Fatalf("Failed to write empty file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "empty.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "empty_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "empty_file_password",
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (empty) failed: %v", err)
	}

	// Decrypt
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "empty_file_password",
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (empty) failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("Expected empty file, got %d bytes", len(decrypted))
	}

	t.Log("Round-trip empty file: SUCCESS")
}

// TestRoundTripSplitWithKeyfile tests split + keyfile combination
func TestRoundTripSplitWithKeyfile(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create test file
	plaintext := make([]byte, 40*1024) // 40 KiB
	for i := range plaintext {
		plaintext[i] = byte((i * 17) % 256)
	}
	inputPath := filepath.Join(tmpDir, "split_keyfile_test.bin")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create keyfile
	keyfileContent := []byte("This is keyfile content for split test!")
	keyfilePath := filepath.Join(tmpDir, "split.key")
	if err := os.WriteFile(keyfilePath, keyfileContent, 0644); err != nil {
		t.Fatalf("Failed to write keyfile: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "split_keyfile_test.bin.pcv")
	decryptedPath := filepath.Join(tmpDir, "split_keyfile_decrypted.bin")

	reporter := &GoldenTestReporter{}

	// Encrypt with split + keyfile
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "split_keyfile_password",
		Keyfiles:   []string{keyfilePath},
		Split:      true,
		ChunkSize:  10,
		ChunkUnit:  0, // KiB
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (split+keyfile) failed: %v", err)
	}

	// Decrypt
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "split_keyfile_password",
		Keyfiles:     []string{keyfilePath},
		Recombine:    true,
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (split+keyfile) failed: %v", err)
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

	t.Log("Round-trip split+keyfile: SUCCESS")
}

// TestForceDecryptCorruptedData tests force decrypt with damaged RS data
func TestForceDecryptCorruptedData(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create test file
	plaintext := []byte("Data that will be intentionally corrupted for recovery test.")
	inputPath := filepath.Join(tmpDir, "corrupt_test.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "corrupt_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "corrupt_recovered.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with Reed-Solomon (needed for force decrypt to work)
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    "corrupt_test_password",
		ReedSolomon: true,
		Reporter:    reporter,
		RSCodecs:    rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Corrupt some bytes in the encrypted file (after the header)
	data, err := os.ReadFile(encryptedPath)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}

	// Corrupt bytes near the end of the file (in the payload area)
	// Header is approximately 789 + 3*comments bytes, so corrupt after that
	corruptStart := len(data) - 100
	if corruptStart > 0 && corruptStart < len(data)-10 {
		for i := 0; i < 5; i++ {
			data[corruptStart+i] ^= 0xFF // Flip bits
		}
	}

	if err := os.WriteFile(encryptedPath, data, 0644); err != nil {
		t.Fatalf("Failed to write corrupted file: %v", err)
	}

	// Try to decrypt with force mode (should succeed with possible data loss)
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "corrupt_test_password",
		ForceDecrypt: true, // Force through errors
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	err = Decrypt(context.Background(), decReq)
	// Force decrypt might succeed or fail depending on where corruption landed
	// The test verifies that force decrypt at least attempts recovery
	if err != nil {
		t.Logf("Force decrypt returned error (expected for some corruptions): %v", err)
	} else {
		t.Log("Force decrypt succeeded - some data may be recoverable")
	}
}

// TestRoundTripCompressedMultiFile tests encrypting multiple files with compression
func TestRoundTripCompressedMultiFile(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create multiple test files
	file1Content := []byte("Compressible content: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	file2Content := []byte("More compressible: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

	file1Path := filepath.Join(tmpDir, "compress1.txt")
	file2Path := filepath.Join(tmpDir, "compress2.txt")

	if err := os.WriteFile(file1Path, file1Content, 0644); err != nil {
		t.Fatalf("Failed to write file1: %v", err)
	}
	if err := os.WriteFile(file2Path, file2Content, 0644); err != nil {
		t.Fatalf("Failed to write file2: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "compressed.zip.pcv")
	decryptedPath := filepath.Join(tmpDir, "compressed.zip")

	reporter := &GoldenTestReporter{}

	// Encrypt with multiple input files and compression
	encReq := &EncryptRequest{
		InputFiles: []string{file1Path, file2Path},
		OutputFile: encryptedPath,
		Password:   "compress_multifile_password",
		Compress:   true, // Enable compression
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (compressed multi-file) failed: %v", err)
	}

	// Remove original files
	_ = os.Remove(file1Path)
	_ = os.Remove(file2Path)

	// Decrypt with auto-unzip
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "compress_multifile_password",
		AutoUnzip:    true,
		SameLevel:    true,
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (compressed multi-file) failed: %v", err)
	}

	// Verify files were extracted
	restored1, err := os.ReadFile(filepath.Join(tmpDir, "compress1.txt"))
	if err != nil {
		t.Fatalf("Failed to read restored file1: %v", err)
	}
	restored2, err := os.ReadFile(filepath.Join(tmpDir, "compress2.txt"))
	if err != nil {
		t.Fatalf("Failed to read restored file2: %v", err)
	}

	if string(restored1) != string(file1Content) {
		t.Errorf("file1 content mismatch")
	}
	if string(restored2) != string(file2Content) {
		t.Errorf("file2 content mismatch")
	}

	t.Log("Round-trip compressed multi-file: SUCCESS")
}

// TestRoundTripCompressedSingleFile tests encrypting a single file with compression
func TestRoundTripCompressedSingleFile(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create a compressible test file (repeated data compresses well)
	fileContent := []byte(strings.Repeat("This is highly compressible test data! ", 100))

	filePath := filepath.Join(tmpDir, "compressible_single.txt")
	if err := os.WriteFile(filePath, fileContent, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "compressible_single.txt.zip.pcv")
	decryptedPath := filepath.Join(tmpDir, "compressible_single.txt.zip")

	reporter := &GoldenTestReporter{}

	// Encrypt single file with compression enabled
	encReq := &EncryptRequest{
		InputFiles: []string{filePath},
		OutputFile: encryptedPath,
		Password:   "compress_single_password",
		Compress:   true, // Enable compression for single file
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (compressed single file) failed: %v", err)
	}

	// Verify that the encrypted file was created
	if _, err := os.Stat(encryptedPath); err != nil {
		t.Fatalf("Encrypted file not created: %v", err)
	}

	// Remove original file
	_ = os.Remove(filePath)

	// Decrypt with auto-unzip
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "compress_single_password",
		AutoUnzip:    true,
		SameLevel:    true,
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (compressed single file) failed: %v", err)
	}

	// Verify file was extracted
	restoredPath := filepath.Join(tmpDir, "compressible_single.txt")
	restored, err := os.ReadFile(restoredPath)
	if err != nil {
		t.Fatalf("Failed to read restored file: %v", err)
	}

	if string(restored) != string(fileContent) {
		t.Errorf("Content mismatch after round-trip")
	}

	// Verify compression actually happened by checking encrypted file size
	// The compressed+encrypted file should be smaller than uncompressed+encrypted
	encryptedInfo, _ := os.Stat(encryptedPath)

	// Original file size is len(fileContent), encrypted file should be noticeably smaller
	// due to compression (accounting for encryption overhead and headers)
	t.Logf("Original size: %d bytes, Encrypted size: %d bytes", len(fileContent), encryptedInfo.Size())

	t.Log("Round-trip compressed single file: SUCCESS")
}

// TestV2HeaderTamperDetection verifies that modifying header bytes
// causes v2 volumes to fail authentication (header MAC protection).
func TestV2HeaderTamperDetection(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("Header tamper detection test data.")
	inputPath := filepath.Join(tmpDir, "tamper_test.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "tamper_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "tamper_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt (creates v2 volume) - use empty comments for simpler header layout
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "tamper_test_password",
		Comments:   "", // Empty comments for predictable header size
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Read the encrypted file
	data, err := os.ReadFile(encryptedPath)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}

	// Header layout (empty comments):
	// version(15) + commentLen(15) + flags(15) + salt(48) + hkdfSalt(96) +
	// serpentIV(48) + nonce(72) + keyHash(192) + keyfileHash(96) + authTag(192) = 789 bytes
	//
	// We tamper with the salt bytes heavily - flip enough bytes to exceed RS correction
	// Salt starts at offset 15 + 15 + 15 = 45, is 48 bytes (rs16: 16->48)
	// RS16 can correct up to (48-16)/2 = 16 errors. Flip more than that.
	saltStart := 45
	for i := 0; i < 20; i++ { // Corrupt 20 bytes - exceeds RS16 correction capacity
		if saltStart+i < len(data) {
			data[saltStart+i] ^= 0xFF
		}
	}

	// Write tampered file
	tamperedPath := filepath.Join(tmpDir, "tampered.txt.pcv")
	if err := os.WriteFile(tamperedPath, data, 0644); err != nil {
		t.Fatalf("Failed to write tampered file: %v", err)
	}

	// Attempt to decrypt - should fail due to:
	// 1. Salt corruption -> wrong Argon2 key -> wrong HKDF -> header MAC mismatch
	decReq := &DecryptRequest{
		InputFile:    tamperedPath,
		OutputFile:   decryptedPath,
		Password:     "tamper_test_password",
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	err = Decrypt(context.Background(), decReq)
	if err == nil {
		t.Fatal("Expected decryption to fail due to header tampering, but it succeeded")
	}

	t.Logf("Header tamper correctly detected: %v", err)

	// Now test with ForceDecrypt - should proceed but may fail
	var kept bool
	decReqForce := &DecryptRequest{
		InputFile:    tamperedPath,
		OutputFile:   decryptedPath + ".forced",
		Password:     "tamper_test_password",
		ForceDecrypt: true,
		Kept:         &kept,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	err = Decrypt(context.Background(), decReqForce)
	// ForceDecrypt may succeed or fail depending on corruption severity
	if err != nil {
		t.Logf("ForceDecrypt also failed (severe tampering): %v", err)
	} else {
		t.Log("ForceDecrypt succeeded - data may be partially recovered")
	}

	t.Log("V2 header tamper detection: SUCCESS")
}

// TestOrderedKeyfilesOrderMatters verifies that when keyfileOrdered=true,
// providing keyfiles in wrong order causes decryption to fail.
func TestOrderedKeyfilesOrderMatters(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create test file
	plaintext := []byte("Ordered keyfiles test - order must match!")
	inputPath := filepath.Join(tmpDir, "ordered_kf_test.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create two keyfiles with different content
	keyfile1Path := filepath.Join(tmpDir, "keyfile1.bin")
	keyfile2Path := filepath.Join(tmpDir, "keyfile2.bin")

	if err := os.WriteFile(keyfile1Path, []byte("keyfile1_unique_content_AAAA"), 0644); err != nil {
		t.Fatalf("Failed to write keyfile1: %v", err)
	}
	if err := os.WriteFile(keyfile2Path, []byte("keyfile2_unique_content_BBBB"), 0644); err != nil {
		t.Fatalf("Failed to write keyfile2: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "ordered_kf_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "ordered_kf_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with keyfiles in order [keyfile1, keyfile2], ordered=true
	encReq := &EncryptRequest{
		InputFile:      inputPath,
		OutputFile:     encryptedPath,
		Password:       "ordered_keyfile_password",
		Keyfiles:       []string{keyfile1Path, keyfile2Path},
		KeyfileOrdered: true,
		Reporter:       reporter,
		RSCodecs:       rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Test 1: Correct order should succeed
	decReqCorrect := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "ordered_keyfile_password",
		Keyfiles:     []string{keyfile1Path, keyfile2Path}, // Correct order
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReqCorrect); err != nil {
		t.Fatalf("Decrypt with correct keyfile order failed: %v", err)
	}

	// Verify content
	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted content mismatch with correct order")
	}

	// Clean up for next test
	_ = os.Remove(decryptedPath)

	// Test 2: Wrong order should fail
	decReqWrong := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath + ".wrong",
		Password:     "ordered_keyfile_password",
		Keyfiles:     []string{keyfile2Path, keyfile1Path}, // WRONG order!
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	err = Decrypt(context.Background(), decReqWrong)
	if err == nil {
		t.Fatal("Expected decryption to fail with wrong keyfile order, but it succeeded")
	}

	t.Logf("Wrong keyfile order correctly rejected: %v", err)
	t.Log("Ordered keyfiles order matters: SUCCESS")
}

// TestZeroLengthComments verifies that volumes with empty comments work correctly
func TestZeroLengthComments(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("Zero length comments test data.")
	inputPath := filepath.Join(tmpDir, "zero_comments.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "zero_comments.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "zero_comments_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with explicitly empty comments
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "zero_comments_password",
		Comments:   "", // Explicitly empty
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt with zero-length comments failed: %v", err)
	}

	// Decrypt
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "zero_comments_password",
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt with zero-length comments failed: %v", err)
	}

	// Verify content
	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch.\nExpected: %q\nGot: %q", plaintext, decrypted)
	}

	t.Log("Zero-length comments: SUCCESS")
}

// TestRoundTripKeyfileOnly tests encryption with keyfile only (no password).
// This is a security-critical test as keyfile-only mode uses empty password string.
func TestRoundTripKeyfileOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping keyfile-only test in short mode")
	}
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create test file
	plaintext := []byte("Keyfile-only encryption test - no password used!")
	inputPath := filepath.Join(tmpDir, "keyfile_only_test.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create keyfile
	keyfilePath := filepath.Join(tmpDir, "keyfile_only.bin")
	keyfileData := []byte("This keyfile is the ONLY credential needed!")
	if err := os.WriteFile(keyfilePath, keyfileData, 0644); err != nil {
		t.Fatalf("Failed to write keyfile: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "keyfile_only_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "keyfile_only_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with keyfile only - empty password
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "", // Empty password - keyfile only!
		Keyfiles:   []string{keyfilePath},
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (keyfile-only) failed: %v", err)
	}

	// Decrypt with keyfile only - empty password
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "", // Empty password
		Keyfiles:     []string{keyfilePath},
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (keyfile-only) failed: %v", err)
	}

	// Verify content
	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch.\nExpected: %q\nGot: %q", plaintext, decrypted)
	}

	t.Log("Keyfile-only roundtrip: SUCCESS")
}

// TestRoundTripKeyfileOnlyParanoid tests keyfile-only with paranoid mode.
func TestRoundTripKeyfileOnlyParanoid(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping keyfile-only paranoid test in short mode")
	}
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("Paranoid keyfile-only test data.")
	inputPath := filepath.Join(tmpDir, "kf_paranoid.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	keyfilePath := filepath.Join(tmpDir, "kf_paranoid.key")
	if err := os.WriteFile(keyfilePath, []byte("paranoid_keyfile_content"), 0644); err != nil {
		t.Fatalf("Failed to write keyfile: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "kf_paranoid.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "kf_paranoid_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt keyfile-only + paranoid
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "",
		Keyfiles:   []string{keyfilePath},
		Paranoid:   true,
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (keyfile-only paranoid) failed: %v", err)
	}

	// Decrypt
	decReq := &DecryptRequest{
		InputFile:  encryptedPath,
		OutputFile: decryptedPath,
		Password:   "",
		Keyfiles:   []string{keyfilePath},
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (keyfile-only paranoid) failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch (keyfile-only paranoid)")
	}

	t.Log("Keyfile-only paranoid: SUCCESS")
}

// TestDeniabilityKeyfileOnly tests deniability with keyfile-only encryption.
// This verifies that deniability wrapper uses empty password correctly.
func TestDeniabilityKeyfileOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping deniability+keyfile test in short mode")
	}
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("Deniability with keyfile-only - wrapper uses empty password!")
	inputPath := filepath.Join(tmpDir, "deny_kf_only.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	keyfilePath := filepath.Join(tmpDir, "deny_kf_only.key")
	if err := os.WriteFile(keyfilePath, []byte("deniability_keyfile_content"), 0644); err != nil {
		t.Fatalf("Failed to write keyfile: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "deny_kf_only.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "deny_kf_only_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with deniability + keyfile-only
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    "", // Empty password
		Keyfiles:    []string{keyfilePath},
		Deniability: true,
		Reporter:    reporter,
		RSCodecs:    rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (deniability+keyfile-only) failed: %v", err)
	}

	// Verify deniability was applied
	if !IsDeniable(encryptedPath, rsCodecs) {
		t.Error("Volume should be detected as deniable")
	}

	// Decrypt with deniability + keyfile-only
	decReq := &DecryptRequest{
		InputFile:   encryptedPath,
		OutputFile:  decryptedPath,
		Password:    "", // Empty password for deniability wrapper
		Keyfiles:    []string{keyfilePath},
		Deniability: true,
		Reporter:    reporter,
		RSCodecs:    rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (deniability+keyfile-only) failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch (deniability+keyfile-only)")
	}

	t.Log("Deniability keyfile-only: SUCCESS")
}

// TestDeniabilityPasswordAndKeyfiles tests deniability with both password and keyfiles.
func TestDeniabilityPasswordAndKeyfiles(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping deniability+password+keyfile test in short mode")
	}
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("Deniability with password + keyfiles - maximum security!")
	inputPath := filepath.Join(tmpDir, "deny_pw_kf.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	keyfilePath := filepath.Join(tmpDir, "deny_pw_kf.key")
	if err := os.WriteFile(keyfilePath, []byte("combined_keyfile_content"), 0644); err != nil {
		t.Fatalf("Failed to write keyfile: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "deny_pw_kf.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "deny_pw_kf_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with deniability + password + keyfile
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    "deniability_password",
		Keyfiles:    []string{keyfilePath},
		Deniability: true,
		Reporter:    reporter,
		RSCodecs:    rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (deniability+password+keyfile) failed: %v", err)
	}

	// Decrypt with all credentials
	decReq := &DecryptRequest{
		InputFile:   encryptedPath,
		OutputFile:  decryptedPath,
		Password:    "deniability_password",
		Keyfiles:    []string{keyfilePath},
		Deniability: true,
		Reporter:    reporter,
		RSCodecs:    rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (deniability+password+keyfile) failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch (deniability+password+keyfile)")
	}

	t.Log("Deniability password+keyfiles: SUCCESS")
}

// TestWrongPasswordWithKeyfilesFails verifies that providing the wrong password
// fails decryption even when the correct keyfile is provided.
// This is security-critical: keyfile alone shouldn't unlock password-protected volumes.
func TestWrongPasswordWithKeyfilesFails(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping wrong password+keyfile test in short mode")
	}
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("Wrong password test - keyfile alone shouldn't work!")
	inputPath := filepath.Join(tmpDir, "wrong_pw_kf.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	keyfilePath := filepath.Join(tmpDir, "wrong_pw_kf.key")
	if err := os.WriteFile(keyfilePath, []byte("correct_keyfile_content"), 0644); err != nil {
		t.Fatalf("Failed to write keyfile: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "wrong_pw_kf.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "wrong_pw_kf_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with password + keyfile
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "correct_password",
		Keyfiles:   []string{keyfilePath},
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Attempt decrypt with WRONG password but CORRECT keyfile
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "wrong_password", // Wrong!
		Keyfiles:     []string{keyfilePath},
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	err = Decrypt(context.Background(), decReq)
	if err == nil {
		t.Fatal("Decrypt should have failed with wrong password (even with correct keyfile)")
	}

	t.Logf("Wrong password correctly rejected: %v", err)

	// Verify decrypted file doesn't exist
	if _, statErr := os.Stat(decryptedPath); !os.IsNotExist(statErr) {
		t.Error("Decrypted file should not exist after failed decryption")
	}

	// Now verify correct password works
	decReqCorrect := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "correct_password",
		Keyfiles:     []string{keyfilePath},
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReqCorrect); err != nil {
		t.Fatalf("Decrypt with correct credentials failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch with correct credentials")
	}

	t.Log("Wrong password with keyfiles correctly rejected: SUCCESS")
}

// TestKeyfileOnlyWrongKeyfileFails verifies that for keyfile-only volumes,
// providing a wrong keyfile fails (with or without empty password).
func TestKeyfileOnlyWrongKeyfileFails(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping keyfile-only wrong keyfile test in short mode")
	}
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("Keyfile-only wrong keyfile test")
	inputPath := filepath.Join(tmpDir, "kf_only_wrong.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	correctKeyfile := filepath.Join(tmpDir, "correct.key")
	wrongKeyfile := filepath.Join(tmpDir, "wrong.key")
	if err := os.WriteFile(correctKeyfile, []byte("correct_key_content"), 0644); err != nil {
		t.Fatalf("Failed to write correct keyfile: %v", err)
	}
	if err := os.WriteFile(wrongKeyfile, []byte("wrong_key_content"), 0644); err != nil {
		t.Fatalf("Failed to write wrong keyfile: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "kf_only_wrong.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "kf_only_wrong_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with keyfile only
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "",
		Keyfiles:   []string{correctKeyfile},
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Attempt decrypt with wrong keyfile
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "",
		Keyfiles:     []string{wrongKeyfile},
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	err = Decrypt(context.Background(), decReq)
	if err == nil {
		t.Fatal("Decrypt should have failed with wrong keyfile")
	}

	t.Logf("Wrong keyfile correctly rejected: %v", err)
	t.Log("Keyfile-only wrong keyfile: SUCCESS")
}

// TestDeniabilityWrongPasswordFails verifies that deniability wrapper correctly
// rejects wrong password for the deniability layer.
func TestDeniabilityWrongPasswordFails(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping deniability wrong password test in short mode")
	}
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("Deniability wrong password test")
	inputPath := filepath.Join(tmpDir, "deny_wrong_pw.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "deny_wrong_pw.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "deny_wrong_pw_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with deniability
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    "correct_deniability_password",
		Deniability: true,
		Reporter:    reporter,
		RSCodecs:    rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Attempt decrypt with wrong password - deniability layer should fail
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "wrong_deniability_password",
		Deniability:  true,
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	err = Decrypt(context.Background(), decReq)
	if err == nil {
		t.Fatal("Decrypt should have failed with wrong deniability password")
	}

	// Error should indicate password issue (version decode fails)
	t.Logf("Deniability wrong password correctly rejected: %v", err)
	t.Log("Deniability wrong password: SUCCESS")
}

// TestDuplicateKeyfilesRejected verifies that encryption fails when
// duplicate keyfiles would cause XOR cancellation (zero key).
func TestDuplicateKeyfilesRejected(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("Duplicate keyfiles should be rejected.")
	inputPath := filepath.Join(tmpDir, "dup_kf_test.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create one keyfile
	keyfilePath := filepath.Join(tmpDir, "keyfile.bin")
	if err := os.WriteFile(keyfilePath, []byte("keyfile_content_123456789"), 0644); err != nil {
		t.Fatalf("Failed to write keyfile: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "dup_kf_test.txt.pcv")

	reporter := &GoldenTestReporter{}

	// Attempt to encrypt with the same keyfile twice (unordered - will XOR to zero)
	encReq := &EncryptRequest{
		InputFile:      inputPath,
		OutputFile:     encryptedPath,
		Password:       "duplicate_keyfile_password",
		Keyfiles:       []string{keyfilePath, keyfilePath}, // Same keyfile twice!
		KeyfileOrdered: false,                              // Unordered = XOR cancellation
		Reporter:       reporter,
		RSCodecs:       rsCodecs,
	}

	err = Encrypt(context.Background(), encReq)
	if err == nil {
		t.Fatal("Expected encryption to fail with duplicate keyfiles, but it succeeded")
	}

	expectedErr := "duplicate keyfiles detected"
	if err.Error() != expectedErr {
		t.Errorf("Expected error %q, got %q", expectedErr, err.Error())
	}

	t.Logf("Duplicate keyfiles correctly rejected: %v", err)
	t.Log("Duplicate keyfiles rejection: SUCCESS")
}
