package volume

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/header"
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	perrors "Picocrypt-NG/internal/errors"
)

type autoUnzipOrderingReporter struct {
	mu            sync.Mutex
	outputPath    string
	encryptedPath string
	unzipping     bool
	observed      bool
	err           error
}

func (r *autoUnzipOrderingReporter) SetStatus(text string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if text == "Unzipping..." {
		r.unzipping = true
	}
}

func (r *autoUnzipOrderingReporter) SetProgress(float32, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.unzipping || r.observed {
		return
	}
	r.observed = true
	outputInfo, err := os.Lstat(r.outputPath)
	if err != nil {
		r.err = fmt.Errorf("requested output is absent during extraction: %w", err)
		return
	}
	if !outputInfo.IsDir() {
		r.err = fmt.Errorf("requested output is %s during extraction, want owned directory", outputInfo.Mode())
		return
	}
	if _, err := os.Lstat(r.encryptedPath); err != nil {
		r.err = fmt.Errorf("encrypted input is unavailable during extraction: %w", err)
	}
}

func (*autoUnzipOrderingReporter) SetCanCancel(bool) {}
func (*autoUnzipOrderingReporter) Update()           {}
func (*autoUnzipOrderingReporter) IsCancelled() bool { return false }

func (r *autoUnzipOrderingReporter) result() (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.observed, r.err
}

type autoUnzipParentSwapReporter struct {
	linkPath       string
	replacementDir string
	swapped        bool
	err            error
}

func (r *autoUnzipParentSwapReporter) SetStatus(text string) {
	if text != "Unzipping..." || r.swapped || r.err != nil {
		return
	}
	if err := os.Remove(r.linkPath); err != nil {
		r.err = fmt.Errorf("remove original output-parent link: %w", err)
		return
	}
	if err := os.Symlink(r.replacementDir, r.linkPath); err != nil {
		r.err = fmt.Errorf("replace output-parent link: %w", err)
		return
	}
	r.swapped = true
}

func (*autoUnzipParentSwapReporter) SetProgress(float32, string) {}
func (*autoUnzipParentSwapReporter) SetCanCancel(bool)           {}
func (*autoUnzipParentSwapReporter) Update()                     {}
func (*autoUnzipParentSwapReporter) IsCancelled() bool           { return false }

type autoUnzipParentReplaceReporter struct {
	parentPath string
	movedPath  string
	replaced   bool
	err        error
}

func (r *autoUnzipParentReplaceReporter) SetStatus(text string) {
	if text != "Unzipping..." || r.replaced || r.err != nil {
		return
	}
	if err := os.Rename(r.parentPath, r.movedPath); err != nil {
		r.err = fmt.Errorf("move original output parent: %w", err)
		return
	}
	if err := os.Mkdir(r.parentPath, 0o700); err != nil {
		r.err = fmt.Errorf("create replacement output parent: %w", err)
		return
	}
	r.replaced = true
}

func (*autoUnzipParentReplaceReporter) SetProgress(float32, string) {}
func (*autoUnzipParentReplaceReporter) SetCanCancel(bool)           {}
func (*autoUnzipParentReplaceReporter) Update()                     {}
func (*autoUnzipParentReplaceReporter) IsCancelled() bool           { return false }

type autoUnzipExtractRootReplaceReporter struct {
	extractPath string
	movedPath   string
	foreign     []byte
	replaced    bool
	err         error
}

func (r *autoUnzipExtractRootReplaceReporter) SetStatus(text string) {
	if text != "Unzipping..." || r.replaced || r.err != nil {
		return
	}
	if err := os.Rename(r.extractPath, r.movedPath); err != nil {
		r.err = fmt.Errorf("move reserved extraction root: %w", err)
		return
	}
	if err := os.Mkdir(r.extractPath, 0o700); err != nil {
		r.err = fmt.Errorf("create replacement extraction root: %w", err)
		return
	}
	if err := os.WriteFile(filepath.Join(r.extractPath, "foreign.txt"), r.foreign, 0o600); err != nil {
		r.err = fmt.Errorf("write foreign extraction-root entry: %w", err)
		return
	}
	r.replaced = true
}

func (*autoUnzipExtractRootReplaceReporter) SetProgress(float32, string) {}
func (*autoUnzipExtractRootReplaceReporter) SetCanCancel(bool)           {}
func (*autoUnzipExtractRootReplaceReporter) Update()                     {}
func (*autoUnzipExtractRootReplaceReporter) IsCancelled() bool           { return false }

// readVolumeHeader opens an encrypted .pcv volume and decodes its header using the
// production header reader. It is the read-back seam for flag/comment assertions:
// tests use it to prove that EncryptRequest options are actually persisted into the
// on-disk header (not merely honored in-memory during the round-trip).
func readVolumeHeader(t *testing.T, encryptedPath string) *header.VolumeHeader {
	t.Helper()
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}
	fin, err := os.Open(encryptedPath)
	if err != nil {
		t.Fatalf("Failed to open encrypted volume: %v", err)
	}
	defer func() { _ = fin.Close() }()

	res, err := NewHeaderReaderForTest(fin, rsCodecs).ReadHeader()
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if res.DecodeError != nil {
		t.Fatalf("header decode error: %v", res.DecodeError)
	}
	return res.Header
}

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
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "test_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    []byte("testpassword123"),
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
		Password:     []byte("testpassword123"),
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

// TestEncryptRejectsOverflowingChunkSizeEarly proves volume.Encrypt rejects an
// overflowing split chunk size at the pipeline entry — before preprocessing, key
// derivation, or writing any output — so the just-encrypted volume can never be
// silently destroyed by the final split step (the fileops.Split data-loss path).
func TestEncryptRejectsOverflowingChunkSizeEarly(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(inputPath, []byte("payload"), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	outputPath := filepath.Join(tmpDir, "test.txt.pcv")

	req := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: outputPath,
		Password:   []byte("testpassword123"),
		Split:      true,
		ChunkSize:  1 << 23, // 2^23 TiB overflows int64 when scaled to bytes
		ChunkUnit:  fileops.SplitUnitTiB,
	}

	err := Encrypt(context.Background(), req)
	if !errors.Is(err, perrors.ErrChunkSizeTooLarge) {
		t.Fatalf("Encrypt() error = %v, want ErrChunkSizeTooLarge", err)
	}
	if _, statErr := os.Stat(outputPath); !os.IsNotExist(statErr) {
		t.Errorf("output must not exist after early rejection, stat err = %v", statErr)
	}
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
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "paranoid_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "paranoid_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with paranoid mode
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   []byte("paranoid_password"),
		Paranoid:   true,
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (paranoid) failed: %v", err)
	}

	// The Paranoid flag must be persisted into the on-disk header (dropping the
	// flag write would still round-trip but fail to record paranoid mode).
	h := readVolumeHeader(t, encryptedPath)
	if !h.Flags.Paranoid {
		t.Error("header Flags.Paranoid = false, want true for paranoid volume")
	}
	if h.Flags.UseKeyfiles {
		t.Error("header Flags.UseKeyfiles = true, want false (no keyfiles used)")
	}
	if h.Flags.ReedSolomon {
		t.Error("header Flags.ReedSolomon = true, want false (RS not enabled)")
	}

	// Decrypt
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     []byte("paranoid_password"),
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

	// Size the plaintext so the on-disk Padded flag is set. encrypt.go computes
	// Padded = (Total % MiB) >= (MiB - RS128DataSize), i.e. the final partial-MiB
	// block lands within the last 128 bytes of a 1 MiB block. (1<<20)-1 bytes makes
	// Total % MiB = MiB-1, which satisfies that bound, so Padded must be true. NOTE:
	// a tiny plaintext does NOT pad (Total % MiB is far below the bound) — the size
	// here is load-bearing for the Padded assertion below.
	plaintext := make([]byte, (1<<20)-1)
	for i := range plaintext {
		plaintext[i] = byte((i * 7) % 256)
	}
	inputPath := filepath.Join(tmpDir, "rs_test.bin")
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "rs_test.bin.pcv")
	decryptedPath := filepath.Join(tmpDir, "rs_decrypted.bin")

	reporter := &GoldenTestReporter{}

	// Encrypt with Reed-Solomon
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    []byte("rs_password"),
		ReedSolomon: true,
		Reporter:    reporter,
		RSCodecs:    rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (RS) failed: %v", err)
	}

	// The ReedSolomon flag must be persisted, and for this deliberately-sized input
	// the final block pads, so the Padded flag must also be set (Padded otherwise
	// has zero coverage). Dropping either flag write fails here.
	h := readVolumeHeader(t, encryptedPath)
	if !h.Flags.ReedSolomon {
		t.Error("header Flags.ReedSolomon = false, want true for Reed-Solomon volume")
	}
	if !h.Flags.Padded {
		t.Error("header Flags.Padded = false, want true (input sized to MiB-1 pads its final block)")
	}

	// Decrypt
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     []byte("rs_password"),
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
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "deny_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "deny_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with deniability
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    []byte("deny_password"),
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
		Password:     []byte("deny_password"),
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
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "full_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "full_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with all options
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    []byte("full_options_password"),
		Paranoid:    true,
		ReedSolomon: true,
		Deniability: true,
		Reporter:    reporter,
		RSCodecs:    rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (all options) failed: %v", err)
	}

	// Deniability is enabled, so the outer header is randomized and cannot be decoded
	// for flags; instead assert the deniability wrap is present (dropping it with all
	// options set would leave a decodable, non-deniable header).
	if !IsDeniable(encryptedPath, rsCodecs) {
		t.Error("all-options volume with Deniability set should be detected as deniable")
	}

	// Decrypt
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     []byte("full_options_password"),
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
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "comments_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "comments_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with comments
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   []byte("comments_password"),
		Comments:   "This is a test comment! 日本語テスト 🔐",
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (with comments) failed: %v", err)
	}

	// Comments are stored in the (plaintext) header and must round-trip exactly,
	// including multibyte UTF-8 — no prior test reads a non-empty comment back.
	h := readVolumeHeader(t, encryptedPath)
	if h.Comments != "This is a test comment! 日本語テスト 🔐" {
		t.Errorf("header Comments = %q, want %q", h.Comments, "This is a test comment! 日本語テスト 🔐")
	}

	// Decrypt
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     []byte("comments_password"),
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
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create keyfile
	keyfilePath := filepath.Join(tmpDir, "keyfile.bin")
	keyfileData := []byte("This is my secret keyfile content!")
	if err := os.WriteFile(keyfilePath, keyfileData, 0o644); err != nil {
		t.Fatalf("Failed to write keyfile: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "keyfile_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "keyfile_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with keyfile
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   []byte("password_with_keyfile"),
		Keyfiles:   []string{keyfilePath},
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (with keyfile) failed: %v", err)
	}

	// The UseKeyfiles flag must be persisted for self-encrypted volumes, otherwise
	// decryption could not know a keyfile is required.
	h := readVolumeHeader(t, encryptedPath)
	if !h.Flags.UseKeyfiles {
		t.Error("header Flags.UseKeyfiles = false, want true for keyfile-protected volume")
	}

	// Decrypt with keyfile
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     []byte("password_with_keyfile"),
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
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create keyfiles
	keyfile1 := filepath.Join(tmpDir, "keyfile1.bin")
	keyfile2 := filepath.Join(tmpDir, "keyfile2.bin")
	if err := os.WriteFile(keyfile1, []byte("First keyfile content"), 0o644); err != nil {
		t.Fatalf("Failed to write keyfile1: %v", err)
	}
	if err := os.WriteFile(keyfile2, []byte("Second keyfile content"), 0o644); err != nil {
		t.Fatalf("Failed to write keyfile2: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "multi_keyfile_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "multi_keyfile_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with multiple keyfiles (unordered - default)
	encReq := &EncryptRequest{
		InputFile:      inputPath,
		OutputFile:     encryptedPath,
		Password:       []byte("multi_keyfile_pass"),
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
		Password:     []byte("multi_keyfile_pass"),
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
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create keyfiles
	keyfile1 := filepath.Join(tmpDir, "ordered1.bin")
	keyfile2 := filepath.Join(tmpDir, "ordered2.bin")
	if err := os.WriteFile(keyfile1, []byte("First ordered keyfile"), 0o644); err != nil {
		t.Fatalf("Failed to write keyfile1: %v", err)
	}
	if err := os.WriteFile(keyfile2, []byte("Second ordered keyfile"), 0o644); err != nil {
		t.Fatalf("Failed to write keyfile2: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "ordered_keyfile_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "ordered_keyfile_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with ordered keyfiles
	encReq := &EncryptRequest{
		InputFile:      inputPath,
		OutputFile:     encryptedPath,
		Password:       []byte("ordered_keyfile_pass"),
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
		Password:     []byte("ordered_keyfile_pass"),
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
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create correct keyfile
	correctKeyfile := filepath.Join(tmpDir, "correct_keyfile.bin")
	if err := os.WriteFile(correctKeyfile, []byte("Correct keyfile"), 0o644); err != nil {
		t.Fatalf("Failed to write correct keyfile: %v", err)
	}

	// Create wrong keyfile
	wrongKeyfile := filepath.Join(tmpDir, "wrong_keyfile.bin")
	if err := os.WriteFile(wrongKeyfile, []byte("Wrong keyfile"), 0o644); err != nil {
		t.Fatalf("Failed to write wrong keyfile: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "secret.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "secret_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with correct keyfile
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   []byte("keyfile_password"),
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
		Password:     []byte("keyfile_password"),
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
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
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
		Password:   []byte("split_password"),
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
		// A 100 KiB input split into 10 KiB chunks MUST produce multiple chunks;
		// zero chunks means splitting silently failed — fail loud (Rule 12), never
		// skip a broken split as if it were an environment gap.
		if len(chunks) == 0 {
			t.Fatalf("split produced zero chunks for %q (splitting is broken)", encryptedPath)
		}
	}
	t.Logf("Created %d chunks", len(chunks))

	// Decrypt with recombine
	// InputFile should be the base path (without .N suffix) for recombine
	decReq := &DecryptRequest{
		InputFile:    encryptedPath, // Base path - recombine will look for .0, .1, etc.
		OutputFile:   decryptedPath,
		Password:     []byte("split_password"),
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

// TestRoundTripDecryptFromFirstChunkWithRecombine verifies the documented API
// path where InputFile points at the first chunk rather than the base .pcv path.
func TestRoundTripDecryptFromFirstChunkWithRecombine(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := make([]byte, 1024*64)
	for i := range plaintext {
		plaintext[i] = byte(i % 251)
	}
	inputPath := filepath.Join(tmpDir, "split_first_chunk.bin")
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "split_first_chunk.bin.pcv")
	decryptedPath := filepath.Join(tmpDir, "split_first_chunk_decrypted.bin")
	reporter := &GoldenTestReporter{}

	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   []byte("split_password"),
		Split:      true,
		ChunkSize:  8,
		ChunkUnit:  0,
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}
	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (split) failed: %v", err)
	}

	firstChunk := encryptedPath + ".0"
	if _, err := os.Stat(firstChunk); err != nil {
		t.Fatalf("Expected first chunk to exist: %v", err)
	}

	decReq := &DecryptRequest{
		InputFile:    firstChunk,
		OutputFile:   decryptedPath,
		Password:     []byte("split_password"),
		Recombine:    true,
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}
	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (first chunk + recombine) failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if len(decrypted) != len(plaintext) {
		t.Fatalf("Length mismatch. Expected %d, got %d", len(plaintext), len(decrypted))
	}
	for i := range plaintext {
		if decrypted[i] != plaintext[i] {
			t.Fatalf("Content mismatch at byte %d", i)
		}
	}
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
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "secret.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "secret_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   []byte("correct_password"),
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
		Password:     []byte("wrong_password"),
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
	if err := os.MkdirAll(testDir, 0o755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	testFile := filepath.Join(testDir, "test_file.txt")
	if err := os.WriteFile(testFile, testContent, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create zip file
	zipPath := filepath.Join(tmpDir, "test.zip")
	if err := createTestZip(zipPath, testDir); err != nil {
		t.Fatalf("Failed to create test zip: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "test.zip.pcv")
	decryptedPath := filepath.Join(tmpDir, "test.zip")

	reporter := &GoldenTestReporter{}

	// Encrypt the zip file
	encReq := &EncryptRequest{
		InputFile:  zipPath,
		OutputFile: encryptedPath,
		Password:   []byte("autounzip_password"),
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
		Password:     []byte("autounzip_password"),
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

func TestAutoUnzipWithoutZipSuffixKeepsRecoverableStateVisibleDuringExtraction(t *testing.T) {
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	if err := os.Mkdir(sourceDir, 0o700); err != nil {
		t.Fatalf("create source directory: %v", err)
	}
	payload := bytes.Repeat([]byte("real auto-unzip ordering payload"), 4096)
	if err := os.WriteFile(filepath.Join(sourceDir, "payload.txt"), payload, 0o600); err != nil {
		t.Fatalf("write source payload: %v", err)
	}
	plainZip := filepath.Join(tmpDir, "source.zip")
	if err := createTestZip(plainZip, sourceDir); err != nil {
		t.Fatalf("create source ZIP: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "source.zip.pcv")
	password := []byte("auto-unzip-ordering-password")
	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile:  plainZip,
		OutputFile: encryptedPath,
		Password:   append([]byte(nil), password...),
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("encrypt source ZIP: %v", err)
	}
	if err := os.Remove(plainZip); err != nil {
		t.Fatalf("remove plaintext ZIP fixture: %v", err)
	}
	if err := os.RemoveAll(sourceDir); err != nil {
		t.Fatalf("remove source fixture: %v", err)
	}

	outputPath := filepath.Join(tmpDir, "recovered")
	reporter := &autoUnzipOrderingReporter{
		outputPath:    outputPath,
		encryptedPath: encryptedPath,
	}
	if err := Decrypt(context.Background(), &DecryptRequest{
		InputFile:  encryptedPath,
		OutputFile: outputPath,
		Password:   append([]byte(nil), password...),
		AutoUnzip:  true,
		Reporter:   reporter,
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("decrypt and auto-unzip: %v", err)
	}

	observed, orderingErr := reporter.result()
	if !observed {
		t.Fatal("real extraction produced no progress observation")
	}
	if orderingErr != nil {
		t.Fatalf("unsafe auto-unzip publication order: %v", orderingErr)
	}
	assertFileBytes(t, filepath.Join(outputPath, "source", "payload.txt"), payload)
	if _, err := os.Lstat(encryptedPath); err != nil {
		t.Fatalf("encrypted input must remain recoverable: %v", err)
	}
}

func TestAutoUnzipWithoutZipSuffixRejectsOutputParentSwap(t *testing.T) {
	tmpDir := t.TempDir()
	plainZip := filepath.Join(tmpDir, "payload.zip")
	payload := bytes.Repeat([]byte("pinned auto-unzip parent payload"), 512)
	createStoredZipEntryForVolumeTest(t, plainZip, "payload.txt", payload)

	encryptedPath := filepath.Join(tmpDir, "payload.pcv")
	password := "auto-unzip-parent-swap-password"
	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile:  plainZip,
		OutputFile: encryptedPath,
		Password:   []byte(password),
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("encrypt ZIP fixture: %v", err)
	}
	if err := os.Remove(plainZip); err != nil {
		t.Fatalf("remove plaintext ZIP fixture: %v", err)
	}
	encryptedInfo, err := os.Lstat(encryptedPath)
	if err != nil {
		t.Fatalf("inspect encrypted input: %v", err)
	}
	encryptedBytes, err := os.ReadFile(encryptedPath)
	if err != nil {
		t.Fatalf("read encrypted input: %v", err)
	}

	originalDir := filepath.Join(tmpDir, "original")
	replacementDir := filepath.Join(tmpDir, "replacement")
	for _, path := range []string{originalDir, replacementDir} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("create output parent %s: %v", path, err)
		}
	}
	outputLink := filepath.Join(tmpDir, "output-link")
	if err := os.Symlink(originalDir, outputLink); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}
	outputPath := filepath.Join(outputLink, "recovered")
	reporter := &autoUnzipParentSwapReporter{
		linkPath:       outputLink,
		replacementDir: replacementDir,
	}

	err = Decrypt(context.Background(), &DecryptRequest{
		InputFile:  encryptedPath,
		OutputFile: outputPath,
		Password:   []byte(password),
		AutoUnzip:  true,
		Reporter:   reporter,
		RSCodecs:   newRSCodecsT(t),
	})
	if err == nil {
		t.Fatal("Decrypt succeeded after the output parent changed")
	}
	if reporter.err != nil {
		t.Fatalf("swap output parent: %v", reporter.err)
	}
	if !reporter.swapped {
		t.Fatal("real decrypt pipeline never reached the auto-unzip parent swap")
	}
	for _, parent := range []string{originalDir, replacementDir} {
		entries, readErr := os.ReadDir(parent)
		if readErr != nil {
			t.Fatalf("read output parent %s: %v", parent, readErr)
		}
		if len(entries) != 0 {
			t.Fatalf("output parent %s contains residue after rejected swap: %v", parent, entries)
		}
	}
	currentEncryptedInfo, err := os.Lstat(encryptedPath)
	if err != nil {
		t.Fatalf("encrypted input disappeared after rejected swap: %v", err)
	}
	if !os.SameFile(encryptedInfo, currentEncryptedInfo) {
		t.Fatal("encrypted input path was replaced after rejected swap")
	}
	assertFileBytes(t, encryptedPath, encryptedBytes)

	safeOutput := filepath.Join(tmpDir, "safe-recovered")
	if err := Decrypt(context.Background(), &DecryptRequest{
		InputFile:  encryptedPath,
		OutputFile: safeOutput,
		Password:   []byte(password),
		AutoUnzip:  true,
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("decrypt unchanged volume to a stable output: %v", err)
	}
	assertFileBytes(t, filepath.Join(safeOutput, "payload.txt"), payload)
}

func TestAutoUnzipSameLevelRejectsOutputParentSwap(t *testing.T) {
	tmpDir := t.TempDir()
	plainZip := filepath.Join(tmpDir, "same-level.zip")
	payload := bytes.Repeat([]byte("same-level pinned parent payload"), 512)
	createStoredZipEntryForVolumeTest(t, plainZip, "payload.txt", payload)
	plainZipBytes, err := os.ReadFile(plainZip)
	if err != nil {
		t.Fatalf("read plaintext ZIP fixture: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "same-level.pcv")
	password := "same-level-parent-swap-password"
	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile:  plainZip,
		OutputFile: encryptedPath,
		Password:   []byte(password),
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("encrypt ZIP fixture: %v", err)
	}
	if err := os.Remove(plainZip); err != nil {
		t.Fatalf("remove plaintext ZIP fixture: %v", err)
	}
	encryptedInfo, err := os.Lstat(encryptedPath)
	if err != nil {
		t.Fatalf("inspect encrypted input: %v", err)
	}
	encryptedBytes, err := os.ReadFile(encryptedPath)
	if err != nil {
		t.Fatalf("read encrypted input: %v", err)
	}

	outputDir := filepath.Join(tmpDir, "output")
	movedOriginalDir := filepath.Join(tmpDir, "moved-original")
	if err := os.Mkdir(outputDir, 0o700); err != nil {
		t.Fatalf("create output parent: %v", err)
	}
	outputPath := filepath.Join(outputDir, "recovered.zip")
	reporter := &autoUnzipParentReplaceReporter{
		parentPath: outputDir,
		movedPath:  movedOriginalDir,
	}

	err = Decrypt(context.Background(), &DecryptRequest{
		InputFile:  encryptedPath,
		OutputFile: outputPath,
		Password:   []byte(password),
		AutoUnzip:  true,
		SameLevel:  true,
		Reporter:   reporter,
		RSCodecs:   newRSCodecsT(t),
	})
	if reporter.err != nil {
		if !windowsPreventedOpenHandleRename(reporter.err) {
			t.Fatalf("replace output parent: %v", reporter.err)
		}
		if err != nil {
			t.Fatalf("same-level Decrypt after the OS prevented parent replacement: %v", err)
		}
		if reporter.replaced {
			t.Fatal("reporter marked a blocked output-parent replacement as completed")
		}
		assertFileBytes(t, filepath.Join(outputDir, "payload.txt"), payload)
		if _, statErr := os.Lstat(outputPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("successful same-level auto-unzip retained its archive: %v", statErr)
		}
		currentEncryptedInfo, statErr := os.Lstat(encryptedPath)
		if statErr != nil {
			t.Fatalf("encrypted input disappeared after prevented parent replacement: %v", statErr)
		}
		if !os.SameFile(encryptedInfo, currentEncryptedInfo) {
			t.Fatal("encrypted input path changed after prevented parent replacement")
		}
		assertFileBytes(t, encryptedPath, encryptedBytes)
		return
	}
	if err == nil {
		t.Fatal("same-level Decrypt succeeded after the output parent changed")
	}
	if !reporter.replaced {
		t.Fatal("real decrypt pipeline never reached the same-level parent replacement")
	}
	replacementEntries, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatalf("read replacement output parent: %v", err)
	}
	if len(replacementEntries) != 0 {
		t.Fatalf("same-level extraction wrote into replacement parent: %v", replacementEntries)
	}
	recoverableArchive := filepath.Join(movedOriginalDir, "recovered.zip")
	assertFileBytes(t, recoverableArchive, plainZipBytes)
	requireStoredZipEntryForVolumeTest(t, recoverableArchive, "payload.txt", payload)
	originalEntries, err := os.ReadDir(movedOriginalDir)
	if err != nil {
		t.Fatalf("read original output parent: %v", err)
	}
	if len(originalEntries) != 1 || originalEntries[0].Name() != "recovered.zip" {
		t.Fatalf("original output parent contains unexpected residue: %v", originalEntries)
	}

	currentEncryptedInfo, err := os.Lstat(encryptedPath)
	if err != nil {
		t.Fatalf("encrypted input disappeared after rejected swap: %v", err)
	}
	if !os.SameFile(encryptedInfo, currentEncryptedInfo) {
		t.Fatal("encrypted input path was replaced after rejected same-level swap")
	}
	assertFileBytes(t, encryptedPath, encryptedBytes)

	retryDir := filepath.Join(tmpDir, "retry")
	if err := os.Mkdir(retryDir, 0o700); err != nil {
		t.Fatalf("create stable retry parent: %v", err)
	}
	retryArchive := filepath.Join(retryDir, "recovered.zip")
	if err := Decrypt(context.Background(), &DecryptRequest{
		InputFile:  encryptedPath,
		OutputFile: retryArchive,
		Password:   []byte(password),
		AutoUnzip:  true,
		SameLevel:  true,
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("decrypt unchanged volume into stable same-level parent: %v", err)
	}
	assertFileBytes(t, filepath.Join(retryDir, "payload.txt"), payload)
	if _, err := os.Lstat(retryArchive); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stable same-level retry left its decrypted archive: %v", err)
	}
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
	if err := os.MkdirAll(volumeDir, 0o755); err != nil {
		t.Fatalf("Failed to create volume directory: %v", err)
	}

	// Create a test file and zip it
	testContent := []byte("Same-level unzip test content!")
	testDir := filepath.Join(tmpDir, "source_folder")
	if err := os.MkdirAll(testDir, 0o755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	testFile := filepath.Join(testDir, "same_level_test.txt")
	if err := os.WriteFile(testFile, testContent, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create zip file
	zipPath := filepath.Join(tmpDir, "samelevel.zip")
	if err := createTestZip(zipPath, testDir); err != nil {
		t.Fatalf("Failed to create test zip: %v", err)
	}

	encryptedPath := filepath.Join(volumeDir, "samelevel.zip.pcv")
	decryptedPath := filepath.Join(volumeDir, "samelevel.zip")

	reporter := &GoldenTestReporter{}

	// Encrypt the zip file
	encReq := &EncryptRequest{
		InputFile:  zipPath,
		OutputFile: encryptedPath,
		Password:   []byte("samelevel_password"),
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
		Password:     []byte("samelevel_password"),
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

func TestAutoUnzipSameLevelPreservesKeyfileCollision(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Create RS codecs: %v", err)
	}
	tmpDir := t.TempDir()
	volumeDir := filepath.Join(tmpDir, "volume")
	if err := os.Mkdir(volumeDir, 0o700); err != nil {
		t.Fatalf("Create volume directory: %v", err)
	}

	keyfilePath := filepath.Join(volumeDir, "keyfile.bin")
	keyfileData := []byte("key material must never be replaced by archive contents")
	if err := os.WriteFile(keyfilePath, keyfileData, 0o600); err != nil {
		t.Fatalf("Create keyfile: %v", err)
	}
	keyfileInfo, err := os.Lstat(keyfilePath)
	if err != nil {
		t.Fatalf("Inspect keyfile: %v", err)
	}

	zipPath := filepath.Join(tmpDir, "source.zip")
	archivePayload := []byte("untrusted archive entry named like the keyfile")
	createStoredZipEntryForVolumeTest(t, zipPath, filepath.Base(keyfilePath), archivePayload)
	encryptedPath := filepath.Join(volumeDir, "archive.pcv")
	password := []byte("auto-unzip-keyfile-collision")
	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile:  zipPath,
		OutputFile: encryptedPath,
		Password:   password,
		Keyfiles:   []string{keyfilePath},
		Reporter:   &GoldenTestReporter{},
		RSCodecs:   rsCodecs,
	}); err != nil {
		t.Fatalf("Encrypt keyfile-protected ZIP: %v", err)
	}

	decryptedPath := filepath.Join(volumeDir, "archive.zip")
	err = Decrypt(context.Background(), &DecryptRequest{
		InputFile:  encryptedPath,
		OutputFile: decryptedPath,
		Password:   password,
		Keyfiles:   []string{keyfilePath},
		AutoUnzip:  true,
		SameLevel:  true,
		Reporter:   &GoldenTestReporter{},
		RSCodecs:   rsCodecs,
	})
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("Decrypt auto-unzip collision error = %v, want os.ErrExist", err)
	}

	gotKeyfile, err := os.ReadFile(keyfilePath)
	if err != nil {
		t.Fatalf("Read keyfile after collision: %v", err)
	}
	if string(gotKeyfile) != string(keyfileData) {
		t.Fatalf("Keyfile changed: got %q, want %q", gotKeyfile, keyfileData)
	}
	currentKeyfileInfo, err := os.Lstat(keyfilePath)
	if err != nil {
		t.Fatalf("Inspect keyfile after collision: %v", err)
	}
	if !os.SameFile(keyfileInfo, currentKeyfileInfo) {
		t.Fatal("Keyfile path was replaced")
	}
	requireStoredZipEntryForVolumeTest(t, decryptedPath, filepath.Base(keyfilePath), archivePayload)
	if _, err := os.Stat(encryptedPath); err != nil {
		t.Fatalf("Encrypted input was removed after extraction collision: %v", err)
	}
}

func TestAutoUnzipSameLevelPreservesArchiveOnSelfCollision(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Create RS codecs: %v", err)
	}
	tmpDir := t.TempDir()
	sourceZip := filepath.Join(tmpDir, "source.zip")
	outputPath := filepath.Join(tmpDir, "archive.zip")
	payload := []byte("entry intentionally collides with the decrypted archive")
	createStoredZipEntryForVolumeTest(t, sourceZip, filepath.Base(outputPath), payload)

	encryptedPath := filepath.Join(tmpDir, "archive.pcv")
	password := []byte("auto-unzip-self-collision")
	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile:  sourceZip,
		OutputFile: encryptedPath,
		Password:   password,
		Reporter:   &GoldenTestReporter{},
		RSCodecs:   rsCodecs,
	}); err != nil {
		t.Fatalf("Encrypt self-colliding ZIP: %v", err)
	}

	err = Decrypt(context.Background(), &DecryptRequest{
		InputFile:  encryptedPath,
		OutputFile: outputPath,
		Password:   password,
		AutoUnzip:  true,
		SameLevel:  true,
		Reporter:   &GoldenTestReporter{},
		RSCodecs:   rsCodecs,
	})
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("Decrypt auto-unzip self-collision error = %v, want os.ErrExist", err)
	}
	requireStoredZipEntryForVolumeTest(t, outputPath, filepath.Base(outputPath), payload)
}

func TestAutoUnzipPreservesPreexistingLegacyZipSibling(t *testing.T) {
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	if err := os.Mkdir(sourceDir, 0o700); err != nil {
		t.Fatalf("create source directory: %v", err)
	}
	payload := []byte("real auto-unzip payload")
	if err := os.WriteFile(filepath.Join(sourceDir, "payload.txt"), payload, 0o600); err != nil {
		t.Fatalf("write source payload: %v", err)
	}

	plainZip := filepath.Join(tmpDir, "source.zip")
	if err := createTestZip(plainZip, sourceDir); err != nil {
		t.Fatalf("create source ZIP: %v", err)
	}
	volumePath := filepath.Join(tmpDir, "source.zip.pcv")
	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile:  plainZip,
		OutputFile: volumePath,
		Password:   []byte("legacy-zip-sibling-password"),
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("encrypt source ZIP: %v", err)
	}
	if err := os.Remove(plainZip); err != nil {
		t.Fatalf("remove plaintext ZIP fixture: %v", err)
	}
	if err := os.RemoveAll(sourceDir); err != nil {
		t.Fatalf("remove plaintext source fixture: %v", err)
	}

	outputPath := filepath.Join(tmpDir, "recovered")
	legacyZip := outputPath + ".zip"
	foreignBytes := []byte("foreign file at the old predictable auto-unzip path")
	if err := os.WriteFile(legacyZip, foreignBytes, 0o640); err != nil {
		t.Fatalf("write protected legacy ZIP sibling: %v", err)
	}

	if err := Decrypt(context.Background(), &DecryptRequest{
		InputFile:  volumePath,
		OutputFile: outputPath,
		Password:   []byte("legacy-zip-sibling-password"),
		AutoUnzip:  true,
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("decrypt and auto-unzip: %v", err)
	}

	assertFileBytes(t, legacyZip, foreignBytes)
	assertFileBytes(t, filepath.Join(outputPath, "source", "payload.txt"), payload)
	matches, err := filepath.Glob(filepath.Join(tmpDir, ".picocrypt-unpack-*"))
	if err != nil {
		t.Fatalf("glob auto-unzip work directories: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("auto-unzip leaked private work paths: %v", matches)
	}
}

func TestAutoUnzipMalformedZipPublishesRecoverablePlaintextArchive(t *testing.T) {
	tmpDir := t.TempDir()
	malformedZip := []byte("PK\x03\x04not-a-valid-zip-central-directory")
	plaintextPath := filepath.Join(tmpDir, "malformed.zip")
	if err := os.WriteFile(plaintextPath, malformedZip, 0o600); err != nil {
		t.Fatalf("write malformed ZIP fixture: %v", err)
	}
	encryptedPath := filepath.Join(tmpDir, "malformed.zip.pcv")
	password := "malformed-auto-unzip-password"
	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile:  plaintextPath,
		OutputFile: encryptedPath,
		Password:   []byte(password),
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("encrypt malformed ZIP fixture: %v", err)
	}
	if err := os.Remove(plaintextPath); err != nil {
		t.Fatalf("remove plaintext fixture: %v", err)
	}
	encryptedInfo, err := os.Lstat(encryptedPath)
	if err != nil {
		t.Fatalf("inspect encrypted input: %v", err)
	}
	encryptedBytes, err := os.ReadFile(encryptedPath)
	if err != nil {
		t.Fatalf("read encrypted input: %v", err)
	}

	outputPath := filepath.Join(tmpDir, "recovered")
	err = Decrypt(context.Background(), &DecryptRequest{
		InputFile:  encryptedPath,
		OutputFile: outputPath,
		Password:   []byte(password),
		AutoUnzip:  true,
		RSCodecs:   newRSCodecsT(t),
	})
	if err == nil {
		t.Fatal("Decrypt succeeded while auto-unpacking a malformed ZIP")
	}
	if !strings.Contains(err.Error(), "unzip") {
		t.Fatalf("Decrypt error = %v, want an unzip error", err)
	}
	outputInfo, err := os.Lstat(outputPath)
	if err != nil {
		t.Fatalf("recoverable plaintext archive was not published: %v", err)
	}
	if !outputInfo.Mode().IsRegular() {
		t.Fatalf("recoverable output mode = %s, want regular archive file", outputInfo.Mode())
	}
	assertFileBytes(t, outputPath, malformedZip)

	currentEncryptedInfo, err := os.Lstat(encryptedPath)
	if err != nil {
		t.Fatalf("encrypted input disappeared after malformed ZIP failure: %v", err)
	}
	if !os.SameFile(encryptedInfo, currentEncryptedInfo) {
		t.Fatal("encrypted input path was replaced after malformed ZIP failure")
	}
	assertFileBytes(t, encryptedPath, encryptedBytes)

	secondOutput := filepath.Join(tmpDir, "recovered-again")
	if err := Decrypt(context.Background(), &DecryptRequest{
		InputFile:  encryptedPath,
		OutputFile: secondOutput,
		Password:   []byte(password),
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("decrypt unchanged volume without auto-unzip: %v", err)
	}
	assertFileBytes(t, secondOutput, malformedZip)
}

func TestAutoUnzipZipOutputDoesNotLeaveStaleExistingArchive(t *testing.T) {
	tmpDir := t.TempDir()
	plainZip := filepath.Join(tmpDir, "source.zip")
	payload := []byte("real payload replacing a stale decrypted archive")
	createStoredZipEntryForVolumeTest(t, plainZip, "payload.txt", payload)

	encryptedPath := filepath.Join(tmpDir, "source.pcv")
	password := "auto-unzip-existing-zip-output-password"
	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile:  plainZip,
		OutputFile: encryptedPath,
		Password:   []byte(password),
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("encrypt ZIP fixture: %v", err)
	}
	if err := os.Remove(plainZip); err != nil {
		t.Fatalf("remove plaintext ZIP fixture: %v", err)
	}

	outputArchive := filepath.Join(tmpDir, "recovered.zip")
	staleBytes := []byte("stale existing output must not survive successful auto-unzip")
	if err := os.WriteFile(outputArchive, staleBytes, 0o600); err != nil {
		t.Fatalf("write stale output archive: %v", err)
	}
	if err := Decrypt(context.Background(), &DecryptRequest{
		InputFile:  encryptedPath,
		OutputFile: outputArchive,
		Password:   []byte(password),
		AutoUnzip:  true,
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("decrypt over stale archive and auto-unzip: %v", err)
	}

	if _, err := os.Lstat(outputArchive); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful auto-unzip left a stale or decrypted archive: %v", err)
	}
	assertFileBytes(t, filepath.Join(tmpDir, "recovered", "payload.txt"), payload)
	if _, err := os.Lstat(encryptedPath); err != nil {
		t.Fatalf("encrypted input disappeared after successful auto-unzip: %v", err)
	}
}

func TestAutoUnzipZipOutputRejectsLateExtractionRootReplacement(t *testing.T) {
	tmpDir := t.TempDir()
	plainZip := filepath.Join(tmpDir, "source.zip")
	payload := []byte("plaintext must not enter a late replacement root")
	createStoredZipEntryForVolumeTest(t, plainZip, "payload.txt", payload)
	plainZipBytes, err := os.ReadFile(plainZip)
	if err != nil {
		t.Fatalf("read plaintext ZIP fixture: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "source.pcv")
	password := "auto-unzip-late-root-password"
	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile:  plainZip,
		OutputFile: encryptedPath,
		Password:   []byte(password),
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("encrypt ZIP fixture: %v", err)
	}
	if err := os.Remove(plainZip); err != nil {
		t.Fatalf("remove plaintext ZIP fixture: %v", err)
	}
	encryptedInfo, err := os.Lstat(encryptedPath)
	if err != nil {
		t.Fatalf("inspect encrypted input: %v", err)
	}
	encryptedBytes, err := os.ReadFile(encryptedPath)
	if err != nil {
		t.Fatalf("read encrypted input: %v", err)
	}

	outputArchive := filepath.Join(tmpDir, "recovered.zip")
	extractDir := filepath.Join(tmpDir, "recovered")
	movedReservedDir := filepath.Join(tmpDir, "moved-reserved")
	foreignBytes := []byte("foreign replacement root must remain exact")
	reporter := &autoUnzipExtractRootReplaceReporter{
		extractPath: extractDir,
		movedPath:   movedReservedDir,
		foreign:     foreignBytes,
	}
	err = Decrypt(context.Background(), &DecryptRequest{
		InputFile:  encryptedPath,
		OutputFile: outputArchive,
		Password:   []byte(password),
		AutoUnzip:  true,
		Reporter:   reporter,
		RSCodecs:   newRSCodecsT(t),
	})
	if err == nil {
		t.Fatal("Decrypt succeeded after the reserved extraction root was replaced")
	}
	if reporter.err != nil {
		t.Fatalf("replace reserved extraction root: %v", reporter.err)
	}
	if !reporter.replaced {
		t.Fatal("real extraction never reached the late root replacement")
	}
	assertFileBytes(t, filepath.Join(extractDir, "foreign.txt"), foreignBytes)
	if _, err := os.Lstat(filepath.Join(extractDir, "payload.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("plaintext entered the foreign replacement root: %v", err)
	}
	movedEntries, err := os.ReadDir(movedReservedDir)
	if err != nil {
		t.Fatalf("read moved reserved extraction root: %v", err)
	}
	if len(movedEntries) != 0 {
		t.Fatalf("moved reserved extraction root contains plaintext or residue: %v", movedEntries)
	}
	assertFileBytes(t, outputArchive, plainZipBytes)
	requireStoredZipEntryForVolumeTest(t, outputArchive, "payload.txt", payload)

	currentEncryptedInfo, err := os.Lstat(encryptedPath)
	if err != nil {
		t.Fatalf("encrypted input disappeared after rejected root replacement: %v", err)
	}
	if !os.SameFile(encryptedInfo, currentEncryptedInfo) {
		t.Fatal("encrypted input path was replaced after rejected root replacement")
	}
	assertFileBytes(t, encryptedPath, encryptedBytes)
}

// createTestZip creates a zip file from a directory
func createTestZip(zipPath, sourceDir string) error {
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

func createStoredZipEntryForVolumeTest(t *testing.T, zipPath, name string, data []byte) {
	t.Helper()

	file, err := os.OpenFile(zipPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("Create stored ZIP: %v", err)
	}
	writer := zip.NewWriter(file)
	entry, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
	if err != nil {
		_ = writer.Close()
		_ = file.Close()
		t.Fatalf("Create stored ZIP entry: %v", err)
	}
	if _, err := entry.Write(data); err != nil {
		_ = writer.Close()
		_ = file.Close()
		t.Fatalf("Write stored ZIP entry: %v", err)
	}
	if err := writer.Close(); err != nil {
		_ = file.Close()
		t.Fatalf("Close stored ZIP writer: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close stored ZIP: %v", err)
	}
}

func requireStoredZipEntryForVolumeTest(t *testing.T, zipPath, name string, want []byte) {
	t.Helper()

	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("Open preserved ZIP %s: %v", zipPath, err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			t.Errorf("Close preserved ZIP %s: %v", zipPath, err)
		}
	}()
	if len(reader.File) != 1 || reader.File[0].Name != name {
		t.Fatalf("Preserved ZIP entries = %v, want only %q", reader.File, name)
	}
	entry, err := reader.File[0].Open()
	if err != nil {
		t.Fatalf("Open preserved ZIP entry: %v", err)
	}
	got, readErr := io.ReadAll(entry)
	closeErr := entry.Close()
	if readErr != nil {
		t.Fatalf("Read preserved ZIP entry: %v", readErr)
	}
	if closeErr != nil {
		t.Fatalf("Close preserved ZIP entry: %v", closeErr)
	}
	if string(got) != string(want) {
		t.Fatalf("Preserved ZIP entry = %q, want %q", got, want)
	}
}

func TestRoundTripAutoUnzipMultipleFilesFromDifferentDirs(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()
	fileA := filepath.Join(tmpDir, "alpha", "one.txt")
	fileB := filepath.Join(tmpDir, "beta", "two.txt")

	if err := os.MkdirAll(filepath.Dir(fileA), 0o755); err != nil {
		t.Fatalf("Failed to create dir for fileA: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(fileB), 0o755); err != nil {
		t.Fatalf("Failed to create dir for fileB: %v", err)
	}
	if err := os.WriteFile(fileA, []byte("one"), 0o644); err != nil {
		t.Fatalf("Failed to write fileA: %v", err)
	}
	if err := os.WriteFile(fileB, []byte("two"), 0o644); err != nil {
		t.Fatalf("Failed to write fileB: %v", err)
	}

	reporter := &GoldenTestReporter{}
	encryptedPath := filepath.Join(tmpDir, "multi.pcv")
	outputPath := filepath.Join(tmpDir, "multi")

	encReq := &EncryptRequest{
		InputFiles: []string{fileA, fileB},
		OnlyFiles:  []string{fileA, fileB},
		OutputFile: encryptedPath,
		Password:   []byte("pw"),
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}
	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decReq := &DecryptRequest{
		InputFile:  encryptedPath,
		OutputFile: outputPath,
		Password:   []byte("pw"),
		AutoUnzip:  true,
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}
	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(tmpDir, "multi", "alpha", "one.txt")); err != nil {
		t.Fatalf("Missing extracted fileA: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "multi", "beta", "two.txt")); err != nil {
		t.Fatalf("Missing extracted fileB: %v", err)
	}
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

	if err := os.WriteFile(file1Path, file1Content, 0o644); err != nil {
		t.Fatalf("Failed to write file1: %v", err)
	}
	if err := os.WriteFile(file2Path, file2Content, 0o644); err != nil {
		t.Fatalf("Failed to write file2: %v", err)
	}
	if err := os.WriteFile(file3Path, file3Content, 0o644); err != nil {
		t.Fatalf("Failed to write file3: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "multifile.zip.pcv")
	decryptedPath := filepath.Join(tmpDir, "multifile.zip")

	reporter := &GoldenTestReporter{}

	// Encrypt with multiple input files
	encReq := &EncryptRequest{
		InputFiles: []string{file1Path, file2Path, file3Path},
		OutputFile: encryptedPath,
		Password:   []byte("multifile_password"),
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
		Password:     []byte("multifile_password"),
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

// TestRoundTripSingleFileFolderProducesZip is a regression test for issue #130:
// "Zip and Encrypt" of a folder containing a single file must still produce a zip
// archive. The GUI labels a dropped folder "Zip and Encrypt" and names the output
// "<name>.zip.pcv", so decryption must yield a real zip — not the raw inner file.
// Before the fix, a folder with exactly one file (compress off) skipped zipping
// because the decision only looked at file count, so decryption produced a
// ".zip"-named file whose bytes were the raw inner file and which no unzip tool
// (nor Auto unzip) could extract.
func TestRoundTripSingleFileFolderProducesZip(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// A folder ("test_dir") containing exactly one file, mirroring the issue.
	folder := filepath.Join(tmpDir, "test_dir")
	if err := os.MkdirAll(folder, 0o755); err != nil {
		t.Fatalf("Failed to create folder: %v", err)
	}
	innerContent := []byte("hello world\n")
	innerPath := filepath.Join(folder, "hello.txt")
	if err := os.WriteFile(innerPath, innerContent, 0o644); err != nil {
		t.Fatalf("Failed to write inner file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "encrypted.zip.pcv")
	decryptedPath := filepath.Join(tmpDir, "encrypted.zip")

	reporter := &GoldenTestReporter{}

	// Folder selection: one input file, folder recorded in OnlyFolders, compress off.
	encReq := &EncryptRequest{
		InputFiles:  []string{innerPath},
		OnlyFolders: []string{folder},
		OutputFile:  encryptedPath,
		Password:    []byte("pw"),
		Reporter:    reporter,
		RSCodecs:    rsCodecs,
	}
	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt WITHOUT auto-unzip: the on-disk output must itself be a valid zip.
	decReq := &DecryptRequest{
		InputFile:  encryptedPath,
		OutputFile: decryptedPath,
		Password:   []byte("pw"),
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}
	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// The decrypted output must be a real zip archive containing test_dir/hello.txt.
	zr, err := zip.OpenReader(decryptedPath)
	if err != nil {
		t.Fatalf("decrypted output is not a valid zip archive (issue #130): %v", err)
	}
	defer func() { _ = zr.Close() }()

	if len(zr.File) != 1 {
		t.Fatalf("expected 1 zip entry, got %d", len(zr.File))
	}
	entry := zr.File[0]
	if entry.Name != "test_dir/hello.txt" {
		t.Fatalf("expected entry name %q, got %q", "test_dir/hello.txt", entry.Name)
	}

	rc, err := entry.Open()
	if err != nil {
		t.Fatalf("Failed to open zip entry: %v", err)
	}
	got, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatalf("Failed to read zip entry: %v", err)
	}
	if string(got) != string(innerContent) {
		t.Fatalf("zip entry content mismatch: got %q want %q", got, innerContent)
	}
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
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
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
		Password:    []byte("split_rs_password"),
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
		Password:     []byte("split_rs_password"),
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

// TestRoundTripEmptyFile tests encryption/decryption of an empty file
func TestRoundTripEmptyFile(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create empty file
	inputPath := filepath.Join(tmpDir, "empty.txt")
	if err := os.WriteFile(inputPath, []byte{}, 0o644); err != nil {
		t.Fatalf("Failed to write empty file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "empty.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "empty_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   []byte("empty_file_password"),
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
		Password:     []byte("empty_file_password"),
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
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create keyfile
	keyfileContent := []byte("This is keyfile content for split test!")
	keyfilePath := filepath.Join(tmpDir, "split.key")
	if err := os.WriteFile(keyfilePath, keyfileContent, 0o644); err != nil {
		t.Fatalf("Failed to write keyfile: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "split_keyfile_test.bin.pcv")
	decryptedPath := filepath.Join(tmpDir, "split_keyfile_decrypted.bin")

	reporter := &GoldenTestReporter{}

	// Encrypt with split + keyfile
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   []byte("split_keyfile_password"),
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
		Password:     []byte("split_keyfile_password"),
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

// TestForceDecryptCorruptedData proves the ForceDecrypt contract over a corrupted
// payload: without ForceDecrypt a MAC failure is rejected with no output; with it,
// the operation forces through, keeps a best-effort output file, and flags it kept.
func TestForceDecryptCorruptedData(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Reed-Solomon OFF so a single ciphertext-byte flip reliably defeats the MAC
	// (RS correction is covered by TestVerifyFirstCorrectableRS); a multi-KiB payload
	// keeps the flip mid-ciphertext, away from the header and the trailing MAC.
	plaintext := []byte(strings.Repeat("force-decrypt corruption payload. ", 64))
	inputPath := filepath.Join(tmpDir, "corrupt_test.txt")
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}
	encryptedPath := filepath.Join(tmpDir, "corrupt_test.txt.pcv")
	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    []byte("corrupt_test_password"),
		ReedSolomon: false,
		Reporter:    &GoldenTestReporter{},
		RSCodecs:    rsCodecs,
	}); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Flip one ciphertext byte in the middle of the payload.
	data, err := os.ReadFile(encryptedPath)
	if err != nil {
		t.Fatalf("read encrypted: %v", err)
	}
	data[len(data)/2] ^= 0xFF
	if err := os.WriteFile(encryptedPath, data, 0o644); err != nil {
		t.Fatalf("write corrupted: %v", err)
	}

	// Without ForceDecrypt: the MAC failure must be rejected, leaving no output.
	rejectedPath := filepath.Join(tmpDir, "rejected.txt")
	if err := Decrypt(context.Background(), &DecryptRequest{
		InputFile:  encryptedPath,
		OutputFile: rejectedPath,
		Password:   []byte("corrupt_test_password"),
		Reporter:   &GoldenTestReporter{},
		RSCodecs:   rsCodecs,
	}); err == nil {
		t.Fatal("decrypt of corrupted data without ForceDecrypt must fail")
	}
	if _, statErr := os.Stat(rejectedPath); !os.IsNotExist(statErr) {
		t.Error("rejected decrypt must not leave an output file")
	}

	// With ForceDecrypt: forces through the MAC failure, keeps a best-effort output
	// file, and flags it as kept (input not authentic).
	var kept bool
	keptPath := filepath.Join(tmpDir, "kept.txt")
	if err := Decrypt(context.Background(), &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   keptPath,
		Password:     []byte("corrupt_test_password"),
		ForceDecrypt: true,
		Kept:         &kept,
		Reporter:     &GoldenTestReporter{},
		RSCodecs:     rsCodecs,
	}); err != nil {
		t.Fatalf("ForceDecrypt over corrupted data must succeed, got: %v", err)
	}
	if !kept {
		t.Error("ForceDecrypt over a MAC failure must set kept=true")
	}
	if _, statErr := os.Stat(keptPath); statErr != nil {
		t.Errorf("ForceDecrypt must produce a best-effort output file: %v", statErr)
	}
}

// TestRoundTripCompressedMultiFile tests encrypting multiple files with compression
func TestRoundTripCompressedMultiFile(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create multiple test files. Make them large and highly repetitive so the
	// compressed+encrypted volume is reliably smaller than the raw input even after
	// zip-per-entry and encryption overhead (a tight margin would make the size
	// assertion flaky). Each compresses to a tiny fraction of its size.
	file1Content := []byte(strings.Repeat("Compressible content: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n", 2000))
	file2Content := []byte(strings.Repeat("More compressible: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n", 2000))

	file1Path := filepath.Join(tmpDir, "compress1.txt")
	file2Path := filepath.Join(tmpDir, "compress2.txt")

	if err := os.WriteFile(file1Path, file1Content, 0o644); err != nil {
		t.Fatalf("Failed to write file1: %v", err)
	}
	if err := os.WriteFile(file2Path, file2Content, 0o644); err != nil {
		t.Fatalf("Failed to write file2: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "compressed.zip.pcv")
	decryptedPath := filepath.Join(tmpDir, "compressed.zip")

	reporter := &GoldenTestReporter{}

	// Encrypt with multiple input files and compression
	encReq := &EncryptRequest{
		InputFiles: []string{file1Path, file2Path},
		OutputFile: encryptedPath,
		Password:   []byte("compress_multifile_password"),
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
		Password:     []byte("compress_multifile_password"),
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

	// Compression must shrink the volume below the combined raw input size; if the
	// Compress flag were ignored, the stored zip would exceed the inputs.
	encryptedInfo, err := os.Stat(encryptedPath)
	if err != nil {
		t.Fatalf("Failed to stat encrypted file: %v", err)
	}
	totalRaw := int64(len(file1Content) + len(file2Content))
	if encryptedInfo.Size() >= totalRaw {
		t.Errorf("compressed volume size = %d bytes, want < total raw input %d (Compress flag ignored?)",
			encryptedInfo.Size(), totalRaw)
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
	if err := os.WriteFile(filePath, fileContent, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "compressible_single.txt.zip.pcv")
	decryptedPath := filepath.Join(tmpDir, "compressible_single.txt.zip")

	reporter := &GoldenTestReporter{}

	// Encrypt single file with compression enabled
	encReq := &EncryptRequest{
		InputFiles: []string{filePath},
		OutputFile: encryptedPath,
		Password:   []byte("compress_single_password"),
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
		Password:     []byte("compress_single_password"),
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

	// Compression must actually shrink the volume: the input is highly repetitive,
	// so the compressed+encrypted output must be smaller than the raw plaintext even
	// after zip/header/encryption overhead. If the Compress flag were ignored, the
	// stored zip would be at least as large as the plaintext and this would fail.
	encryptedInfo, err := os.Stat(encryptedPath)
	if err != nil {
		t.Fatalf("Failed to stat encrypted file: %v", err)
	}
	if encryptedInfo.Size() >= int64(len(fileContent)) {
		t.Errorf("compressed volume size = %d bytes, want < plaintext size %d (Compress flag ignored?)",
			encryptedInfo.Size(), len(fileContent))
	}

	t.Log("Round-trip compressed single file: SUCCESS")
}

func TestRoundTripCompressedSingleFileViaInputFileField(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	filePath := filepath.Join(tmpDir, "compressible_inputfile.txt")
	content := []byte(strings.Repeat("This compresses well. ", 100))
	if err := os.WriteFile(filePath, content, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "compressible_inputfile.txt.zip.pcv")
	decryptedPath := filepath.Join(tmpDir, "compressible_inputfile.txt.zip")

	reporter := &GoldenTestReporter{}

	encReq := &EncryptRequest{
		InputFile:  filePath,
		OutputFile: encryptedPath,
		Password:   []byte("compress_inputfile_password"),
		Compress:   true,
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (compressed inputfile) failed: %v", err)
	}

	_ = os.Remove(filePath)

	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     []byte("compress_inputfile_password"),
		AutoUnzip:    true,
		SameLevel:    true,
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (compressed inputfile) failed: %v", err)
	}

	if _, err := os.Stat(filePath); err != nil {
		t.Fatalf("Expected restored file at %s: %v", filePath, err)
	}
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
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "tamper_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "tamper_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt (creates v2 volume) - use empty comments for simpler header layout
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   []byte("tamper_test_password"),
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
	for i := range 20 { // Corrupt 20 bytes - exceeds RS16 correction capacity
		if saltStart+i < len(data) {
			data[saltStart+i] ^= 0xFF
		}
	}

	// Write tampered file
	tamperedPath := filepath.Join(tmpDir, "tampered.txt.pcv")
	if err := os.WriteFile(tamperedPath, data, 0o644); err != nil {
		t.Fatalf("Failed to write tampered file: %v", err)
	}

	// Without ForceDecrypt, the over-budget RS16 corruption is rejected as a
	// damaged header before key derivation.
	decReq := &DecryptRequest{
		InputFile:    tamperedPath,
		OutputFile:   decryptedPath,
		Password:     []byte("tamper_test_password"),
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	err = Decrypt(context.Background(), decReq)
	if !errors.Is(err, header.ErrCorruptedHeader) {
		t.Fatalf("Decrypt error = %v; want ErrCorruptedHeader", err)
	}

	t.Logf("Header tamper correctly detected: %v", err)

	// Now test with ForceDecrypt - should proceed but may fail
	var kept bool
	decReqForce := &DecryptRequest{
		InputFile:    tamperedPath,
		OutputFile:   decryptedPath + ".forced",
		Password:     []byte("tamper_test_password"),
		ForceDecrypt: true,
		Kept:         &kept,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	err = Decrypt(context.Background(), decReqForce)
	// Documented ForceDecrypt behavior: salt corruption yields a wrong Argon2 key,
	// so BOTH the header MAC and the payload MAC mismatch — but ForceDecrypt bypasses
	// those gates (decrypt.go:323) and finalizes the volume anyway (decrypt.go:816),
	// marking it Kept and producing an output file. Assert that observable outcome so
	// this half can fail (e.g. if ForceDecrypt silently aborted or stopped setting
	// Kept) rather than passing for either result.
	if err != nil {
		t.Fatalf("ForceDecrypt should proceed past the damaged header, got error: %v", err)
	}
	if !kept {
		t.Fatal("ForceDecrypt finalized a MAC-mismatched volume but did not set Kept=true")
	}
	forcedOutput := decryptedPath + ".forced"
	info, statErr := os.Stat(forcedOutput)
	if statErr != nil {
		t.Fatalf("ForceDecrypt did not produce an output file at %s: %v", forcedOutput, statErr)
	}
	if info.Size() == 0 {
		t.Fatalf("ForceDecrypt produced an empty output file at %s", forcedOutput)
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
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create two keyfiles with different content
	keyfile1Path := filepath.Join(tmpDir, "keyfile1.bin")
	keyfile2Path := filepath.Join(tmpDir, "keyfile2.bin")

	if err := os.WriteFile(keyfile1Path, []byte("keyfile1_unique_content_AAAA"), 0o644); err != nil {
		t.Fatalf("Failed to write keyfile1: %v", err)
	}
	if err := os.WriteFile(keyfile2Path, []byte("keyfile2_unique_content_BBBB"), 0o644); err != nil {
		t.Fatalf("Failed to write keyfile2: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "ordered_kf_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "ordered_kf_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with keyfiles in order [keyfile1, keyfile2], ordered=true
	encReq := &EncryptRequest{
		InputFile:      inputPath,
		OutputFile:     encryptedPath,
		Password:       []byte("ordered_keyfile_password"),
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
		Password:     []byte("ordered_keyfile_password"),
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
		Password:     []byte("ordered_keyfile_password"),
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
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "zero_comments.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "zero_comments_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with explicitly empty comments
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   []byte("zero_comments_password"),
		Comments:   "", // Explicitly empty
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt with zero-length comments failed: %v", err)
	}

	// An empty Comments request must store zero comment bytes in the header; any
	// spurious comment bytes would be a regression.
	h := readVolumeHeader(t, encryptedPath)
	if len(h.Comments) != 0 {
		t.Errorf("header Comments length = %d, want 0; got %q", len(h.Comments), h.Comments)
	}

	// Decrypt
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     []byte("zero_comments_password"),
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
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create keyfile
	keyfilePath := filepath.Join(tmpDir, "keyfile_only.bin")
	keyfileData := []byte("This keyfile is the ONLY credential needed!")
	if err := os.WriteFile(keyfilePath, keyfileData, 0o644); err != nil {
		t.Fatalf("Failed to write keyfile: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "keyfile_only_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "keyfile_only_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with keyfile only - empty password
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   []byte(""), // Empty password - keyfile only!
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
		Password:     []byte(""), // Empty password
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
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	keyfilePath := filepath.Join(tmpDir, "kf_paranoid.key")
	if err := os.WriteFile(keyfilePath, []byte("paranoid_keyfile_content"), 0o644); err != nil {
		t.Fatalf("Failed to write keyfile: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "kf_paranoid.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "kf_paranoid_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt keyfile-only + paranoid
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   []byte(""),
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
		Password:   []byte(""),
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
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	keyfilePath := filepath.Join(tmpDir, "deny_kf_only.key")
	if err := os.WriteFile(keyfilePath, []byte("deniability_keyfile_content"), 0o644); err != nil {
		t.Fatalf("Failed to write keyfile: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "deny_kf_only.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "deny_kf_only_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with deniability + keyfile-only
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    []byte(""), // Empty password
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
		Password:    []byte(""), // Empty password for deniability wrapper
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
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	keyfilePath := filepath.Join(tmpDir, "deny_pw_kf.key")
	if err := os.WriteFile(keyfilePath, []byte("combined_keyfile_content"), 0o644); err != nil {
		t.Fatalf("Failed to write keyfile: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "deny_pw_kf.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "deny_pw_kf_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with deniability + password + keyfile
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    []byte("deniability_password"),
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
		Password:    []byte("deniability_password"),
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
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	keyfilePath := filepath.Join(tmpDir, "wrong_pw_kf.key")
	if err := os.WriteFile(keyfilePath, []byte("correct_keyfile_content"), 0o644); err != nil {
		t.Fatalf("Failed to write keyfile: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "wrong_pw_kf.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "wrong_pw_kf_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with password + keyfile
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   []byte("correct_password"),
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
		Password:     []byte("wrong_password"), // Wrong!
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
		Password:     []byte("correct_password"),
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
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	correctKeyfile := filepath.Join(tmpDir, "correct.key")
	wrongKeyfile := filepath.Join(tmpDir, "wrong.key")
	if err := os.WriteFile(correctKeyfile, []byte("correct_key_content"), 0o644); err != nil {
		t.Fatalf("Failed to write correct keyfile: %v", err)
	}
	if err := os.WriteFile(wrongKeyfile, []byte("wrong_key_content"), 0o644); err != nil {
		t.Fatalf("Failed to write wrong keyfile: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "kf_only_wrong.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "kf_only_wrong_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with keyfile only
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   []byte(""),
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
		Password:     []byte(""),
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
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "deny_wrong_pw.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "deny_wrong_pw_dec.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with deniability
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    []byte("correct_deniability_password"),
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
		Password:     []byte("wrong_deniability_password"),
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
	if err := os.WriteFile(inputPath, plaintext, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create one keyfile
	keyfilePath := filepath.Join(tmpDir, "keyfile.bin")
	if err := os.WriteFile(keyfilePath, []byte("keyfile_content_123456789"), 0o644); err != nil {
		t.Fatalf("Failed to write keyfile: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "dup_kf_test.txt.pcv")

	reporter := &GoldenTestReporter{}

	// Attempt to encrypt with the same keyfile twice (unordered - will XOR to zero)
	encReq := &EncryptRequest{
		InputFile:      inputPath,
		OutputFile:     encryptedPath,
		Password:       []byte("duplicate_keyfile_password"),
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
