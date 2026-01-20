package volume

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"Picocrypt-NG/internal/encoding"
)

// GoldenTestReporter is a minimal reporter for testing
type GoldenTestReporter struct {
	status    string
	cancelled bool
}

func (r *GoldenTestReporter) SetStatus(text string) {
	r.status = text
}

func (r *GoldenTestReporter) SetProgress(fraction float32, info string) {}

func (r *GoldenTestReporter) SetCanCancel(can bool) {}

func (r *GoldenTestReporter) Update() {}

func (r *GoldenTestReporter) IsCancelled() bool {
	return r.cancelled
}

// Test password for all golden files
const goldenPassword = "test"

// Expected plaintext content
const expectedContent = "There is a test file for Picocrypt validation.\n"

// Golden test corpus paths (relative to testdata/golden/)
var goldenTestCases = []struct {
	name        string
	file        string
	deniability bool
	paranoid    bool
	reedSolomon bool
}{
	{
		name:        "v1_basic",
		file:        "pico_test_v1.txt.pcv",
		deniability: false,
		paranoid:    false,
		reedSolomon: false,
	},
	{
		name:        "v2_basic",
		file:        "pico_test_v2.txt.pcv",
		deniability: false,
		paranoid:    false,
		reedSolomon: false,
	},
	{
		name:        "v1_deny_paranoid_rs",
		file:        "pico_test_v1_deny_paranoid_rs.txt.pcv",
		deniability: true,
		paranoid:    true,
		reedSolomon: true,
	},
	{
		name:        "v2_deny_paranoid_rs",
		file:        "pico_test_v2_deny_paranoid_rs.txt.pcv",
		deniability: true,
		paranoid:    true,
		reedSolomon: true,
	},
}

// Golden test corpus for compressed (zip) files
var goldenCompressedTestCases = []struct {
	name        string
	file        string
	deniability bool
	paranoid    bool
	reedSolomon bool
}{
	{
		name:        "v1_compress",
		file:        "pico_test_v1_compress.zip.pcv",
		deniability: false,
		paranoid:    false,
		reedSolomon: false,
	},
	{
		name:        "v2_compress",
		file:        "pico_test_v2_compress.zip.pcv",
		deniability: false,
		paranoid:    false,
		reedSolomon: false,
	},
	{
		name:        "v1_deny_paranoid_rs_compress",
		file:        "pico_test_v1_deny_paranoid_rs_compress.zip.pcv",
		deniability: true,
		paranoid:    true,
		reedSolomon: true,
	},
	{
		name:        "v2_deny_paranoid_rs_compress",
		file:        "pico_test_v2_deny_paranoid_rs_compress.zip.pcv",
		deniability: true,
		paranoid:    true,
		reedSolomon: true,
	},
}

func TestGoldenDecryption(t *testing.T) {
	// Find the testdata directory
	testdataPath := findTestdata(t)

	// Initialize RS codecs
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	for _, tc := range goldenTestCases {
		t.Run(tc.name, func(t *testing.T) {
			inputPath := filepath.Join(testdataPath, tc.file)

			// Skip if file doesn't exist
			if _, err := os.Stat(inputPath); os.IsNotExist(err) {
				t.Skipf("Golden file not found: %s", inputPath)
			}

			// Create temp output file
			tmpDir := t.TempDir()
			outputPath := filepath.Join(tmpDir, "decrypted.txt")

			// Copy input file to temp (to avoid modifying original during deniability removal)
			workingPath := inputPath
			if tc.deniability {
				workingPath = filepath.Join(tmpDir, tc.file)
				copyFile(t, inputPath, workingPath)
			}

			reporter := &GoldenTestReporter{}

			req := &DecryptRequest{
				InputFile:    workingPath,
				OutputFile:   outputPath,
				Password:     goldenPassword,
				ForceDecrypt: false,
				AutoUnzip:    false,
				SameLevel:    false,
				Recombine:    false,
				Deniability:  tc.deniability,
				Reporter:     reporter,
				RSCodecs:     rsCodecs,
			}

			err := Decrypt(context.Background(), req)
			if err != nil {
				t.Fatalf("Decrypt failed: %v (status: %s)", err, reporter.status)
			}

			// Verify output exists
			if _, err := os.Stat(outputPath); os.IsNotExist(err) {
				t.Fatal("Output file was not created")
			}

			// Read and verify content
			content, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatalf("Failed to read output: %v", err)
			}

			if string(content) != expectedContent {
				t.Errorf("Content mismatch.\nExpected: %q\nGot: %q", expectedContent, string(content))
			}

			t.Logf("Successfully decrypted %s", tc.file)
		})
	}
}

// TestGoldenCompressedDecryption tests decrypting compressed (zip) golden files
func TestGoldenCompressedDecryption(t *testing.T) {
	testdataPath := findTestdata(t)

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	for _, tc := range goldenCompressedTestCases {
		t.Run(tc.name, func(t *testing.T) {
			inputPath := filepath.Join(testdataPath, tc.file)

			// Skip if file doesn't exist
			if _, err := os.Stat(inputPath); os.IsNotExist(err) {
				t.Skipf("Golden file not found: %s", inputPath)
			}

			tmpDir := t.TempDir()
			outputPath := filepath.Join(tmpDir, strings.TrimSuffix(tc.file, ".pcv"))

			// Copy input file to temp (to avoid modifying original during deniability removal)
			workingPath := inputPath
			if tc.deniability {
				workingPath = filepath.Join(tmpDir, tc.file)
				copyFile(t, inputPath, workingPath)
			}

			reporter := &GoldenTestReporter{}

			req := &DecryptRequest{
				InputFile:    workingPath,
				OutputFile:   outputPath,
				Password:     goldenPassword,
				ForceDecrypt: false,
				AutoUnzip:    false, // Don't auto-unzip, we'll verify the zip content manually
				SameLevel:    false,
				Recombine:    false,
				Deniability:  tc.deniability,
				Reporter:     reporter,
				RSCodecs:     rsCodecs,
			}

			err := Decrypt(context.Background(), req)
			if err != nil {
				t.Fatalf("Decrypt failed: %v (status: %s)", err, reporter.status)
			}

			// Verify output exists
			if _, err := os.Stat(outputPath); os.IsNotExist(err) {
				t.Fatal("Output file was not created")
			}

			// Verify it's a valid zip file and check contents
			zipReader, err := zip.OpenReader(outputPath)
			if err != nil {
				t.Fatalf("Failed to open zip: %v", err)
			}
			defer func() { _ = zipReader.Close() }()

			// Find and verify the test file inside the zip
			found := false
			for _, f := range zipReader.File {
				// Look for pico_test.txt inside the zip (might be in a folder)
				if strings.HasSuffix(f.Name, "pico_test.txt") {
					found = true
					rc, err := f.Open()
					if err != nil {
						t.Fatalf("Failed to open file in zip: %v", err)
					}
					content, err := io.ReadAll(rc)
					_ = rc.Close()
					if err != nil {
						t.Fatalf("Failed to read file in zip: %v", err)
					}

					if string(content) != expectedContent {
						t.Errorf("Content mismatch in zip.\nExpected: %q\nGot: %q", expectedContent, string(content))
					}
					break
				}
			}

			if !found {
				// List what's in the zip for debugging
				t.Log("Files in zip:")
				for _, f := range zipReader.File {
					t.Logf("  - %s", f.Name)
				}
				t.Error("pico_test.txt not found in zip")
			}

			t.Logf("Successfully decrypted and verified %s", tc.file)
		})
	}
}

func TestGoldenV1Detection(t *testing.T) {
	testdataPath := findTestdata(t)

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	// Test v1 file detection
	v1Path := filepath.Join(testdataPath, "pico_test_v1.txt.pcv")
	if _, err := os.Stat(v1Path); os.IsNotExist(err) {
		t.Skip("v1 golden file not found")
	}

	fin, err := os.Open(v1Path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fin.Close() }()

	// Read version
	versionEnc := make([]byte, 15)
	_, _ = fin.Read(versionEnc)

	versionDec, err := encoding.Decode(rsCodecs.RS5, versionEnc, false)
	if err != nil {
		t.Fatalf("Failed to decode version: %v", err)
	}

	version := string(versionDec)
	t.Logf("V1 file version: %s", version)

	if version[0:2] != "v1" {
		t.Errorf("Expected v1.x version, got: %s", version)
	}
}

func TestGoldenV2Detection(t *testing.T) {
	testdataPath := findTestdata(t)

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	// Test v2 file detection
	v2Path := filepath.Join(testdataPath, "pico_test_v2.txt.pcv")
	if _, err := os.Stat(v2Path); os.IsNotExist(err) {
		t.Skip("v2 golden file not found")
	}

	fin, err := os.Open(v2Path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fin.Close() }()

	// Read version
	versionEnc := make([]byte, 15)
	_, _ = fin.Read(versionEnc)

	versionDec, err := encoding.Decode(rsCodecs.RS5, versionEnc, false)
	if err != nil {
		t.Fatalf("Failed to decode version: %v", err)
	}

	version := string(versionDec)
	t.Logf("V2 file version: %s", version)

	if version[0:2] != "v2" {
		t.Errorf("Expected v2.x version, got: %s", version)
	}
}

func TestGoldenDeniabilityDetection(t *testing.T) {
	testdataPath := findTestdata(t)

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	testCases := []struct {
		file             string
		shouldBeDeniable bool
	}{
		{"pico_test_v1.txt.pcv", false},
		{"pico_test_v2.txt.pcv", false},
		{"pico_test_v1_deny_paranoid_rs.txt.pcv", true},
		{"pico_test_v2_deny_paranoid_rs.txt.pcv", true},
		// Compressed variants
		{"pico_test_v1_compress.zip.pcv", false},
		{"pico_test_v2_compress.zip.pcv", false},
		{"pico_test_v1_deny_paranoid_rs_compress.zip.pcv", true},
		{"pico_test_v2_deny_paranoid_rs_compress.zip.pcv", true},
	}

	for _, tc := range testCases {
		t.Run(tc.file, func(t *testing.T) {
			path := filepath.Join(testdataPath, tc.file)
			if _, err := os.Stat(path); os.IsNotExist(err) {
				t.Skipf("File not found: %s", path)
			}

			isDeniable := IsDeniable(path, rsCodecs)
			if isDeniable != tc.shouldBeDeniable {
				t.Errorf("IsDeniable(%s) = %v, want %v", tc.file, isDeniable, tc.shouldBeDeniable)
			}
		})
	}
}

func TestGoldenWrongPassword(t *testing.T) {
	testdataPath := findTestdata(t)

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	v2Path := filepath.Join(testdataPath, "pico_test_v2.txt.pcv")
	if _, err := os.Stat(v2Path); os.IsNotExist(err) {
		t.Skip("v2 golden file not found")
	}

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "decrypted.txt")

	req := &DecryptRequest{
		InputFile:    v2Path,
		OutputFile:   outputPath,
		Password:     "wrong_password",
		ForceDecrypt: false,
		AutoUnzip:    false,
		SameLevel:    false,
		Recombine:    false,
		Deniability:  false,
		Reporter:     &GoldenTestReporter{},
		RSCodecs:     rsCodecs,
	}

	err = Decrypt(context.Background(), req)
	if err == nil {
		t.Error("Decrypt should have failed with wrong password")
	} else {
		t.Logf("Expected error: %v", err)
	}

	// Output should not exist
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Error("Output file should not exist after failed decryption")
	}
}

func TestGoldenV1WrongPassword(t *testing.T) {
	testdataPath := findTestdata(t)

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	v1Path := filepath.Join(testdataPath, "pico_test_v1.txt.pcv")
	if _, err := os.Stat(v1Path); os.IsNotExist(err) {
		t.Skip("v1 golden file not found")
	}

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "decrypted.txt")

	req := &DecryptRequest{
		InputFile:    v1Path,
		OutputFile:   outputPath,
		Password:     "wrong_password",
		ForceDecrypt: false,
		AutoUnzip:    false,
		SameLevel:    false,
		Recombine:    false,
		Deniability:  false,
		Reporter:     &GoldenTestReporter{},
		RSCodecs:     rsCodecs,
	}

	err = Decrypt(context.Background(), req)
	if err == nil {
		t.Error("Decrypt should have failed with wrong password")
	} else {
		t.Logf("Expected error: %v", err)
	}
}

func TestGoldenHeaderParsing(t *testing.T) {
	testdataPath := findTestdata(t)

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	testFiles := []string{
		"pico_test_v1.txt.pcv",
		"pico_test_v2.txt.pcv",
	}

	for _, file := range testFiles {
		t.Run(file, func(t *testing.T) {
			path := filepath.Join(testdataPath, file)
			if _, err := os.Stat(path); os.IsNotExist(err) {
				t.Skipf("File not found: %s", path)
			}

			fin, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = fin.Close() }()

			reader := NewHeaderReaderForTest(fin, rsCodecs)
			result, err := reader.ReadHeader()
			if err != nil {
				t.Fatalf("Failed to read header: %v", err)
			}

			h := result.Header
			t.Logf("Version: %s", h.Version)
			t.Logf("Comments: %s", h.Comments)
			t.Logf("Flags: Paranoid=%v UseKeyfiles=%v KeyfileOrdered=%v ReedSolomon=%v Padded=%v",
				h.Flags.Paranoid, h.Flags.UseKeyfiles, h.Flags.KeyfileOrdered, h.Flags.ReedSolomon, h.Flags.Padded)
			t.Logf("Salt: %x", h.Salt)
			t.Logf("HKDFSalt: %x", h.HKDFSalt)
			t.Logf("SerpentIV: %x", h.SerpentIV)
			t.Logf("Nonce: %x", h.Nonce)
			t.Logf("KeyHash (first 16): %x", h.KeyHash[:16])
			t.Logf("KeyfileHash: %x", h.KeyfileHash)
			t.Logf("AuthTag (first 16): %x", h.AuthTag[:16])

			if result.DecodeError != nil {
				t.Logf("Decode error (header might still be usable): %v", result.DecodeError)
			}
		})
	}
}

// Helper functions

func findTestdata(t *testing.T) string {
	// Try various relative paths from test location
	candidates := []string{
		"../../testdata/golden",
		"../testdata/golden",
		"testdata/golden",
		"src/testdata/golden",
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			absPath, _ := filepath.Abs(c)
			return absPath
		}
	}

	// Try from workspace root
	if wd, err := os.Getwd(); err == nil {
		for _, c := range candidates {
			path := filepath.Join(wd, c)
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	}

	t.Fatal("Could not find testdata/golden directory")
	return ""
}

func copyFile(t *testing.T, src, dst string) {
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("Failed to read source file: %v", err)
	}
	if err := os.WriteFile(dst, data, 0644); err != nil {
		t.Fatalf("Failed to write destination file: %v", err)
	}
}

// NewHeaderReaderForTest creates a header reader for testing
// This is a workaround to access header.Reader from the volume package
func NewHeaderReaderForTest(r *os.File, rs *encoding.RSCodecs) *headerReaderWrapper {
	return &headerReaderWrapper{r: r, rs: rs}
}

type headerReaderWrapper struct {
	r  *os.File
	rs *encoding.RSCodecs
}

type headerReadResult struct {
	Header      *volumeHeader
	DecodeError error
}

type volumeHeader struct {
	Version     string
	Comments    string
	Flags       volumeFlags
	Salt        []byte
	HKDFSalt    []byte
	SerpentIV   []byte
	Nonce       []byte
	KeyHash     []byte
	KeyfileHash []byte
	AuthTag     []byte
}

type volumeFlags struct {
	Paranoid       bool
	UseKeyfiles    bool
	KeyfileOrdered bool
	ReedSolomon    bool
	Padded         bool
}

func (r *headerReaderWrapper) ReadHeader() (*headerReadResult, error) {
	result := &headerReadResult{
		Header: &volumeHeader{},
	}
	h := result.Header
	var decodeErrors []error

	// Read version (15 bytes -> 5 bytes)
	versionEnc := make([]byte, 15)
	if _, err := r.r.Read(versionEnc); err != nil {
		return nil, err
	}
	versionDec, err := encoding.Decode(r.rs.RS5, versionEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
	}
	h.Version = string(versionDec)

	// Read comment length (15 bytes -> 5 bytes)
	commentLenEnc := make([]byte, 15)
	if _, err := r.r.Read(commentLenEnc); err != nil {
		return nil, err
	}
	commentLenDec, err := encoding.Decode(r.rs.RS5, commentLenEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
	}

	var commentsLen int
	for _, b := range commentLenDec {
		if b >= '0' && b <= '9' {
			commentsLen = commentsLen*10 + int(b-'0')
		}
	}

	// Read comments
	comments := make([]byte, 0, commentsLen)
	for i := 0; i < commentsLen; i++ {
		cEnc := make([]byte, 3)
		if _, err := r.r.Read(cEnc); err != nil {
			return nil, fmt.Errorf("read comment byte %d: %w", i, err)
		}
		cDec, err := encoding.Decode(r.rs.RS1, cEnc, false)
		if err != nil {
			decodeErrors = append(decodeErrors, err)
		}
		comments = append(comments, cDec...)
	}
	h.Comments = string(comments)

	// Read flags (15 bytes -> 5 bytes)
	flagsEnc := make([]byte, 15)
	if _, err := r.r.Read(flagsEnc); err != nil {
		return nil, fmt.Errorf("read flags: %w", err)
	}
	flagsDec, err := encoding.Decode(r.rs.RS5, flagsEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
	}
	if len(flagsDec) >= 5 {
		h.Flags.Paranoid = flagsDec[0] == 1
		h.Flags.UseKeyfiles = flagsDec[1] == 1
		h.Flags.KeyfileOrdered = flagsDec[2] == 1
		h.Flags.ReedSolomon = flagsDec[3] == 1
		h.Flags.Padded = flagsDec[4] == 1
	}

	// Read salt (48 bytes -> 16 bytes)
	saltEnc := make([]byte, 48)
	if _, err := r.r.Read(saltEnc); err != nil {
		return nil, fmt.Errorf("read salt: %w", err)
	}
	h.Salt, err = encoding.Decode(r.rs.RS16, saltEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
	}

	// Read HKDF salt (96 bytes -> 32 bytes)
	hkdfSaltEnc := make([]byte, 96)
	if _, err := r.r.Read(hkdfSaltEnc); err != nil {
		return nil, fmt.Errorf("read hkdf salt: %w", err)
	}
	h.HKDFSalt, err = encoding.Decode(r.rs.RS32, hkdfSaltEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
	}

	// Read Serpent IV (48 bytes -> 16 bytes)
	serpentIVEnc := make([]byte, 48)
	if _, err := r.r.Read(serpentIVEnc); err != nil {
		return nil, fmt.Errorf("read serpent iv: %w", err)
	}
	h.SerpentIV, err = encoding.Decode(r.rs.RS16, serpentIVEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
	}

	// Read nonce (72 bytes -> 24 bytes)
	nonceEnc := make([]byte, 72)
	if _, err := r.r.Read(nonceEnc); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	h.Nonce, err = encoding.Decode(r.rs.RS24, nonceEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
	}

	// Read key hash (192 bytes -> 64 bytes)
	keyHashEnc := make([]byte, 192)
	if _, err := r.r.Read(keyHashEnc); err != nil {
		return nil, fmt.Errorf("read key hash: %w", err)
	}
	h.KeyHash, err = encoding.Decode(r.rs.RS64, keyHashEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
	}

	// Read keyfile hash (96 bytes -> 32 bytes)
	keyfileHashEnc := make([]byte, 96)
	if _, err := r.r.Read(keyfileHashEnc); err != nil {
		return nil, fmt.Errorf("read keyfile hash: %w", err)
	}
	h.KeyfileHash, err = encoding.Decode(r.rs.RS32, keyfileHashEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
	}

	// Read auth tag (192 bytes -> 64 bytes)
	authTagEnc := make([]byte, 192)
	if _, err := r.r.Read(authTagEnc); err != nil {
		return nil, fmt.Errorf("read auth tag: %w", err)
	}
	h.AuthTag, err = encoding.Decode(r.rs.RS64, authTagEnc, false)
	if err != nil {
		decodeErrors = append(decodeErrors, err)
	}

	// Set combined decode error if any occurred
	if len(decodeErrors) > 0 {
		result.DecodeError = decodeErrors[0] // Report first error
	}

	return result, nil
}
