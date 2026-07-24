package fileops

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTempZipCiphersClose(t *testing.T) {
	ciphers, err := NewTempZipCiphers()
	if err != nil {
		t.Fatalf("NewTempZipCiphers() failed: %v", err)
	}

	// Save references to the backing arrays before Close() to verify zeroing
	keyRef := ciphers.key.Bytes()
	nonceRef := ciphers.nonce.Bytes()

	ciphers.Close()

	// Key and nonce should be zeroed
	for i, b := range keyRef {
		if b != 0 {
			t.Errorf("Key byte %d = %d; want 0 after Close()", i, b)
			break
		}
	}
	for i, b := range nonceRef {
		if b != 0 {
			t.Errorf("Nonce byte %d = %d; want 0 after Close()", i, b)
			break
		}
	}

	// Ciphers should be nil
	if ciphers.Writer != nil {
		t.Error("Writer should be nil after Close()")
	}
	if ciphers.Reader != nil {
		t.Error("Reader should be nil after Close()")
	}
	if ciphers.key != nil {
		t.Error("key Secret should be nil after Close()")
	}
	if ciphers.nonce != nil {
		t.Error("nonce Secret should be nil after Close()")
	}
}

func TestTempZipCiphersCloseNil(t *testing.T) {
	// Close on nil should not panic
	var ciphers *TempZipCiphers
	ciphers.Close()
}

func TestTempZipCiphersEncryptDecrypt(t *testing.T) {
	ciphers, err := NewTempZipCiphers()
	if err != nil {
		t.Fatalf("NewTempZipCiphers() failed: %v", err)
	}
	defer ciphers.Close()

	// Create a buffer to simulate a file
	var buf bytes.Buffer

	// Encrypt some data using the Writer cipher
	plaintext := []byte("Hello, World! This is test data for encryption.")
	ew := &encryptedWriter{w: &buf, cipher: ciphers.Writer}
	n, err := ew.Write(plaintext)
	if err != nil {
		t.Fatalf("encryptedWriter.Write() failed: %v", err)
	}
	if n != len(plaintext) {
		t.Errorf("Write returned %d; want %d", n, len(plaintext))
	}

	// The encrypted data should be different from plaintext
	encrypted := buf.Bytes()
	if bytes.Equal(encrypted, plaintext) {
		t.Error("Encrypted data should be different from plaintext")
	}

	// Decrypt using the Reader cipher
	er := &encryptedReader{r: bytes.NewReader(encrypted), cipher: ciphers.Reader}
	decrypted := make([]byte, len(encrypted))
	n, err = er.Read(decrypted)
	if err != nil {
		t.Fatalf("encryptedReader.Read() failed: %v", err)
	}
	if n != len(plaintext) {
		t.Errorf("Read returned %d; want %d", n, len(plaintext))
	}

	// Decrypted should match original plaintext
	if !bytes.Equal(decrypted[:n], plaintext) {
		t.Errorf("Decrypted = %q; want %q", decrypted[:n], plaintext)
	}
}

func TestCreateZip(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	file1 := filepath.Join(tmpDir, "file1.txt")
	file2 := filepath.Join(tmpDir, "file2.txt")
	content1 := []byte("Content of file 1")
	content2 := []byte("Content of file 2, a bit longer")

	if err := os.WriteFile(file1, content1, 0o644); err != nil {
		t.Fatalf("Create file1: %v", err)
	}
	if err := os.WriteFile(file2, content2, 0o644); err != nil {
		t.Fatalf("Create file2: %v", err)
	}

	// Create zip
	zipPath := filepath.Join(tmpDir, "test.zip")
	err := CreateZip(ZipOptions{
		Files:      []string{file1, file2},
		RootDir:    tmpDir,
		OutputPath: zipPath,
		Compress:   false,
	})
	if err != nil {
		t.Fatalf("CreateZip failed: %v", err)
	}

	// Verify zip was created
	if _, err := os.Stat(zipPath); err != nil {
		t.Fatalf("Zip file not created: %v", err)
	}

	// Read and verify zip contents
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("Open zip: %v", err)
	}
	defer reader.Close()

	if len(reader.File) != 2 {
		t.Errorf("Zip contains %d files; want 2", len(reader.File))
	}

	// Each entry must appear under its exact relative name with its exact body.
	// Checking against an explicit want map (and asserting every key is seen)
	// catches a mutation that writes an entry under the wrong/extra name or
	// emits an empty body — a plain "if name == known" branch silently passes
	// both because the unmatched arm leaves expected==nil and bytes.Equal(nil,nil).
	want := map[string][]byte{
		"file1.txt": content1,
		"file2.txt": content2,
	}
	seen := make(map[string]bool, len(want))
	for _, f := range reader.File {
		exp, ok := want[f.Name]
		if !ok {
			t.Errorf("unexpected zip entry %q", f.Name)
			continue
		}
		seen[f.Name] = true

		rc, err := f.Open()
		if err != nil {
			t.Fatalf("Open %s in zip: %v", f.Name, err)
		}
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("Read %s from zip: %v", f.Name, err)
		}

		if !bytes.Equal(content, exp) {
			t.Errorf("Content of %s = %q; want %q", f.Name, content, exp)
		}
	}

	for name := range want {
		if !seen[name] {
			t.Errorf("expected zip entry %q was missing", name)
		}
	}
}

func TestCreateZipRejectsExistingOutputAliases(t *testing.T) {
	tests := []struct {
		name      string
		makeAlias func(t *testing.T, victim, output string)
	}{
		{
			name: "regular file",
			makeAlias: func(t *testing.T, victim, output string) {
				t.Helper()
				if err := os.Rename(victim, output); err != nil {
					t.Fatalf("move victim into output path: %v", err)
				}
			},
		},
		{
			name: "hardlink",
			makeAlias: func(t *testing.T, victim, output string) {
				t.Helper()
				if err := os.Link(victim, output); err != nil {
					t.Fatalf("create hardlink: %v", err)
				}
			},
		},
		{
			name: "symlink",
			makeAlias: func(t *testing.T, victim, output string) {
				t.Helper()
				if err := os.Symlink(victim, output); err != nil {
					t.Skipf("symlinks unavailable on this platform: %v", err)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "input.txt")
			if err := os.WriteFile(input, []byte("payload for a real zip entry"), 0o600); err != nil {
				t.Fatalf("write input: %v", err)
			}

			victim := filepath.Join(dir, "victim.bin")
			victimBytes := []byte("existing output must never be truncated")
			if err := os.WriteFile(victim, victimBytes, 0o640); err != nil {
				t.Fatalf("write victim: %v", err)
			}
			output := filepath.Join(dir, "output.zip")
			tc.makeAlias(t, victim, output)

			// The regular-file case moved the victim to the output name.
			protected := victim
			if tc.name == "regular file" {
				protected = output
			}
			beforeInfo, err := os.Stat(protected)
			if err != nil {
				t.Fatalf("stat protected file before CreateZip: %v", err)
			}
			beforeLeaf, err := os.Lstat(output)
			if err != nil {
				t.Fatalf("lstat output before CreateZip: %v", err)
			}

			err = CreateZip(ZipOptions{
				Files:      []string{input},
				RootDir:    dir,
				OutputPath: output,
			})
			if !errors.Is(err, os.ErrExist) {
				t.Fatalf("CreateZip error = %v, want an os.ErrExist-compatible error", err)
			}

			got, err := os.ReadFile(protected)
			if err != nil {
				t.Fatalf("read protected file after CreateZip: %v", err)
			}
			if !bytes.Equal(got, victimBytes) {
				t.Fatalf("protected contents changed: got %q, want %q", got, victimBytes)
			}
			afterInfo, err := os.Stat(protected)
			if err != nil {
				t.Fatalf("stat protected file after CreateZip: %v", err)
			}
			if !os.SameFile(beforeInfo, afterInfo) {
				t.Fatal("CreateZip replaced the protected filesystem object")
			}
			afterLeaf, err := os.Lstat(output)
			if err != nil {
				t.Fatalf("lstat output after CreateZip: %v", err)
			}
			if beforeLeaf.Mode() != afterLeaf.Mode() {
				t.Fatalf("output leaf type or mode changed: before=%v after=%v", beforeLeaf.Mode(), afterLeaf.Mode())
			}

			if tc.name != "regular file" {
				outputInfo, err := os.Stat(output)
				if err != nil {
					t.Fatalf("stat output alias after CreateZip: %v", err)
				}
				if !os.SameFile(afterInfo, outputInfo) {
					t.Fatal("output no longer aliases the protected file")
				}
			}
		})
	}
}

func TestCreateZipRefusesReplacementAtCompletedOutputPath(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.bin")
	if err := os.WriteFile(input, bytes.Repeat([]byte("zip-race-payload"), 128*1024), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	output := filepath.Join(dir, "output.zip")
	replaced := false
	var assertUnchanged func()
	err := CreateZip(ZipOptions{
		Files:      []string{input},
		RootDir:    dir,
		OutputPath: output,
		Progress: func(float32, string) {
			if replaced {
				return
			}
			if err := os.Remove(output); err != nil {
				t.Fatalf("remove operation-owned ZIP output: %v", err)
			}
			assertUnchanged = installOccupiedPath(t, output, "regular")
			replaced = true
		},
	})
	if err == nil || err.Error() != "zip output path changed during creation" {
		t.Fatalf("CreateZip error = %v, want changed-output refusal", err)
	}
	if !replaced {
		t.Fatal("test did not replace the operation-owned ZIP output")
	}
	assertUnchanged()
}

// TestCreateZipReportsSpeedAndETA verifies the compression pass reports a status
// with throughput and ETA (like split/recombine/encrypt), not just a percentage.
func TestCreateZipReportsSpeedAndETA(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "input.bin")
	// Enough bytes to drive at least one in-loop progress tick.
	if err := os.WriteFile(inputPath, bytes.Repeat([]byte("x"), 2*1024*1024), 0o644); err != nil {
		t.Fatalf("Create input: %v", err)
	}

	var statuses []string
	err := CreateZip(ZipOptions{
		Files:      []string{inputPath},
		RootDir:    tmpDir,
		OutputPath: filepath.Join(tmpDir, "out.zip"),
		Compress:   true,
		Progress:   func(p float32, info string) {},
		Status:     func(s string) { statuses = append(statuses, s) },
	})
	if err != nil {
		t.Fatalf("CreateZip failed: %v", err)
	}

	for _, s := range statuses {
		if strings.Contains(s, "MiB/s") && strings.Contains(s, "ETA:") {
			return
		}
	}
	t.Errorf("expected a compression status reporting speed+ETA, got %v", statuses)
}

func TestCreateZipWithCompression(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a compressible file (repeated data compresses well)
	file1 := filepath.Join(tmpDir, "compressible.txt")
	content := bytes.Repeat([]byte("AAAA"), 10000) // 40 KB of A's

	if err := os.WriteFile(file1, content, 0o644); err != nil {
		t.Fatalf("Create file: %v", err)
	}

	// Create zip without compression
	zipNoCompress := filepath.Join(tmpDir, "nocompress.zip")
	err := CreateZip(ZipOptions{
		Files:      []string{file1},
		RootDir:    tmpDir,
		OutputPath: zipNoCompress,
		Compress:   false,
	})
	if err != nil {
		t.Fatalf("CreateZip (no compress) failed: %v", err)
	}

	// Create zip with compression
	zipCompress := filepath.Join(tmpDir, "compress.zip")
	err = CreateZip(ZipOptions{
		Files:      []string{file1},
		RootDir:    tmpDir,
		OutputPath: zipCompress,
		Compress:   true,
	})
	if err != nil {
		t.Fatalf("CreateZip (compress) failed: %v", err)
	}

	// Compare sizes
	statNoCompress, _ := os.Stat(zipNoCompress)
	statCompress, _ := os.Stat(zipCompress)

	if statCompress.Size() >= statNoCompress.Size() {
		t.Errorf("Compressed size (%d) should be smaller than uncompressed (%d)",
			statCompress.Size(), statNoCompress.Size())
	}

	t.Logf("Uncompressed: %d bytes, Compressed: %d bytes",
		statNoCompress.Size(), statCompress.Size())
}

func TestCreateZipWithEncryption(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test file
	file1 := filepath.Join(tmpDir, "secret.txt")
	content := []byte("Secret content that should be encrypted")

	if err := os.WriteFile(file1, content, 0o644); err != nil {
		t.Fatalf("Create file: %v", err)
	}

	// Create cipher for temp encryption
	ciphers, err := NewTempZipCiphers()
	if err != nil {
		t.Fatalf("NewTempZipCiphers() failed: %v", err)
	}
	defer ciphers.Close()

	// Create encrypted zip
	zipPath := filepath.Join(tmpDir, "encrypted.tmp")
	err = CreateZip(ZipOptions{
		Files:      []string{file1},
		RootDir:    tmpDir,
		OutputPath: zipPath,
		Compress:   false,
		Cipher:     ciphers,
	})
	if err != nil {
		t.Fatalf("CreateZip with encryption failed: %v", err)
	}

	// Read the encrypted file
	encryptedData, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatalf("Read encrypted zip: %v", err)
	}

	// The file should NOT be a valid zip (it's encrypted)
	_, err = zip.OpenReader(zipPath)
	if err == nil {
		t.Error("Encrypted zip should not be readable as a normal zip")
	}

	// Decrypt and verify it's a valid zip
	decryptedPath := filepath.Join(tmpDir, "decrypted.zip")
	decryptedFile, err := os.Create(decryptedPath)
	if err != nil {
		t.Fatalf("Create decrypted file: %v", err)
	}

	reader := WrapReaderWithCipher(bytes.NewReader(encryptedData), ciphers)
	decrypted := make([]byte, len(encryptedData))
	n, err := reader.Read(decrypted)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("Read decrypted data: %v", err)
	}
	_, _ = decryptedFile.Write(decrypted[:n])
	_ = decryptedFile.Close()

	// Now it should be a valid zip
	zipReader, err := zip.OpenReader(decryptedPath)
	if err != nil {
		t.Fatalf("Open decrypted zip: %v", err)
	}
	defer zipReader.Close()

	if len(zipReader.File) != 1 {
		t.Fatalf("Decrypted zip contains %d files; want 1", len(zipReader.File))
	}

	// Read the single entry back and compare against the original literal.
	// A "valid zip with 1 entry" check is not enough: if the Writer/Reader
	// ciphers ever desync (different key/nonce), the structure can still parse
	// while the body is garbage. Asserting the exact plaintext catches that.
	rc, err := zipReader.File[0].Open()
	if err != nil {
		t.Fatalf("Open entry in decrypted zip: %v", err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatalf("Read entry from decrypted zip: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("decrypted entry body = %q; want %q", got, content)
	}
}

func TestCreateZipCancellation(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test file
	file1 := filepath.Join(tmpDir, "file.txt")
	content := bytes.Repeat([]byte("X"), 10000)
	if err := os.WriteFile(file1, content, 0o644); err != nil {
		t.Fatalf("Create file: %v", err)
	}

	// Cancel immediately
	zipPath := filepath.Join(tmpDir, "cancelled.zip")
	err := CreateZip(ZipOptions{
		Files:      []string{file1},
		RootDir:    tmpDir,
		OutputPath: zipPath,
		Cancel:     func() bool { return true },
	})

	if err == nil {
		t.Error("Expected cancellation error")
	}
	if err.Error() != "operation cancelled" {
		t.Errorf("Expected 'operation cancelled', got: %v", err)
	}

	// Zip should not exist
	if _, err := os.Stat(zipPath); !os.IsNotExist(err) {
		t.Error("Cancelled zip should be removed")
	}
}

func TestWrapReaderWithCipher(t *testing.T) {
	// Test with nil cipher
	reader := bytes.NewReader([]byte("test"))
	wrapped := WrapReaderWithCipher(reader, nil)
	if wrapped != reader {
		t.Error("WrapReaderWithCipher(nil) should return original reader")
	}

	// Test with actual cipher
	ciphers, err := NewTempZipCiphers()
	if err != nil {
		t.Fatalf("NewTempZipCiphers() failed: %v", err)
	}
	defer ciphers.Close()

	reader2 := bytes.NewReader([]byte("test data"))
	wrapped2 := WrapReaderWithCipher(reader2, ciphers)
	if wrapped2 == reader2 {
		t.Error("WrapReaderWithCipher should wrap the reader")
	}

	// Round-trip: encrypt a known plaintext with the Writer cipher, then read it
	// back through WrapReaderWithCipher and assert we recover the plaintext.
	// This pins the wrapper to the *Reader* cipher: if it were wired to the Writer
	// cipher (or made a no-op), the keystream would not cancel and the output
	// would differ from the plaintext, failing bytes.Equal.
	plaintext := []byte("round-trip plaintext for cipher wiring check")
	var encBuf bytes.Buffer
	ew := &encryptedWriter{w: &encBuf, cipher: ciphers.Writer}
	if _, err := ew.Write(plaintext); err != nil {
		t.Fatalf("encryptedWriter.Write() failed: %v", err)
	}
	if bytes.Equal(encBuf.Bytes(), plaintext) {
		t.Fatal("ciphertext must differ from plaintext")
	}

	rt := WrapReaderWithCipher(bytes.NewReader(encBuf.Bytes()), ciphers)
	got, err := io.ReadAll(rt)
	if err != nil {
		t.Fatalf("io.ReadAll(wrapped) failed: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip = %q; want %q", got, plaintext)
	}
}

func TestCreateZipWithSubdirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a subdirectory with a file
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatalf("Create subdir: %v", err)
	}

	file1 := filepath.Join(tmpDir, "root.txt")
	file2 := filepath.Join(subDir, "nested.txt")

	if err := os.WriteFile(file1, []byte("root file"), 0o644); err != nil {
		t.Fatalf("Create file1: %v", err)
	}
	if err := os.WriteFile(file2, []byte("nested file"), 0o644); err != nil {
		t.Fatalf("Create file2: %v", err)
	}

	// Create zip
	zipPath := filepath.Join(tmpDir, "test.zip")
	err := CreateZip(ZipOptions{
		Files:      []string{file1, file2},
		RootDir:    tmpDir,
		OutputPath: zipPath,
	})
	if err != nil {
		t.Fatalf("CreateZip failed: %v", err)
	}

	// Verify paths in zip
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("Open zip: %v", err)
	}
	defer reader.Close()

	foundPaths := make(map[string]bool)
	for _, f := range reader.File {
		foundPaths[f.Name] = true
	}

	if !foundPaths["root.txt"] {
		t.Error("root.txt not found in zip")
	}
	if !foundPaths["subdir/nested.txt"] {
		t.Error("subdir/nested.txt not found in zip")
	}

	t.Log("Subdirectory structure preserved in zip")
}

func TestCreateZipRejectsNonLocalEntryName(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "file.txt")
	if err := os.WriteFile(inputPath, []byte("content"), 0o644); err != nil {
		t.Fatalf("Create file: %v", err)
	}

	zipPath := filepath.Join(tmpDir, "bad.zip")
	const offending = "../escape.txt"
	err := CreateZip(ZipOptions{
		Files:      []string{inputPath},
		RootDir:    tmpDir,
		EntryNames: map[string]string{inputPath: offending},
		OutputPath: zipPath,
	})
	if err == nil {
		t.Fatal("Expected non-local entry name error")
	}

	// Reject for the right reason, and name the offending entry — so the test
	// fails if the guard is replaced by some unrelated error, or accepts a
	// non-local name under a different message.
	if !strings.Contains(err.Error(), "is not local") {
		t.Errorf("error = %v; want it to contain %q", err, "is not local")
	}
	if !strings.Contains(err.Error(), offending) {
		t.Errorf("error = %v; want it to name the offending entry %q", err, offending)
	}

	// Security outcome: no partial zip left behind and no escape artifact written
	// outside RootDir. If the non-local entry were accepted, CreateZip would have
	// produced the zip (and a real traversal write could escape tmpDir).
	if _, statErr := os.Stat(zipPath); !os.IsNotExist(statErr) {
		t.Errorf("zip file should not exist after rejection, stat err = %v", statErr)
	}
	escapeArtifact := filepath.Join(tmpDir, "..", "escape.txt")
	if _, statErr := os.Stat(escapeArtifact); !os.IsNotExist(statErr) {
		t.Errorf("escape artifact %q should not exist, stat err = %v", escapeArtifact, statErr)
	}
}
