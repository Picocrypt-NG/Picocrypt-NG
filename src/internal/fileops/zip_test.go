package fileops

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestTempZipCiphers(t *testing.T) {
	ciphers, err := NewTempZipCiphers()
	if err != nil {
		t.Fatalf("NewTempZipCiphers() failed: %v", err)
	}

	if ciphers.Writer == nil {
		t.Error("Writer cipher should not be nil")
	}
	if ciphers.Reader == nil {
		t.Error("Reader cipher should not be nil")
	}
	if len(ciphers.key) != 32 {
		t.Errorf("Key length = %d; want 32", len(ciphers.key))
	}
	if len(ciphers.nonce) != 12 {
		t.Errorf("Nonce length = %d; want 12", len(ciphers.nonce))
	}
}

func TestTempZipCiphersClose(t *testing.T) {
	ciphers, err := NewTempZipCiphers()
	if err != nil {
		t.Fatalf("NewTempZipCiphers() failed: %v", err)
	}

	// Save references to check zeroing
	keyRef := ciphers.key
	nonceRef := ciphers.nonce

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
		t.Error("key should be nil after Close()")
	}
	if ciphers.nonce != nil {
		t.Error("nonce should be nil after Close()")
	}
}

func TestTempZipCiphersCloseIdempotent(t *testing.T) {
	ciphers, err := NewTempZipCiphers()
	if err != nil {
		t.Fatalf("NewTempZipCiphers() failed: %v", err)
	}

	// Multiple Close() calls should be safe
	ciphers.Close()
	ciphers.Close()
	ciphers.Close()
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

	if err := os.WriteFile(file1, content1, 0644); err != nil {
		t.Fatalf("Create file1: %v", err)
	}
	if err := os.WriteFile(file2, content2, 0644); err != nil {
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

	// Verify file contents
	for _, f := range reader.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("Open %s in zip: %v", f.Name, err)
		}
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("Read %s from zip: %v", f.Name, err)
		}

		var expected []byte
		if f.Name == "file1.txt" {
			expected = content1
		} else if f.Name == "file2.txt" {
			expected = content2
		}

		if !bytes.Equal(content, expected) {
			t.Errorf("Content of %s mismatch", f.Name)
		}
	}

	t.Log("Zip creation successful")
}

func TestCreateZipWithCompression(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a compressible file (repeated data compresses well)
	file1 := filepath.Join(tmpDir, "compressible.txt")
	content := bytes.Repeat([]byte("AAAA"), 10000) // 40 KB of A's

	if err := os.WriteFile(file1, content, 0644); err != nil {
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

	if err := os.WriteFile(file1, content, 0644); err != nil {
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
	if err != nil && err != io.EOF {
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
		t.Errorf("Decrypted zip contains %d files; want 1", len(zipReader.File))
	}

	t.Log("Encrypted zip creation and decryption successful")
}

func TestCreateZipCancellation(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test file
	file1 := filepath.Join(tmpDir, "file.txt")
	content := bytes.Repeat([]byte("X"), 10000)
	if err := os.WriteFile(file1, content, 0644); err != nil {
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

func TestCreateZipProgress(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	file1 := filepath.Join(tmpDir, "file1.txt")
	file2 := filepath.Join(tmpDir, "file2.txt")
	if err := os.WriteFile(file1, bytes.Repeat([]byte("A"), 1000), 0644); err != nil {
		t.Fatalf("Create file1: %v", err)
	}
	if err := os.WriteFile(file2, bytes.Repeat([]byte("B"), 1000), 0644); err != nil {
		t.Fatalf("Create file2: %v", err)
	}

	progressCalls := 0
	statusCalls := 0

	zipPath := filepath.Join(tmpDir, "progress.zip")
	err := CreateZip(ZipOptions{
		Files:      []string{file1, file2},
		RootDir:    tmpDir,
		OutputPath: zipPath,
		Progress: func(p float32, info string) {
			progressCalls++
		},
		Status: func(s string) {
			statusCalls++
		},
	})

	if err != nil {
		t.Fatalf("CreateZip failed: %v", err)
	}

	if progressCalls == 0 {
		t.Error("Progress callback was never called")
	}

	t.Logf("Progress called %d times", progressCalls)
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
}

func TestCreateZipWithSubdirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a subdirectory with a file
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("Create subdir: %v", err)
	}

	file1 := filepath.Join(tmpDir, "root.txt")
	file2 := filepath.Join(subDir, "nested.txt")

	if err := os.WriteFile(file1, []byte("root file"), 0644); err != nil {
		t.Fatalf("Create file1: %v", err)
	}
	if err := os.WriteFile(file2, []byte("nested file"), 0644); err != nil {
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
