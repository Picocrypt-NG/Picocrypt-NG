package fileops

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

// TestUnpackPathTraversalPrevention verifies that zip files with "../" in
// filenames are rejected to prevent path traversal attacks.
func TestUnpackPathTraversalPrevention(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a malicious zip file with path traversal attempt
	maliciousZipPath := filepath.Join(tmpDir, "malicious.zip")
	createMaliciousZip(t, maliciousZipPath)

	// Attempt to unpack - should fail
	err := Unpack(UnpackOptions{
		ZipPath:    maliciousZipPath,
		ExtractDir: filepath.Join(tmpDir, "extracted"),
	})

	if err == nil {
		t.Fatal("Expected error for path traversal attempt, got nil")
	}

	expectedErr := "potentially malicious zip item path"
	if err.Error() != expectedErr {
		t.Errorf("Expected error %q, got %q", expectedErr, err.Error())
	}

	t.Logf("Path traversal correctly blocked: %v", err)
}

// TestUnpackPathTraversalVariants tests various path traversal attempts
func TestUnpackPathTraversalVariants(t *testing.T) {
	maliciousPaths := []string{
		"../etc/passwd",
		"foo/../../../etc/passwd",
		"..\\windows\\system32\\config\\sam",
		"normal/../../etc/passwd",
		"a/b/c/../../../../../../../etc/passwd",
	}

	for _, malPath := range maliciousPaths {
		t.Run(malPath, func(t *testing.T) {
			tmpDir := t.TempDir()
			zipPath := filepath.Join(tmpDir, "test.zip")

			// Create zip with malicious path
			f, err := os.Create(zipPath)
			if err != nil {
				t.Fatalf("Create zip file: %v", err)
			}

			w := zip.NewWriter(f)
			_, err = w.Create(malPath)
			if err != nil {
				// Some paths may be rejected by the zip library itself
				_ = w.Close()
				_ = f.Close()
				t.Skipf("Zip library rejected path: %v", err)
				return
			}
			_ = w.Close()
			_ = f.Close()

			// Attempt to unpack
			err = Unpack(UnpackOptions{
				ZipPath:    zipPath,
				ExtractDir: filepath.Join(tmpDir, "out"),
			})

			if err == nil {
				t.Errorf("Expected error for malicious path %q, got nil", malPath)
			} else {
				t.Logf("Path %q correctly blocked: %v", malPath, err)
			}
		})
	}
}

// TestUnpackNormalPaths verifies that normal paths work correctly
func TestUnpackNormalPaths(t *testing.T) {
	normalPaths := []string{
		"file.txt",
		"dir/file.txt",
		"dir/subdir/file.txt",
		"a.b.c/d.e.f/file.txt",
		// Files with double dots in name (NOT path traversal)
		"test..txt",
		"file..backup",
		"dir/file..copy.txt",
		"Исследования..копия.docx",
	}

	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "normal.zip")

	// Create zip with normal paths
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("Create zip file: %v", err)
	}

	w := zip.NewWriter(f)
	for _, path := range normalPaths {
		fw, err := w.Create(path)
		if err != nil {
			t.Fatalf("Create entry %q: %v", path, err)
		}
		_, _ = fw.Write([]byte("test content"))
	}
	_ = w.Close()
	_ = f.Close()

	// Unpack should succeed
	extractDir := filepath.Join(tmpDir, "extracted")
	err = Unpack(UnpackOptions{
		ZipPath:    zipPath,
		ExtractDir: extractDir,
	})

	if err != nil {
		t.Fatalf("Unpack failed for normal paths: %v", err)
	}

	// Verify files were created
	for _, path := range normalPaths {
		fullPath := filepath.Join(extractDir, path)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			t.Errorf("Expected file %q to exist", fullPath)
		}
	}

	t.Log("Normal paths unpacked successfully")
}

// TestUnpackCancellation verifies that unpack can be cancelled
func TestUnpackCancellation(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "test.zip")

	// Create zip with multiple files
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("Create zip file: %v", err)
	}

	w := zip.NewWriter(f)
	for i := 0; i < 10; i++ {
		fw, err := w.CreateHeader(&zip.FileHeader{
			Name:   filepath.Join("dir", "file"+string(rune('0'+i))+".txt"),
			Method: zip.Store,
		})
		if err != nil {
			t.Fatalf("Create entry: %v", err)
		}
		_, _ = fw.Write([]byte("test content for file"))
	}
	_ = w.Close()
	_ = f.Close()

	// Cancel after first file
	cancelAfter := 1
	cancelled := false
	count := 0

	extractDir := filepath.Join(tmpDir, "extracted")
	err = Unpack(UnpackOptions{
		ZipPath:    zipPath,
		ExtractDir: extractDir,
		Cancel: func() bool {
			count++
			if count > cancelAfter && !cancelled {
				cancelled = true
				return true
			}
			return false
		},
	})

	if err == nil {
		t.Fatal("Expected cancellation error, got nil")
	}

	if err.Error() != "operation cancelled" {
		t.Errorf("Expected 'operation cancelled' error, got: %v", err)
	}

	t.Logf("Unpack correctly cancelled: %v", err)
}

// createMaliciousZip creates a zip file with a path traversal attempt
func createMaliciousZip(t *testing.T, path string) {
	t.Helper()

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create zip file: %v", err)
	}
	defer func() { _ = f.Close() }()

	w := zip.NewWriter(f)
	defer func() { _ = w.Close() }()

	// Create a file with path traversal in name
	fw, err := w.Create("../escape.txt")
	if err != nil {
		t.Fatalf("Create malicious entry: %v", err)
	}
	_, _ = fw.Write([]byte("malicious content"))
}
