package cli

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestEncryptDirectoryProducesZip is the CLI-side regression for issue #130.
//
// The desktop UI labels a dropped folder "Zip and Encrypt" and names the output
// "<name>.zip.pcv"; the headless CLI takes the symmetric path (a directory input
// is recorded in OnlyFolders, see encrypt.go IsDir branch). A folder holding a
// single file used to skip zipping because the decision only looked at file
// count, so decryption produced a ".zip"-named file whose bytes were the raw
// inner file and which no unzip tool could extract.
//
// This exercises the real `encrypt`/`decrypt` commands end to end so the wiring
// (IsDir -> OnlyFolders -> volume zip decision) is covered on every CI platform,
// not just through the volume package directly. It must fail before the fix.
func TestEncryptDirectoryProducesZip(t *testing.T) {
	resetEncryptFlagsForDirTest()
	resetDecryptFlagsForDirTest()
	t.Cleanup(resetEncryptFlagsForDirTest)
	t.Cleanup(resetDecryptFlagsForDirTest)

	tmpDir := t.TempDir()

	// A folder ("test_dir") containing exactly one file, mirroring the issue.
	folder := filepath.Join(tmpDir, "test_dir")
	if err := os.MkdirAll(folder, 0o755); err != nil {
		t.Fatalf("create folder: %v", err)
	}
	innerContent := []byte("hello world\n")
	innerPath := filepath.Join(folder, "hello.txt")
	if err := os.WriteFile(innerPath, innerContent, 0o644); err != nil {
		t.Fatalf("write inner file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "encrypted.zip.pcv")
	decryptedPath := filepath.Join(tmpDir, "decrypted.zip")

	// Encrypt the directory through the real CLI command.
	encOutput = encryptedPath
	encPassword = "pw"
	encQuiet = true
	encYes = true
	if err := encryptCmd.RunE(encryptCmd, []string{folder}); err != nil {
		t.Fatalf("encrypt directory: %v", err)
	}

	// Decrypt WITHOUT auto-unzip: the on-disk output must itself be a valid zip.
	decOutput = decryptedPath
	decPassword = "pw"
	decQuiet = true
	decYes = true
	if err := decryptCmd.RunE(decryptCmd, []string{encryptedPath}); err != nil {
		t.Fatalf("decrypt: %v", err)
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
		t.Fatalf("open zip entry: %v", err)
	}
	got, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatalf("read zip entry: %v", err)
	}
	if string(got) != string(innerContent) {
		t.Fatalf("zip entry content = %q, want %q", got, innerContent)
	}
}

// resetEncryptFlagsForDirTest clears the package-level encrypt flags this test
// touches so leftover state from other tests (or this one) cannot bleed in.
func resetEncryptFlagsForDirTest() {
	encGlob = nil
	encLegacyInputs = nil
	encOutput = ""
	encPassword = ""
	encKeyfiles = nil
	encKeyfileOrder = false
	encParanoid = false
	encReedSolomon = false
	encDeniability = false
	encCompress = false
	encSplit = false
	encSplitSize = 0
	encSplitUnit = "MiB"
	encQuiet = false
	encYes = false
	encFollowSymlinks = false
}

// resetDecryptFlagsForDirTest clears the package-level decrypt flags this test
// touches so leftover state cannot bleed in.
func resetDecryptFlagsForDirTest() {
	decLegacyInputs = nil
	decOutput = ""
	decPassword = ""
	decKeyfiles = nil
	decForce = false
	decVerifyFirst = false
	decAutoUnzip = false
	decSameLevel = false
	decRecombine = false
	decDeniability = false
	decQuiet = false
	decYes = false
}
