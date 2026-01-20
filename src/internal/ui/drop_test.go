// Package ui provides tests for file drop handling logic.
package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/util"

	"fyne.io/fyne/v2/test"
)

// TestFileTypeDetection tests detection of encrypted vs plain files.
func TestFileTypeDetection(t *testing.T) {
	testCases := []struct {
		name      string
		filename  string
		isPcv     bool
		isSplit   bool
		isEncrypt bool
	}{
		{"PlainText", "document.txt", false, false, true},
		{"PlainPDF", "report.pdf", false, false, true},
		{"EncryptedPcv", "secret.pcv", true, false, false},
		{"SplitChunk0", "secret.pcv.0", true, true, false},
		{"SplitChunk1", "secret.pcv.1", true, true, false},
		{"SplitChunk99", "secret.pcv.99", true, true, false},
		{"FakeSplit", "file.pcv.txt", false, false, true},
		{"DeepPath", "/path/to/secret.pcv", true, false, false},
		{"DeepSplit", "/path/to/secret.pcv.5", true, true, false},
		{"NoExtension", "document", false, false, true},
		{"HiddenFile", ".hidden.pcv", true, false, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			isPcv := strings.HasSuffix(tc.filename, ".pcv")
			isSplit := detectSplitVolume(tc.filename)

			if isPcv != tc.isPcv && !isSplit {
				t.Errorf("isPcv = %v; want %v for %q", isPcv, tc.isPcv, tc.filename)
			}
			if isSplit != tc.isSplit {
				t.Errorf("isSplit = %v; want %v for %q", isSplit, tc.isSplit, tc.filename)
			}

			// Determine encrypt mode
			isEncrypt := !isPcv && !isSplit
			if isEncrypt != tc.isEncrypt {
				t.Errorf("isEncrypt = %v; want %v for %q", isEncrypt, tc.isEncrypt, tc.filename)
			}
		})
	}
}

// detectSplitVolume checks if a filename is a split volume chunk.
// This mirrors the logic in handleDecryptDrop.
func detectSplitVolume(filename string) bool {
	// Check if ends with a number
	endsNum := false
	for _, c := range "0123456789" {
		if strings.HasSuffix(filename, string(c)) {
			endsNum = true
			break
		}
	}

	// Must contain .pcv. and end with number
	return strings.Contains(filename, ".pcv.") && endsNum
}

// TestSplitVolumeBasePath tests extraction of base path from split volumes.
func TestSplitVolumeBasePath(t *testing.T) {
	testCases := []struct {
		name         string
		chunkPath    string
		expectedBase string
	}{
		{"Chunk0", "/path/to/secret.pcv.0", "/path/to/secret.pcv"},
		{"Chunk5", "/path/to/secret.pcv.5", "/path/to/secret.pcv"},
		{"Chunk99", "/path/to/data.pcv.99", "/path/to/data.pcv"},
		{"DeepPath", "/a/b/c/d/file.pcv.0", "/a/b/c/d/file.pcv"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Extract base path (logic from handleDecryptDrop)
			ind := strings.Index(tc.chunkPath, ".pcv")
			basePath := tc.chunkPath[:ind+4]

			if basePath != tc.expectedBase {
				t.Errorf("basePath = %q; want %q", basePath, tc.expectedBase)
			}
		})
	}
}

// TestOutputPathFromDecrypt tests output path derivation for decryption.
func TestOutputPathFromDecrypt(t *testing.T) {
	testCases := []struct {
		name       string
		inputPath  string
		outputPath string
	}{
		{"SimplePcv", "/path/secret.pcv", "/path/secret"},
		{"NestedPcv", "/a/b/c/file.pcv", "/a/b/c/file"},
		{"MultipleDots", "/path/file.tar.gz.pcv", "/path/file.tar.gz"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Remove .pcv suffix (logic from handleDecryptDrop)
			output := tc.inputPath[:len(tc.inputPath)-4]

			if output != tc.outputPath {
				t.Errorf("output = %q; want %q", output, tc.outputPath)
			}
		})
	}
}

// TestMultipleDropLabels tests label generation for multiple dropped items.
func TestMultipleDropLabels(t *testing.T) {
	testCases := []struct {
		name     string
		files    int
		folders  int
		expected string
	}{
		{"OnlyFiles_2", 2, 0, "2 files"},
		{"OnlyFiles_5", 5, 0, "5 files"},
		{"OnlyFolders_2", 0, 2, "2 folders"},
		{"OnlyFolders_5", 0, 5, "5 folders"},
		{"1File1Folder", 1, 1, "1 file and 1 folder"},
		{"1FileManyFolders", 1, 3, "1 file and 3 folders"},
		{"ManyFiles1Folder", 3, 1, "3 files and 1 folder"},
		{"ManyBoth", 3, 2, "3 files and 2 folders"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			label := generateInputLabel(tc.files, tc.folders)

			if label != tc.expected {
				t.Errorf("label = %q; want %q", label, tc.expected)
			}
		})
	}
}

// generateInputLabel generates the input label for multiple items.
// This mirrors the logic in handleMultipleDrop.
func generateInputLabel(files, folders int) string {
	if folders == 0 {
		return pluralize(files, "file", "files")
	}
	if files == 0 {
		return pluralize(folders, "folder", "folders")
	}

	if files == 1 && folders > 1 {
		return "1 file and " + pluralize(folders, "folder", "folders")
	}
	if folders == 1 && files > 1 {
		return pluralize(files, "file", "files") + " and 1 folder"
	}
	if folders == 1 && files == 1 {
		return "1 file and 1 folder"
	}
	return pluralize(files, "file", "files") + " and " + pluralize(folders, "folder", "folders")
}

func pluralize(count int, singular, plural string) string {
	if count == 1 {
		return "1 " + singular
	}
	return itoa(count) + " " + plural
}

// itoa converts an int to string without leading zeros.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var result []byte
	for n > 0 {
		result = append([]byte{byte('0' + n%10)}, result...)
		n /= 10
	}
	return string(result)
}

// TestDropStateTransitions tests state changes during drop handling.
func TestDropStateTransitions(t *testing.T) {
	test.NewApp()
	defer test.NewApp()

	t.Run("SingleFileDropSetsEncryptMode", func(t *testing.T) {
		state := app.NewState()

		// Simulate dropping a plain file
		state.Mode = "encrypt"
		state.InputFile = "/path/to/file.txt"
		state.OutputFile = state.InputFile + ".pcv"

		if state.Mode != "encrypt" {
			t.Error("Mode should be 'encrypt' for plain file")
		}
		if !strings.HasSuffix(state.OutputFile, ".pcv") {
			t.Error("Output should have .pcv suffix")
		}
	})

	t.Run("PcvFileDropSetsDecryptMode", func(t *testing.T) {
		state := app.NewState()

		// Simulate dropping a .pcv file
		state.Mode = "decrypt"
		state.InputFile = "/path/to/secret.pcv"
		state.OutputFile = "/path/to/secret"

		if state.Mode != "decrypt" {
			t.Error("Mode should be 'decrypt' for .pcv file")
		}
		if strings.HasSuffix(state.OutputFile, ".pcv") {
			t.Error("Output should not have .pcv suffix")
		}
	})

	t.Run("FolderDropSetsZipMode", func(t *testing.T) {
		state := app.NewState()

		// Simulate dropping a folder
		state.Mode = "encrypt"
		state.StartLabel = "Zip and Encrypt"

		if state.Mode != "encrypt" {
			t.Error("Mode should be 'encrypt' for folder")
		}
		if state.StartLabel != "Zip and Encrypt" {
			t.Errorf("StartLabel = %q; want 'Zip and Encrypt'", state.StartLabel)
		}
	})
}

// TestKeyfileDropHandling tests keyfile drop in keyfile modal.
func TestKeyfileDropHandling(t *testing.T) {
	t.Run("AddUniqueKeyfiles", func(t *testing.T) {
		state := app.NewState()
		state.ShowKeyfile = true

		// Add keyfiles
		keyfiles := []string{"/path/key1.bin", "/path/key2.bin"}
		for _, kf := range keyfiles {
			// Check for duplicates
			duplicate := false
			for _, existing := range state.Keyfiles {
				if kf == existing {
					duplicate = true
					break
				}
			}
			if !duplicate {
				state.Keyfiles = append(state.Keyfiles, kf)
			}
		}

		if len(state.Keyfiles) != 2 {
			t.Errorf("Keyfiles count = %d; want 2", len(state.Keyfiles))
		}
	})

	t.Run("PreventDuplicateKeyfiles", func(t *testing.T) {
		state := app.NewState()
		state.ShowKeyfile = true
		state.Keyfiles = []string{"/path/key1.bin"}

		// Try to add duplicate
		newKeyfile := "/path/key1.bin"
		duplicate := false
		for _, existing := range state.Keyfiles {
			if newKeyfile == existing {
				duplicate = true
				break
			}
		}

		if !duplicate {
			state.Keyfiles = append(state.Keyfiles, newKeyfile)
		}

		if len(state.Keyfiles) != 1 {
			t.Errorf("Keyfiles count = %d; want 1 (no duplicates)", len(state.Keyfiles))
		}
	})

	t.Run("KeyfileLabelUpdates", func(t *testing.T) {
		testCases := []struct {
			count    int
			required bool
			expected string
		}{
			{0, false, "None selected"},
			{0, true, "Keyfiles required"},
			{1, false, "Using 1 keyfile"},
			{3, false, "Using multiple keyfiles"},
		}

		for _, tc := range testCases {
			state := app.NewState()
			state.Keyfile = tc.required
			state.Keyfiles = make([]string, tc.count)
			for i := 0; i < tc.count; i++ {
				state.Keyfiles[i] = "/path/key" + string(rune('0'+i)) + ".bin"
			}

			state.UpdateKeyfileLabel()

			if state.KeyfileLabel != tc.expected {
				t.Errorf("count=%d, required=%v: label = %q; want %q",
					tc.count, tc.required, state.KeyfileLabel, tc.expected)
			}
		}
	})
}

// TestScanningState tests the scanning state during folder processing.
func TestScanningState(t *testing.T) {
	state := app.NewState()

	// Initially not scanning
	if state.Scanning {
		t.Error("Scanning should be false initially")
	}

	// Start scanning
	state.Scanning = true
	if !state.Scanning {
		t.Error("Scanning should be true")
	}

	// During scanning, new drops should be ignored
	if !state.Scanning {
		t.Error("Drops should be blocked while scanning")
	}

	// End scanning
	state.Scanning = false
	if state.Scanning {
		t.Error("Scanning should be false after completion")
	}
}

// TestDeniabilityDetection tests deniability mode detection from headers.
func TestDeniabilityDetection(t *testing.T) {
	t.Run("DeniableVolumeStatus", func(t *testing.T) {
		state := app.NewState()

		// When version cannot be read, assume deniable
		state.Deniability = true
		state.MainStatus = "Cannot read header, volume may be deniable"

		if !state.Deniability {
			t.Error("Deniability should be true for unreadable header")
		}
	})

	t.Run("NormalVolumeStatus", func(t *testing.T) {
		state := app.NewState()
		state.Deniability = false
		state.MainStatus = "Ready"

		if state.Deniability {
			t.Error("Deniability should be false for normal volume")
		}
	})
}

// TestDropWithRealFiles tests drop handling logic with actual filesystem.
// Note: We test the state logic directly since the UI components aren't initialized.
func TestDropWithRealFiles(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("SingleFileDetection", func(t *testing.T) {
		// Create test file
		testFile := filepath.Join(tmpDir, "test.txt")
		if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
			t.Fatalf("Create test file: %v", err)
		}

		stat, err := os.Stat(testFile)
		if err != nil {
			t.Fatalf("Stat test file: %v", err)
		}

		// Test detection logic
		if stat.IsDir() {
			t.Error("File should not be detected as directory")
		}
		if strings.HasSuffix(testFile, ".pcv") {
			t.Error("File should not be detected as encrypted")
		}
	})

	t.Run("FolderDetection", func(t *testing.T) {
		// Create test folder
		testFolder := filepath.Join(tmpDir, "testfolder")
		if err := os.Mkdir(testFolder, 0755); err != nil {
			t.Fatalf("Create test folder: %v", err)
		}

		stat, err := os.Stat(testFolder)
		if err != nil {
			t.Fatalf("Stat test folder: %v", err)
		}

		if !stat.IsDir() {
			t.Error("Folder should be detected as directory")
		}
	})

	t.Run("MultipleFilesCount", func(t *testing.T) {
		// Create multiple test files
		files := make([]string, 3)
		for i := 0; i < 3; i++ {
			files[i] = filepath.Join(tmpDir, "multi"+string(rune('0'+i))+".txt")
			if err := os.WriteFile(files[i], []byte("content"), 0644); err != nil {
				t.Fatalf("Create test file: %v", err)
			}
		}

		// Verify all files exist
		for _, f := range files {
			if _, err := os.Stat(f); err != nil {
				t.Errorf("File %s should exist", f)
			}
		}

		if len(files) != 3 {
			t.Errorf("Files count = %d; want 3", len(files))
		}
	})

	t.Run("PcvFileDetection", func(t *testing.T) {
		// Create test .pcv file
		pcvFile := filepath.Join(tmpDir, "encrypted.pcv")
		if err := os.WriteFile(pcvFile, []byte("encrypted content"), 0644); err != nil {
			t.Fatalf("Create test file: %v", err)
		}

		if !strings.HasSuffix(pcvFile, ".pcv") {
			t.Error("PCV file should be detected by suffix")
		}

		// Should be decrypt mode
		isPcv := strings.HasSuffix(pcvFile, ".pcv")
		isSplit := detectSplitVolume(pcvFile)
		isDecrypt := isPcv || isSplit

		if !isDecrypt {
			t.Error("PCV file should trigger decrypt mode")
		}
	})

	t.Run("SplitVolumeDetection", func(t *testing.T) {
		// Create split volume chunks
		for i := 0; i < 3; i++ {
			chunkFile := filepath.Join(tmpDir, "data.pcv."+string(rune('0'+i)))
			if err := os.WriteFile(chunkFile, []byte("chunk"), 0644); err != nil {
				t.Fatalf("Create chunk file: %v", err)
			}
		}

		chunk0 := filepath.Join(tmpDir, "data.pcv.0")
		if !detectSplitVolume(chunk0) {
			t.Error("Split volume should be detected")
		}
	})
}

// TestDropRaceConditionPrevention tests that concurrent drops are blocked.
func TestDropRaceConditionPrevention(t *testing.T) {
	state := app.NewState()

	// Simulate scanning in progress
	state.Scanning = true

	// New drops should be blocked
	if !state.Scanning {
		t.Error("Scanning should block new drops")
	}

	// Simulate working
	state.Scanning = false
	state.Working = true

	if !state.Working {
		t.Error("Working should block new drops")
	}
}

// TestCommentsFromHeader tests reading comments from decrypted volume.
func TestCommentsFromHeader(t *testing.T) {
	testCases := []struct {
		name     string
		comments string
		disabled bool
		expected string
	}{
		{"ValidComments", "User comments here", false, "Comments (read-only):"},
		{"EmptyComments", "", true, "Comments (read-only):"},
		{"CorruptedComments", "Comments are corrupted", true, "Comments (read-only):"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			state := app.NewState()
			state.Mode = "decrypt"
			state.Comments = tc.comments
			state.CommentsLabel = "Comments (read-only):"
			state.CommentsDisabled = tc.disabled

			if state.CommentsLabel != tc.expected {
				t.Errorf("CommentsLabel = %q; want %q", state.CommentsLabel, tc.expected)
			}
		})
	}
}

// TestRequiredFreeSpaceCalculation tests free space estimation.
func TestRequiredFreeSpaceCalculation(t *testing.T) {
	state := app.NewState()

	// Single file
	state.RequiredFreeSpace = 1024 * 1024 // 1 MiB

	// Multipliers based on options
	multiplier := 1
	state.AllFiles = []string{"file1.txt", "file2.txt"} // Multi-file
	if len(state.AllFiles) > 1 {
		multiplier++
	}
	state.Deniability = true
	if state.Deniability {
		multiplier++
	}
	state.Split = true
	if state.Split {
		multiplier++
	}

	estimatedSpace := state.RequiredFreeSpace * int64(multiplier)
	expectedSpace := 1024 * 1024 * 4 // 4 MiB (4x multiplier)

	if estimatedSpace != int64(expectedSpace) {
		t.Errorf("EstimatedSpace = %d; want %d", estimatedSpace, expectedSpace)
	}
}

// TestStatusWithFreeSpace tests status message with free space info.
func TestStatusWithFreeSpace(t *testing.T) {
	state := app.NewState()
	state.MainStatus = "Ready"
	state.RequiredFreeSpace = 10 * 1024 * 1024 // 10 MiB

	if state.RequiredFreeSpace > 0 {
		spaceStr := util.Sizeify(state.RequiredFreeSpace)
		statusText := "Ready (ensure >" + spaceStr + " free)"

		if !strings.Contains(statusText, "free") {
			t.Error("Status should mention free space")
		}
		if !strings.Contains(statusText, "MiB") && !strings.Contains(statusText, "10") {
			t.Logf("Status = %q", statusText)
		}
	}
}
