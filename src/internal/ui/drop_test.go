// Package ui provides tests for file drop handling logic.
package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/util"
	"bytes"
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
)

// TestFileTypeDetection tests detection of encrypted vs plain files.
func TestFileTypeDetection(t *testing.T) {
	testCases := []struct {
		name     string
		filename string
		isPcv    bool
		isSplit  bool
	}{
		{"PlainText", "document.txt", false, false},
		{"PlainPDF", "report.pdf", false, false},
		{"EncryptedPcv", "secret.pcv", true, false},
		{"EncryptedPcvUppercase", "secret.PCV", true, false},
		{"SplitChunk0", "secret.pcv.0", true, true},
		{"SplitChunk1", "secret.pcv.1", true, true},
		{"SplitChunk99", "secret.pcv.99", true, true},
		{"FakeSplit", "file.pcv.txt", false, false},
		{"FalsePositiveBackup", "backup.pcv.tmp1", false, false},
		{"FalsePositiveVersioned", "notes.pcv.v2", false, false},
		{"DeepPath", "/path/to/secret.pcv", true, false},
		{"DeepSplit", "/path/to/secret.pcv.5", true, true},
		{"NoExtension", "document", false, false},
		{"HiddenFile", ".hidden.pcv", true, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Exercise the production classifiers directly: isDecryptVolumePath
			// (drop.go) decides encrypt-vs-decrypt mode (a split chunk is also a
			// decrypt volume), IsSplitChunkPath (fileops) decides recombine.
			isDecrypt := isDecryptVolumePath(tc.filename)
			isSplit := fileops.IsSplitChunkPath(tc.filename)

			// tc.isPcv == "is this dropped as a volume to decrypt?"
			if isDecrypt != tc.isPcv {
				t.Errorf("isDecryptVolumePath = %v; want %v for %q", isDecrypt, tc.isPcv, tc.filename)
			}
			if isSplit != tc.isSplit {
				t.Errorf("IsSplitChunkPath = %v; want %v for %q", isSplit, tc.isSplit, tc.filename)
			}
		})
	}
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
			basePath, ok := fileops.SplitChunkBase(tc.chunkPath)
			if !ok {
				t.Fatalf("SplitChunkBase(%q) returned ok=false", tc.chunkPath)
			}

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
		{"UppercasePcv", "/path/SECRET.PCV", "/path/SECRET"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := trimPCVSuffix(tc.inputPath)

			if output != tc.outputPath {
				t.Errorf("output = %q; want %q", output, tc.outputPath)
			}
		})
	}
}

// TestMultipleDropLabels drives the real handleMultipleDrop (via onDrop) with
// actual files/folders on disk and asserts the rendered input label it produces.
// The label grammar (singular/plural, "and") is production logic in drop.go and
// app.go; this test must fail if that logic changes, so it never recomputes the
// expected string itself.
func TestMultipleDropLabels(t *testing.T) {
	if raceEnabled {
		// Drives real onDrop with folders, whose background scan goroutine calls
		// refreshAdvanced -> the split-unit Select refresh. That measures glyphs on
		// the render goroutine concurrently with the go-text cmapCache first-write,
		// tripping the upstream Fyne v2.7.x font-cache race this file quarantines
		// (same reason as the scheduleStartupPaths tests). Runs on the arm64 matrix.
		t.Skip("Fyne internal font-cache races under -race; covered on arm64 matrix")
	}
	fyneApp := newTestFyneApp(t)

	testCases := []struct {
		name     string
		files    int
		folders  int
		expected string
	}{
		{"OnlyFiles_2", 2, 0, trn("selection.files", "{{.Count}} files", 2, map[string]any{"Count": 2})},
		{"OnlyFiles_5", 5, 0, trn("selection.files", "{{.Count}} files", 5, map[string]any{"Count": 5})},
		{"OnlyFolders_2", 0, 2, trn("selection.folders", "{{.Count}} folders", 2, map[string]any{"Count": 2})},
		{"OnlyFolders_5", 0, 5, trn("selection.folders", "{{.Count}} folders", 5, map[string]any{"Count": 5})},
		{"1File1Folder", 1, 1, tr("selection.mixed", "{{.Files}} and {{.Folders}}", map[string]any{"Files": "1 file", "Folders": "1 folder"})},
		{"1FileManyFolders", 1, 3, tr("selection.mixed", "{{.Files}} and {{.Folders}}", map[string]any{"Files": "1 file", "Folders": "3 folders"})},
		{"ManyFiles1Folder", 3, 1, tr("selection.mixed", "{{.Files}} and {{.Folders}}", map[string]any{"Files": "3 files", "Folders": "1 folder"})},
		{"ManyBoth", 3, 2, tr("selection.mixed", "{{.Files}} and {{.Folders}}", map[string]any{"Files": "3 files", "Folders": "2 folders"})},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			a := createUIReadyDropTestApp(t, fyneApp)
			dir := t.TempDir()

			var paths []string
			for i := range tc.files {
				p := filepath.Join(dir, "file"+strconv.Itoa(i)+".txt")
				if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
					t.Fatalf("write file: %v", err)
				}
				paths = append(paths, p)
			}
			for i := range tc.folders {
				p := filepath.Join(dir, "folder"+strconv.Itoa(i))
				if err := os.Mkdir(p, 0o755); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				paths = append(paths, p)
			}

			fyne.DoAndWait(func() {
				a.onDrop(paths)
			})
			waitForDropProcessing(t, a)

			var label string
			fyne.DoAndWait(func() {
				snap := a.State.UISnapshot()
				label = renderInputSummary(snap.InputSummary)
			})
			// handleMultipleDrop appends a " (size)" summary for the file count;
			// the grammar prefix is what this test pins.
			if !strings.HasPrefix(label, tc.expected) {
				t.Errorf("InputLabel = %q; want prefix %q", label, tc.expected)
			}
		})
	}
}

func TestApplyDropErrorPreservesStatusAfterReset(t *testing.T) {
	newTestFyneApp(t)

	testCases := []struct {
		name              string
		status            string
		closeKeyfileModal bool
	}{
		{name: "DecryptDrop", status: "Read access denied", closeKeyfileModal: false},
		{name: "KeyfileDrop", status: "Cannot read keyfile", closeKeyfileModal: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			a := &App{
				State:             mustNewState(t),
				advancedContainer: container.NewVBox(),
			}
			a.State.SetStartAction(app.StartActionDecrypt)
			a.State.SetStatus("Old status", util.GREEN)

			a.applyDropError(tc.status, tc.closeKeyfileModal)

			snap := a.State.UISnapshot()
			if snap.StartAction != app.StartActionStart {
				t.Fatalf("expected resetUI() to run, StartAction = %v", snap.StartAction)
			}
			if snap.Status.Kind != app.StatusCustom || snap.Status.Text != tc.status {
				t.Fatalf("Status = %#v, want custom %q", snap.Status, tc.status)
			}
			if snap.Status.Color != util.RED {
				t.Fatalf("Status.Color = %#v, want %#v", snap.Status.Color, util.RED)
			}
		})
	}
}

func TestApplyStartupPathsLoadsInitialFiles(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	inputFile := filepath.Join(t.TempDir(), "report.txt")
	if err := os.WriteFile(inputFile, []byte("quarterly report"), 0o644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	fyne.DoAndWait(func() {
		a.applyStartupPaths([]string{inputFile})
	})
	waitForDropProcessing(t, a)
	state := snapshotDropState(t, a)

	if state.Mode != "encrypt" {
		t.Fatalf("Mode = %q; want encrypt", state.Mode)
	}
	if state.InputFile != inputFile {
		t.Fatalf("InputFile = %q; want %q", state.InputFile, inputFile)
	}
	if state.OutputFile != inputFile+".pcv" {
		t.Fatalf("OutputFile = %q; want %q", state.OutputFile, inputFile+".pcv")
	}
	if len(state.AllFiles) != 1 || state.AllFiles[0] != inputFile {
		t.Fatalf("AllFiles = %#v; want [%q]", state.AllFiles, inputFile)
	}
	if len(state.OnlyFiles) != 1 || state.OnlyFiles[0] != inputFile {
		t.Fatalf("OnlyFiles = %#v; want [%q]", state.OnlyFiles, inputFile)
	}
}

func TestApplyStartupPathsLoadsDecryptVolume(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	inputFile := filepath.Join("..", "..", "testdata", "golden", "pico_test_v2.txt.pcv")

	fyne.DoAndWait(func() {
		a.applyStartupPaths([]string{inputFile})
	})
	state := snapshotDropState(t, a)

	if state.Mode != "decrypt" {
		t.Fatalf("Mode = %q; want decrypt", state.Mode)
	}
	if state.InputFile != inputFile {
		t.Fatalf("InputFile = %q; want %q", state.InputFile, inputFile)
	}
	if state.OutputFile != strings.TrimSuffix(inputFile, ".pcv") {
		t.Fatalf("OutputFile = %q; want %q", state.OutputFile, strings.TrimSuffix(inputFile, ".pcv"))
	}
	if len(state.OnlyFiles) != 1 || state.OnlyFiles[0] != inputFile {
		t.Fatalf("OnlyFiles = %#v; want [%q]", state.OnlyFiles, inputFile)
	}
}

func TestApplyStartupPathsWithMacOSProcessSerialLoadsDecryptVolume(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	inputFile := filepath.Join("..", "..", "testdata", "golden", "pico_test_v2.txt.pcv")

	fyne.DoAndWait(func() {
		a.applyStartupPaths([]string{"-psn_0_12345", inputFile})
	})
	state := snapshotDropState(t, a)

	if state.Mode != "decrypt" {
		t.Fatalf("Mode = %q; want decrypt", state.Mode)
	}
	if state.InputFile != inputFile {
		t.Fatalf("InputFile = %q; want %q", state.InputFile, inputFile)
	}
}

func TestApplyStartupPathsTreatsUppercaseVolumeExtensionAsDecrypt(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	tempDir := t.TempDir()
	original := filepath.Join("..", "..", "testdata", "golden", "pico_test_v2.txt.pcv")
	inputFile := filepath.Join(tempDir, "PICO_TEST_V2.TXT.PCV")
	data, err := os.ReadFile(original)
	if err != nil {
		t.Fatalf("Read golden volume: %v", err)
	}
	if err := os.WriteFile(inputFile, data, 0o644); err != nil {
		t.Fatalf("Write uppercase volume: %v", err)
	}

	fyne.DoAndWait(func() {
		a.applyStartupPaths([]string{inputFile})
	})
	state := snapshotDropState(t, a)

	if state.Mode != "decrypt" {
		t.Fatalf("Mode = %q; want decrypt", state.Mode)
	}
	if state.InputFile != inputFile {
		t.Fatalf("InputFile = %q; want %q", state.InputFile, inputFile)
	}
	if state.OutputFile != strings.TrimSuffix(inputFile, ".PCV") {
		t.Fatalf("OutputFile = %q; want %q", state.OutputFile, strings.TrimSuffix(inputFile, ".PCV"))
	}
}

func TestApplyStartupPathsIgnoresMacOSProcessSerialNumber(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)

	fyne.DoAndWait(func() {
		a.applyStartupPaths([]string{"-psn_0_12345"})
	})
	state := snapshotDropState(t, a)

	if state.MainStatus != "Ready" {
		t.Fatalf("MainStatus = %q; want Ready", state.MainStatus)
	}
	if state.Mode != "" {
		t.Fatalf("Mode = %q; want empty", state.Mode)
	}
	if state.InputFile != "" {
		t.Fatalf("InputFile = %q; want empty", state.InputFile)
	}
}

func TestApplyStartupPathsIgnoresMissingNonFlagArgs(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)

	fyne.DoAndWait(func() {
		a.applyStartupPaths([]string{filepath.Join(t.TempDir(), "missing.txt")})
	})
	state := snapshotDropState(t, a)

	if state.MainStatus != "Ready" {
		t.Fatalf("MainStatus = %q; want Ready", state.MainStatus)
	}
	if state.Mode != "" {
		t.Fatalf("Mode = %q; want empty", state.Mode)
	}
}

func TestApplyStartupPathsSkipsInvalidArgsWhenValidPathsRemain(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	tempDir := t.TempDir()
	missingPath := filepath.Join(tempDir, "missing.txt")
	inputFile := filepath.Join(tempDir, "report.txt")
	if err := os.WriteFile(inputFile, []byte("quarterly report"), 0o644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	fyne.DoAndWait(func() {
		a.applyStartupPaths([]string{missingPath, inputFile})
	})
	waitForDropProcessing(t, a)
	state := snapshotDropState(t, a)

	if state.Mode != "encrypt" {
		t.Fatalf("Mode = %q; want encrypt", state.Mode)
	}
	if state.InputFile != inputFile {
		t.Fatalf("InputFile = %q; want %q", state.InputFile, inputFile)
	}
	snap := a.State.UISnapshot()
	if snap.Status.Kind != app.StatusReady {
		t.Fatalf("Status.Kind = %v; want StatusReady", snap.Status.Kind)
	}
}

func TestApplyStartupPathsAllowsHyphenPrefixedFilename(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	inputFile := filepath.Join(t.TempDir(), "-secret.txt")
	if err := os.WriteFile(inputFile, []byte("secret"), 0o644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	fyne.DoAndWait(func() {
		a.applyStartupPaths([]string{inputFile})
	})
	waitForDropProcessing(t, a)
	state := snapshotDropState(t, a)

	if state.Mode != "encrypt" {
		t.Fatalf("Mode = %q; want encrypt", state.Mode)
	}
	if state.InputFile != inputFile {
		t.Fatalf("InputFile = %q; want %q", state.InputFile, inputFile)
	}
}

func TestApplyStartupPathsReportsAccessError(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	originalStat := startupPathStat
	startupPathStat = func(path string) (os.FileInfo, error) {
		return nil, os.ErrPermission
	}
	defer func() {
		startupPathStat = originalStat
	}()

	fyne.DoAndWait(func() {
		a.applyStartupPaths([]string{"blocked.txt"})
	})

	snap := a.State.UISnapshot()
	if got := renderStatus(snap.Status, snap); got != startupPathAccessStatus() {
		t.Fatalf("rendered status = %q; want %q", got, startupPathAccessStatus())
	}
	if snap.Status.Color != util.RED {
		t.Fatalf("Status.Color = %#v; want %#v", snap.Status.Color, util.RED)
	}
}

func TestApplyStartupPathsPreservesPartialAccessWarning(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	inputFile := filepath.Join(t.TempDir(), "report.txt")
	if err := os.WriteFile(inputFile, []byte("quarterly report"), 0o644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	originalStat := startupPathStat
	startupPathStat = func(path string) (os.FileInfo, error) {
		if path == "blocked.txt" {
			return nil, os.ErrPermission
		}
		return originalStat(path)
	}
	defer func() {
		startupPathStat = originalStat
	}()

	fyne.DoAndWait(func() {
		a.applyStartupPaths([]string{"blocked.txt", inputFile})
	})
	waitForDropProcessing(t, a)
	state := snapshotDropState(t, a)

	if state.Mode != "encrypt" {
		t.Fatalf("Mode = %q; want encrypt", state.Mode)
	}
	if state.InputFile != inputFile {
		t.Fatalf("InputFile = %q; want %q", state.InputFile, inputFile)
	}
	snap := a.State.UISnapshot()
	if got := renderStatus(snap.Status, snap); got != startupPathPartialAccessStatus() {
		t.Fatalf("rendered status = %q; want %q", got, startupPathPartialAccessStatus())
	}
}

func TestCollectStartupPathsAllowsHyphenPrefixedFilename(t *testing.T) {
	validPaths, err := collectStartupPaths([]string{"-secret.txt"}, func(path string) (os.FileInfo, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatalf("collectStartupPaths returned error: %v", err)
	}
	if len(validPaths) != 1 || validPaths[0] != "-secret.txt" {
		t.Fatalf("validPaths = %#v; want [-secret.txt]", validPaths)
	}
}

func TestCollectStartupPathsSkipsMissingAndReportsAccessError(t *testing.T) {
	validPaths, err := collectStartupPaths([]string{"missing.txt", "blocked.txt"}, func(path string) (os.FileInfo, error) {
		switch path {
		case "missing.txt":
			return nil, os.ErrNotExist
		case "blocked.txt":
			return nil, os.ErrPermission
		default:
			return nil, nil
		}
	})
	if len(validPaths) != 0 {
		t.Fatalf("validPaths = %#v; want empty", validPaths)
	}
	if err == nil {
		t.Fatal("collectStartupPaths should report non-missing access errors")
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("error = %v; want permission error", err)
	}
}

func TestAppendScannedFilesUpdatesState(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)

	files := []scannedFile{
		{path: "/tmp/a.txt", size: 10},
		{path: "/tmp/b.txt", size: 25},
	}

	fyne.DoAndWait(func() {
		a.appendScannedFiles(files)
	})

	state := snapshotDropState(t, a)
	if len(state.AllFiles) != 2 {
		t.Fatalf("AllFiles = %#v; want 2 entries", state.AllFiles)
	}
	if a.State.CompressTotal != 35 {
		t.Fatalf("CompressTotal = %d; want 35", a.State.CompressTotal)
	}
	if a.State.RequiredFreeSpace != 35 {
		t.Fatalf("RequiredFreeSpace = %d; want 35", a.State.RequiredFreeSpace)
	}
	snap := a.State.UISnapshot()
	label := renderInputSummary(snap.InputSummary)
	if !strings.Contains(label, util.Sizeify(35)) {
		t.Fatalf("rendered input label = %q; want size summary %q", label, util.Sizeify(35))
	}
}

func TestFolderWalkErrorClearsScanningState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission-based walk failure setup is not reliable on Windows")
	}

	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	rootDir := t.TempDir()
	blockedDir := filepath.Join(rootDir, "blocked")
	if err := os.Mkdir(blockedDir, 0o700); err != nil {
		t.Fatalf("create blocked dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rootDir, "visible.txt"), []byte("ok"), 0o600); err != nil {
		t.Fatalf("create visible file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(blockedDir, "secret.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatalf("create blocked file: %v", err)
	}
	if err := os.Chmod(blockedDir, 0); err != nil {
		t.Fatalf("chmod blocked dir: %v", err)
	}
	defer func() {
		_ = os.Chmod(blockedDir, 0o700)
	}()

	fyne.DoAndWait(func() {
		a.onDrop([]string{rootDir})
	})

	waitForDropProcessing(t, a)
	fyne.DoAndWait(func() {})

	if a.State.IsScanning() {
		t.Fatal("Scanning should be false after folder walk error")
	}
}

func TestScheduleStartupPathsDefersUntilLifecycleStart(t *testing.T) {
	if raceEnabled {
		// Skipped under -race: Fyne v2.7.3 internal/cache/base.go
		// expiringCache.setAlive performs racy first-writes on combinatorial
		// font/glyph cache keys when test.NewApp drives Button.SetText →
		// Refresh → MeasureText. The race is benign (first writes converge),
		// not in our code, and the test still runs on the no-race matrix
		// (Linux arm64). Re-evaluate when Fyne ships a fix upstream.
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	withOpenedPathsFlushDelay(t, 10*time.Millisecond)

	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	inputFile := filepath.Join(t.TempDir(), "startup.txt")
	if err := os.WriteFile(inputFile, []byte("payload"), 0o644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	fake := newLifecycleCaptureApp(fyne.CurrentApp())
	a.fyneApp = fake

	a.scheduleStartupPaths([]string{inputFile})

	state := snapshotDropState(t, a)
	if state.InputFile != "" {
		t.Fatalf("InputFile = %q before start hook; want empty", state.InputFile)
	}
	if fake.started == nil {
		t.Fatal("expected startup hook to be registered")
	}

	fake.started()
	waitForInputFile(t, a, inputFile)
	state = snapshotDropState(t, a)

	if state.InputFile != inputFile {
		t.Fatalf("InputFile = %q after start hook; want %q", state.InputFile, inputFile)
	}
}

func TestScheduleStartupPathsSkipsMissingArgvWhenValidPathsRemain(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	resetOpenedPathsForTest(t)
	withOpenedPathsFlushDelay(t, 10*time.Millisecond)

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	tempDir := t.TempDir()
	missingPath := filepath.Join(tempDir, "missing.txt")
	inputFile := filepath.Join(tempDir, "report.txt")
	if err := os.WriteFile(inputFile, []byte("quarterly report"), 0o644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	fake := newLifecycleCaptureApp(fyne.CurrentApp())
	a.fyneApp = fake
	a.scheduleStartupPaths([]string{missingPath, inputFile})
	if fake.started == nil {
		t.Fatal("expected startup hook to be registered")
	}

	fake.started()
	waitForInputFile(t, a, inputFile)
	state := snapshotDropState(t, a)
	if state.InputFile != inputFile {
		t.Fatalf("InputFile = %q; want %q", state.InputFile, inputFile)
	}
}

func TestScheduleStartupPathsPreservesPartialAccessWarningForArgv(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	resetOpenedPathsForTest(t)
	withOpenedPathsFlushDelay(t, 10*time.Millisecond)

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	inputFile := filepath.Join(t.TempDir(), "report.txt")
	if err := os.WriteFile(inputFile, []byte("quarterly report"), 0o644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	originalStat := startupPathStat
	startupPathStat = func(path string) (os.FileInfo, error) {
		if path == "blocked.txt" {
			return nil, os.ErrPermission
		}
		return originalStat(path)
	}
	defer func() {
		startupPathStat = originalStat
	}()

	fake := newLifecycleCaptureApp(fyne.CurrentApp())
	a.fyneApp = fake
	a.scheduleStartupPaths([]string{"blocked.txt", inputFile})
	if fake.started == nil {
		t.Fatal("expected startup hook to be registered")
	}

	fake.started()
	waitForInputFile(t, a, inputFile)
	state := snapshotDropState(t, a)
	if state.InputFile != inputFile {
		t.Fatalf("InputFile = %q; want %q", state.InputFile, inputFile)
	}
	snap := a.State.UISnapshot()
	if got := renderStatus(snap.Status, snap); got != startupPathPartialAccessStatus() {
		t.Fatalf("rendered status = %q; want %q", got, startupPathPartialAccessStatus())
	}
}

// TestScheduleStartupPathsAlwaysWiresStartHook verifies that scheduleStartupPaths
// registers the OnStarted callback even when startupPaths is empty. On darwin,
// Apple-Event-buffered paths from a Finder cold launch may be the only source
// of startup paths and are drained inside the OnStarted closure via
// drainOpenedPaths(). Removing the wiring on empty input would silently lose
// those events. (FA-MAC-03 / Plan 03-03)
func TestScheduleStartupPathsAlwaysWiresStartHook(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}

	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)

	fake := newLifecycleCaptureApp(fyne.CurrentApp())
	a.fyneApp = fake

	a.scheduleStartupPaths(nil)

	if fake.started == nil {
		t.Fatal("expected startup hook to be registered even for empty startupPaths (AE paths may arrive)")
	}

	// Firing the hook with empty CLI args + nil drain (non-darwin stub returns nil)
	// must be a safe no-op: no panic, no state mutation.
	fake.started()
	waitForDropProcessing(t, a)
	state := snapshotDropState(t, a)
	if state.InputFile != "" {
		t.Fatalf("InputFile = %q after start hook with no inputs; want empty", state.InputFile)
	}
}

// TestScheduleStartupPathsAppliesWarmOpenedPaths covers issue #127: a path opened
// while the app is already running (a warm application:openURLs: event, simulated
// here by appendOpenedPath after the lifecycle start hook fired) must be drained
// and applied through the normal drop handler. Before the event-driven wiring,
// drainOpenedPaths ran exactly once inside the start hook, so any path arriving
// afterward was silently lost — the app merely came to the foreground.
func TestScheduleStartupPathsAppliesWarmOpenedPaths(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	withOpenedPathsFlushDelay(t, 10*time.Millisecond)

	// Reset package-global bridge state: other tests fire the start hook and leave
	// a notify handler registered.
	setOpenedPathsNotify(nil)
	drainOpenedPaths()
	t.Cleanup(func() {
		setOpenedPathsNotify(nil)
		drainOpenedPaths()
	})

	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	inputFile := filepath.Join(t.TempDir(), "warm-open.txt")
	if err := os.WriteFile(inputFile, []byte("payload"), 0o644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	fake := newLifecycleCaptureApp(fyne.CurrentApp())
	a.fyneApp = fake

	a.scheduleStartupPaths(nil)
	if fake.started == nil {
		t.Fatal("expected startup hook to be registered")
	}

	// Fire the start hook with nothing buffered: still no input applied.
	fake.started()
	waitForDropProcessing(t, a)
	if state := snapshotDropState(t, a); state.InputFile != "" {
		t.Fatalf("InputFile = %q before any opened path; want empty", state.InputFile)
	}

	// A warm openURLs event arrives after launch: the bridge appends the
	// path(s) for the event, then flushes once, which fires the notify handler.
	appendOpenedPath(inputFile)
	flushOpenedPaths()
	waitForInputFile(t, a, inputFile)

	if state := snapshotDropState(t, a); state.InputFile != inputFile {
		t.Fatalf("InputFile = %q after warm opened path; want %q", state.InputFile, inputFile)
	}
}

func TestSeparateWarmOpenedPathReplacesSelectionAfterFirstSessionApplied(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	withOpenedPathsFlushDelay(t, 10*time.Millisecond)
	setOpenedPathsNotify(nil)
	drainOpenedPaths()
	t.Cleanup(func() {
		setOpenedPathsNotify(nil)
		drainOpenedPaths()
	})

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	tempDir := t.TempDir()
	first := filepath.Join(tempDir, "first.txt")
	second := filepath.Join(tempDir, "second.txt")
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, []byte("payload"), 0o644); err != nil {
			t.Fatalf("Create test file %q: %v", path, err)
		}
	}

	fake := newLifecycleCaptureApp(fyne.CurrentApp())
	a.fyneApp = fake
	a.scheduleStartupPaths(nil)
	fake.started()

	appendOpenedPath(first)
	flushOpenedPaths()
	waitForInputFile(t, a, first)

	appendOpenedPath(second)
	flushOpenedPaths()
	waitForInputFile(t, a, second)

	state := snapshotDropState(t, a)
	if !reflect.DeepEqual(state.AllFiles, []string{second}) {
		t.Fatalf("AllFiles = %#v; want separate later open to replace with [%q]", state.AllFiles, second)
	}
}

func TestScheduleStartupPathsCoalescesColdAndLateOpenedBatches(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	withOpenedPathsFlushDelay(t, 25*time.Millisecond)

	setOpenedPathsNotify(nil)
	drainOpenedPaths()
	t.Cleanup(func() {
		setOpenedPathsNotify(nil)
		drainOpenedPaths()
	})

	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	tempDir := t.TempDir()
	paths := []string{
		filepath.Join(tempDir, "a.txt"),
		filepath.Join(tempDir, "b.txt"),
		filepath.Join(tempDir, "c.txt"),
	}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("payload"), 0o644); err != nil {
			t.Fatalf("Create test file %q: %v", path, err)
		}
	}

	appendOpenedPath(paths[0])
	appendOpenedPath(paths[1])

	fake := newLifecycleCaptureApp(fyne.CurrentApp())
	a.fyneApp = fake
	a.scheduleStartupPaths(nil)
	if fake.started == nil {
		t.Fatal("expected startup hook to be registered")
	}
	fake.started()

	appendOpenedPath(paths[2])
	flushOpenedPaths()

	waitForAllFiles(t, a, paths)
}

func TestOpenedPathsWaitForReadinessBeforeApply(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	resetOpenedPathsForTest(t)
	withOpenedPathsFlushDelay(t, 10*time.Millisecond)
	oldCheck := checkOpenedPathReadiness
	oldPoll := openedPathPollInterval
	checks := 0
	defer func() {
		checkOpenedPathReadiness = oldCheck
		openedPathPollInterval = oldPoll
	}()
	openedPathPollInterval = 5 * time.Millisecond

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	inputFile := filepath.Join(t.TempDir(), "icloud.txt")
	if err := os.WriteFile(inputFile, []byte("payload"), 0o644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	checkOpenedPathReadiness = func(ctx context.Context, paths []string) openedPathReadinessResult {
		checks++
		if checks == 1 {
			return openedPathReadinessResult{{Path: inputFile, State: openedPathPending}}
		}
		return openedPathReadinessResult{{Path: inputFile, State: openedPathReady}}
	}

	fake := newLifecycleCaptureApp(fyne.CurrentApp())
	a.fyneApp = fake
	a.scheduleStartupPaths(nil)
	fake.started()
	appendOpenedPath(inputFile)
	flushOpenedPaths()

	waitForInputFile(t, a, inputFile)
	if checks < 2 {
		t.Fatalf("readiness checks = %d; want at least 2", checks)
	}
}

func TestOpenedPathsMergeLateICloudFileDeliveriesDuringReadiness(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	resetOpenedPathsForTest(t)
	oldCheck := checkOpenedPathReadiness
	oldPoll := openedPathPollInterval
	oldSettle := openedPathCloudSettleDelay
	defer func() {
		checkOpenedPathReadiness = oldCheck
		openedPathPollInterval = oldPoll
		openedPathCloudSettleDelay = oldSettle
	}()
	openedPathPollInterval = 5 * time.Millisecond
	openedPathCloudSettleDelay = 40 * time.Millisecond

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	tempDir := t.TempDir()
	first := filepath.Join(tempDir, "icloud-first.txt")
	second := filepath.Join(tempDir, "icloud-second.txt")
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, []byte("payload"), 0o644); err != nil {
			t.Fatalf("Create test file %q: %v", path, err)
		}
	}

	release := make(chan struct{})
	checkOpenedPathReadiness = func(ctx context.Context, paths []string) openedPathReadinessResult {
		result := make(openedPathReadinessResult, 0, len(paths))
		for _, path := range paths {
			item := openedPathReadiness{Path: path, State: openedPathPending, IsUbiquitous: true}
			select {
			case <-release:
				item.State = openedPathReady
			default:
			}
			result = append(result, item)
		}
		return result
	}

	a.applyOpenedPaths([]string{first})
	waitForOpenedPathLateCollection(t, a)

	a.applyOpenedPaths([]string{second})
	close(release)

	waitForAllFiles(t, a, []string{first, second})
}

func TestOpenedPathsCollectsReadyUbiquitousFilesAcrossSlowCallbacks(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	resetOpenedPathsForTest(t)
	oldCheck := checkOpenedPathReadiness
	oldPoll := openedPathPollInterval
	oldSettle := openedPathCloudSettleDelay
	defer func() {
		checkOpenedPathReadiness = oldCheck
		openedPathPollInterval = oldPoll
		openedPathCloudSettleDelay = oldSettle
	}()
	openedPathPollInterval = 5 * time.Millisecond
	openedPathCloudSettleDelay = 80 * time.Millisecond

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	tempDir := t.TempDir()
	first := filepath.Join(tempDir, "ready-icloud-first.txt")
	second := filepath.Join(tempDir, "ready-icloud-second.txt")
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, []byte("payload"), 0o644); err != nil {
			t.Fatalf("Create test file %q: %v", path, err)
		}
	}

	checkStarted := make(chan struct{})
	checkOpenedPathReadiness = func(ctx context.Context, paths []string) openedPathReadinessResult {
		select {
		case <-checkStarted:
		default:
			close(checkStarted)
		}
		result := make(openedPathReadinessResult, 0, len(paths))
		for _, path := range paths {
			result = append(result, openedPathReadiness{Path: path, State: openedPathReady, IsUbiquitous: true})
		}
		return result
	}

	a.applyOpenedPaths([]string{first})
	select {
	case <-checkStarted:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for first readiness check")
	}

	time.Sleep(20 * time.Millisecond)
	a.applyOpenedPaths([]string{second})

	waitForAllFiles(t, a, []string{first, second})
}

func TestICloudFolderOpenDoesNotWaitForLateFileCollection(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	resetOpenedPathsForTest(t)
	oldCheck := checkOpenedPathReadiness
	oldPoll := openedPathPollInterval
	oldSettle := openedPathCloudSettleDelay
	defer func() {
		checkOpenedPathReadiness = oldCheck
		openedPathPollInterval = oldPoll
		openedPathCloudSettleDelay = oldSettle
	}()
	openedPathPollInterval = 5 * time.Millisecond
	openedPathCloudSettleDelay = time.Hour

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	folder := filepath.Join(t.TempDir(), "icloud-folder")
	if err := os.Mkdir(folder, 0o755); err != nil {
		t.Fatalf("Create test folder: %v", err)
	}
	if err := os.WriteFile(filepath.Join(folder, "child.txt"), []byte("payload"), 0o644); err != nil {
		t.Fatalf("Create child file: %v", err)
	}

	checkOpenedPathReadiness = func(ctx context.Context, paths []string) openedPathReadinessResult {
		result := make(openedPathReadinessResult, 0, len(paths))
		for _, path := range paths {
			result = append(result, openedPathReadiness{
				Path:         path,
				State:        openedPathReady,
				IsUbiquitous: true,
				IsDir:        true,
			})
		}
		return result
	}

	a.applyOpenedPaths([]string{folder})
	waitForOnlyFolders(t, a, []string{folder})
}

func TestManualDropCancelsCloudOpenCollectionAndSuppressesLateFiles(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	resetOpenedPathsForTest(t)
	oldCheck := checkOpenedPathReadiness
	oldPoll := openedPathPollInterval
	oldSettle := openedPathCloudSettleDelay
	oldSuppress := openedPathCloudCancelSuppressDelay
	defer func() {
		checkOpenedPathReadiness = oldCheck
		openedPathPollInterval = oldPoll
		openedPathCloudSettleDelay = oldSettle
		openedPathCloudCancelSuppressDelay = oldSuppress
	}()
	openedPathPollInterval = 5 * time.Millisecond
	openedPathCloudSettleDelay = 20 * time.Millisecond
	openedPathCloudCancelSuppressDelay = 500 * time.Millisecond

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	tempDir := t.TempDir()
	cloudFirst := filepath.Join(tempDir, "cloud-first.txt")
	cloudLate := filepath.Join(tempDir, "cloud-late.txt")
	manual := filepath.Join(tempDir, "manual.txt")
	for _, path := range []string{cloudFirst, cloudLate, manual} {
		if err := os.WriteFile(path, []byte("payload"), 0o644); err != nil {
			t.Fatalf("Create test file %q: %v", path, err)
		}
	}

	release := make(chan struct{})
	checkOpenedPathReadiness = func(ctx context.Context, paths []string) openedPathReadinessResult {
		result := make(openedPathReadinessResult, 0, len(paths))
		for _, path := range paths {
			item := openedPathReadiness{Path: path, State: openedPathPending, IsUbiquitous: true}
			select {
			case <-release:
				item.State = openedPathReady
			default:
			}
			result = append(result, item)
		}
		return result
	}

	a.applyOpenedPaths([]string{cloudFirst})
	waitForOpenedPathLateCollection(t, a)

	fyne.DoAndWait(func() {
		a.cancelOpenedPathReadiness()
		a.onDrop([]string{manual})
	})
	a.applyOpenedPaths([]string{cloudLate})
	close(release)

	waitForInputFile(t, a, manual)
	assertInputFileDoesNotBecome(t, a, cloudLate, 200*time.Millisecond)
}

func TestManualDropCancelsReadinessBeforeCloudMetadataAndSuppressesLateFiles(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	resetOpenedPathsForTest(t)
	oldCheck := checkOpenedPathReadiness
	oldPoll := openedPathPollInterval
	oldSuppress := openedPathCloudCancelSuppressDelay
	defer func() {
		checkOpenedPathReadiness = oldCheck
		openedPathPollInterval = oldPoll
		openedPathCloudCancelSuppressDelay = oldSuppress
	}()
	openedPathPollInterval = 5 * time.Millisecond
	openedPathCloudCancelSuppressDelay = 500 * time.Millisecond

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	tempDir := t.TempDir()
	cloudFirst := filepath.Join(tempDir, "cloud-before-metadata.txt")
	cloudLate := filepath.Join(tempDir, "cloud-late-before-metadata.txt")
	manual := filepath.Join(tempDir, "manual-before-metadata.txt")
	for _, path := range []string{cloudFirst, cloudLate, manual} {
		if err := os.WriteFile(path, []byte("payload"), 0o644); err != nil {
			t.Fatalf("Create test file %q: %v", path, err)
		}
	}

	checkStarted := make(chan struct{})
	release := make(chan struct{})
	checkOpenedPathReadiness = func(ctx context.Context, paths []string) openedPathReadinessResult {
		select {
		case <-checkStarted:
		default:
			close(checkStarted)
		}
		select {
		case <-ctx.Done():
			return openedPathReadinessResult{{Path: paths[0], State: openedPathPending}}
		case <-release:
		}

		result := make(openedPathReadinessResult, 0, len(paths))
		for _, path := range paths {
			result = append(result, openedPathReadiness{Path: path, State: openedPathReady, IsUbiquitous: true})
		}
		return result
	}

	a.applyOpenedPaths([]string{cloudFirst})
	select {
	case <-checkStarted:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for readiness check to start")
	}

	fyne.DoAndWait(func() {
		a.cancelOpenedPathReadiness()
		a.onDrop([]string{manual})
	})
	a.applyOpenedPaths([]string{cloudLate})
	close(release)

	waitForInputFile(t, a, manual)
	assertInputFileDoesNotBecome(t, a, cloudLate, 200*time.Millisecond)
}

func TestLateICloudFileDuringQueuedReadyApplyExtendsSameSelection(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	resetOpenedPathsForTest(t)
	oldCheck := checkOpenedPathReadiness
	oldPoll := openedPathPollInterval
	oldSettle := openedPathCloudSettleDelay
	oldBeforeApply := beforeOpenedPathReadyApply
	defer func() {
		checkOpenedPathReadiness = oldCheck
		openedPathPollInterval = oldPoll
		openedPathCloudSettleDelay = oldSettle
		beforeOpenedPathReadyApply = oldBeforeApply
	}()
	openedPathPollInterval = 5 * time.Millisecond
	openedPathCloudSettleDelay = 0

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	tempDir := t.TempDir()
	first := filepath.Join(tempDir, "queued-ready-first.txt")
	second := filepath.Join(tempDir, "queued-ready-second.txt")
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, []byte("payload"), 0o644); err != nil {
			t.Fatalf("Create test file %q: %v", path, err)
		}
	}

	readyApplyStarted := make(chan struct{})
	releaseReadyApply := make(chan struct{})
	defer func() {
		select {
		case <-releaseReadyApply:
		default:
			close(releaseReadyApply)
		}
	}()
	beforeOpenedPathReadyApply = func() {
		select {
		case <-readyApplyStarted:
		default:
			close(readyApplyStarted)
		}
		<-releaseReadyApply
	}

	checkStarted := make(chan struct{})
	checkOpenedPathReadiness = func(ctx context.Context, paths []string) openedPathReadinessResult {
		select {
		case <-checkStarted:
		default:
			close(checkStarted)
		}
		result := make(openedPathReadinessResult, 0, len(paths))
		for _, path := range paths {
			result = append(result, openedPathReadiness{Path: path, State: openedPathReady, IsUbiquitous: true})
		}
		return result
	}

	a.applyOpenedPaths([]string{first})
	select {
	case <-checkStarted:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for readiness check to start")
	}
	select {
	case <-readyApplyStarted:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for ready apply to start")
	}

	a.applyOpenedPaths([]string{second})
	close(releaseReadyApply)

	waitForAllFiles(t, a, []string{first, second})
}

// TestOpenedPathsMergeSecondBatchDuringFirstReadinessCheck covers the #127
// loss window before late collection is enabled: a second openURLs batch that
// arrives while the very first readiness check is still running must extend
// the active session instead of replacing it.
func TestOpenedPathsMergeSecondBatchDuringFirstReadinessCheck(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	resetOpenedPathsForTest(t)
	oldCheck := checkOpenedPathReadiness
	oldPoll := openedPathPollInterval
	oldSettle := openedPathCloudSettleDelay
	defer func() {
		checkOpenedPathReadiness = oldCheck
		openedPathPollInterval = oldPoll
		openedPathCloudSettleDelay = oldSettle
	}()
	openedPathPollInterval = 5 * time.Millisecond
	openedPathCloudSettleDelay = 20 * time.Millisecond

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	tempDir := t.TempDir()
	first := filepath.Join(tempDir, "during-check-first.txt")
	second := filepath.Join(tempDir, "during-check-second.txt")
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, []byte("payload"), 0o644); err != nil {
			t.Fatalf("Create test file %q: %v", path, err)
		}
	}

	firstCheckToken := make(chan struct{}, 1)
	firstCheckToken <- struct{}{}
	firstCheckStarted := make(chan struct{})
	releaseFirstCheck := make(chan struct{})
	defer func() {
		select {
		case <-releaseFirstCheck:
		default:
			close(releaseFirstCheck)
		}
	}()
	checkOpenedPathReadiness = func(ctx context.Context, paths []string) openedPathReadinessResult {
		select {
		case <-firstCheckToken:
			close(firstCheckStarted)
			<-releaseFirstCheck
		default:
		}
		result := make(openedPathReadinessResult, 0, len(paths))
		for _, path := range paths {
			result = append(result, openedPathReadiness{Path: path, State: openedPathReady, IsUbiquitous: true})
		}
		return result
	}

	a.applyOpenedPaths([]string{first})
	select {
	case <-firstCheckStarted:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for first readiness check to start")
	}

	a.applyOpenedPaths([]string{second})
	close(releaseFirstCheck)

	waitForAllFiles(t, a, []string{first, second})
}

// TestLateICloudBatchAfterReadyApplyExtendsSameSelection covers the #127 loss
// window after apply: when a cloud-backed opened selection was already applied
// and Finder delivers another batch of the same gesture, the late batch must
// extend the applied selection instead of replacing it.
func TestLateICloudBatchAfterReadyApplyExtendsSameSelection(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	resetOpenedPathsForTest(t)
	oldCheck := checkOpenedPathReadiness
	oldPoll := openedPathPollInterval
	oldSettle := openedPathCloudSettleDelay
	defer func() {
		checkOpenedPathReadiness = oldCheck
		openedPathPollInterval = oldPoll
		openedPathCloudSettleDelay = oldSettle
	}()
	openedPathPollInterval = 5 * time.Millisecond
	openedPathCloudSettleDelay = 0

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	tempDir := t.TempDir()
	first := filepath.Join(tempDir, "post-apply-first.txt")
	second := filepath.Join(tempDir, "post-apply-second.txt")
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, []byte("payload"), 0o644); err != nil {
			t.Fatalf("Create test file %q: %v", path, err)
		}
	}

	checkOpenedPathReadiness = func(ctx context.Context, paths []string) openedPathReadinessResult {
		result := make(openedPathReadinessResult, 0, len(paths))
		for _, path := range paths {
			result = append(result, openedPathReadiness{Path: path, State: openedPathReady, IsUbiquitous: true})
		}
		return result
	}

	a.applyOpenedPaths([]string{first})
	waitForAllFiles(t, a, []string{first})

	a.applyOpenedPaths([]string{second})
	waitForAllFiles(t, a, []string{first, second})
}

// TestLateICloudFileBatchAfterFolderApplyExtendsSameSelection covers the #127
// folder variant: an iCloud folder applies immediately (it never enables late
// collection), so a file batch from the same gesture lands after apply and must
// extend the folder selection instead of replacing it.
func TestLateICloudFileBatchAfterFolderApplyExtendsSameSelection(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	resetOpenedPathsForTest(t)
	oldCheck := checkOpenedPathReadiness
	oldPoll := openedPathPollInterval
	oldSettle := openedPathCloudSettleDelay
	defer func() {
		checkOpenedPathReadiness = oldCheck
		openedPathPollInterval = oldPoll
		openedPathCloudSettleDelay = oldSettle
	}()
	openedPathPollInterval = 5 * time.Millisecond
	openedPathCloudSettleDelay = 20 * time.Millisecond

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	tempDir := t.TempDir()
	folder := filepath.Join(tempDir, "icloud-late-folder")
	if err := os.Mkdir(folder, 0o755); err != nil {
		t.Fatalf("Create test folder: %v", err)
	}
	if err := os.WriteFile(filepath.Join(folder, "child.txt"), []byte("payload"), 0o644); err != nil {
		t.Fatalf("Create child file: %v", err)
	}
	file := filepath.Join(tempDir, "icloud-late-file.txt")
	if err := os.WriteFile(file, []byte("payload"), 0o644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	checkOpenedPathReadiness = func(ctx context.Context, paths []string) openedPathReadinessResult {
		result := make(openedPathReadinessResult, 0, len(paths))
		for _, path := range paths {
			stat, err := os.Stat(path)
			result = append(result, openedPathReadiness{
				Path:         path,
				State:        openedPathReady,
				IsUbiquitous: true,
				IsDir:        err == nil && stat.IsDir(),
			})
		}
		return result
	}

	a.applyOpenedPaths([]string{folder})
	waitForOnlyFolders(t, a, []string{folder})

	a.applyOpenedPaths([]string{file})

	deadline := time.Now().Add(2 * time.Second)
	for {
		state := snapshotDropState(t, a)
		if reflect.DeepEqual(state.OnlyFolders, []string{folder}) && reflect.DeepEqual(state.OnlyFiles, []string{file}) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("selection = folders %#v, files %#v; want folder %q extended with file %q",
				state.OnlyFolders, state.OnlyFiles, folder, file)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestSeparateICloudOpenAfterMergeWindowReplacesSelection pins the gesture
// boundary: once the post-apply merge window has expired, a later cloud open is
// a separate gesture and replaces the selection — matching the local-file
// semantics in TestSeparateWarmOpenedPathReplacesSelectionAfterFirstSessionApplied.
func TestSeparateICloudOpenAfterMergeWindowReplacesSelection(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	resetOpenedPathsForTest(t)
	oldCheck := checkOpenedPathReadiness
	oldPoll := openedPathPollInterval
	oldSettle := openedPathCloudSettleDelay
	oldMergeWindow := openedPathCloudPostApplyMergeDelay
	defer func() {
		checkOpenedPathReadiness = oldCheck
		openedPathPollInterval = oldPoll
		openedPathCloudSettleDelay = oldSettle
		openedPathCloudPostApplyMergeDelay = oldMergeWindow
	}()
	openedPathPollInterval = 5 * time.Millisecond
	openedPathCloudSettleDelay = 0
	openedPathCloudPostApplyMergeDelay = 30 * time.Millisecond

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	tempDir := t.TempDir()
	first := filepath.Join(tempDir, "expired-window-first.txt")
	second := filepath.Join(tempDir, "expired-window-second.txt")
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, []byte("payload"), 0o644); err != nil {
			t.Fatalf("Create test file %q: %v", path, err)
		}
	}

	checkOpenedPathReadiness = func(ctx context.Context, paths []string) openedPathReadinessResult {
		result := make(openedPathReadinessResult, 0, len(paths))
		for _, path := range paths {
			result = append(result, openedPathReadiness{Path: path, State: openedPathReady, IsUbiquitous: true})
		}
		return result
	}

	a.applyOpenedPaths([]string{first})
	waitForAllFiles(t, a, []string{first})

	time.Sleep(80 * time.Millisecond)

	a.applyOpenedPaths([]string{second})
	waitForAllFiles(t, a, []string{second})
}

// TestManualDropAfterCloudApplySuppressesLateBatch ensures a manual drop that
// replaces an already-applied cloud open selection also suppresses late
// batches of that gesture: they must not overwrite what the user just chose.
func TestManualDropAfterCloudApplySuppressesLateBatch(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	resetOpenedPathsForTest(t)
	oldCheck := checkOpenedPathReadiness
	oldPoll := openedPathPollInterval
	oldSettle := openedPathCloudSettleDelay
	oldSuppress := openedPathCloudCancelSuppressDelay
	defer func() {
		checkOpenedPathReadiness = oldCheck
		openedPathPollInterval = oldPoll
		openedPathCloudSettleDelay = oldSettle
		openedPathCloudCancelSuppressDelay = oldSuppress
	}()
	openedPathPollInterval = 5 * time.Millisecond
	openedPathCloudSettleDelay = 0
	openedPathCloudCancelSuppressDelay = 500 * time.Millisecond

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	tempDir := t.TempDir()
	cloudFirst := filepath.Join(tempDir, "cloud-applied.txt")
	cloudLate := filepath.Join(tempDir, "cloud-late-after-apply.txt")
	manual := filepath.Join(tempDir, "manual-after-apply.txt")
	for _, path := range []string{cloudFirst, cloudLate, manual} {
		if err := os.WriteFile(path, []byte("payload"), 0o644); err != nil {
			t.Fatalf("Create test file %q: %v", path, err)
		}
	}

	checkOpenedPathReadiness = func(ctx context.Context, paths []string) openedPathReadinessResult {
		result := make(openedPathReadinessResult, 0, len(paths))
		for _, path := range paths {
			result = append(result, openedPathReadiness{Path: path, State: openedPathReady, IsUbiquitous: true})
		}
		return result
	}

	a.applyOpenedPaths([]string{cloudFirst})
	waitForAllFiles(t, a, []string{cloudFirst})

	fyne.DoAndWait(func() {
		a.cancelOpenedPathReadiness()
		a.onDrop([]string{manual})
	})
	a.applyOpenedPaths([]string{cloudLate})

	waitForInputFile(t, a, manual)
	assertInputFileDoesNotBecome(t, a, cloudLate, 200*time.Millisecond)
}

// TestForeignScanFinishesOpenedPathReadinessSession pins manual-drop priority:
// when a scan that does NOT belong to an opened-path gesture is running (no
// recent cloud apply record), a readiness session must finish at the apply
// gate instead of waiting out the scan and stomping the user's selection.
func TestForeignScanFinishesOpenedPathReadinessSession(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	resetOpenedPathsForTest(t)
	oldCheck := checkOpenedPathReadiness
	oldPoll := openedPathPollInterval
	oldSettle := openedPathCloudSettleDelay
	defer func() {
		checkOpenedPathReadiness = oldCheck
		openedPathPollInterval = oldPoll
		openedPathCloudSettleDelay = oldSettle
	}()
	openedPathPollInterval = 5 * time.Millisecond
	openedPathCloudSettleDelay = 0

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	cloudFile := filepath.Join(t.TempDir(), "cloud-during-foreign-scan.txt")
	if err := os.WriteFile(cloudFile, []byte("payload"), 0o644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	checkOpenedPathReadiness = func(ctx context.Context, paths []string) openedPathReadinessResult {
		result := make(openedPathReadinessResult, 0, len(paths))
		for _, path := range paths {
			result = append(result, openedPathReadiness{Path: path, State: openedPathReady, IsUbiquitous: true})
		}
		return result
	}

	fyne.DoAndWait(func() {
		a.State.SetScanning(true)
	})
	defer fyne.DoAndWait(func() {
		a.State.SetScanning(false)
	})

	a.applyOpenedPaths([]string{cloudFile})

	deadline := time.Now().Add(2 * time.Second)
	for {
		a.openReadinessMu.Lock()
		active := a.openReadinessCancel != nil
		a.openReadinessMu.Unlock()
		if !active {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("readiness session survived a foreign scan instead of finishing")
		}
		time.Sleep(10 * time.Millisecond)
	}

	fyne.DoAndWait(func() {
		a.State.SetScanning(false)
	})
	assertInputFileDoesNotBecome(t, a, cloudFile, 200*time.Millisecond)
}

// TestOpenedPathSessionSurvivesOwnGestureScan pins the opposite case: while a
// scan from an earlier apply of the SAME gesture runs (fresh cloud apply
// record), the late-batch session must stay alive and apply the union once the
// scan settles.
func TestOpenedPathSessionSurvivesOwnGestureScan(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	resetOpenedPathsForTest(t)
	oldCheck := checkOpenedPathReadiness
	oldPoll := openedPathPollInterval
	oldSettle := openedPathCloudSettleDelay
	defer func() {
		checkOpenedPathReadiness = oldCheck
		openedPathPollInterval = oldPoll
		openedPathCloudSettleDelay = oldSettle
	}()
	openedPathPollInterval = 5 * time.Millisecond
	openedPathCloudSettleDelay = 0

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	tempDir := t.TempDir()
	first := filepath.Join(tempDir, "own-scan-first.txt")
	late := filepath.Join(tempDir, "own-scan-late.txt")
	for _, path := range []string{first, late} {
		if err := os.WriteFile(path, []byte("payload"), 0o644); err != nil {
			t.Fatalf("Create test file %q: %v", path, err)
		}
	}

	checkOpenedPathReadiness = func(ctx context.Context, paths []string) openedPathReadinessResult {
		result := make(openedPathReadinessResult, 0, len(paths))
		for _, path := range paths {
			result = append(result, openedPathReadiness{Path: path, State: openedPathReady, IsUbiquitous: true})
		}
		return result
	}

	a.applyOpenedPaths([]string{first})
	waitForAllFiles(t, a, []string{first})

	fyne.DoAndWait(func() {
		a.State.SetScanning(true)
	})
	a.applyOpenedPaths([]string{late})
	time.Sleep(50 * time.Millisecond)
	fyne.DoAndWait(func() {
		a.State.SetScanning(false)
	})

	waitForAllFiles(t, a, []string{first, late})
}

// TestManualDropAfterCloudApplySuppressesLateBatchUntilMergeWindowEnds covers
// the suppress/merge window gap: gesture batches may straggle for the whole
// post-apply merge window, so a manual drop that cancels a fresh cloud apply
// must suppress stragglers for that window too — not only for the shorter
// cancel-suppress delay.
func TestManualDropAfterCloudApplySuppressesLateBatchUntilMergeWindowEnds(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	resetOpenedPathsForTest(t)
	oldCheck := checkOpenedPathReadiness
	oldPoll := openedPathPollInterval
	oldSettle := openedPathCloudSettleDelay
	oldSuppress := openedPathCloudCancelSuppressDelay
	oldMergeWindow := openedPathCloudPostApplyMergeDelay
	defer func() {
		checkOpenedPathReadiness = oldCheck
		openedPathPollInterval = oldPoll
		openedPathCloudSettleDelay = oldSettle
		openedPathCloudCancelSuppressDelay = oldSuppress
		openedPathCloudPostApplyMergeDelay = oldMergeWindow
	}()
	openedPathPollInterval = 5 * time.Millisecond
	openedPathCloudSettleDelay = 0
	openedPathCloudCancelSuppressDelay = 50 * time.Millisecond
	openedPathCloudPostApplyMergeDelay = 600 * time.Millisecond

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	tempDir := t.TempDir()
	cloudFirst := filepath.Join(tempDir, "cloud-gap-applied.txt")
	cloudLate := filepath.Join(tempDir, "cloud-gap-late.txt")
	manual := filepath.Join(tempDir, "manual-gap.txt")
	for _, path := range []string{cloudFirst, cloudLate, manual} {
		if err := os.WriteFile(path, []byte("payload"), 0o644); err != nil {
			t.Fatalf("Create test file %q: %v", path, err)
		}
	}

	checkOpenedPathReadiness = func(ctx context.Context, paths []string) openedPathReadinessResult {
		result := make(openedPathReadinessResult, 0, len(paths))
		for _, path := range paths {
			result = append(result, openedPathReadiness{Path: path, State: openedPathReady, IsUbiquitous: true})
		}
		return result
	}

	a.applyOpenedPaths([]string{cloudFirst})
	waitForAllFiles(t, a, []string{cloudFirst})

	fyne.DoAndWait(func() {
		a.cancelOpenedPathReadiness()
		a.onDrop([]string{manual})
	})

	// Past the cancel-suppress delay but still inside the merge window.
	time.Sleep(150 * time.Millisecond)
	a.applyOpenedPaths([]string{cloudLate})

	waitForInputFile(t, a, manual)
	assertInputFileDoesNotBecome(t, a, cloudLate, 200*time.Millisecond)
}

// TestStragglersCannotShortenManualDropSuppressionWindow guards the suppress
// window arithmetic: a suppressed straggler must never SHORTEN the window that
// cancelOpenedPathReadiness armed for the rest of the merge window — otherwise
// a second straggler arriving in the gap would stomp the manual selection.
func TestStragglersCannotShortenManualDropSuppressionWindow(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	resetOpenedPathsForTest(t)
	oldCheck := checkOpenedPathReadiness
	oldPoll := openedPathPollInterval
	oldSettle := openedPathCloudSettleDelay
	oldSuppress := openedPathCloudCancelSuppressDelay
	oldMergeWindow := openedPathCloudPostApplyMergeDelay
	defer func() {
		checkOpenedPathReadiness = oldCheck
		openedPathPollInterval = oldPoll
		openedPathCloudSettleDelay = oldSettle
		openedPathCloudCancelSuppressDelay = oldSuppress
		openedPathCloudPostApplyMergeDelay = oldMergeWindow
	}()
	openedPathPollInterval = 5 * time.Millisecond
	openedPathCloudSettleDelay = 0
	openedPathCloudCancelSuppressDelay = 50 * time.Millisecond
	openedPathCloudPostApplyMergeDelay = 600 * time.Millisecond

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	tempDir := t.TempDir()
	cloudFirst := filepath.Join(tempDir, "cloud-shorten-applied.txt")
	cloudLate1 := filepath.Join(tempDir, "cloud-shorten-late1.txt")
	cloudLate2 := filepath.Join(tempDir, "cloud-shorten-late2.txt")
	manual := filepath.Join(tempDir, "manual-shorten.txt")
	for _, path := range []string{cloudFirst, cloudLate1, cloudLate2, manual} {
		if err := os.WriteFile(path, []byte("payload"), 0o644); err != nil {
			t.Fatalf("Create test file %q: %v", path, err)
		}
	}

	checkOpenedPathReadiness = func(ctx context.Context, paths []string) openedPathReadinessResult {
		result := make(openedPathReadinessResult, 0, len(paths))
		for _, path := range paths {
			result = append(result, openedPathReadiness{Path: path, State: openedPathReady, IsUbiquitous: true})
		}
		return result
	}

	a.applyOpenedPaths([]string{cloudFirst})
	waitForAllFiles(t, a, []string{cloudFirst})

	fyne.DoAndWait(func() {
		a.cancelOpenedPathReadiness()
		a.onDrop([]string{manual})
	})

	// First straggler inside the armed window: must be suppressed without
	// collapsing the window down to the short cancel-suppress delay.
	time.Sleep(100 * time.Millisecond)
	a.applyOpenedPaths([]string{cloudLate1})

	// Second straggler past the short delay but still inside the merge window.
	time.Sleep(150 * time.Millisecond)
	a.applyOpenedPaths([]string{cloudLate2})

	waitForInputFile(t, a, manual)
	assertInputFileDoesNotBecome(t, a, cloudLate1, 200*time.Millisecond)
	assertInputFileDoesNotBecome(t, a, cloudLate2, 200*time.Millisecond)
}

func TestOpenedPathReadinessCancellationPreventsStaleApply(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	oldCheck := checkOpenedPathReadiness
	oldPoll := openedPathPollInterval
	defer func() {
		checkOpenedPathReadiness = oldCheck
		openedPathPollInterval = oldPoll
	}()
	openedPathPollInterval = 5 * time.Millisecond

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	pendingFile := filepath.Join(t.TempDir(), "pending.txt")
	manualFile := filepath.Join(t.TempDir(), "manual.txt")
	for _, path := range []string{pendingFile, manualFile} {
		if err := os.WriteFile(path, []byte("payload"), 0o644); err != nil {
			t.Fatalf("Create test file %q: %v", path, err)
		}
	}

	release := make(chan struct{})
	checkOpenedPathReadiness = func(ctx context.Context, paths []string) openedPathReadinessResult {
		select {
		case <-ctx.Done():
			return openedPathReadinessResult{{Path: pendingFile, State: openedPathPending}}
		case <-release:
			return openedPathReadinessResult{{Path: pendingFile, State: openedPathReady}}
		}
	}

	a.applyOpenedPaths([]string{pendingFile})
	fyne.DoAndWait(func() {
		a.cancelOpenedPathReadiness()
		a.onDrop([]string{manualFile})
	})
	close(release)

	waitForInputFile(t, a, manualFile)
	state := snapshotDropState(t, a)
	if state.InputFile == pendingFile {
		t.Fatalf("stale opened path %q applied after cancellation", pendingFile)
	}
}

func TestInvalidStartCancelsOpenedPathReadiness(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	oldCheck := checkOpenedPathReadiness
	oldPoll := openedPathPollInterval
	defer func() {
		checkOpenedPathReadiness = oldCheck
		openedPathPollInterval = oldPoll
	}()
	openedPathPollInterval = 5 * time.Millisecond

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	pendingFile := filepath.Join(t.TempDir(), "pending-start.txt")
	if err := os.WriteFile(pendingFile, []byte("payload"), 0o644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	checkStarted := make(chan struct{})
	release := make(chan struct{})
	checkOpenedPathReadiness = func(ctx context.Context, paths []string) openedPathReadinessResult {
		select {
		case <-checkStarted:
		default:
			close(checkStarted)
		}
		select {
		case <-ctx.Done():
			return openedPathReadinessResult{{Path: pendingFile, State: openedPathPending}}
		case <-release:
			return openedPathReadinessResult{{Path: pendingFile, State: openedPathReady}}
		}
	}

	a.applyOpenedPaths([]string{pendingFile})
	defer a.cancelOpenedPathReadiness()
	select {
	case <-checkStarted:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for readiness check to start")
	}

	fyne.DoAndWait(func() {
		a.onClickStart()
	})
	close(release)

	assertInputFileDoesNotBecome(t, a, pendingFile, 200*time.Millisecond)
}

func TestOpenedPathReadinessPendingStatusDoesNotOverwriteBusyStatus(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	oldCheck := checkOpenedPathReadiness
	oldPoll := openedPathPollInterval
	defer func() {
		checkOpenedPathReadiness = oldCheck
		openedPathPollInterval = oldPoll
	}()
	openedPathPollInterval = 5 * time.Millisecond

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	pendingFile := filepath.Join(t.TempDir(), "pending-status.txt")
	if err := os.WriteFile(pendingFile, []byte("payload"), 0o644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	checkStarted := make(chan struct{})
	checkOpenedPathReadiness = func(ctx context.Context, paths []string) openedPathReadinessResult {
		select {
		case <-checkStarted:
		default:
			close(checkStarted)
		}
		return openedPathReadinessResult{{Path: pendingFile, State: openedPathPending}}
	}

	const busyStatus = "Encrypting active file"
	fyne.DoAndWait(func() {
		a.State.SetWorking(true)
		a.State.SetStatus(busyStatus, util.WHITE)
		a.refreshUI()
	})
	defer func() {
		a.cancelOpenedPathReadiness()
		fyne.DoAndWait(func() {
			a.State.SetWorking(false)
		})
	}()

	a.applyOpenedPaths([]string{pendingFile})
	select {
	case <-checkStarted:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for readiness check to start")
	}

	assertMainStatusStays(t, a, busyStatus, 200*time.Millisecond)
}

// TestOpenedPathsBatchDeliversWholeGestureAsOneDrop covers the first #127
// batching fix: when one application:openURLs: callback contains several files,
// the bridge must surface it as ONE drop carrying every path. The previous code
// notified after every appended path, so a three-file callback produced three
// single-path drops — each replacing the prior selection or hitting onDrop's
// scanning guard, losing files. The darwin bridge appends all paths and flushes
// once; this asserts that contract at the platform-neutral layer so it guards
// the regression on every CI platform, including the amd64 -race job (it touches
// no Fyne rendering, so it is not -race-skipped).
func TestOpenedPathsBatchDeliversWholeGestureAsOneDrop(t *testing.T) {
	withOpenedPathsFlushDelay(t, 10*time.Millisecond)
	// Reset package-global bridge state other tests may have left behind.
	setOpenedPathsNotify(nil)
	drainOpenedPaths()
	t.Cleanup(func() {
		setOpenedPathsNotify(nil)
		drainOpenedPaths()
	})

	batches := make(chan []string, 1)
	setOpenedPathsNotify(func() {
		batches <- drainOpenedPaths()
	})

	// One openURLs: event carrying three files: append each, then flush once.
	paths := []string{"/tmp/a.txt", "/tmp/b.txt", "/tmp/c.txt"}
	for _, p := range paths {
		appendOpenedPath(p)
	}
	flushOpenedPaths()

	var got []string
	select {
	case got = <-batches:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for opened paths notification")
	}

	select {
	case extra := <-batches:
		t.Fatalf("notify fired more than once for one openURLs gesture; extra batch: %#v", extra)
	default:
	}
	if len(got) != len(paths) {
		t.Fatalf("drained %d path(s); want all %d delivered in one drop: got %v", len(got), len(paths), got)
	}
	for i := range paths {
		if got[i] != paths[i] {
			t.Fatalf("path[%d] = %q; want %q (order and completeness must be preserved)", i, got[i], paths[i])
		}
	}
}

// TestKeyfileDropHandling drives the real handleKeyfileDrop with on-disk
// keyfiles, a duplicate path, and a directory, asserting the resulting
// State.Keyfiles. The dedup + directory guard (drop.go:482) is production
// logic, so the test must never recompute it inline.
func TestKeyfileDropHandling(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)

	dir := t.TempDir()
	key1 := filepath.Join(dir, "key1.bin")
	key2 := filepath.Join(dir, "key2.bin")
	subdir := filepath.Join(dir, "adir")
	for _, p := range []string{key1, key2} {
		if err := os.WriteFile(p, []byte("k"), 0o644); err != nil {
			t.Fatalf("write keyfile %q: %v", p, err)
		}
	}
	if err := os.Mkdir(subdir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// key1 is dropped twice (duplicate) and a directory is included; both must
	// be skipped by the !duplicate && !stat.IsDir() guard in handleKeyfileDrop.
	var handled bool
	fyne.DoAndWait(func() {
		a.State.ShowKeyfile = true
		handled = a.handleKeyfileDrop([]string{key1, key2, key1, subdir})
	})
	if !handled {
		t.Fatalf("handleKeyfileDrop returned false; want true (modal open, no stat error)")
	}

	var got []string
	var label string
	fyne.DoAndWait(func() {
		got = append([]string(nil), a.State.Keyfiles...)
		label = a.keyfileLabel.Text
	})

	if len(got) != 2 {
		t.Fatalf("Keyfiles = %#v; want 2 entries (duplicate and directory skipped)", got)
	}
	if got[0] != key1 || got[1] != key2 {
		t.Fatalf("Keyfiles = %#v; want [%q %q] in order", got, key1, key2)
	}
	wantLabel := trn("keyfiles.count", "{{.Count}} keyfiles", 2, map[string]any{"Count": 2})
	if label != wantLabel {
		t.Fatalf("rendered keyfile label = %q; want %q", label, wantLabel)
	}
}

// TestStatusFreeSpaceMultiplier drives the real updateUIState free-space
// estimation: with a ready semantic status and RequiredFreeSpace set,
// updateUIState (app.go) rewrites the status label to "Ready (ensure >SIZE
// free)" where SIZE is RequiredFreeSpace times a multiplier that grows with
// multi-file/deniability/split/etc. The test intentionally poisons Status.Text
// in ready cases so it fails if updateUIState compares display text instead of
// the semantic status kind.
func TestStatusFreeSpaceMultiplier(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	const base = int64(1024 * 1024) // 1 MiB

	t.Run("SingleFileNoOptions", func(t *testing.T) {
		a := createUIReadyDropTestApp(t, fyneApp)
		fyne.DoAndWait(func() {
			a.State.Mode = "encrypt"
			a.State.Password = "secret"
			a.State.CPassword = "secret"
			a.State.AllFiles = []string{"only.txt"}
			a.State.OnlyFiles = []string{"only.txt"}
			a.State.Status = app.StatusMessage{Kind: app.StatusReady, Text: "Localized ready", Color: util.WHITE}
			a.State.RequiredFreeSpace = base
			a.updateUIState()
		})

		want := tr("status.ready_free_space", "Ready (ensure >{{.Size}} free)", map[string]any{
			"Size": util.Sizeify(base * 1),
		})
		if got := statusLabelText(t, a); got != want {
			t.Fatalf("status = %q; want %q (1x multiplier)", got, want)
		}
	})

	t.Run("MultiFileDeniabilitySplit", func(t *testing.T) {
		a := createUIReadyDropTestApp(t, fyneApp)
		fyne.DoAndWait(func() {
			a.State.Mode = "encrypt"
			a.State.Password = "secret"
			a.State.CPassword = "secret"
			// 2 files (+1) + deniability (+1) + split (+1) => 4x
			a.State.AllFiles = []string{"a.txt", "b.txt"}
			a.State.OnlyFiles = []string{"a.txt", "b.txt"}
			a.State.Deniability = true
			a.State.Split = true
			a.State.Status = app.StatusMessage{Kind: app.StatusReady, Text: "Localized ready", Color: util.WHITE}
			a.State.RequiredFreeSpace = base
			a.updateUIState()
		})

		want := tr("status.ready_free_space", "Ready (ensure >{{.Size}} free)", map[string]any{
			"Size": util.Sizeify(base * 4),
		})
		if got := statusLabelText(t, a); got != want {
			t.Fatalf("status = %q; want %q (4x multiplier)", got, want)
		}
	})

	t.Run("CustomReadyTextDoesNotTriggerFreeSpace", func(t *testing.T) {
		a := createUIReadyDropTestApp(t, fyneApp)
		fyne.DoAndWait(func() {
			a.State.Mode = "encrypt"
			a.State.Password = "secret"
			a.State.CPassword = "secret"
			a.State.AllFiles = []string{"only.txt"}
			a.State.OnlyFiles = []string{"only.txt"}
			a.State.SetCustomStatus("Ready", util.WHITE)
			a.State.RequiredFreeSpace = base
			a.updateUIState()
		})

		if got := statusLabelText(t, a); got != "Ready" {
			t.Fatalf("status = %q; want custom Ready text without free-space suffix", got)
		}
	})
}

func statusLabelText(t *testing.T, a *App) string {
	t.Helper()
	var text string
	fyne.DoAndWait(func() {
		text = a.statusLabel.text
	})
	return text
}

func createUIReadyDropTestApp(t *testing.T, fyneApp fyne.App) *App {
	t.Helper()

	a, err := NewApp("v2.09")
	if err != nil {
		t.Fatalf("Failed to create test app: %v", err)
	}

	a.fyneApp = fyneApp
	fyne.DoAndWait(func() {
		a.Window = fyneApp.NewWindow("drop-test")
		a.Window.SetContent(a.buildUI())
	})
	return a
}

func waitForDropProcessing(t *testing.T, a *App) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !a.State.IsScanning() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	if a.State.IsScanning() {
		t.Fatal("drop processing did not finish")
	}
}

func waitForInputFile(t *testing.T, a *App, want string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		state := snapshotDropState(t, a)
		if state.InputFile == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	state := snapshotDropState(t, a)
	t.Fatalf("InputFile = %q; want %q", state.InputFile, want)
}

func assertInputFileDoesNotBecome(t *testing.T, a *App, unwanted string, duration time.Duration) {
	t.Helper()

	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		state := snapshotDropState(t, a)
		if state.InputFile == unwanted {
			t.Fatalf("InputFile became stale opened path %q", unwanted)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForAllFiles(t *testing.T, a *App, want []string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		state := snapshotDropState(t, a)
		if reflect.DeepEqual(state.AllFiles, want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	state := snapshotDropState(t, a)
	t.Fatalf("AllFiles = %#v; want %#v", state.AllFiles, want)
}

func waitForOpenedPathLateCollection(t *testing.T, a *App) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		a.openReadinessMu.Lock()
		collecting := a.openReadinessCancel != nil && a.openReadinessCollectLate
		a.openReadinessMu.Unlock()
		if collecting {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	a.openReadinessMu.Lock()
	paths := append([]string(nil), a.openReadinessPaths...)
	collecting := a.openReadinessCollectLate
	active := a.openReadinessCancel != nil
	a.openReadinessMu.Unlock()
	t.Fatalf("opened path readiness late collection did not start: active=%v collectLate=%v paths=%#v", active, collecting, paths)
}

func assertMainStatusStays(t *testing.T, a *App, want string, duration time.Duration) {
	t.Helper()

	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		state := snapshotDropState(t, a)
		if state.MainStatus != want {
			t.Fatalf("rendered status = %q; want it to stay %q", state.MainStatus, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type dropStateSnapshot struct {
	Mode        string
	MainStatus  string
	InputFile   string
	OutputFile  string
	OnlyFiles   []string
	OnlyFolders []string
	AllFiles    []string
}

func snapshotDropState(t *testing.T, a *App) dropStateSnapshot {
	t.Helper()

	var state dropStateSnapshot
	fyne.DoAndWait(func() {
		snap := a.State.UISnapshot()
		state = dropStateSnapshot{
			Mode:        a.State.Mode,
			MainStatus:  renderStatus(snap.Status, snap),
			InputFile:   a.State.InputFile,
			OutputFile:  a.State.OutputFile,
			OnlyFiles:   append([]string(nil), a.State.OnlyFiles...),
			OnlyFolders: append([]string(nil), a.State.OnlyFolders...),
			AllFiles:    append([]string(nil), a.State.AllFiles...),
		}
	})
	return state
}

func waitForOnlyFolders(t *testing.T, a *App, want []string) {
	t.Helper()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		state := snapshotDropState(t, a)
		if reflect.DeepEqual(state.OnlyFolders, want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	state := snapshotDropState(t, a)
	t.Fatalf("OnlyFolders = %#v; want %#v", state.OnlyFolders, want)
}

func craftFullHeaderBytes(t *testing.T, rs *encoding.RSCodecs, comments string) []byte {
	t.Helper()

	h := header.NewVolumeHeader(
		bytes.Repeat([]byte{0x11}, header.SaltSize),
		bytes.Repeat([]byte{0x22}, header.HKDFSaltSize),
		bytes.Repeat([]byte{0x33}, header.SerpentIVSize),
		bytes.Repeat([]byte{0x44}, header.NonceSize),
	)
	h.Comments = comments

	var buf bytes.Buffer
	if _, err := header.NewWriter(&buf, rs).WriteHeader(h); err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}
	return buf.Bytes()
}

func TestHandleDecryptDropNonCommentDecodeErrorIsHeaderDamage(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)

	raw := craftFullHeaderBytes(t, rs, "visible")
	saltOffset := header.VersionEncSize + header.CommentLenEncSize + len("visible")*3 + header.FlagsEncSize
	for i := range 17 {
		raw[saltOffset+i] ^= 0xff
	}

	pcvPath := filepath.Join(t.TempDir(), "non-comment-corrupt.pcv")
	if err := os.WriteFile(pcvPath, raw, 0o644); err != nil {
		t.Fatalf("write crafted .pcv: %v", err)
	}

	fyne.DoAndWait(func() {
		a.onDrop([]string{pcvPath})
	})
	waitForDropProcessing(t, a)

	var comments, mainStatus string
	fyne.DoAndWait(func() {
		snap := a.State.UISnapshot()
		comments = a.State.Comments
		mainStatus = renderStatus(snap.Status, snap)
	})

	if comments == tr("comments.corrupted", "Comments are corrupted") {
		t.Fatalf("Comments = %q; non-comment header corruption must not be labeled as comment damage", comments)
	}
	wantStatus := tr("drop.header_damaged", "The volume header is damaged")
	if mainStatus != wantStatus {
		t.Fatalf("MainStatus = %q; want %q", mainStatus, wantStatus)
	}
}

func TestHandleDecryptDropCommentDecodeErrorUsesSemanticPreviewState(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)

	raw := craftFullHeaderBytes(t, rs, "visible")
	commentOffset := header.VersionEncSize + header.CommentLenEncSize
	copy(raw[commentOffset:commentOffset+3], []byte{0x00, 0x01, 0x02})

	pcvPath := filepath.Join(t.TempDir(), "comment-corrupt.pcv")
	if err := os.WriteFile(pcvPath, raw, 0o644); err != nil {
		t.Fatalf("write crafted .pcv: %v", err)
	}

	fyne.DoAndWait(func() {
		a.onDrop([]string{pcvPath})
	})
	waitForDropProcessing(t, a)

	var comments string
	var previewState app.CommentsPreviewState
	fyne.DoAndWait(func() {
		comments = a.State.Comments
		previewState = a.State.CommentsPreviewState
	})

	if comments != "" {
		t.Fatalf("Comments = %q; want empty payload when comment preview is corrupted", comments)
	}
	if previewState != app.CommentsPreviewCorrupted {
		t.Fatalf("CommentsPreviewState = %v; want CommentsPreviewCorrupted", previewState)
	}
}

// TestHandleDecryptDropMalformedCommentLen drops a crafted .pcv whose 5-digit
// comment-length RS5 field decodes to a non-digit / "negative"-looking value.
// The original hand-rolled parse did strconv.Atoi then make([]byte, n*3), which
// panics ("makeslice: len out of range") on a negative length. Routing through
// the validated parser (SEC-01) must instead yield a graceful status and never
// panic / over-allocate.
func TestHandleDecryptDropMalformedCommentLen(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	cases := []struct {
		name       string
		version    string
		commentLen string
	}{
		// "-0001" -> Atoi == -1 -> make([]byte, -3) panics in the old code.
		{"negative comment length", "v2.09", "-0001"},
		// A non-digit field that also fails the ^\d{5}$ guard.
		{"non-digit comment length", "v2.09", "0x009"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fyneApp := newTestFyneApp(t)
			a := createUIReadyDropTestApp(t, fyneApp)

			// Craft a .pcv: valid version field + malformed comment-length field.
			raw := craftPreviewBytes(t, rs, tc.version, tc.commentLen, "", []byte{0, 0, 0, 0, 0})
			// Pad so any reader past the header does not hit an unexpected EOF.
			raw = append(raw, make([]byte, header.BaseHeaderSize)...)

			pcvPath := filepath.Join(t.TempDir(), "crafted.pcv")
			if err := os.WriteFile(pcvPath, raw, 0o644); err != nil {
				t.Fatalf("write crafted .pcv: %v", err)
			}

			// Drive through onDrop -> handleDecryptDrop. The old hand-rolled
			// path panics here on the negative length; the validated path must
			// set a graceful status instead.
			fyne.DoAndWait(func() {
				a.onDrop([]string{pcvPath})
			})
			waitForDropProcessing(t, a)

			var comments, mainStatus, mode string
			fyne.DoAndWait(func() {
				snap := a.State.UISnapshot()
				comments = a.State.Comments
				mainStatus = renderStatus(snap.Status, snap)
				mode = a.State.Mode
			})

			if mode != "decrypt" {
				t.Fatalf("Mode = %q; want decrypt", mode)
			}
			if comments == "Comment length is corrupted" || comments == tr("comments.corrupted", "Comments are corrupted") {
				t.Fatalf("Comments = %q; malformed comment length is non-comment header damage", comments)
			}
			wantStatus := tr("drop.header_damaged", "The volume header is damaged")
			if mainStatus != wantStatus {
				t.Fatalf("MainStatus = %q; want %q", mainStatus, wantStatus)
			}
		})
	}
}

type lifecycleCaptureApp struct {
	driver  fyne.Driver
	started func()
	stopped func()
	bg      func()
	fg      func()
}

func newLifecycleCaptureApp(base fyne.App) *lifecycleCaptureApp {
	return &lifecycleCaptureApp{driver: base.Driver()}
}

func (a *lifecycleCaptureApp) NewWindow(title string) fyne.Window {
	return fyne.CurrentApp().NewWindow(title)
}
func (a *lifecycleCaptureApp) OpenURL(*url.URL) error              { return nil }
func (a *lifecycleCaptureApp) Icon() fyne.Resource                 { return nil }
func (a *lifecycleCaptureApp) SetIcon(fyne.Resource)               {}
func (a *lifecycleCaptureApp) Run()                                {}
func (a *lifecycleCaptureApp) Quit()                               {}
func (a *lifecycleCaptureApp) Driver() fyne.Driver                 { return a.driver }
func (a *lifecycleCaptureApp) UniqueID() string                    { return "lifecycle-capture-app" }
func (a *lifecycleCaptureApp) SendNotification(*fyne.Notification) {}
func (a *lifecycleCaptureApp) Settings() fyne.Settings             { return fyne.CurrentApp().Settings() }
func (a *lifecycleCaptureApp) Preferences() fyne.Preferences       { return fyne.CurrentApp().Preferences() }
func (a *lifecycleCaptureApp) Storage() fyne.Storage               { return fyne.CurrentApp().Storage() }
func (a *lifecycleCaptureApp) Lifecycle() fyne.Lifecycle           { return a }
func (a *lifecycleCaptureApp) Metadata() fyne.AppMetadata          { return fyne.AppMetadata{} }
func (a *lifecycleCaptureApp) CloudProvider() fyne.CloudProvider   { return nil }
func (a *lifecycleCaptureApp) SetCloudProvider(fyne.CloudProvider) {}
func (a *lifecycleCaptureApp) Clipboard() fyne.Clipboard           { return fyne.CurrentApp().Clipboard() }

func (a *lifecycleCaptureApp) SetOnEnteredForeground(fn func()) { a.fg = fn }
func (a *lifecycleCaptureApp) SetOnExitedForeground(fn func())  { a.bg = fn }
func (a *lifecycleCaptureApp) SetOnStarted(fn func())           { a.started = fn }
func (a *lifecycleCaptureApp) SetOnStopped(fn func())           { a.stopped = fn }
