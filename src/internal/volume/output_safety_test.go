package volume

import (
	perrors "Picocrypt-NG/internal/errors"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/header"
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func windowsPreventedOpenHandleRename(err error) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	// Windows can report either access denied or sharing violation when an
	// open file or directory handle prevents pathname replacement.
	return errors.Is(err, syscall.Errno(5)) || errors.Is(err, syscall.Errno(32))
}

type pathSwapReporter struct {
	trigger string
	path    string
	backup  string
	foreign []byte

	once sync.Once
	err  error
}

func (r *pathSwapReporter) SetStatus(status string) {
	if !strings.HasPrefix(status, r.trigger) {
		return
	}
	r.once.Do(func() {
		if err := os.Rename(r.path, r.backup); err != nil {
			r.err = err
			return
		}
		r.err = os.WriteFile(r.path, r.foreign, 0o600)
	})
}

func (*pathSwapReporter) SetProgress(float32, string) {}
func (*pathSwapReporter) SetCanCancel(bool)           {}
func (*pathSwapReporter) Update()                     {}
func (*pathSwapReporter) IsCancelled() bool           { return false }

type cleanupPermissionReporter struct {
	dir       string
	once      sync.Once
	stagePath string
	err       error
}

func (*cleanupPermissionReporter) SetStatus(string)            {}
func (*cleanupPermissionReporter) SetProgress(float32, string) {}
func (*cleanupPermissionReporter) Update()                     {}
func (*cleanupPermissionReporter) IsCancelled() bool           { return false }

func (r *cleanupPermissionReporter) SetCanCancel(can bool) {
	if !can {
		return
	}
	r.once.Do(func() {
		entries, err := os.ReadDir(r.dir)
		if err != nil {
			r.err = err
			return
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".picocrypt-") {
				r.stagePath = filepath.Join(r.dir, entry.Name())
				break
			}
		}
		if r.stagePath == "" {
			r.err = errors.New("decrypt enabled cancellation before creating its stage")
			return
		}
		r.err = os.Chmod(r.dir, 0o500)
	})
}

type pathMoveReporter struct {
	trigger     string
	path        string
	backup      string
	replacement string

	once sync.Once
	err  error
}

func (r *pathMoveReporter) SetStatus(status string) {
	if !strings.HasPrefix(status, r.trigger) {
		return
	}
	r.once.Do(func() {
		if err := os.Rename(r.path, r.backup); err != nil {
			r.err = err
			return
		}
		r.err = os.Rename(r.replacement, r.path)
	})
}

func (*pathMoveReporter) SetProgress(float32, string) {}
func (*pathMoveReporter) SetCanCancel(bool)           {}
func (*pathMoveReporter) Update()                     {}
func (*pathMoveReporter) IsCancelled() bool           { return false }

func encryptSafetyFixture(t *testing.T, dir, name string, plaintext []byte) (string, []byte) {
	t.Helper()

	inputPath := filepath.Join(dir, name+".txt")
	if err := os.WriteFile(inputPath, plaintext, 0o600); err != nil {
		t.Fatalf("write plaintext fixture: %v", err)
	}

	volumePath := filepath.Join(dir, name+".pcv")
	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: volumePath,
		Password:   []byte("output-safety-password"),
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("encrypt fixture: %v", err)
	}

	volumeBytes, err := os.ReadFile(volumePath)
	if err != nil {
		t.Fatalf("read encrypted fixture: %v", err)
	}
	return volumePath, volumeBytes
}

func assertFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read protected file %q: %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("protected file %q changed: got %q, want %q", path, got, want)
	}
}

func TestEncryptRejectsOutputAliasesOfProtectedFiles(t *testing.T) {
	tests := []struct {
		name      string
		protected string
		alias     string
	}{
		{name: "input exact", protected: "input", alias: "exact"},
		{name: "input hardlink", protected: "input", alias: "hardlink"},
		{name: "input symlink", protected: "input", alias: "symlink"},
		{name: "keyfile exact", protected: "keyfile", alias: "exact"},
		{name: "keyfile hardlink", protected: "keyfile", alias: "hardlink"},
		{name: "keyfile symlink", protected: "keyfile", alias: "symlink"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			plaintext := []byte("encrypt alias rejection must preserve this input")
			inputPath := filepath.Join(dir, "plaintext.txt")
			if err := os.WriteFile(inputPath, plaintext, 0o600); err != nil {
				t.Fatalf("write plaintext: %v", err)
			}
			keyfilePath := filepath.Join(dir, "keyfile.bin")
			keyfileBytes := []byte("encrypt alias rejection must preserve this keyfile")
			if err := os.WriteFile(keyfilePath, keyfileBytes, 0o600); err != nil {
				t.Fatalf("write keyfile: %v", err)
			}

			protectedPath := inputPath
			protectedBytes := plaintext
			keyfiles := []string(nil)
			if tc.protected == "keyfile" {
				protectedPath = keyfilePath
				protectedBytes = keyfileBytes
				keyfiles = []string{keyfilePath}
			}

			outputPath := protectedPath
			switch tc.alias {
			case "hardlink":
				outputPath = filepath.Join(dir, "output-hardlink.pcv")
				if err := os.Link(protectedPath, outputPath); err != nil {
					t.Fatalf("create hardlink: %v", err)
				}
			case "symlink":
				outputPath = filepath.Join(dir, "output-symlink.pcv")
				if err := os.Symlink(protectedPath, outputPath); err != nil {
					t.Skipf("symlinks unavailable on this platform: %v", err)
				}
			}

			err := Encrypt(context.Background(), &EncryptRequest{
				InputFile:  inputPath,
				OutputFile: outputPath,
				Password:   []byte("protected-alias-password"),
				Keyfiles:   keyfiles,
				RSCodecs:   newRSCodecsT(t),
			})
			var validationErr *perrors.ValidationError
			if !errors.As(err, &validationErr) || validationErr.Field != "OutputFile" {
				t.Fatalf("Encrypt error = %v, want OutputFile validation error", err)
			}
			assertFileBytes(t, protectedPath, protectedBytes)

			switch tc.alias {
			case "hardlink":
				protectedInfo, statErr := os.Stat(protectedPath)
				if statErr != nil {
					t.Fatalf("stat protected path: %v", statErr)
				}
				outputInfo, statErr := os.Stat(outputPath)
				if statErr != nil {
					t.Fatalf("stat hardlink output: %v", statErr)
				}
				if !os.SameFile(protectedInfo, outputInfo) {
					t.Fatal("hardlink output no longer aliases the protected file")
				}
			case "symlink":
				outputInfo, lstatErr := os.Lstat(outputPath)
				if lstatErr != nil {
					t.Fatalf("lstat symlink output: %v", lstatErr)
				}
				if outputInfo.Mode()&os.ModeSymlink == 0 {
					t.Fatal("symlink output was replaced")
				}
			}

			safeVolume := filepath.Join(dir, "safe-output.pcv")
			if err := Encrypt(context.Background(), &EncryptRequest{
				InputFile:  inputPath,
				OutputFile: safeVolume,
				Password:   []byte("protected-alias-password"),
				Keyfiles:   keyfiles,
				RSCodecs:   newRSCodecsT(t),
			}); err != nil {
				t.Fatalf("safe Encrypt failed after alias rejection: %v", err)
			}
			safePlaintext := filepath.Join(dir, "safe-output.txt")
			if err := Decrypt(context.Background(), &DecryptRequest{
				InputFile:  safeVolume,
				OutputFile: safePlaintext,
				Password:   []byte("protected-alias-password"),
				Keyfiles:   keyfiles,
				RSCodecs:   newRSCodecsT(t),
			}); err != nil {
				t.Fatalf("decrypt safe volume: %v", err)
			}
			assertFileBytes(t, safePlaintext, plaintext)
		})
	}
}

func TestDecryptRejectsOutputAliasingInputWithoutMutation(t *testing.T) {
	dir := t.TempDir()
	volumePath, before := encryptSafetyFixture(t, dir, "same-path", []byte("plaintext must not replace its encrypted volume"))

	err := Decrypt(context.Background(), &DecryptRequest{
		InputFile:  volumePath,
		OutputFile: volumePath,
		Password:   []byte("output-safety-password"),
		RSCodecs:   newRSCodecsT(t),
	})
	if err == nil {
		t.Fatal("Decrypt succeeded with output aliasing the encrypted input")
	}
	assertFileBytes(t, volumePath, before)
}

func TestDecryptRejectsOutputAliasesOfProtectedFiles(t *testing.T) {
	tests := []struct {
		name      string
		protected string
		alias     string
	}{
		{name: "input exact", protected: "input", alias: "exact"},
		{name: "input hardlink", protected: "input", alias: "hardlink"},
		{name: "input symlink", protected: "input", alias: "symlink"},
		{name: "keyfile exact", protected: "keyfile", alias: "exact"},
		{name: "keyfile hardlink", protected: "keyfile", alias: "hardlink"},
		{name: "keyfile symlink", protected: "keyfile", alias: "symlink"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			plaintext := []byte("protected-alias round-trip payload")
			inputPath := filepath.Join(dir, "plaintext.txt")
			if err := os.WriteFile(inputPath, plaintext, 0o600); err != nil {
				t.Fatalf("write plaintext: %v", err)
			}
			keyfilePath := filepath.Join(dir, "keyfile.bin")
			keyfileBytes := []byte("keyfile bytes that must survive alias rejection")
			if err := os.WriteFile(keyfilePath, keyfileBytes, 0o600); err != nil {
				t.Fatalf("write keyfile: %v", err)
			}

			volumePath := filepath.Join(dir, "volume.pcv")
			keyfiles := []string(nil)
			if tc.protected == "keyfile" {
				keyfiles = []string{keyfilePath}
			}
			if err := Encrypt(context.Background(), &EncryptRequest{
				InputFile:  inputPath,
				OutputFile: volumePath,
				Password:   []byte("protected-alias-password"),
				Keyfiles:   keyfiles,
				RSCodecs:   newRSCodecsT(t),
			}); err != nil {
				t.Fatalf("encrypt fixture: %v", err)
			}

			protectedPath := volumePath
			protectedBytes, err := os.ReadFile(volumePath)
			if err != nil {
				t.Fatalf("read volume fixture: %v", err)
			}
			if tc.protected == "keyfile" {
				protectedPath = keyfilePath
				protectedBytes = keyfileBytes
			}

			outputPath := protectedPath
			switch tc.alias {
			case "hardlink":
				outputPath = filepath.Join(dir, "output-hardlink")
				if err := os.Link(protectedPath, outputPath); err != nil {
					t.Fatalf("create hardlink: %v", err)
				}
			case "symlink":
				outputPath = filepath.Join(dir, "output-symlink")
				if err := os.Symlink(protectedPath, outputPath); err != nil {
					t.Skipf("symlinks unavailable on this platform: %v", err)
				}
			}

			err = Decrypt(context.Background(), &DecryptRequest{
				InputFile:  volumePath,
				OutputFile: outputPath,
				Password:   []byte("protected-alias-password"),
				Keyfiles:   keyfiles,
				RSCodecs:   newRSCodecsT(t),
			})
			var validationErr *perrors.ValidationError
			if !errors.As(err, &validationErr) || validationErr.Field != "OutputFile" {
				t.Fatalf("Decrypt error = %v, want OutputFile validation error", err)
			}
			assertFileBytes(t, protectedPath, protectedBytes)

			switch tc.alias {
			case "hardlink":
				protectedInfo, statErr := os.Stat(protectedPath)
				if statErr != nil {
					t.Fatalf("stat protected path: %v", statErr)
				}
				outputInfo, statErr := os.Stat(outputPath)
				if statErr != nil {
					t.Fatalf("stat hardlink output: %v", statErr)
				}
				if !os.SameFile(protectedInfo, outputInfo) {
					t.Fatal("hardlink output no longer aliases the protected file")
				}
			case "symlink":
				outputInfo, lstatErr := os.Lstat(outputPath)
				if lstatErr != nil {
					t.Fatalf("lstat symlink output: %v", lstatErr)
				}
				if outputInfo.Mode()&os.ModeSymlink == 0 {
					t.Fatal("symlink output was replaced")
				}
			}

			safeOutput := filepath.Join(dir, "safe-output.txt")
			if err := Decrypt(context.Background(), &DecryptRequest{
				InputFile:  volumePath,
				OutputFile: safeOutput,
				Password:   []byte("protected-alias-password"),
				Keyfiles:   keyfiles,
				RSCodecs:   newRSCodecsT(t),
			}); err != nil {
				t.Fatalf("safe Decrypt failed after alias rejection: %v", err)
			}
			assertFileBytes(t, safeOutput, plaintext)
		})
	}
}

func TestEncryptCompressionPreservesPreexistingLegacyTemp(t *testing.T) {
	dir := t.TempDir()
	plaintext := []byte("compressed payload")
	inputPath := filepath.Join(dir, "payload.txt")
	if err := os.WriteFile(inputPath, plaintext, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	outputPath := filepath.Join(dir, "archive.pcv")
	legacyTemp := filepath.Join(dir, "archive.tmp")
	foreignBytes := []byte("foreign file using the old predictable temp name")
	if err := os.WriteFile(legacyTemp, foreignBytes, 0o600); err != nil {
		t.Fatalf("write protected temp: %v", err)
	}

	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: outputPath,
		Password:   []byte("output-safety-password"),
		Compress:   true,
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	assertFileBytes(t, legacyTemp, foreignBytes)

	decryptedZip := filepath.Join(dir, "safe-output.zip")
	if err := Decrypt(context.Background(), &DecryptRequest{
		InputFile:  outputPath,
		OutputFile: decryptedZip,
		Password:   []byte("output-safety-password"),
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("decrypt compressed volume: %v", err)
	}
	reader, err := zip.OpenReader(decryptedZip)
	if err != nil {
		t.Fatalf("open decrypted ZIP: %v", err)
	}
	defer func() { _ = reader.Close() }()
	if len(reader.File) != 1 {
		t.Fatalf("decrypted ZIP entries = %d, want 1", len(reader.File))
	}
	entry, err := reader.File[0].Open()
	if err != nil {
		t.Fatalf("open decrypted ZIP entry: %v", err)
	}
	got, err := io.ReadAll(entry)
	_ = entry.Close()
	if err != nil {
		t.Fatalf("read decrypted ZIP entry: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypted ZIP payload = %q, want %q", got, plaintext)
	}
}

func TestEncryptPreservesPreexistingLegacyIncomplete(t *testing.T) {
	dir := t.TempDir()
	plaintext := []byte("payload")
	inputPath := filepath.Join(dir, "payload.txt")
	if err := os.WriteFile(inputPath, plaintext, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	outputPath := filepath.Join(dir, "output.pcv")
	legacyIncomplete := outputPath + ".incomplete"
	foreignBytes := []byte("foreign file using the old predictable incomplete name")
	if err := os.WriteFile(legacyIncomplete, foreignBytes, 0o600); err != nil {
		t.Fatalf("write protected incomplete: %v", err)
	}

	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: outputPath,
		Password:   []byte("output-safety-password"),
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	assertFileBytes(t, legacyIncomplete, foreignBytes)

	safeOutput := filepath.Join(dir, "safe-output.txt")
	if err := Decrypt(context.Background(), &DecryptRequest{
		InputFile:  outputPath,
		OutputFile: safeOutput,
		Password:   []byte("output-safety-password"),
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("decrypt safe output: %v", err)
	}
	assertFileBytes(t, safeOutput, plaintext)
}

func TestDecryptFailurePreservesPreexistingLegacyIncomplete(t *testing.T) {
	dir := t.TempDir()
	volumePath, _ := encryptSafetyFixture(t, dir, "wrong-password", []byte("secret"))

	outputPath := filepath.Join(dir, "plaintext.txt")
	legacyIncomplete := outputPath + ".incomplete"
	foreignBytes := []byte("foreign file using the old predictable incomplete name")
	if err := os.WriteFile(legacyIncomplete, foreignBytes, 0o600); err != nil {
		t.Fatalf("write protected incomplete: %v", err)
	}

	err := Decrypt(context.Background(), &DecryptRequest{
		InputFile:  volumePath,
		OutputFile: outputPath,
		Password:   []byte("wrong-password"),
		RSCodecs:   newRSCodecsT(t),
	})
	if !header.IsPasswordError(err) {
		t.Fatalf("Decrypt error = %v, want a typed password authentication error", err)
	}
	assertFileBytes(t, legacyIncomplete, foreignBytes)
}

func TestDecryptFailureRemovesOnlyItsOwnedStage(t *testing.T) {
	dir := t.TempDir()
	volumePath, volumeBytes := encryptSafetyFixture(t, dir, "corrupt-payload", []byte("payload whose MAC must fail"))
	volumeBytes[len(volumeBytes)-1] ^= 0x80
	if err := os.WriteFile(volumePath, volumeBytes, 0o600); err != nil {
		t.Fatalf("corrupt encrypted payload: %v", err)
	}

	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read directory before decrypt: %v", err)
	}
	outputPath := filepath.Join(dir, "recovered.txt")
	err = Decrypt(context.Background(), &DecryptRequest{
		InputFile:  volumePath,
		OutputFile: outputPath,
		Password:   []byte("output-safety-password"),
		RSCodecs:   newRSCodecsT(t),
	})
	if !errors.Is(err, perrors.ErrCorruptData) {
		t.Fatalf("Decrypt error = %v, want ErrCorruptData", err)
	}
	if _, statErr := os.Stat(outputPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed decrypt published an output: %v", statErr)
	}

	after, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read directory after decrypt: %v", err)
	}
	if len(after) != len(before) {
		t.Fatalf("failed decrypt leaked a stage: before=%v after=%v", before, after)
	}
	assertFileBytes(t, volumePath, volumeBytes)
}

func TestDecryptSurfacesPlaintextStageCleanupFailure(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires Unix directory permissions enforced for an unprivileged user")
	}

	dir := t.TempDir()
	plaintext := []byte("plaintext residue must be reported if cleanup cannot remove it")
	volumePath, volumeBytes := encryptSafetyFixture(t, dir, "cleanup-failure", plaintext)
	volumeBytes[len(volumeBytes)-1] ^= 0x80
	if err := os.WriteFile(volumePath, volumeBytes, 0o600); err != nil {
		t.Fatalf("Corrupt encrypted payload: %v", err)
	}

	outputDir := filepath.Join(dir, "output")
	if err := os.Mkdir(outputDir, 0o700); err != nil {
		t.Fatalf("Create output directory: %v", err)
	}
	reporter := &cleanupPermissionReporter{dir: outputDir}
	outputPath := filepath.Join(outputDir, "recovered.txt")
	err := Decrypt(context.Background(), &DecryptRequest{
		InputFile:  volumePath,
		OutputFile: outputPath,
		Password:   []byte("output-safety-password"),
		Reporter:   reporter,
		RSCodecs:   newRSCodecsT(t),
	})
	if chmodErr := os.Chmod(outputDir, 0o700); chmodErr != nil {
		t.Fatalf("Restore output directory permissions: %v", chmodErr)
	}
	if reporter.err != nil {
		t.Fatalf("Arrange real cleanup failure: %v", reporter.err)
	}
	if !errors.Is(err, perrors.ErrCorruptData) {
		t.Fatalf("Decrypt error = %v, want original ErrCorruptData preserved", err)
	}
	if !strings.Contains(err.Error(), "remove staged output") ||
		!strings.Contains(err.Error(), reporter.stagePath) {
		t.Fatalf("Decrypt error = %v, want explicit retained stage path %q", err, reporter.stagePath)
	}
	if _, statErr := os.Lstat(outputPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("Failed decrypt published final output: %v", statErr)
	}
	gotStage, readErr := os.ReadFile(reporter.stagePath)
	if readErr != nil {
		t.Fatalf("Read reported plaintext residue: %v", readErr)
	}
	wantStage := append([]byte(nil), plaintext...)
	wantStage[len(wantStage)-1] ^= 0x80
	if !bytes.Equal(gotStage, wantStage) {
		t.Fatalf("Reported residue = %q, want the actual decrypted payload %q", gotStage, wantStage)
	}
	if removeErr := os.Remove(reporter.stagePath); removeErr != nil {
		t.Fatalf("Remove reported test residue: %v", removeErr)
	}
}

func TestZipDetectionUsesRetainedStageAfterPathReplacement(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "decrypted-output")
	payload := []byte("valid ZIP payload")
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	entry, err := writer.CreateHeader(&zip.FileHeader{
		Name:   "payload.txt",
		Method: zip.Store,
	})
	if err != nil {
		t.Fatalf("create ZIP entry: %v", err)
	}
	if _, err := entry.Write(payload); err != nil {
		t.Fatalf("write ZIP entry: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close ZIP fixture: %v", err)
	}

	ctx := &OperationContext{OutputFile: outputPath}
	if err := ctx.beginStagedOutput(); err != nil {
		t.Fatalf("begin staged output: %v", err)
	}
	defer func() {
		if err := ctx.Close(); err != nil {
			t.Errorf("close operation context: %v", err)
		}
	}()
	if _, err := ctx.stagedOutput.File().Write(archive.Bytes()); err != nil {
		t.Fatalf("write retained ZIP stage: %v", err)
	}

	stagePath := ctx.stagedOutput.Path()
	if err := os.Remove(stagePath); err != nil {
		t.Skipf("platform prevents replacing an open staged file: %v", err)
	}
	foreign := []byte("foreign replacement is not a ZIP")
	if err := os.WriteFile(stagePath, foreign, 0o600); err != nil {
		t.Fatalf("write replacement at staged path: %v", err)
	}

	isZip, err := isStagedOutputZip(ctx)
	if err != nil {
		t.Fatalf("detect ZIP through retained stage: %v", err)
	}
	if !isZip {
		t.Fatal("ZIP detection followed the replacement path instead of the retained stage")
	}
	assertFileBytes(t, stagePath, foreign)
}

func TestEncryptSplitDoesNotRemoveReplacementAtUnsplitPath(t *testing.T) {
	dir := t.TempDir()
	plaintext := bytes.Repeat([]byte("split-race-payload"), 8192)
	inputPath := filepath.Join(dir, "input.bin")
	if err := os.WriteFile(inputPath, plaintext, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	outputPath := filepath.Join(dir, "output.pcv")
	ownedBackup := filepath.Join(dir, "owned-unsplit-volume.pcv")
	foreignBytes := []byte("replacement at the unsplit pathname must survive")
	reporter := &pathSwapReporter{
		trigger: "Splitting at ",
		path:    outputPath,
		backup:  ownedBackup,
		foreign: foreignBytes,
	}

	err := Encrypt(context.Background(), &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: outputPath,
		Password:   []byte("split-race-password"),
		Split:      true,
		ChunkSize:  2,
		ChunkUnit:  fileops.SplitUnitTotal,
		Reporter:   reporter,
		RSCodecs:   newRSCodecsT(t),
	})
	if reporter.err != nil {
		if windowsPreventedOpenHandleRename(reporter.err) {
			if err != nil {
				t.Fatalf("Encrypt after the OS prevented unsplit output replacement: %v", err)
			}
			if _, statErr := os.Lstat(outputPath); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("successful split retained the unsplit output: %v", statErr)
			}
			safeOutput := filepath.Join(dir, "safe-output.bin")
			if err := Decrypt(context.Background(), &DecryptRequest{
				InputFile:  outputPath + ".0",
				OutputFile: safeOutput,
				Password:   []byte("split-race-password"),
				Recombine:  true,
				RSCodecs:   newRSCodecsT(t),
			}); err != nil {
				t.Fatalf("decrypt split output after prevented replacement: %v", err)
			}
			assertFileBytes(t, safeOutput, plaintext)
			return
		}
		t.Fatalf("replace unsplit output during real Split: %v", reporter.err)
	}
	if err == nil || !strings.Contains(err.Error(), "changed during splitting") {
		t.Fatalf("Encrypt error = %v, want explicit refusal to remove a replaced output path", err)
	}
	assertFileBytes(t, outputPath, foreignBytes)

	safeOutput := filepath.Join(dir, "safe-output.bin")
	if err := Decrypt(context.Background(), &DecryptRequest{
		InputFile:  ownedBackup,
		OutputFile: safeOutput,
		Password:   []byte("split-race-password"),
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("decrypt operation-owned unsplit volume: %v", err)
	}
	assertFileBytes(t, safeOutput, plaintext)
}

func TestEncryptSplitRejectsReplacementBeforeOpeningOwnedOutput(t *testing.T) {
	dir := t.TempDir()
	plaintext := bytes.Repeat([]byte("split-preopen-race-payload"), 4096)
	inputPath := filepath.Join(dir, "input.bin")
	if err := os.WriteFile(inputPath, plaintext, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	outputPath := filepath.Join(dir, "output.pcv")
	ownedBackup := filepath.Join(dir, "owned-unsplit-volume.pcv")
	foreignBytes := []byte("replacement before Split opens its input must survive")
	reporter := &pathSwapReporter{
		trigger: "Splitting...",
		path:    outputPath,
		backup:  ownedBackup,
		foreign: foreignBytes,
	}

	err := Encrypt(context.Background(), &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: outputPath,
		Password:   []byte("split-preopen-race-password"),
		Split:      true,
		ChunkSize:  2,
		ChunkUnit:  fileops.SplitUnitTotal,
		Reporter:   reporter,
		RSCodecs:   newRSCodecsT(t),
	})
	if reporter.err != nil {
		t.Fatalf("replace unsplit output before Split opens it: %v", reporter.err)
	}
	if err == nil || !strings.Contains(err.Error(), "input path changed before splitting") {
		t.Fatalf("Encrypt error = %v, want changed-input refusal", err)
	}
	assertFileBytes(t, outputPath, foreignBytes)
	for _, chunk := range []string{outputPath + ".0", outputPath + ".1"} {
		if _, statErr := os.Lstat(chunk); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("foreign replacement was split into %q: %v", chunk, statErr)
		}
	}

	safeOutput := filepath.Join(dir, "safe-output.bin")
	if err := Decrypt(context.Background(), &DecryptRequest{
		InputFile:  ownedBackup,
		OutputFile: safeOutput,
		Password:   []byte("split-preopen-race-password"),
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("decrypt operation-owned unsplit volume: %v", err)
	}
	assertFileBytes(t, safeOutput, plaintext)
}

func TestDecryptRecombineDoesNotRemoveReplacementAtTemporaryPath(t *testing.T) {
	dir := t.TempDir()
	plaintext := bytes.Repeat([]byte("recombine-race-payload"), 4096)
	inputPath := filepath.Join(dir, "input.bin")
	if err := os.WriteFile(inputPath, plaintext, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	volumeBase := filepath.Join(dir, "split-volume.pcv")
	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: volumeBase,
		Password:   []byte("recombine-race-password"),
		Split:      true,
		ChunkSize:  2,
		ChunkUnit:  fileops.SplitUnitTotal,
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("encrypt split fixture: %v", err)
	}

	ownedBackup := filepath.Join(dir, "owned-recombined-volume.pcv")
	foreignBytes := []byte("replacement at the recombined pathname must survive")
	reporter := &pathSwapReporter{
		trigger: "Reading values...",
		path:    volumeBase,
		backup:  ownedBackup,
		foreign: foreignBytes,
	}
	outputPath := filepath.Join(dir, "unsafe-output.bin")
	err := Decrypt(context.Background(), &DecryptRequest{
		InputFile:  volumeBase,
		OutputFile: outputPath,
		Password:   []byte("recombine-race-password"),
		Recombine:  true,
		Reporter:   reporter,
		RSCodecs:   newRSCodecsT(t),
	})
	if reporter.err != nil {
		t.Fatalf("replace recombined path before header read: %v", reporter.err)
	}
	if err == nil {
		t.Fatal("Decrypt unexpectedly accepted the foreign replacement as a volume")
	}
	assertFileBytes(t, volumeBase, foreignBytes)
	if _, statErr := os.Stat(outputPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed decrypt published an output: %v", statErr)
	}

	safeOutput := filepath.Join(dir, "safe-recombined-output.bin")
	if err := Decrypt(context.Background(), &DecryptRequest{
		InputFile:  ownedBackup,
		OutputFile: safeOutput,
		Password:   []byte("recombine-race-password"),
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("decrypt operation-owned recombined volume: %v", err)
	}
	assertFileBytes(t, safeOutput, plaintext)
}

func TestDecryptRecombineRefusesDifferentValidVolumeAtOwnedPath(t *testing.T) {
	dir := t.TempDir()
	password := []byte("recombine-valid-swap-password")
	ownedPlaintext := []byte("plaintext from the split volume")
	ownedInput := filepath.Join(dir, "owned.txt")
	if err := os.WriteFile(ownedInput, ownedPlaintext, 0o600); err != nil {
		t.Fatalf("write split plaintext: %v", err)
	}
	volumeBase := filepath.Join(dir, "split-volume.pcv")
	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile:  ownedInput,
		OutputFile: volumeBase,
		Password:   password,
		Split:      true,
		ChunkSize:  2,
		ChunkUnit:  fileops.SplitUnitTotal,
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("encrypt split fixture: %v", err)
	}

	foreignPlaintext := []byte("plaintext from a different valid volume")
	foreignInput := filepath.Join(dir, "foreign.txt")
	if err := os.WriteFile(foreignInput, foreignPlaintext, 0o600); err != nil {
		t.Fatalf("write foreign plaintext: %v", err)
	}
	foreignVolume := filepath.Join(dir, "foreign.pcv")
	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile:  foreignInput,
		OutputFile: foreignVolume,
		Password:   password,
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("encrypt foreign volume: %v", err)
	}
	foreignBytes, err := os.ReadFile(foreignVolume)
	if err != nil {
		t.Fatalf("read foreign volume: %v", err)
	}

	ownedBackup := filepath.Join(dir, "owned-recombined-volume.pcv")
	reporter := &pathMoveReporter{
		trigger:     "Reading values...",
		path:        volumeBase,
		backup:      ownedBackup,
		replacement: foreignVolume,
	}
	outputPath := filepath.Join(dir, "must-not-publish.txt")
	err = Decrypt(context.Background(), &DecryptRequest{
		InputFile:  volumeBase,
		OutputFile: outputPath,
		Password:   password,
		Recombine:  true,
		Reporter:   reporter,
		RSCodecs:   newRSCodecsT(t),
	})
	if reporter.err != nil {
		t.Fatalf("replace recombined path with valid volume: %v", reporter.err)
	}
	if err == nil || !strings.Contains(err.Error(), "recombined") {
		t.Fatalf("Decrypt error = %v, want recombined identity refusal", err)
	}
	if _, statErr := os.Lstat(outputPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("foreign plaintext was published before identity refusal: %v", statErr)
	}
	assertFileBytes(t, volumeBase, foreignBytes)

	ownedOutput := filepath.Join(dir, "owned-output.txt")
	if err := Decrypt(context.Background(), &DecryptRequest{
		InputFile:  ownedBackup,
		OutputFile: ownedOutput,
		Password:   password,
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("decrypt operation-owned recombined volume: %v", err)
	}
	assertFileBytes(t, ownedOutput, ownedPlaintext)

	foreignOutput := filepath.Join(dir, "foreign-output.txt")
	if err := Decrypt(context.Background(), &DecryptRequest{
		InputFile:  volumeBase,
		OutputFile: foreignOutput,
		Password:   password,
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("decrypt preserved foreign volume: %v", err)
	}
	assertFileBytes(t, foreignOutput, foreignPlaintext)
}

// A split input is temporarily recombined at its base path. Publishing
// plaintext to that same path would replace the operation's own encrypted
// input and then make cleanup report a late failure. Reject the conflict before
// recombination, exactly as for a non-split volume.
func TestDecryptRecombineRejectsTemporaryVolumeAsOutput(t *testing.T) {
	dir := t.TempDir()
	plaintext := []byte("split input must remain recoverable after output rejection")
	volumePath, _ := encryptSafetyFixture(t, dir, "split-alias", plaintext)

	chunks, err := fileops.Split(fileops.SplitOptions{
		InputPath: volumePath,
		ChunkSize: 2,
		Unit:      fileops.SplitUnitTotal,
	})
	if err != nil {
		t.Fatalf("split encrypted fixture: %v", err)
	}
	if err := os.Remove(volumePath); err != nil {
		t.Fatalf("remove unsplit fixture: %v", err)
	}
	chunkBytes := make(map[string][]byte, len(chunks))
	for _, chunk := range chunks {
		data, readErr := os.ReadFile(chunk)
		if readErr != nil {
			t.Fatalf("read chunk %q: %v", chunk, readErr)
		}
		chunkBytes[chunk] = data
	}

	err = Decrypt(context.Background(), &DecryptRequest{
		InputFile:  chunks[0],
		OutputFile: volumePath,
		Password:   []byte("output-safety-password"),
		Recombine:  true,
		RSCodecs:   newRSCodecsT(t),
	})
	var validationErr *perrors.ValidationError
	if !errors.As(err, &validationErr) || validationErr.Field != "OutputFile" {
		t.Fatalf("Decrypt error = %v, want OutputFile validation error", err)
	}
	if _, statErr := os.Lstat(volumePath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("rejected decrypt created the temporary volume/output path: %v", statErr)
	}
	for chunk, want := range chunkBytes {
		assertFileBytes(t, chunk, want)
	}

	safeOutput := filepath.Join(dir, "safe-split-output.txt")
	if err := Decrypt(context.Background(), &DecryptRequest{
		InputFile:  chunks[0],
		OutputFile: safeOutput,
		Password:   []byte("output-safety-password"),
		Recombine:  true,
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("safe split Decrypt failed after rejection: %v", err)
	}
	assertFileBytes(t, safeOutput, plaintext)
	if _, statErr := os.Lstat(volumePath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("safe decrypt left the recombined temporary volume: %v", statErr)
	}
}

func TestAddDeniabilityPreservesPreexistingLegacyTemp(t *testing.T) {
	dir := t.TempDir()
	plaintext := []byte("inner volume")
	volumePath, _ := encryptSafetyFixture(t, dir, "deniable", plaintext)

	legacyTemp := volumePath + ".tmp"
	foreignBytes := []byte("foreign file using the old predictable deniability temp name")
	if err := os.WriteFile(legacyTemp, foreignBytes, 0o600); err != nil {
		t.Fatalf("write protected temp: %v", err)
	}

	if err := AddDeniability(volumePath, []byte("output-safety-password"), nil); err != nil {
		t.Fatalf("AddDeniability failed: %v", err)
	}
	assertFileBytes(t, legacyTemp, foreignBytes)

	innerStage, err := RemoveDeniability(
		volumePath,
		[]byte("output-safety-password"),
		nil,
		newRSCodecsT(t),
	)
	if err != nil {
		t.Fatalf("RemoveDeniability failed after wrapping: %v", err)
	}
	defer innerStage.Cleanup()
	safeOutput := filepath.Join(dir, "safe-deniable-output.txt")
	if err := Decrypt(context.Background(), &DecryptRequest{
		InputFile:  innerStage.Path(),
		OutputFile: safeOutput,
		Password:   []byte("output-safety-password"),
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("decrypt unwrapped volume: %v", err)
	}
	assertFileBytes(t, safeOutput, plaintext)
}

func TestAddDeniabilityDoesNotReplaceChangedVolumePath(t *testing.T) {
	dir := t.TempDir()
	plaintext := []byte("inner volume survives deniability path replacement")
	volumePath, _ := encryptSafetyFixture(t, dir, "deniability-race", plaintext)
	ownedBackup := filepath.Join(dir, "owned-inner-volume.pcv")
	foreignBytes := []byte("replacement at the volume pathname must survive")
	reporter := &pathSwapReporter{
		trigger: "Adding deniability at ",
		path:    volumePath,
		backup:  ownedBackup,
		foreign: foreignBytes,
	}

	err := AddDeniability(volumePath, []byte("output-safety-password"), reporter)
	if reporter.err != nil {
		if windowsPreventedOpenHandleRename(reporter.err) {
			if err != nil {
				t.Fatalf("AddDeniability after the OS prevented volume replacement: %v", err)
			}
			innerStage, removeErr := RemoveDeniability(
				volumePath,
				[]byte("output-safety-password"),
				nil,
				newRSCodecsT(t),
			)
			if removeErr != nil {
				t.Fatalf("remove deniability after prevented replacement: %v", removeErr)
			}
			defer innerStage.Cleanup()
			safeOutput := filepath.Join(dir, "safe-inner-output.txt")
			if err := Decrypt(context.Background(), &DecryptRequest{
				InputFile:  innerStage.Path(),
				OutputFile: safeOutput,
				Password:   []byte("output-safety-password"),
				RSCodecs:   newRSCodecsT(t),
			}); err != nil {
				t.Fatalf("decrypt volume after prevented replacement: %v", err)
			}
			assertFileBytes(t, safeOutput, plaintext)
			return
		}
		t.Fatalf("replace volume path during AddDeniability: %v", reporter.err)
	}
	if err == nil || !strings.Contains(err.Error(), "volume path changed") {
		t.Fatalf("AddDeniability error = %v, want changed-volume refusal", err)
	}
	assertFileBytes(t, volumePath, foreignBytes)

	safeOutput := filepath.Join(dir, "safe-inner-output.txt")
	if err := Decrypt(context.Background(), &DecryptRequest{
		InputFile:  ownedBackup,
		OutputFile: safeOutput,
		Password:   []byte("output-safety-password"),
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("decrypt original volume after deniability refusal: %v", err)
	}
	assertFileBytes(t, safeOutput, plaintext)
}

func TestRemoveDeniabilityDoesNotOverwriteInputNamedTmp(t *testing.T) {
	dir := t.TempDir()
	plaintext := []byte("inner volume")
	volumePath, _ := encryptSafetyFixture(t, dir, "wrapped", plaintext)
	tmpNamedVolume := filepath.Join(dir, "wrapped.tmp")
	if err := os.Rename(volumePath, tmpNamedVolume); err != nil {
		t.Fatalf("rename fixture: %v", err)
	}
	if err := AddDeniability(tmpNamedVolume, []byte("output-safety-password"), nil); err != nil {
		t.Fatalf("AddDeniability failed: %v", err)
	}

	before, err := os.ReadFile(tmpNamedVolume)
	if err != nil {
		t.Fatalf("read wrapped fixture: %v", err)
	}
	decryptedStage, err := RemoveDeniability(
		tmpNamedVolume,
		[]byte("output-safety-password"),
		nil,
		newRSCodecsT(t),
	)
	if err != nil {
		t.Fatalf("RemoveDeniability failed: %v", err)
	}
	t.Cleanup(func() {
		if err := decryptedStage.Cleanup(); err != nil {
			t.Errorf("Cleanup decrypted stage: %v", err)
		}
	})

	if decryptedStage.Path() == tmpNamedVolume {
		t.Fatalf("RemoveDeniability returned its input path %q as temporary output", decryptedStage.Path())
	}
	assertFileBytes(t, tmpNamedVolume, before)

	safeOutput := filepath.Join(dir, "safe-unwrapped-output.txt")
	if err := Decrypt(context.Background(), &DecryptRequest{
		InputFile:  decryptedStage.Path(),
		OutputFile: safeOutput,
		Password:   []byte("output-safety-password"),
		RSCodecs:   newRSCodecsT(t),
	}); err != nil {
		t.Fatalf("decrypt unwrapped volume: %v", err)
	}
	assertFileBytes(t, safeOutput, plaintext)
}
