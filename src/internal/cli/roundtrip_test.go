package cli

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestCLIRoundTrip encrypts a fixed plaintext then decrypts it using the real
// Cobra commands and asserts recovered bytes == original. Each row is a
// distinct flag combination. The fast-KDF seam lives in internal/volume and is
// not exported to this package, so we keep payloads tiny (8 bytes) to limit
// wall-clock time while still exercising the full codepath.
func TestCLIRoundTrip(t *testing.T) {
	plaintext := []byte("testdata")

	tests := []struct {
		name         string
		setupEncrypt func(t *testing.T, in, out string)
		setupDecrypt func(t *testing.T, in, out string)
		wantErr      bool // expect decrypt to fail (wrong-password row)
	}{
		{
			name: "plain",
			setupEncrypt: func(t *testing.T, in, out string) {
				encPassword = "pass1"
			},
			setupDecrypt: func(t *testing.T, in, out string) {
				decPassword = "pass1"
			},
		},
		{
			name: "paranoid",
			setupEncrypt: func(t *testing.T, in, out string) {
				encPassword = "pass4"
				encParanoid = true
			},
			setupDecrypt: func(t *testing.T, in, out string) {
				decPassword = "pass4"
			},
		},
		{
			name: "reed-solomon",
			setupEncrypt: func(t *testing.T, in, out string) {
				encPassword = "pass5"
				encReedSolomon = true
			},
			setupDecrypt: func(t *testing.T, in, out string) {
				decPassword = "pass5"
			},
		},
		{
			name: "deniability",
			setupEncrypt: func(t *testing.T, in, out string) {
				encPassword = "pass6"
				encDeniability = true
				encParanoid = true
			},
			setupDecrypt: func(t *testing.T, in, out string) {
				decPassword = "pass6"
				decPCV3Format = "d1"
			},
		},
		{
			// compress wraps the file in a zip before encryption; the decrypted
			// output is a zip archive. We verify the zip contains the plaintext.
			name: "compress",
			setupEncrypt: func(t *testing.T, in, out string) {
				encPassword = "pass7"
				encCompress = true
			},
			setupDecrypt: func(t *testing.T, in, out string) {
				decPassword = "pass7"
			},
		},
		{
			name: "verify-first",
			setupEncrypt: func(t *testing.T, in, out string) {
				encPassword = "pass8"
			},
			setupDecrypt: func(t *testing.T, in, out string) {
				decPassword = "pass8"
				decVerifyFirst = true
			},
		},
		{
			name: "wrong password",
			setupEncrypt: func(t *testing.T, in, out string) {
				encPassword = "correct"
			},
			setupDecrypt: func(t *testing.T, in, out string) {
				decPassword = "wrong"
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset all flags before and after each sub-test to prevent bleed.
			resetEncryptFlagsForDirTest()
			resetDecryptFlagsForDirTest()
			t.Cleanup(resetEncryptFlagsForDirTest)
			t.Cleanup(resetDecryptFlagsForDirTest)

			tmpDir := t.TempDir()
			inputFile := filepath.Join(tmpDir, "plain.bin")
			encryptedFile := filepath.Join(tmpDir, "enc.pcv")
			decryptedFile := filepath.Join(tmpDir, "dec.bin")

			if err := os.WriteFile(inputFile, plaintext, 0o600); err != nil {
				t.Fatalf("write input: %v", err)
			}

			// --- ENCRYPT ---
			encOutput = encryptedFile
			encQuiet = true
			encYes = true
			tc.setupEncrypt(t, inputFile, encryptedFile)

			if tc.name == "verify-first" {
				// Preserve the legacy verify-first contract using a frozen legacy fixture.
				copyCLITestFile(t, filepath.Join("..", "..", "testdata", "golden", "pico_test_v2.txt.pcv"), encryptedFile)
			} else {
				requireNativePCV3FileError(t, encryptCmd.RunE(encryptCmd, []string{inputFile}))
			}

			// --- DECRYPT ---
			decOutput = decryptedFile
			decQuiet = true
			decYes = true
			tc.setupDecrypt(t, encryptedFile, decryptedFile)
			if tc.name == "verify-first" {
				decPassword = "test"
			} else {
				decPCV3Factors = "password"
			}
			if tc.name == "compress" {
				decPCV3Archive = "extract"
				decPCV3ExtractTo = t.TempDir()
			}

			decErr := decryptCmd.RunE(decryptCmd, []string{encryptedFile})
			if tc.wantErr {
				if decErr == nil {
					t.Fatal("expected decrypt error (wrong password), got nil")
				}
				if exitCodeForError(decErr) != ExitGeneralError || !isExitCodeError(decErr) {
					t.Fatalf("wrong-password error not classified: %v", decErr)
				}
				if _, err := os.Lstat(decryptedFile); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("wrong password produced output: %v", err)
				}

				return
			}
			if tc.name == "verify-first" {
				if decErr != nil {
					t.Fatalf("legacy verify-first decrypt: %v", decErr)
				}
			} else {
				requireNativePCV3FileError(t, decErr)
			}

			// Assert recovered bytes == original.
			// The compress case produces a zip archive; verify the first entry.
			if tc.name == "compress" {
				got, err := os.ReadFile(filepath.Join(decPCV3ExtractTo, filepath.Base(inputFile)))
				if err != nil || !bytes.Equal(got, plaintext) {
					t.Fatalf("compressed payload = %q, %v", got, err)
				}
			} else {
				got, err := os.ReadFile(decryptedFile)
				if err != nil {
					t.Fatalf("read decrypted output: %v", err)
				}
				want := plaintext
				if tc.name == "verify-first" {
					var err error
					want, err = os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "pico_test.txt"))
					if err != nil {
						t.Fatal(err)
					}
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("roundtrip mismatch: got %q, want %q", got, want)
				}
			}
		})
	}
}

func TestPCV3CLIRoundTrip(t *testing.T) {
	plaintext := []byte("PCV3 Linux CLI round-trip\n")
	comment := "authenticated PCV3 note\nsecond line"
	dir := t.TempDir()
	input := filepath.Join(dir, "plain.bin")
	volume := filepath.Join(dir, "encrypted.pcv")
	output := filepath.Join(dir, "plain.out")
	if err := os.WriteFile(input, plaintext, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	binary := buildCLITestBinary(t)
	existingVolume := filepath.Join(dir, "existing.pcv")
	existingBytes := []byte("existing output must survive")
	if err := os.WriteFile(existingVolume, existingBytes, 0o600); err != nil {
		t.Fatalf("write existing output: %v", err)
	}
	refused := runCLITestCommand(
		t,
		binary,
		"encrypt", input, "-o", existingVolume, "--pcv3", "-p", "roundtrip-password", "--quiet", "--yes",
	)
	if refused.exitCode == 0 || !strings.Contains(refused.stderr, "already exists") {
		t.Fatalf("occupied PCV3 creation exit=%d stderr=%q", refused.exitCode, refused.stderr)
	}
	if got, err := os.ReadFile(existingVolume); err != nil || !bytes.Equal(got, existingBytes) {
		t.Fatalf("refused PCV3 write changed existing output: %q, %v", got, err)
	}

	encrypted := runCLITestCommand(
		t,
		binary,
		"encrypt", input, "-o", volume, "--pcv3", "-p", "roundtrip-password",
		"--comments", comment, "--quiet",
	)
	requireNativePCV3Published(t, encrypted, "")
	encoded, err := os.ReadFile(volume)
	if err != nil {
		t.Fatalf("read PCV3 volume: %v", err)
	}
	if len(encoded) < 4 || !bytes.Equal(encoded[:4], []byte{'P', 'C', 'V', 0}) {
		t.Fatalf("encrypted output does not have the PCV3 discriminator: %x", encoded)
	}

	decrypted := runCLITestCommand(
		t,
		binary,
		"decrypt", volume, "-o", output,
		"--pcv3-factors=password", "-p", "roundtrip-password", "--quiet",
	)
	requireNativePCV3Published(t, decrypted, comment)
	if !strings.Contains(decrypted.stderr, "Comment: "+strconv.Quote(comment)+"\n") {
		t.Fatalf("PCV3 decrypt did not show the authenticated comment: %q", decrypted.stderr)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read decrypted output: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("PCV3 round-trip mismatch: got %q, want %q", got, plaintext)
	}
	overwriteSentinel := []byte("existing plaintext must survive PCV3 --yes")
	if err := os.WriteFile(output, overwriteSentinel, 0o600); err != nil {
		t.Fatalf("replace output with overwrite sentinel: %v", err)
	}
	occupied := runCLITestCommand(
		t,
		binary,
		"decrypt", volume, "-o", output, "--yes",
		"--pcv3-factors=password", "-p", "roundtrip-password", "--quiet",
	)
	if occupied.exitCode == 0 || !strings.Contains(occupied.stderr, "already exists") {
		t.Fatalf("occupied PCV3 decrypt exit=%d stderr=%q", occupied.exitCode, occupied.stderr)
	}
	if got, err := os.ReadFile(output); err != nil || !bytes.Equal(got, overwriteSentinel) {
		t.Fatalf("occupied PCV3 decrypt changed output: %q err=%v", got, err)
	}

	wrongOutput := filepath.Join(dir, "wrong-password.out")
	wrong := runCLITestCommand(
		t,
		binary,
		"decrypt", volume, "-o", wrongOutput,
		"--pcv3-factors=password", "-p", "wrong-password", "--quiet",
	)
	if wrong.exitCode == 0 {
		t.Fatal("PCV3 decrypt accepted the wrong password")
	}
	if strings.Contains(wrong.stderr, comment) {
		t.Fatalf("failed PCV3 authentication exposed the comment: %q", wrong.stderr)
	}
	if _, err := os.Lstat(wrongOutput); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed PCV3 authentication created output: %v", err)
	}

	keyfileA := filepath.Join(dir, "a.key")
	keyfileB := filepath.Join(dir, "b.key")
	for path, data := range map[string][]byte{
		keyfileA: []byte("first keyfile"),
		keyfileB: []byte("second keyfile"),
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write keyfile: %v", err)
		}
	}
	keyfileVolume := filepath.Join(dir, "keyfiles.pcv")
	keyfileOutput := filepath.Join(dir, "keyfiles.out")
	encrypted = runCLITestCommand(
		t,
		binary,
		"encrypt", input, "-o", keyfileVolume, "--pcv3", "--paranoid", "--reed-solomon",
		"-k", keyfileA, "-k", keyfileB, "-p", "", "--quiet",
	)
	requireNativePCV3Published(t, encrypted, "")
	if strings.Contains(encrypted.stderr, "Password:") {
		t.Fatalf("explicit keyfile-only encryption prompted for a password: %q", encrypted.stderr)
	}
	decrypted = runCLITestCommand(
		t,
		binary,
		"decrypt", keyfileVolume, "-o", keyfileOutput,
		"--pcv3-factors=keyfiles", "--pcv3-keyfile-order=unordered",
		"-k", keyfileA, "-k", keyfileB, "-p", "", "--quiet",
	)
	requireNativePCV3Published(t, decrypted, "")
	got, err = os.ReadFile(keyfileOutput)
	if err != nil {
		t.Fatalf("read keyfile-decrypted output: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("PCV3 keyfile round-trip mismatch: got %q, want %q", got, plaintext)
	}

	archiveInput := filepath.Join(dir, "archive.txt")
	archivePlaintext := []byte("PCV3 archive payload\n")
	if err := os.WriteFile(archiveInput, archivePlaintext, 0o600); err != nil {
		t.Fatalf("write archive input: %v", err)
	}
	archiveVolume := filepath.Join(dir, "archive.pcv")
	extractRoot := filepath.Join(dir, "extracted")
	if err := os.Mkdir(extractRoot, 0o700); err != nil {
		t.Fatalf("create extraction root: %v", err)
	}
	encrypted = runCLITestCommand(
		t,
		binary,
		"encrypt", archiveInput, "-o", archiveVolume, "--pcv3", "--compress",
		"-p", "archive-password", "--quiet",
	)
	requireNativePCV3Published(t, encrypted, "")
	decrypted = runCLITestCommand(
		t,
		binary,
		"decrypt", archiveVolume, "-o", filepath.Join(dir, "archive-stage"),
		"--pcv3-factors=password", "-p", "archive-password",
		"--pcv3-archive=extract", "--pcv3-extract-to="+extractRoot, "--quiet",
	)
	requireNativePCV3Published(t, decrypted, "")
	got, err = os.ReadFile(filepath.Join(extractRoot, filepath.Base(archiveInput)))
	if err != nil {
		t.Fatalf("read extracted PCV3 archive file: %v", err)
	}
	if !bytes.Equal(got, archivePlaintext) {
		t.Fatalf("PCV3 archive round-trip mismatch: got %q, want %q", got, archivePlaintext)
	}

	d1ArchiveVolume := filepath.Join(dir, "d1-archive.zip.pcv")
	d1ArchiveOutput := filepath.Join(dir, "d1-archive.zip")
	encrypted = runCLITestCommand(
		t,
		binary,
		"encrypt", archiveInput, "-o", d1ArchiveVolume,
		"--pcv3", "--deniability", "--paranoid", "--compress",
		"-p", "d1-archive-password", "--quiet",
	)
	requireNativePCV3Published(t, encrypted, "")
	d1ExtractRoot := filepath.Join(dir, "d1-extract")
	if err := os.Mkdir(d1ExtractRoot, 0o700); err != nil {
		t.Fatalf("create D1 extraction root: %v", err)
	}
	extractAttempt := runCLITestCommand(
		t,
		binary,
		"decrypt", d1ArchiveVolume, "-o", d1ArchiveOutput, "--pcv3-format=d1",
		"--pcv3-factors=password", "-p", "d1-archive-password",
		"--pcv3-archive=extract", "--pcv3-extract-to="+d1ExtractRoot, "--quiet",
	)
	if extractAttempt.exitCode == 0 || !strings.Contains(extractAttempt.stderr, "D1 archive") {
		t.Fatalf("D1 archive extraction was not rejected explicitly: exit %d stderr %q", extractAttempt.exitCode, extractAttempt.stderr)
	}
	decrypted = runCLITestCommand(
		t,
		binary,
		"decrypt", d1ArchiveVolume, "-o", d1ArchiveOutput, "--pcv3-format=d1",
		"--pcv3-factors=password", "-p", "d1-archive-password", "--quiet",
	)
	requireNativePCV3Published(t, decrypted, "")
	assertZipContainsPlaintext(t, d1ArchiveOutput, archivePlaintext)

	d1Volume := filepath.Join(dir, "deniable.pcv")
	d1Output := filepath.Join(dir, "deniable.out")
	d1Comment := "authenticated D1 note\nsecond line"
	encrypted = runCLITestCommand(
		t,
		binary,
		"encrypt", input, "-o", d1Volume, "--pcv3", "--deniability", "--paranoid",
		"-p", "d1-password", "--comments", d1Comment, "--quiet",
	)
	requireNativePCV3Published(t, encrypted, "")
	decrypted = runCLITestCommand(
		t,
		binary,
		"decrypt", d1Volume, "-o", d1Output, "--pcv3-format=d1",
		"--pcv3-factors=password", "-p", "d1-password", "--quiet",
	)
	requireNativePCV3Published(t, decrypted, d1Comment)
	if !strings.Contains(decrypted.stderr, "Comment: "+strconv.Quote(d1Comment)+"\n") {
		t.Fatalf("PCV3 D1 decrypt did not show the authenticated comment: %q", decrypted.stderr)
	}
	got, err = os.ReadFile(d1Output)
	if err != nil {
		t.Fatalf("read D1-decrypted output: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("PCV3 D1 round-trip mismatch: got %q, want %q", got, plaintext)
	}
	wrongD1Output := filepath.Join(dir, "deniable-wrong.out")
	wrongD1 := runCLITestCommand(
		t,
		binary,
		"decrypt", d1Volume, "-o", wrongD1Output, "--pcv3-format=d1",
		"--pcv3-factors=password", "-p", "wrong-d1-password", "--quiet",
	)
	if wrongD1.exitCode == 0 {
		t.Fatal("PCV3 D1 decrypt accepted the wrong password")
	}
	if strings.Contains(wrongD1.stderr, d1Comment) {
		t.Fatalf("failed PCV3 D1 authentication exposed the comment: %q", wrongD1.stderr)
	}
	if _, err := os.Lstat(wrongD1Output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed PCV3 D1 authentication created output: %v", err)
	}
}

func TestPCV3CLIStreamPasswordFDKeepsCredentialOutOfPayloadAndOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("inherited Unix file descriptors are not available on Windows")
	}

	binary := buildCLITestBinary(t)
	plaintext := []byte("PCV3 password-fd stream payload\n")
	password := []byte("password-fd-secret")
	for _, test := range []struct {
		name         string
		encryptFlags []string
		decryptFlags []string
		normal       bool
	}{
		{name: "normal", normal: true},
		{
			name:         "d1",
			encryptFlags: []string{"--deniability", "--paranoid"},
			decryptFlags: []string{"--pcv3-format=d1"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			encryptArgs := []string{
				"encrypt", "-", "-o", "-", "--pcv3",
				"--password-fd=3", "--quiet",
			}
			encryptArgs = append(encryptArgs, test.encryptFlags...)
			encrypted := runCLITestCommandWithInputAndPasswordFD(
				t, binary, plaintext, password, encryptArgs...,
			)
			if encrypted.exitCode != 0 {
				t.Fatalf("stream encrypt exit = %d, stderr = %q", encrypted.exitCode, encrypted.stderr)
			}
			if bytes.Contains(encrypted.stdout, password) || strings.Contains(encrypted.stderr, string(password)) {
				t.Fatal("stream encryption disclosed the password")
			}
			if test.normal != bytes.HasPrefix(encrypted.stdout, []byte{'P', 'C', 'V', 0}) {
				t.Fatalf("stream output format does not match %s intent", test.name)
			}

			decryptArgs := []string{
				"decrypt", "-", "-o", "-", "--pcv3-factors=password",
				"--password-fd=3", "--quiet",
			}
			decryptArgs = append(decryptArgs, test.decryptFlags...)
			decrypted := runCLITestCommandWithInputAndPasswordFD(
				t, binary, encrypted.stdout, password, decryptArgs...,
			)
			if decrypted.exitCode != 0 {
				t.Fatalf("stream decrypt exit = %d, stderr = %q", decrypted.exitCode, decrypted.stderr)
			}
			if !bytes.Equal(decrypted.stdout, plaintext) {
				t.Fatalf("stream round-trip = %q; want %q", decrypted.stdout, plaintext)
			}
			if strings.Contains(decrypted.stderr, string(password)) {
				t.Fatal("stream decryption disclosed the password")
			}
		})
	}
}

func TestPCV3CLIKeyfileOnlyD1RoundTripAndWrongKeyRefusal(t *testing.T) {
	binary := buildCLITestBinary(t)
	directory := t.TempDir()
	plaintext := []byte("PCV3 D1 keyfile-only CLI round-trip\n")
	input := filepath.Join(directory, "plain.bin")
	volume := filepath.Join(directory, "keyfile-only-d1.pcv")
	output := filepath.Join(directory, "plain.out")
	wrongOutput := filepath.Join(directory, "wrong.out")
	keyfile := filepath.Join(directory, "keyfile.bin")
	wrongKeyfile := filepath.Join(directory, "wrong-keyfile.bin")
	for path, content := range map[string][]byte{
		input:        plaintext,
		keyfile:      []byte("high-entropy-test-keyfile-factor"),
		wrongKeyfile: []byte("different-test-keyfile-factor"),
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatalf("write %s: %v", filepath.Base(path), err)
		}
	}

	encrypted := runCLITestCommand(
		t,
		binary,
		"encrypt", input, "-o", volume,
		"--pcv3", "--deniability", "--paranoid",
		"-k", keyfile, "-p", "", "--quiet",
	)
	requireNativePCV3Published(t, encrypted, "")
	encoded, err := os.ReadFile(volume)
	if err != nil {
		t.Fatalf("read D1 volume: %v", err)
	}
	if bytes.HasPrefix(encoded, []byte{'P', 'C', 'V', 0}) {
		t.Fatal("keyfile-only D1 exposed the Normal PCV3 discriminator")
	}

	decrypted := runCLITestCommand(
		t,
		binary,
		"decrypt", volume, "-o", output,
		"--pcv3-format=d1", "--pcv3-factors=keyfiles",
		"--pcv3-keyfile-order=unordered", "-k", keyfile, "-p", "", "--quiet",
	)
	requireNativePCV3Published(t, decrypted, "")
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read decrypted output: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("keyfile-only D1 plaintext = %q; want %q", got, plaintext)
	}

	wrong := runCLITestCommand(
		t,
		binary,
		"decrypt", volume, "-o", wrongOutput,
		"--pcv3-format=d1", "--pcv3-factors=keyfiles",
		"--pcv3-keyfile-order=unordered", "-k", wrongKeyfile, "-p", "", "--quiet",
	)
	if wrong.exitCode == 0 {
		t.Fatal("keyfile-only D1 accepted the wrong keyfile")
	}
	if _, err := os.Lstat(wrongOutput); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrong keyfile created output: %v", err)
	}
}

func TestPCV3CLIDecryptUsesDefaultOutput(t *testing.T) {
	plaintext := []byte("PCV3 default output\n")
	dir := t.TempDir()
	input := filepath.Join(dir, "report")
	volume := input + ".pcv"
	if err := os.WriteFile(input, plaintext, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	binary := buildCLITestBinary(t)
	encrypted := runCLITestCommand(
		t,
		binary,
		"encrypt", input, "-o", volume, "--pcv3", "-p", "default-output-password", "--quiet",
	)
	requireNativePCV3Published(t, encrypted, "")
	if err := os.Remove(input); err != nil {
		t.Fatalf("remove original before decrypt: %v", err)
	}

	decrypted := runCLITestCommand(
		t,
		binary,
		"decrypt", volume, "--pcv3-factors=password", "-p", "default-output-password", "--quiet",
	)
	requireNativePCV3Published(t, decrypted, "")
	got, err := os.ReadFile(input)
	if err != nil {
		t.Fatalf("read default output: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("default output = %q; want %q", got, plaintext)
	}

	hiddenVolume := filepath.Join(dir, ".pcv")
	hiddenOutput := hiddenVolume + ".decrypted"
	encoded, err := os.ReadFile(volume)
	if err != nil {
		t.Fatalf("read encrypted fixture: %v", err)
	}
	if err := os.WriteFile(hiddenVolume, encoded, 0o600); err != nil {
		t.Fatalf("write .pcv fixture: %v", err)
	}
	decrypted = runCLITestCommand(
		t,
		binary,
		"decrypt", hiddenVolume, "--pcv3-factors=password", "-p", "default-output-password", "--quiet",
	)
	requireNativePCV3Published(t, decrypted, "")
	got, err = os.ReadFile(hiddenOutput)
	if err != nil {
		t.Fatalf("read .pcv default output: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf(".pcv default output = %q; want %q", got, plaintext)
	}
}

func TestPCV3CLISplitRoundTrip(t *testing.T) {
	binary := buildCLITestBinary(t)
	for _, test := range []struct {
		name         string
		encryptFlags []string
		decryptFlags []string
	}{
		{name: "normal"},
		{
			name:         "d1",
			encryptFlags: []string{"--deniability", "--paranoid"},
			decryptFlags: []string{"--pcv3-format=d1"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			plaintext := make([]byte, 16*1024)
			for index := range plaintext {
				plaintext[index] = byte(index*31 + 7)
			}
			input := filepath.Join(dir, "plain.bin")
			volume := filepath.Join(dir, "split.pcv")
			output := filepath.Join(dir, "plain.out")
			if err := os.WriteFile(input, plaintext, 0o600); err != nil {
				t.Fatalf("write input: %v", err)
			}

			encryptArgs := []string{
				"encrypt", input, "-o", volume, "--pcv3",
				"--split", "--split-size=1", "--split-unit=KiB",
				"-p", "split-password", "--quiet",
			}
			encryptArgs = append(encryptArgs, test.encryptFlags...)
			encrypted := runCLITestCommand(t, binary, encryptArgs...)
			if runtime.GOOS == "windows" {
				const splitNotice = "All parts were created. Write durability could not be confirmed, so the complete encrypted file and source files were kept.\n"
				if strings.Count(encrypted.stderr, splitNotice) != 1 {
					t.Fatalf("uncertain split lost retention notice: %q", encrypted.stderr)
				}
				encrypted.stderr = strings.Replace(encrypted.stderr, splitNotice, "", 1)
			}
			requireNativePCV3Published(t, encrypted, "")
			chunkCount := 0
			var combined bytes.Buffer
			for ; ; chunkCount++ {
				chunk, err := os.ReadFile(fmt.Sprintf("%s.%d", volume, chunkCount))
				if errors.Is(err, os.ErrNotExist) {
					break
				}
				if err != nil {
					t.Fatalf("inspect chunk %d: %v", chunkCount, err)
				}
				combined.Write(chunk)
			}
			if chunkCount <= 10 {
				t.Fatalf("chunk count = %d; want more than 10 to exercise numeric ordering", chunkCount)
			}
			if runtime.GOOS == "windows" {
				retained, err := os.ReadFile(volume)
				if err != nil || !bytes.Equal(retained, combined.Bytes()) {
					t.Fatalf("uncertain split did not retain complete ciphertext: %v", err)
				}
			} else if _, err := os.Lstat(volume); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unsplit PCV3 remained after durable chunk publication: %v", err)
			}
			if source, err := os.ReadFile(input); err != nil || !bytes.Equal(source, plaintext) {
				t.Fatalf("split changed plaintext source: %v", err)
			}
			if test.name == "d1" {
				chunkZero, err := os.OpenFile(volume+".0", os.O_WRONLY, 0)
				if err != nil {
					t.Fatalf("open D1 chunk zero: %v", err)
				}
				_, writeErr := chunkZero.WriteAt([]byte{'P', 'C', 'V', 0}, 0)
				closeErr := chunkZero.Close()
				if writeErr != nil || closeErr != nil {
					t.Fatalf("force D1 discriminator collision: write=%v close=%v", writeErr, closeErr)
				}
			}

			decryptArgs := []string{
				"decrypt", volume + ".0", "-o", output,
				"--pcv3-factors=password", "-p", "split-password", "--quiet",
			}
			decryptArgs = append(decryptArgs, test.decryptFlags...)
			decrypted := runCLITestCommand(t, binary, decryptArgs...)
			wantExit := nativePCV3FileExit()
			if test.name == "d1" {
				wantExit = ExitPCV3Warning
				if runtime.GOOS == "windows" {
					wantExit = ExitPCV3DurabilityUncertain
				}
			}
			if decrypted.exitCode != wantExit {
				t.Fatalf("split decrypt exit = %d, want %d, stderr = %q", decrypted.exitCode, wantExit, decrypted.stderr)
			}
			if test.name == "normal" {
				requireNativePCV3Published(t, decrypted, "")
			} else if len(decrypted.stdout) != 0 ||
				!strings.HasPrefix(decrypted.stderr, "Outcome: authenticated-degraded\nPublication: "+nativePCV3Publication()+"\n") ||
				!strings.Contains(decrypted.stderr, "Warning: output is authenticated but recovery redundancy is damaged\n") ||
				(runtime.GOOS == "windows" && !strings.Contains(decrypted.stderr, nativePCV3DurabilityWarning)) {
				t.Fatalf("degraded D1 split lost authentication/publication warning: %+v", decrypted)
			}
			got, err := os.ReadFile(output)
			if err != nil {
				t.Fatalf("read output: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatal("split PCV3 round-trip changed plaintext")
			}
			if test.name == "normal" {
				cmd := exec.Command(
					binary,
					"decrypt", volume+".7", "-o", "-",
					"--pcv3-factors=password", "-p", "split-password", "--quiet",
				)
				streamed := runStreamIntegrationCommand(t, cmd, plaintext)
				requireNativePCV3PlaintextStream(t, streamed, plaintext)
			}
		})
	}
}

func runCLITestCommandWithInputAndPasswordFD(
	t *testing.T,
	binary string,
	input, password []byte,
	args ...string,
) cliTestResult {
	t.Helper()
	passwordReader, passwordWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create password pipe: %v", err)
	}
	passwordLine := append(append([]byte(nil), password...), '\n')
	if _, err := passwordWriter.Write(passwordLine); err != nil {
		_ = passwordReader.Close()
		_ = passwordWriter.Close()
		t.Fatalf("write password pipe: %v", err)
	}
	if err := passwordWriter.Close(); err != nil {
		_ = passwordReader.Close()
		t.Fatalf("close password pipe writer: %v", err)
	}

	command := exec.Command(binary, args...)
	command.Stdin = bytes.NewReader(input)
	command.ExtraFiles = []*os.File{passwordReader}
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	runErr := command.Run()
	if err := passwordReader.Close(); err != nil {
		t.Fatalf("close password pipe reader: %v", err)
	}
	exitCode := 0
	if runErr != nil {
		exitCode = 1
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
	}
	return cliTestResult{
		exitCode: exitCode,
		stdout:   append([]byte(nil), stdout.Bytes()...),
		stderr:   stderr.String(),
	}
}

// assertZipContainsPlaintext checks that path is a valid zip whose first entry
// contains exactly plaintext. This is needed for the "compress" round-trip: the
// encrypt step wraps a single file in a zip (Compress=true) before encryption,
// so the decrypted output is a zip archive, not raw bytes.
func assertZipContainsPlaintext(t *testing.T, path string, plaintext []byte) {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("compress: decrypted output is not a valid zip: %v", err)
	}
	defer func() { _ = zr.Close() }()

	if len(zr.File) == 0 {
		t.Fatal("compress: zip archive contains no entries")
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("compress: open first zip entry: %v", err)
	}
	got, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatalf("compress: read first zip entry: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("compress: zip entry content = %q, want %q", got, plaintext)
	}
}

// A completed legacy KDF leaves a reclaimable workspace in the Go heap. A new
// PCV3 operation must observe memory after reclaiming that workspace, while
// retaining its fixed KDF profile and fail-closed admission policy. Run this
// sequential cross-format regression in the memory-bounded integration lane.
func TestPCV3WriteAfterLegacyReadReclaimsCompletedWorkspace(t *testing.T) {
	resetEncryptFlagsForDirTest()
	resetDecryptFlagsForDirTest()
	t.Cleanup(resetEncryptFlagsForDirTest)
	t.Cleanup(resetDecryptFlagsForDirTest)
	dir := t.TempDir()
	legacy := filepath.Join(dir, "legacy.pcv")
	plain := filepath.Join(dir, "plain.txt")
	encrypted := filepath.Join(dir, "current.pcv")
	output := filepath.Join(dir, "recovered.txt")
	copyCLITestFile(t, filepath.Join("..", "..", "testdata", "golden", "pico_test_v2.txt.pcv"), legacy)
	decOutput, decPassword, decQuiet, decYes = plain, "test", true, true
	decVerifyFirst = true
	if err := decryptCmd.RunE(decryptCmd, []string{legacy}); err != nil {
		t.Fatalf("legacy decrypt: %v", err)
	}
	want, err := os.ReadFile(plain)
	if err != nil {
		t.Fatal(err)
	}
	encOutput, encPassword, encQuiet, encYes = encrypted, "new password", true, true
	requireNativePCV3FileError(t, encryptCmd.RunE(encryptCmd, []string{plain}))
	resetDecryptFlagsForDirTest()
	decOutput, decPassword, decPCV3Factors, decQuiet, decYes = output, "new password", "password", true, true
	requireNativePCV3FileError(t, decryptCmd.RunE(decryptCmd, []string{encrypted}))
	got, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("PCV3 recovered plaintext mismatch: %v", err)
	}
	if _, err := os.Stat(plain); err != nil {
		t.Fatalf("plaintext source removed: %v", err)
	}
}
