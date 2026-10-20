package cli

import (
	"Picocrypt-NG/internal/header"
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Real production-KDF subprocess coverage for the stdout transport. Frozen
// readers use the actual CLI executable. The Linux live-descriptor probe uses
// a test-owned embedding host so executable dump protection cannot hide staging.
func TestCLIEncryptedStdoutIntegration(t *testing.T) {
	if testing.Short() || os.Getenv("PICOCRYPT_RUN_CLI_INTEGRATION") != "1" {
		t.Skip("set PICOCRYPT_RUN_CLI_INTEGRATION=1 without -short to run real CLI tests")
	}
	binaryPath := buildStdoutSpoolCLI(t)
	normalRoot := filepath.Join("..", "pcv3operation", "internal", "pcv3", "testdata", "normal")
	d1Root := filepath.Join("..", "pcv3operation", "internal", "pcv3", "testdata", "d1", "independent")
	legacyRoot := filepath.Join("..", "..", "testdata", "golden")
	normalFactors := []string{"--pcv3-factors=combined", "--pcv3-keyfile-order=ordered", "-p", "mix"}
	for _, name := range []string{
		"sha256-b1f51a511f1da0cd348b8f8598db32e61cb963e5fc69e2b41485bf99590ed75a.bin",
		"sha256-16477688c0e00699c6cfa4497a3612d7e83c532062b64b250fed8908128ed548.bin",
	} {
		normalFactors = append(normalFactors, "-k", filepath.Join(normalRoot, "factors", name))
	}
	password := readStdoutFixture(t, filepath.Join(d1Root, "password.bin"))
	d1Factors := []string{
		"--pcv3-format=d1", "--pcv3-factors=combined", "--pcv3-keyfile-order=ordered", "-p", string(password),
		"-k", filepath.Join(d1Root, "keyfile-alpha.bin"), "-k", filepath.Join(d1Root, "keyfile-beta.bin"),
	}

	t.Run("frozen_readers", func(t *testing.T) {
		for _, tc := range []struct {
			name, file, digest string
			factors            []string
			stdin, archive     bool
			pcv3               bool
			comment            string
		}{
			{"normal-empty", filepath.Join(normalRoot, "volumes", "normal-standard-combined-ordered-empty.pcv"), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", normalFactors, false, false, true, "TEST ONLY comment"},
			{"normal-stdin", filepath.Join(normalRoot, "volumes", "normal-standard-combined-ordered-one.pcv"), "dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986", normalFactors, true, false, true, "TEST ONLY comment"},
			{"d1-multi", filepath.Join(d1Root, "d1-multi-standard.pcv"), "8232c26d26c8bd37bc2b6e29e9e5b050fe78b321999c47523758c3b3001b75b8", d1Factors, false, false, true, ""},
			{"d1-multi-rs-stdin", filepath.Join(d1Root, "d1-multi-rs-standard.pcv"), "8232c26d26c8bd37bc2b6e29e9e5b050fe78b321999c47523758c3b3001b75b8", d1Factors, true, false, true, ""},
			{"legacy-v1", filepath.Join(legacyRoot, "pico_test_v1.txt.pcv"), "", []string{"-p", "test"}, false, false, false, ""},
			{"legacy-v2-stdin", filepath.Join(legacyRoot, "pico_test_v2.txt.pcv"), "", []string{"-p", "test"}, true, false, false, ""},
			{"legacy-v1-compressed", filepath.Join(legacyRoot, "pico_test_v1_compress.zip.pcv"), "", []string{"-p", "test"}, false, true, false, ""},
			{"legacy-v2-compressed-stdin", filepath.Join(legacyRoot, "pico_test_v2_compress.zip.pcv"), "", []string{"-p", "test"}, true, true, false, ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				source := readStdoutFixture(t, tc.file)
				input := tc.file
				if tc.stdin {
					input = "-"
				}
				args := append([]string{"decrypt", input, "-o", "-"}, tc.factors...)
				cmd := exec.Command(binaryPath, args...)
				if tc.stdin {
					cmd.Stdin = stdinFile(t, source)
				}
				result := runStreamIntegrationCommand(t, cmd, nil)
				wantStderr := ""
				if tc.pcv3 {
					wantStderr = "Outcome: success\nPublication: not-attempted\n"
					if tc.comment != "" {
						wantStderr += fmt.Sprintf("Comment: %q\n", tc.comment)
					}
				}
				if result.exitCode != 0 || result.stderr != wantStderr {
					t.Fatalf("stdout reader exit=%d stderr=%q", result.exitCode, result.stderr)
				}
				if tc.pcv3 {
					requireStdoutDigest(t, result.stdout, tc.digest)
				} else {
					plaintext := result.stdout
					if tc.archive {
						plaintext = stdoutGoldenZIPPayload(t, plaintext)
					}
					if string(plaintext) != "There is a test file for Picocrypt validation.\n" {
						t.Fatalf("legacy stdout payload differs from frozen golden plaintext: %q", plaintext)
					}
				}
				requireStdoutSourceUnchanged(t, tc.file, source)
			})
		}
	})

	t.Run("legacy_RS_retry", func(t *testing.T) {
		encoded := readStdoutFixture(t, filepath.Join(legacyRoot, "pico_test_v2_keyfile_rs.pcv.b64"))
		volume, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
		if err != nil {
			t.Fatal(err)
		}
		requireStdoutDigest(t, volume, "03dca9ea6793911282c780f3c734897a06cc794726fc398d5dee60cf3ea09e29")
		// The frozen no-comment fixture has four correctable errors in its first
		// payload codeword. Fast decoding cannot authenticate; full RS repairs it.
		for i := range 4 {
			volume[header.HeaderSize(0)+i*31] ^= 0xff
		}
		path := filepath.Join(t.TempDir(), "repairable.pcv")
		if err := os.WriteFile(path, volume, 0o600); err != nil {
			t.Fatal(err)
		}
		result := runStreamIntegrationCommand(t, exec.Command(binaryPath, "decrypt", path, "-o", "-", "-p", "test", "-k", filepath.Join(legacyRoot, "keyfile_alpha.bin")), nil)
		want := make([]byte, 512)
		for i := range want {
			want[i] = byte(i*13 + 7)
		}
		if result.exitCode != 0 || !bytes.Equal(result.stdout, want) {
			t.Fatalf("legacy RS retry exit=%d stdout=%d bytes stderr=%q", result.exitCode, len(result.stdout), result.stderr)
		}
		requireStdoutSourceUnchanged(t, path, volume)
	})

	t.Run("fail_closed_before_first_byte", func(t *testing.T) {
		for _, tc := range []struct {
			name, file, outcome string
			wrong               bool
		}{
			{"wrong-factor", "normal-standard-combined-ordered-one.pcv", "credentials-or-damage", true},
			{"bad-final-tag", "normal-negative-final.pcv", "authentication-failed", false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				path := filepath.Join(normalRoot, "volumes", tc.file)
				source := readStdoutFixture(t, path)
				factors := append([]string(nil), normalFactors...)
				if tc.wrong {
					factors[3] = "wrong-TEST-ONLY-password"
				}
				args := append([]string{"decrypt", "-", "-o", "-"}, factors...)
				cmd := exec.Command(binaryPath, args...)
				cmd.Stdin = stdinFile(t, source)
				result := runStreamIntegrationCommand(t, cmd, nil)
				if result.exitCode != ExitGeneralError || len(result.stdout) != 0 || result.stderr != "Outcome: "+tc.outcome+"\nPublication: not-attempted\n" {
					t.Fatalf("failed authentication released output: exit=%d stdout=%d stderr=%q", result.exitCode, len(result.stdout), result.stderr)
				}
				requireStdoutSourceUnchanged(t, path, source)
			})
		}
	})

	t.Run("force_preserves_forensic_envelope", func(t *testing.T) {
		path := filepath.Join(normalRoot, "volumes", "normal-negative-final.pcv")
		source := readStdoutFixture(t, path)
		args := append([]string{"decrypt", path, "-o", "-", "--pcv3-action=force"}, normalFactors...)
		result := runStreamIntegrationCommand(t, exec.Command(binaryPath, args...), nil)
		artifact := result.stdout
		if result.exitCode != ExitPCV3Warning || !strings.Contains(result.stderr, "Outcome: force-partial\nPublication: not-attempted\n") ||
			!strings.Contains(result.stderr, "Warning: partial recovery output is not a complete plaintext file") {
			t.Fatalf("Force stdout lost warning/provenance: exit=%d stderr=%q", result.exitCode, result.stderr)
		}
		// Fixed independent application envelope contract: partial, no selected
		// unverified role, missing final evidence, one verified 17-byte range.
		if len(artifact) != 137 || !bytes.Equal(artifact[:16], []byte("PICO-RECOVERY-3\x00")) ||
			!bytes.Equal(artifact[16:21], []byte{1, 1, 1, 0, 3}) ||
			binary.BigEndian.Uint64(artifact[32:40]) != 17 || binary.BigEndian.Uint64(artifact[40:48]) != 1 ||
			binary.BigEndian.Uint64(artifact[48:56]) != 1 || binary.BigEndian.Uint64(artifact[56:64]) != 80 ||
			binary.BigEndian.Uint64(artifact[64:72]) != 120 || binary.BigEndian.Uint64(artifact[72:80]) != 137 ||
			binary.BigEndian.Uint64(artifact[80:88]) != 0 || binary.BigEndian.Uint64(artifact[88:96]) != 0 ||
			binary.BigEndian.Uint64(artifact[96:104]) != 17 || binary.BigEndian.Uint64(artifact[104:112]) != 120 ||
			binary.BigEndian.Uint32(artifact[112:116]) != 17 || artifact[116] != 1 {
			t.Fatalf("Force stdout lost forensic envelope/ranges: %x", artifact)
		}
		requireStdoutDigest(t, artifact[120:], "65406d44b7f5b4a66854d96e90a53ffc91e638e151fcc062347d6ec3d1ff0ba7")
		requireStdoutSourceUnchanged(t, path, source)
	})

	t.Run("blocked_stdout", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("Linux /proc descriptor inspection and cooperative POSIX signal lane")
		}
		if os.Getenv("PICOCRYPT_TEST_CLI_BINARY") != "" {
			t.Fatal("blocked_stdout descriptor probe requires the test-owned embedding host; unset PICOCRYPT_TEST_CLI_BINARY")
		}
		path := filepath.Join(d1Root, "d1-multi-standard.pcv")
		source := readStdoutFixture(t, path)
		for _, interrupt := range []bool{false, true} {
			name := "kill"
			if interrupt {
				name = "interrupt-stdin"
			}
			t.Run(name, func(t *testing.T) {
				testBlockedEncryptedStdout(t, path, source, d1Factors, interrupt)
			})
		}
	})
}

func buildStdoutSpoolCLI(t *testing.T) string {
	t.Helper()
	// An explicit artifact path lets the serial integration/performance lane
	// exercise the same frozen binary; ordinary opt-in runs build current src.
	if path := os.Getenv("PICOCRYPT_TEST_CLI_BINARY"); path != "" {
		info, err := os.Stat(path)
		if !filepath.IsAbs(path) || err != nil || !info.Mode().IsRegular() {
			t.Fatalf("PICOCRYPT_TEST_CLI_BINARY must name an absolute regular file: %v", err)
		}
		return path
	}
	name := "picocrypt-stdout-test"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-tags", "cli", "-o", path, "./cmd/picocrypt")
	cmd.Dir = filepath.Join("..", "..")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build real CLI: %v\n%s", err, output)
	}
	return path
}

func readStdoutFixture(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read required stdout fixture %s: %v", path, err)
	}
	return data
}

func requireStdoutDigest(t *testing.T, data []byte, want string) {
	t.Helper()
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != want {
		t.Fatalf("stdout SHA-256=%x (%d bytes), want frozen %s", digest, len(data), want)
	}
}

func requireStdoutSourceUnchanged(t *testing.T, path string, before []byte) {
	t.Helper()
	if after := readStdoutFixture(t, path); !bytes.Equal(after, before) {
		t.Fatal("stdout operation changed its encrypted source")
	}
}

func stdoutGoldenZIPPayload(t *testing.T, data []byte) []byte {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("stdout ZIP: %v", err)
	}
	for _, entry := range reader.File {
		if !entry.FileInfo().IsDir() && filepath.Base(entry.Name) == "pico_test.txt" {
			file, err := entry.Open()
			if err != nil {
				t.Fatal(err)
			}
			payload, err := io.ReadAll(file)
			closeErr := file.Close()
			if err != nil || closeErr != nil {
				t.Fatalf("stdout ZIP payload: read=%v close=%v", err, closeErr)
			}
			return payload
		}
	}
	t.Fatal("stdout ZIP lost frozen pico_test.txt member")
	return nil
}

func stdoutSpoolProbeCommand(args ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestStdoutSpoolEmbeddingCLIProcess$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "PICOCRYPT_STDOUT_PROBE_CHILD=1")
	return cmd
}

func testBlockedEncryptedStdout(t *testing.T, path string, source []byte, factors []string, interrupt bool) {
	t.Helper()
	staging := t.TempDir()
	input := path
	if interrupt {
		input = "-"
	}
	args := append([]string{"decrypt", input, "-o", "-", "--temp-dir", staging, "-q"}, factors...)
	cmd := stdoutSpoolProbeCommand(args...)
	if interrupt {
		cmd.Stdin = stdinFile(t, source)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.Close()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	finished := false
	t.Cleanup(func() {
		if !finished {
			_ = cmd.Process.Kill()
			<-done
		}
	})
	first := make(chan error, 1)
	go func() {
		var one [1]byte
		_, err := io.ReadFull(pipe, one[:])
		if err == nil && one[0] != 7 {
			err = fmt.Errorf("first stdout byte=%x, want independent fixture byte 07", one[0])
		}
		first <- err
	}()
	select {
	case err := <-first:
		if err != nil {
			t.Fatalf("first authenticated stdout byte: %v", err)
		}
	case <-time.After(3 * time.Minute):
		t.Fatal("CLI did not reach authenticated stdout")
	}
	select {
	case err := <-done:
		finished = true
		t.Fatalf("CLI exited before blocking on undrained >1-MiB stdout: %v stderr=%q", err, stderr.String())
	default:
	}
	// Include unlinked descriptors: checking directory names alone would miss
	// the former Unix plaintext temporary file after unlink-before-streaming.
	marker := make([]byte, 64)
	for i := range marker {
		marker[i] = byte(i*29 + 7)
	}
	fdRoot := fmt.Sprintf("/proc/%d/fd", cmd.Process.Pid)
	entries, err := os.ReadDir(fdRoot)
	if err != nil {
		t.Fatal(err)
	}
	sawStage := false
	for _, entry := range entries {
		fdPath := filepath.Join(fdRoot, entry.Name())
		target, err := os.Readlink(fdPath)
		if err != nil || !strings.HasPrefix(target, staging+string(os.PathSeparator)) {
			continue
		}
		info, err := os.Stat(fdPath)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		file, err := os.Open(fdPath)
		if err != nil {
			t.Fatal(err)
		}
		pinnedInfo, statErr := file.Stat()
		if statErr != nil || !pinnedInfo.Mode().IsRegular() || !os.SameFile(info, pinnedInfo) {
			_ = file.Close()
			t.Fatalf("live staging descriptor identity changed: %v", statErr)
		}
		// The fixed fixture is just over one MiB. Keep inspection bounded even
		// if a broken transport unexpectedly grows or reuses a descriptor.
		data, readErr := io.ReadAll(io.LimitReader(file, 2<<20))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("read live staging descriptor: read=%v close=%v", readErr, closeErr)
		}
		if len(data) > 1<<20 {
			sawStage = true
		}
		if bytes.Contains(data, marker) {
			t.Fatal("blocked stdout holds plaintext in a live staging descriptor")
		}
	}
	if !sawStage {
		t.Fatal("did not observe the live encrypted payload stage while stdout was blocked")
	}
	if interrupt {
		err = cmd.Process.Signal(os.Interrupt)
	} else {
		err = cmd.Process.Kill()
	}
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		finished = true
		if err == nil {
			t.Fatal("interrupted stdout reported successful transport")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("interrupted CLI failed to unblock stdout and clean up")
	}
	entries, err = os.ReadDir(staging)
	if err != nil {
		t.Fatal(err)
	}
	if interrupt && len(entries) != 0 {
		t.Fatalf("cooperative cancellation left staging files: %v stderr=%q", entries, stderr.String())
	}
	for _, entry := range entries {
		if data := readStdoutFixture(t, filepath.Join(staging, entry.Name())); bytes.Contains(data, marker) {
			t.Fatal("killed CLI left plaintext staging on disk")
		}
	}
	requireStdoutSourceUnchanged(t, path, source)
}
