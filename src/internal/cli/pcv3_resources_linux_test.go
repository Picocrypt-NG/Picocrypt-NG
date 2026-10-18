//go:build linux && !android

package cli

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// A real native admission refusal must reach CLI users as insufficient
// resources, while preserving the ciphertext and leaving no plaintext or stage.
func TestPCV3CLINativeKDFRefusalExplainsInsufficientResources(t *testing.T) {
	const child = "PICOCRYPT_TEST_KDF_REFUSAL_DIR"
	if dir := os.Getenv(child); dir != "" {
		debug.SetGCPercent(-1)
		runtime.GC()
		status, err := os.ReadFile("/proc/self/status")
		if err != nil {
			t.Fatal(err)
		}
		var virtual uint64
		for _, line := range strings.Split(string(status), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 3 && fields[0] == "VmSize:" {
				virtual, err = strconv.ParseUint(fields[1], 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				virtual *= 1024
			}
		}
		if virtual == 0 {
			t.Fatal("missing virtual size")
		}
		var limit syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_AS, &limit); err != nil {
			t.Fatal(err)
		}
		limit.Cur = virtual + (128 << 20)
		if err := syscall.Setrlimit(syscall.RLIMIT_AS, &limit); err != nil {
			t.Fatal(err)
		}
		rootCmd.SetArgs([]string{
			"decrypt", filepath.Join(dir, "source.pcv"), "-o", filepath.Join(dir, "plaintext"),
			"--pcv3-factors=combined", "--pcv3-keyfile-order=ordered", "-p", "mix", "--quiet",
			"-k", filepath.Join(dir, "one.key"), "-k", filepath.Join(dir, "two.key"),
		})
		os.Exit(exitCodeForError(rootCmd.Execute()))
	}

	dir := t.TempDir()
	volume, _ := pcv3CLICombinedFixture(t)
	source := writePCV3CLIFixture(t, dir, "source.pcv", volume)
	writePCV3CLIFixture(t, dir, "one.key", []byte("one"))
	writePCV3CLIFixture(t, dir, "two.key", []byte("two!"))
	command := exec.Command(os.Args[0], "-test.run=^TestPCV3CLINativeKDFRefusalExplainsInsufficientResources$", "-test.count=1")
	command.Env = append(os.Environ(), child+"="+dir)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != ExitGeneralError {
		t.Fatalf("native KDF refusal = %v stdout %q stderr %q; want exit 1", err, stdout.String(), stderr.String())
	}
	want := "Outcome: operation-failed\nPublication: not-attempted\n" +
		"Required resources are unavailable: this device cannot safely run the fixed security profile right now. Security settings were not reduced, and no output was created.\n"
	if stdout.Len() != 0 || stderr.String() != want {
		t.Fatalf("native KDF refusal stdout %q stderr %q; want empty stdout and stderr %q", stdout.String(), stderr.String(), want)
	}
	got, err := os.ReadFile(source)
	if err != nil || len(got) != len(volume) || sha256.Sum256(got) != sha256.Sum256(volume) {
		t.Fatalf("resource refusal changed ciphertext: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 3 {
		t.Fatalf("resource refusal left plaintext or staging files: entries=%v err=%v", entries, err)
	}
}
