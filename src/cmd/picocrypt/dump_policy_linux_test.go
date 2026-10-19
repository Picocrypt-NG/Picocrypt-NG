//go:build linux && !android

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Run the actual executable entry point in a child, so the test runner retains
// its own dump policy. --version must not bypass the early protection attempt.
func TestMainRestrictsDumpsBeforeCLIDispatch(t *testing.T) {
	if info, err := os.Stat("/.flatpak-info"); err == nil && info.Mode().IsRegular() {
		t.Skip("Flatpak packages intentionally retain their existing dump policy")
	}
	if os.Getenv("PICOCRYPT_DUMP_MAIN_CHILD") == "1" {
		os.Args = []string{os.Args[0], "--version"}
		main()
		got, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
		if err != nil || got != 0 {
			t.Fatalf("dumpable after main(--version) = %d, %v; want 0", got, err)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainRestrictsDumpsBeforeCLIDispatch$")
	cmd.Env = append(os.Environ(), "PICOCRYPT_DUMP_MAIN_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
}

// The same test runs in GUI+CLI and CLI-only builds. A failed startup policy
// must leave public help/version available without entering an operation or GUI.
func TestStartupPolicyFailureKeepsHelpAndRefusesOperations(t *testing.T) {
	if os.Getenv("PICOCRYPT_STARTUP_FAILURE_CHILD") == "1" {
		for i, arg := range os.Args {
			if arg == "--" {
				os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
				break
			}
		}
		run(errors.New("dump protection startup sentinel"))
		return
	}
	for _, tc := range []struct {
		name    string
		args    []string
		allowed bool
	}{
		{"version", []string{"--version"}, true},
		{"root help", []string{"--help"}, true},
		{"operation help", []string{"encrypt", "--help"}, true},
		{"help command", []string{"help", "encrypt"}, true},
		{"encrypt stdin", []string{"encrypt", "-", "--password-fd=3", "--keyfile=KEYFILE", "-o", "OUTPUT"}, false},
		{"decrypt stdin", []string{"decrypt", "-", "--password-fd=3", "--keyfile=KEYFILE", "-o", "OUTPUT"}, false},
		{"verify", []string{"verify", "SOURCE", "--deniability", "--pcv3-factors=combined", "--pcv3-keyfile-order=unordered", "--password-fd=3", "--keyfile=KEYFILE"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			keyfile, output, source := filepath.Join(dir, "keyfile"), filepath.Join(dir, "output.pcv"), filepath.Join(dir, "source.pcv")
			for _, path := range []string{keyfile, source} {
				if err := os.WriteFile(path, []byte("public synthetic fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			input, err := os.CreateTemp(t.TempDir(), "input")
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			if _, err := input.WriteString("public synthetic plaintext\n"); err != nil {
				t.Fatal(err)
			}
			if _, err := input.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			password, err := os.CreateTemp(t.TempDir(), "password")
			if err != nil {
				t.Fatal(err)
			}
			defer password.Close()
			// If the guard is removed, a descriptor read fails before any KDF.
			if _, err := password.WriteString(strings.Repeat("x", (1<<20)+3) + "\n"); err != nil {
				t.Fatal(err)
			}
			if _, err := password.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			watch, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(watch)
			for _, path := range []string{keyfile, source} {
				if _, err := unix.InotifyAddWatch(watch, path, unix.IN_OPEN); err != nil {
					t.Fatal(err)
				}
			}
			args := []string{"-test.run=^TestStartupPolicyFailureKeepsHelpAndRefusesOperations$", "--"}
			for _, arg := range tc.args {
				arg = strings.NewReplacer("KEYFILE", keyfile, "OUTPUT", output, "SOURCE", source).Replace(arg)
				args = append(args, arg)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], args...)
			cmd.Env = append(os.Environ(), "PICOCRYPT_STARTUP_FAILURE_CHILD=1", "TMPDIR="+dir)
			cmd.Stdin = input
			cmd.ExtraFiles = []*os.File{password}
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err = cmd.Run()
			if ctx.Err() != nil {
				t.Fatalf("startup blocked on input: %v", ctx.Err())
			}
			if tc.allowed {
				if err != nil || strings.Contains(stderr.String(), "dump protection startup sentinel") {
					t.Fatalf("public command failed: %v; stderr=%s", err, &stderr)
				}
				if stdout.Len() == 0 {
					t.Fatal("help/version produced no output")
				}
			} else {
				if err == nil || !strings.Contains(stderr.String(), "dump protection startup sentinel") {
					t.Errorf("operation was not refused by startup policy: %v; stderr=%s", err, &stderr)
				}
				if stdout.Len() != 0 {
					t.Errorf("refused operation wrote stdout: %q", &stdout)
				}
			}
			for name, file := range map[string]*os.File{"stdin": input, "password descriptor": password} {
				if position, err := file.Seek(0, io.SeekCurrent); err != nil || position != 0 {
					t.Errorf("%s consumed before refusal: offset=%d, error=%v", name, position, err)
				}
			}
			var event [4096]byte
			if n, err := unix.Read(watch, event[:]); n > 0 || !errors.Is(err, unix.EAGAIN) {
				t.Errorf("keyfile/source opened before refusal: bytes=%d, error=%v", n, err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.Name() != "keyfile" && entry.Name() != "source.pcv" {
					t.Errorf("startup failure created output/staging artifact %q", entry.Name())
				}
			}
		})
	}
}
