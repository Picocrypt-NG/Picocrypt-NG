package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The real interactive CLI discovers inputs before prompting. Replacing a
// selection at that boundary must not encrypt newly introduced private bytes.
func TestEncryptCLIRejectsInputReplacementAfterDiscovery(t *testing.T) {
	if os.Getenv("PICOCRYPT_ARCHIVE_IDENTITY_HELPER") == "1" {
		os.Args = []string{os.Args[0], "encrypt", os.Getenv("PICOCRYPT_ARCHIVE_IDENTITY_SOURCE"), "--compress", "-o", os.Getenv("PICOCRYPT_ARCHIVE_IDENTITY_OUTPUT")}
		Execute("test")
		os.Exit(0)
	}
	for _, kind := range []string{"symlink", "regular"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			source, foreign, output := filepath.Join(dir, "chosen"), filepath.Join(dir, "foreign"), filepath.Join(dir, "out.pcv")
			for path, data := range map[string]string{source: "selected contents", foreign: "unintended secret"} {
				if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "symlink" {
				probe := filepath.Join(dir, "link-probe")
				if err := os.Symlink(foreign, probe); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
				if err := os.Remove(probe); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestEncryptCLIRejectsInputReplacementAfterDiscovery$")
			cmd.Env = append(os.Environ(), "PICOCRYPT_ARCHIVE_IDENTITY_HELPER=1", "PICOCRYPT_ARCHIVE_IDENTITY_SOURCE="+source, "PICOCRYPT_ARCHIVE_IDENTITY_OUTPUT="+output)
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			stderr, err := cmd.StderrPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill() })
			readPrompt := func(want string) {
				t.Helper()
				got := make([]byte, len(want))
				if _, err := io.ReadFull(stderr, got); err != nil || string(got) != want {
					t.Fatalf("password prompt = %q, %v; want %q", got, err, want)
				}
			}
			readPrompt("Password: ")
			if err := os.Rename(source, source+".selected"); err != nil {
				t.Fatal(err)
			}
			if kind == "symlink" {
				err = os.Symlink(foreign, source)
			} else {
				err = os.WriteFile(source, []byte("unintended secret"), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(stdin, "public-test-password\n"); err != nil {
				t.Fatal(err)
			}
			readPrompt("Confirm password: ")
			if _, err := io.WriteString(stdin, "public-test-password\n"); err != nil {
				t.Fatal(err)
			}
			_ = stdin.Close()
			diagnostic, readErr := io.ReadAll(stderr)
			waitErr := cmd.Wait()
			if readErr != nil || waitErr == nil || ctx.Err() != nil {
				t.Fatalf("replaced input was not rejected: wait=%v read=%v ctx=%v stderr=%s", waitErr, readErr, ctx.Err(), diagnostic)
			}
			if bytes.Contains(diagnostic, []byte("Deriving key")) {
				t.Fatalf("replaced input reached KDF: %s", diagnostic)
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("rejected input published output: %v", err)
			}
			for path, want := range map[string]string{source + ".selected": "selected contents", foreign: "unintended secret", source: "unintended secret"} {
				got, err := os.ReadFile(path)
				if err != nil || string(got) != want {
					t.Fatalf("protected input %s = %q, %v", path, got, err)
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".picocrypt-") {
					t.Fatalf("rejection left private stage %q", entry.Name())
				}
			}
		})
	}
}
