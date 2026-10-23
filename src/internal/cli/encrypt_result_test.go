package cli

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/volume"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"syscall"
	"testing"
)

// Exercise the real public writer and CLI terminal path: replacement of the
// output pathname after publication must neither substitute stdout bytes nor
// remove the replacement. Windows instead denies replacement while the retained
// descriptor is live. No KDF, writer, or descriptor behavior is mocked.
func TestEncryptStdoutUsesRetainedDescriptorAfterPathReplacement(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	key := filepath.Join(dir, "key")
	target := filepath.Join(dir, "encrypted")
	for path, data := range map[string][]byte{source: []byte("original plaintext"), key: []byte("stdout ownership keyfile")} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	codecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatal(err)
	}
	result, err := volume.EncryptWithResult(context.Background(), &volume.EncryptRequest{
		InputFile: source, InputFiles: []string{source}, OnlyFiles: []string{source}, OutputFile: target,
		Keyfiles: []string{key}, PCV3: true, RSCodecs: codecs,
	}, pcv3operation.ExecutionOptions{RetainDurableOutput: true})
	if result == nil {
		t.Fatalf("retained encryption returned no result: %v", err)
	}
	followUp := result.OutputFollowUp()
	if followUp != nil {
		t.Cleanup(func() { followUp.Discard() })
	}
	durable := nativeCLIDirectorySyncSupported(t, dir)
	wantClass := pcv3operation.CompletionClean
	if !durable {
		wantClass = pcv3operation.CompletionDurabilityUncertain
		if !errors.Is(err, result) {
			t.Fatalf("uncertain encryption lost its result error: %v", err)
		}
	} else if err != nil {
		t.Fatalf("retained encryption failed: %v", err)
	}
	if result.CompletionClass() != wantClass || followUp == nil {
		t.Fatalf("retained encryption: %v / %v", result, err)
	}
	// Root.Open shares DELETE on Windows, as required when the original
	// publication descriptor retains exact cleanup authority.
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	published, err := root.Open(filepath.Base(target))
	if err != nil {
		t.Fatal(err)
	}
	expected, err := io.ReadAll(published)
	closeErr := published.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("read published ciphertext: %v / %v", err, closeErr)
	}
	renameErr := os.Rename(target, target+".original")
	replacement := []byte("foreign replacement must survive")
	if runtime.GOOS == "windows" {
		if !errors.Is(renameErr, syscall.Errno(32)) {
			t.Fatalf("retained descriptor must deny pathname replacement with a sharing violation: %v", renameErr)
		}
		if _, err := os.Lstat(target + ".original"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("refused replacement relocated ciphertext: %v", err)
		}
	} else {
		if renameErr != nil {
			t.Fatal(renameErr)
		}
		if err := os.WriteFile(target, replacement, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stdout, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stdout.Close() })
	oldStdout := os.Stdout
	os.Stdout = stdout
	t.Cleanup(func() { os.Stdout = oldStdout })
	terminalErr := finishPCV3Encryption(context.Background(), result, nil, true)
	wantExit := ExitPCV3Warning
	if runtime.GOOS == "windows" {
		wantExit = 0
		if !durable {
			wantExit = ExitPCV3DurabilityUncertain
		}
	}
	if (terminalErr == nil) != (wantExit == 0) || exitCodeForError(terminalErr) != wantExit {
		t.Fatalf("stdout result: %v; want exit %d", terminalErr, wantExit)
	}
	if slices.Contains(result.Warnings(), pcv3operation.WarningCleanupIncomplete) != (runtime.GOOS != "windows") {
		t.Fatal("stdout cleanup did not preserve the exact-owner replacement outcome")
	}
	if slices.Contains(result.Warnings(), pcv3operation.WarningCleanupDurabilityUncertain) != !durable {
		t.Fatal("stdout cleanup lost deletion durability truth")
	}
	if result.OutputFollowUp() != nil {
		t.Fatal("stdout transport left reusable output authority")
	}
	if result.SourceDeletionAllowed() {
		t.Fatal("transport must not authorize source deletion")
	}
	got, err := os.ReadFile(stdout.Name())
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatalf("stdout differs from retained ciphertext: got %d want %d, %v", len(got), len(expected), err)
	}
	if runtime.GOOS == "windows" {
		if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stdout left the exact retained ciphertext: %v", err)
		}
	} else {
		got, err = os.ReadFile(target)
		if err != nil || !bytes.Equal(got, replacement) {
			t.Fatalf("replacement changed: %q, %v", got, err)
		}
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("source unavailable: %v", err)
	}
}
