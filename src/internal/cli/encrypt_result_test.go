package cli

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/volume"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

// Exercise the real public writer and CLI terminal path: replacement of the
// output pathname after publication must neither substitute stdout bytes nor
// remove the replacement. No KDF, writer, or descriptor behavior is mocked.
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
	wantClass := pcv3operation.CompletionClean
	if runtime.GOOS == "windows" {
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
	expected, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(target, target+".original"); err != nil {
		t.Fatal(err)
	}
	replacement := []byte("foreign replacement must survive")
	if err := os.WriteFile(target, replacement, 0o600); err != nil {
		t.Fatal(err)
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
	// Exact-owner cleanup cannot remove the replacement. Its uncertainty must
	// be reported as warning status, while the original descriptor is streamed.
	wantExit := ExitPCV3Warning
	if runtime.GOOS == "windows" {
		wantExit = ExitPCV3DurabilityUncertain
	}
	if terminalErr == nil || exitCodeForError(terminalErr) != wantExit {
		t.Fatalf("stdout result: %v", terminalErr)
	}
	if !slices.Contains(result.Warnings(), pcv3operation.WarningCleanupIncomplete) {
		t.Fatal("foreign pathname replacement lost its cleanup warning")
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
	got, err = os.ReadFile(target)
	if err != nil || !bytes.Equal(got, replacement) {
		t.Fatalf("replacement changed: %q, %v", got, err)
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("source unavailable: %v", err)
	}
}
