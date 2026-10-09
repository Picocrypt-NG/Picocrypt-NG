//go:build linux

package volume

import (
	perrors "Picocrypt-NG/internal/errors"
	"Picocrypt-NG/internal/pcv3operation"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPCV3EncryptRejectsKeyfileCountBeforeOpeningDescriptors(t *testing.T) {
	const child = "PICOCRYPT_TEST_PCV3_KEYFILE_LIMIT_CHILD"
	if os.Getenv(child) != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		command := exec.Command(executable, "-test.run=^TestPCV3EncryptRejectsKeyfileCountBeforeOpeningDescriptors$")
		command.Env = append(os.Environ(), child+"=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("descriptor-limited PCV3 encrypt: %v\n%s", err, output)
		}
		return
	}

	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	plaintext := []byte("selected input must survive invalid factor count")
	if err := os.WriteFile(source, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	limit.Cur = min(limit.Max, 64)
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	keyfiles := make([]string, 100)
	for index := range keyfiles {
		keyfiles[index] = source
	}
	target := filepath.Join(directory, "output.pcv")
	result, err := EncryptWithResult(context.Background(), &EncryptRequest{
		PCV3: true, InputFile: source, OutputFile: target,
		Password: []byte("public fixture password"), Keyfiles: keyfiles,
	}, pcv3operation.ExecutionOptions{})
	var validation *perrors.ValidationError
	if result != nil || !errors.As(err, &validation) || validation.Field != "Keyfiles" {
		t.Fatalf("count was not rejected before descriptor acquisition: result=%v error=%v", result, err)
	}
	if errors.Is(err, syscall.EMFILE) {
		t.Fatal("excess keyfiles exhausted descriptors before validation")
	}
	boundary := &EncryptRequest{
		PCV3: true, InputFile: source, OutputFile: target,
		Password: []byte("public fixture password"), Keyfiles: keyfiles[:64],
	}
	if err := boundary.Validate(); err != nil {
		t.Fatalf("the supported 64-keyfile count was refused: %v", err)
	}
	after, readErr := os.ReadFile(source)
	if readErr != nil || !bytes.Equal(after, plaintext) {
		t.Fatalf("input changed after refused write: bytes=%q error=%v", after, readErr)
	}
	afterIdentity, statErr := os.Stat(source)
	if statErr != nil || !os.SameFile(identity, afterIdentity) {
		t.Fatalf("input identity changed: %v", statErr)
	}
	entries, readErr := os.ReadDir(directory)
	if readErr != nil || len(entries) != 1 || entries[0].Name() != "source" {
		t.Fatalf("refused write created output/staging: entries=%v error=%v", entries, readErr)
	}
}
