package cli

import (
	"Picocrypt-NG/internal/pcv3"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCLIRejectsPCV3SwapBeforeLegacyMetadataPrompt(t *testing.T) {
	previousPasswordStdin := decPasswordStdin
	resetDecryptFlagsForDirTest()
	decPasswordStdin = false
	t.Cleanup(func() {
		resetDecryptFlagsForDirTest()
		decPasswordStdin = previousPasswordStdin
	})

	dir := t.TempDir()
	input := filepath.Join(dir, "selected.pcv")
	retainedInput := filepath.Join(dir, "selected-before-swap.pcv")
	replacement := filepath.Join(dir, "claimed-replacement.pcv")
	output := filepath.Join(dir, "existing-output")
	legacyBytes := []byte("legacy-eligible input")
	outputBytes := []byte("must remain unchanged")
	fixture := loadPCV3CLIFixture(t)
	mustWriteCLIContractFile(t, input, legacyBytes)
	mustWriteCLIContractFile(t, replacement, fixture)
	mustWriteCLIContractFile(t, output, outputBytes)

	stdinReader, stdinWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdin pipe: %v", err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		_ = stdinReader.Close()
		_ = stdinWriter.Close()
		t.Fatalf("create stderr pipe: %v", err)
	}

	previousStdin, previousStderr := os.Stdin, os.Stderr
	os.Stdin, os.Stderr = stdinReader, stderrWriter
	restored := false
	restoreProcessFiles := func() {
		if restored {
			return
		}
		restored = true
		os.Stdin, os.Stderr = previousStdin, previousStderr
		_ = stdinReader.Close()
		_ = stdinWriter.Close()
		_ = stderrWriter.Close()
		_ = stderrReader.Close()
	}
	t.Cleanup(restoreProcessFiles)

	decOutput = output
	result := make(chan error, 1)
	go func() {
		result <- decryptCmd.RunE(decryptCmd, []string{input})
	}()

	wantPrompt := fmt.Sprintf("Output file %s already exists. Overwrite? [y/N]: ", output)
	type promptResult struct {
		text string
		err  error
	}
	promptRead := make(chan promptResult, 1)
	go func() {
		buf := make([]byte, len(wantPrompt))
		_, readErr := io.ReadFull(stderrReader, buf)
		promptRead <- promptResult{text: string(buf), err: readErr}
	}()

	var prompt string
	select {
	case read := <-promptRead:
		if read.err != nil {
			_ = stdinWriter.Close()
			commandErr := <-result
			t.Fatalf("read overwrite confirmation: %v; command error: %v; stderr: %q", read.err, commandErr, read.text)
		}
		prompt = read.text
	case commandErr := <-result:
		_ = stderrWriter.Close()
		remainder, _ := io.ReadAll(stderrReader)
		t.Fatalf("command returned before overwrite confirmation: %v; stderr: %q", commandErr, remainder)
	case <-time.After(5 * time.Second):
		_ = stdinWriter.Close()
		select {
		case <-result:
		case <-time.After(time.Second):
		}
		t.Fatal("command did not reach overwrite confirmation")
	}

	if prompt != wantPrompt {
		_ = stdinWriter.Close()
		<-result
		t.Fatalf("overwrite confirmation = %q; want %q", prompt, wantPrompt)
	}

	if err := os.Rename(input, retainedInput); err != nil {
		_ = stdinWriter.Close()
		<-result
		t.Fatalf("retain preflighted legacy input: %v", err)
	}
	if err := os.Rename(replacement, input); err != nil {
		_ = stdinWriter.Close()
		<-result
		t.Fatalf("replace input with claimed PCV3: %v", err)
	}
	if _, err := stdinWriter.Write([]byte("y\n")); err != nil {
		_ = stdinWriter.Close()
		<-result
		t.Fatalf("confirm overwrite: %v", err)
	}
	if err := stdinWriter.Close(); err != nil {
		t.Fatalf("close confirmation input: %v", err)
	}

	var commandErr error
	select {
	case commandErr = <-result:
	case <-time.After(5 * time.Second):
		t.Fatal("command did not reject the replacement before a password prompt")
	}
	if err := stderrWriter.Close(); err != nil {
		t.Fatalf("close stderr capture: %v", err)
	}
	remainder, err := io.ReadAll(stderrReader)
	if err != nil {
		t.Fatalf("read command stderr: %v", err)
	}
	restoreProcessFiles()
	fullStderr := prompt + string(remainder)

	var unavailable pcv3UnavailableError
	if !errors.As(commandErr, &unavailable) || !errors.Is(commandErr, pcv3.ErrReaderUnavailable) {
		t.Fatalf("command error = %v; want translated PCV3-unavailable error retaining ErrReaderUnavailable", commandErr)
	}
	if commandErr.Error() != pcv3UnavailableMessage {
		t.Fatalf("command error = %q; want canonical %q", commandErr, pcv3UnavailableMessage)
	}
	if strings.Contains(fullStderr, "Password:") {
		t.Fatalf("claimed replacement reached password prompt: %q", fullStderr)
	}

	gotOutput, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read existing output: %v", err)
	}
	if !bytes.Equal(gotOutput, outputBytes) {
		t.Fatalf("existing output changed: got %q, want %q", gotOutput, outputBytes)
	}
	if _, err := os.Lstat(output + ".incomplete"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("claimed replacement left an incomplete output: %v", err)
	}
	gotInput, err := os.ReadFile(input)
	if err != nil || !bytes.Equal(gotInput, fixture) {
		t.Fatalf("claimed replacement changed: len=%d err=%v", len(gotInput), err)
	}
	gotRetained, err := os.ReadFile(retainedInput)
	if err != nil || !bytes.Equal(gotRetained, legacyBytes) {
		t.Fatalf("preflighted legacy input changed: got %q err=%v", gotRetained, err)
	}

	names := cliContractDirNames(t, dir)
	slices.Sort(names)
	wantNames := []string{filepath.Base(input), filepath.Base(retainedInput), filepath.Base(output)}
	slices.Sort(wantNames)
	if !slices.Equal(names, wantNames) {
		t.Fatalf("command created staging artifacts: got %v, want only %v", names, wantNames)
	}
}
