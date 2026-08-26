package cli

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/volume"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCLIKeepsPreparedInputAcrossOverwriteAndPasswordPrompts(t *testing.T) {
	for _, test := range []struct {
		name        string
		deniability bool
	}{
		{name: "regular metadata", deniability: false},
		{name: "deniability without metadata", deniability: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			testCLIKeepsPreparedInputAcrossPrompts(t, test.deniability)
		})
	}
}

func testCLIKeepsPreparedInputAcrossPrompts(t *testing.T, deniability bool) {
	previousPasswordStdin := decPasswordStdin
	resetDecryptFlagsForDirTest()
	decPasswordStdin = false
	decDeniability = deniability
	t.Cleanup(func() {
		resetDecryptFlagsForDirTest()
		decPasswordStdin = previousPasswordStdin
	})

	dir := t.TempDir()
	plaintextPath := filepath.Join(dir, "plaintext")
	input := filepath.Join(dir, "selected.pcv")
	retainedInput := filepath.Join(dir, "selected-before-swap.pcv")
	replacement := filepath.Join(dir, "claimed-replacement.pcv")
	output := filepath.Join(dir, "existing-output")
	plaintext := []byte("the CLI must decrypt the descriptor that authorized the password prompt")
	password := []byte("prepared-input-password")
	outputBytes := []byte("must be replaced only after the prepared input authenticates")
	if err := os.WriteFile(plaintextPath, plaintext, 0o600); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	codecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("initialize Reed-Solomon codecs: %v", err)
	}
	if err := volume.Encrypt(t.Context(), &volume.EncryptRequest{
		InputFile:   plaintextPath,
		OutputFile:  input,
		Password:    password,
		Deniability: deniability,
		RSCodecs:    codecs,
	}); err != nil {
		t.Fatalf("create legacy volume: %v", err)
	}
	originalVolume, err := os.ReadFile(input)
	if err != nil {
		t.Fatalf("read legacy volume: %v", err)
	}
	if err := os.Remove(plaintextPath); err != nil {
		t.Fatalf("remove plaintext fixture: %v", err)
	}
	fixture := loadPCV3CLIFixture(t)
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

	wantOverwrite := fmt.Sprintf("Output file %s already exists. Overwrite? [y/N]: ", output)
	overwrite, err := readCLIStderrThroughWithin(stderrReader, wantOverwrite, 5*time.Second)
	if err != nil {
		_ = stdinWriter.Close()
		commandErr := <-result
		t.Fatalf("read overwrite confirmation: %v; command error: %v; stderr: %q", err, commandErr, overwrite)
	}
	if overwrite != wantOverwrite {
		_ = stdinWriter.Close()
		<-result
		t.Fatalf("overwrite confirmation = %q; want %q", overwrite, wantOverwrite)
	}

	if err := os.Rename(input, retainedInput); err != nil {
		if runtime.GOOS == "windows" && (errors.Is(err, syscall.Errno(5)) || errors.Is(err, syscall.Errno(32))) {
			if _, writeErr := stdinWriter.Write([]byte("n\n")); writeErr != nil {
				t.Fatalf("cancel after Windows blocked the open-input rename: %v", writeErr)
			}
			_ = stdinWriter.Close()
			var commandErr error
			select {
			case commandErr = <-result:
			case <-time.After(5 * time.Second):
				t.Fatal("command did not cancel after Windows protected the open input")
			}
			_ = stderrWriter.Close()
			_, _ = io.ReadAll(stderrReader)
			restoreProcessFiles()
			if commandErr == nil || !strings.Contains(commandErr.Error(), "operation cancelled") {
				t.Fatalf("command error after protected-input rename refusal = %v; want cancellation", commandErr)
			}
			gotInput, readErr := os.ReadFile(input)
			if readErr != nil || !bytes.Equal(gotInput, originalVolume) {
				t.Fatalf("Windows protected input changed: len=%d err=%v", len(gotInput), readErr)
			}
			gotOutput, readErr := os.ReadFile(output)
			if readErr != nil || !bytes.Equal(gotOutput, outputBytes) {
				t.Fatalf("cancelled output changed: got %q err=%v", gotOutput, readErr)
			}
			return
		}
		_ = stdinWriter.Close()
		<-result
		t.Fatalf("retain prepared legacy input: %v", err)
	}
	if err := os.Rename(replacement, input); err != nil {
		_ = stdinWriter.Close()
		<-result
		t.Fatalf("replace selected path with claimed PCV3: %v", err)
	}
	if _, err := stdinWriter.Write([]byte("y\n")); err != nil {
		_ = stdinWriter.Close()
		<-result
		t.Fatalf("confirm overwrite: %v", err)
	}

	type promptResult struct {
		text string
		err  error
	}
	passwordPrompt := make(chan promptResult, 1)
	go func() {
		text, readErr := readCLIStderrThrough(stderrReader, "Password: ")
		passwordPrompt <- promptResult{text: text, err: readErr}
	}()
	var prompted string
	select {
	case read := <-passwordPrompt:
		if read.err != nil {
			_ = stdinWriter.Close()
			commandErr := <-result
			t.Fatalf("read password prompt: %v; command error: %v; stderr: %q", read.err, commandErr, read.text)
		}
		prompted = read.text
	case commandErr := <-result:
		t.Fatalf("command returned before password prompt: %v", commandErr)
	case <-time.After(5 * time.Second):
		_ = stdinWriter.Close()
		t.Fatal("command did not reach the password prompt")
	}
	if !strings.HasSuffix(prompted, "Password: ") {
		t.Fatalf("credential output = %q; want terminal password prompt", prompted)
	}
	if _, err := stdinWriter.Write(append(append([]byte(nil), password...), '\n')); err != nil {
		_ = stdinWriter.Close()
		<-result
		t.Fatalf("write password: %v", err)
	}
	if err := stdinWriter.Close(); err != nil {
		t.Fatalf("close command input: %v", err)
	}

	var commandErr error
	select {
	case commandErr = <-result:
	case <-time.After(30 * time.Second):
		t.Fatal("command did not finish decrypting the prepared input")
	}
	if err := stderrWriter.Close(); err != nil {
		t.Fatalf("close stderr capture: %v", err)
	}
	_, _ = io.ReadAll(stderrReader)
	restoreProcessFiles()
	if commandErr != nil {
		t.Fatalf("decrypt prepared input after pathname replacement: %v", commandErr)
	}

	gotOutput, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read decrypted output: %v", err)
	}
	if !bytes.Equal(gotOutput, plaintext) {
		t.Fatalf("decrypted output = %q; want prepared descriptor plaintext %q", gotOutput, plaintext)
	}
	gotInput, err := os.ReadFile(input)
	if err != nil || !bytes.Equal(gotInput, fixture) {
		t.Fatalf("claimed pathname replacement changed: len=%d err=%v", len(gotInput), err)
	}
	gotRetained, err := os.ReadFile(retainedInput)
	if err != nil || !bytes.Equal(gotRetained, originalVolume) {
		t.Fatalf("prepared legacy volume changed: len=%d err=%v", len(gotRetained), err)
	}
	names := cliContractDirNames(t, dir)
	slices.Sort(names)
	wantNames := []string{filepath.Base(input), filepath.Base(retainedInput), filepath.Base(output)}
	slices.Sort(wantNames)
	if !slices.Equal(names, wantNames) {
		t.Fatalf("command left staging artifacts: got %v, want only %v", names, wantNames)
	}
}

func readCLIStderrThrough(reader *os.File, suffix string) (string, error) {
	var out bytes.Buffer
	wantSuffix := []byte(suffix)
	buf := make([]byte, 1)
	for out.Len() <= 64*1024 {
		if _, err := io.ReadFull(reader, buf); err != nil {
			return out.String(), err
		}
		out.WriteByte(buf[0])
		if bytes.HasSuffix(out.Bytes(), wantSuffix) {
			return out.String(), nil
		}
	}
	return out.String(), fmt.Errorf("stderr exceeded 64 KiB before %q", suffix)
}

func readCLIStderrThroughWithin(reader *os.File, suffix string, timeout time.Duration) (string, error) {
	type result struct {
		text string
		err  error
	}
	read := make(chan result, 1)
	go func() {
		text, err := readCLIStderrThrough(reader, suffix)
		read <- result{text: text, err: err}
	}()
	select {
	case got := <-read:
		return got.text, got.err
	case <-time.After(timeout):
		return "", fmt.Errorf("stderr did not reach %q within %s", suffix, timeout)
	}
}
