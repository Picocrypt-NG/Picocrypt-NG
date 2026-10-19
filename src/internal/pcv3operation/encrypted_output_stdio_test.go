package pcv3operation

import (
	"Picocrypt-NG/internal/fileops"
	"bytes"
	"context"
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

func TestEncryptedOutputInheritedStdoutCancellation(t *testing.T) {
	stageDirectory := t.TempDir()
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdoutReader.Close()
	defer stdoutWriter.Close()
	cancelReader, cancelWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer cancelReader.Close()
	defer cancelWriter.Close()
	diagnostics, err := os.CreateTemp(t.TempDir(), "child-diagnostics")
	if err != nil {
		t.Fatal(err)
	}
	defer diagnostics.Close()
	child := exec.Command(os.Args[0], "-test.run=^TestEncryptedOutputInheritedStdoutHelper$")
	child.Env = append(os.Environ(), "PICOCRYPT_STDIO_HELPER="+stageDirectory)
	child.Stdout, child.Stderr, child.Stdin = stdoutWriter, diagnostics, cancelReader
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill() })
	var callerDescriptor, callerFlags string
	if runtime.GOOS == "linux" {
		raw, err := stdoutWriter.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		if err := raw.Control(func(fd uintptr) {
			callerDescriptor = fmt.Sprintf("/proc/self/fdinfo/%d", fd)
		}); err != nil {
			t.Fatal(err)
		}
		callerFlags = inheritedStdoutFlags(t, callerDescriptor)
	}
	var first [1]byte
	firstByte := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(stdoutReader, first[:])
		firstByte <- err
	}()
	select {
	case err := <-firstByte:
		if err != nil {
			t.Fatal("child did not begin its inherited stdout write:", err)
		}
	case <-time.After(5 * time.Second):
		_ = child.Process.Kill()
		_ = stdoutWriter.Close()
		<-firstByte
		_ = child.Wait()
		t.Fatal("child did not begin its inherited stdout write within five seconds")
	}
	if runtime.GOOS == "linux" {
		info, _ := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/1", child.Process.Pid))
		t.Logf("inherited stdout fdinfo: %s", info)
		if inheritedStdoutFlags(t, callerDescriptor) != callerFlags {
			t.Error("active child transport changed the caller's shared pipe flags")
		}
	}
	// No more stdout is read: a multi-megabyte write must block in the real
	// inherited pipe before the child observes cancellation through stdin.
	if _, err := cancelWriter.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("child transport failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		_ = child.Process.Kill()
		<-done
		t.Error("cancellation did not join the inherited stdout writer within three seconds")
	}
	trace, err := os.ReadFile(diagnostics.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("child diagnostics: %s", trace)
	if !strings.Contains(string(trace), "stream canceled and cleaned") {
		t.Error("child did not confirm terminal failure and exact spool cleanup")
	}
	entries, err := os.ReadDir(stageDirectory)
	if err != nil || len(entries) != 0 {
		t.Errorf("canceled inherited stdout left an encrypted spool: entries=%d err=%v", len(entries), err)
	}
	if runtime.GOOS == "linux" && inheritedStdoutFlags(t, callerDescriptor) != callerFlags {
		t.Error("canceled child transport changed the caller's shared pipe flags")
	}
}

func TestEncryptedOutputInheritedStdoutSuccessPreservesCaller(t *testing.T) {
	directory := t.TempDir()
	child := exec.Command(os.Args[0], "-test.run=^TestEncryptedOutputInheritedStdoutHelper$")
	child.Env = append(os.Environ(), "PICOCRYPT_STDIO_HELPER="+directory, "PICOCRYPT_STDIO_SUCCESS=1")
	var diagnostics bytes.Buffer
	child.Stderr = &diagnostics
	got, err := child.Output()
	if err != nil {
		t.Fatalf("successful inherited stdout failed: %v: %s", err, diagnostics.Bytes())
	}
	want := bytes.Repeat([]byte("inherited stdout cancellation fixture\n"), 100000)
	want = append(want, []byte("stdout remains open\n")...)
	if !bytes.Equal(got, want) {
		t.Fatal("inherited stdout changed bytes or closed the successful caller destination")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Error("completed inherited stdout retained its encrypted spool")
	}
}

func inheritedStdoutFlags(t *testing.T, path string) string {
	t.Helper()
	info, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(info), "\n") {
		if strings.HasPrefix(line, "flags:") {
			return line
		}
	}
	t.Fatal("descriptor flag observation is unavailable")
	return ""
}

func TestEncryptedOutputInheritedStdoutHelper(t *testing.T) {
	directory := os.Getenv("PICOCRYPT_STDIO_HELPER")
	if directory == "" {
		return
	}
	spool, err := fileops.CreateEncryptedSpool(context.Background(), fileops.EncryptedSpoolOptions{
		NearPath: filepath.Join(directory, "stdout"), MaxPhysicalBytes: 5 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte("inherited stdout cancellation fixture\n"), 100000)
	if _, err := spool.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := spool.Seal(); err != nil {
		t.Fatal(err)
	}
	path := spool.Path()
	output, err := OwnEncryptedOutput(spool)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(os.Stderr, "inherited stdout deadline capability:", os.Stdout.SetWriteDeadline(time.Time{}))
	if os.Getenv("PICOCRYPT_STDIO_SUCCESS") == "1" {
		flags := ""
		if runtime.GOOS == "linux" {
			flags = inheritedStdoutFlags(t, "/proc/self/fdinfo/1")
		}
		result := output.StreamTo(context.Background(), os.Stdout)
		if result.Code() != OutputActionSaved || result.CleanupIncomplete() || output.State() != StreamComplete {
			t.Fatalf("successful inherited stdout failed: result=%v state=%v", result, output.State())
		}
		if runtime.GOOS == "linux" && inheritedStdoutFlags(t, "/proc/self/fdinfo/1") != flags {
			t.Fatal("successful stdout changed the caller's shared pipe flags")
		}
		if _, err := os.Stdout.WriteString("stdout remains open\n"); err != nil {
			t.Fatal("successful stdout closed the caller destination")
		}
		os.Exit(0)
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished, watcherDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watcherDone)
		var trigger [1]byte
		_, _ = os.Stdin.Read(trigger[:])
		cancel()
		select {
		case <-finished:
		case <-time.After(time.Second):
			stack := make([]byte, 64<<10)
			stack = stack[:runtime.Stack(stack, true)]
			_, _ = os.Stderr.Write(stack)
		}
	}()
	result := output.StreamTo(ctx, os.Stdout)
	close(finished)
	<-watcherDone
	cancel()
	if result.Code() != OutputActionSaveFailed || result.CleanupIncomplete() || output.State() != StreamFailed ||
		spool.File() != nil || spool.Path() != "" {
		t.Fatalf("canceled inherited stdout retained an owner: result=%v state=%v", result, output.State())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("canceled inherited stdout retained its encrypted spool")
	}
	fmt.Fprintln(os.Stderr, "stream canceled and cleaned")
	os.Exit(0)
}
