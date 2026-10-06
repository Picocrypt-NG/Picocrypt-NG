package volume

import (
	"Picocrypt-NG/internal/fileops"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type tempZipDesignPanicReporter struct {
	marker error
	called bool
	before func()
}

func (*tempZipDesignPanicReporter) SetStatus(string)  {}
func (*tempZipDesignPanicReporter) SetCanCancel(bool) {}
func (*tempZipDesignPanicReporter) Update()           {}
func (*tempZipDesignPanicReporter) IsCancelled() bool { return false }
func (r *tempZipDesignPanicReporter) SetProgress(float32, string) {
	r.called = true
	if r.before != nil {
		r.before()
	}
	panic(r.marker)
}

// This regression exercises the exported preparation path used by
// mobile. Its oracle is cleanup of only the operation-owned stage on callback
// panic, while preserving the selected original and an unrelated sibling.
func TestPrepareInputPanicMustCleanupOwnedStage(t *testing.T) {
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "input.txt"), filepath.Join(dir, "unrelated.txt")}
	beforeInfos := make([]os.FileInfo, len(paths))
	beforeHashes := make([][32]byte, len(paths))
	for i, path := range paths {
		data := []byte("non-secret design probe fixture: " + filepath.Base(path))
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		beforeInfos[i] = info
		beforeHashes[i] = sha256.Sum256(data)
		t.Logf("BEFORE file=%s bytes=%d mode=%#o sha256=%x", filepath.Base(path), info.Size(), info.Mode().Perm(), beforeHashes[i])
	}
	beforeEntries, err := os.ReadDir(dir)
	if err != nil || len(beforeEntries) != len(paths) {
		t.Fatalf("fixture inventory before: entries=%d err=%v", len(beforeEntries), err)
	}
	marker := errors.New("TEST ONLY progress callback panic after temp stage creation")
	reporter := &tempZipDesignPanicReporter{marker: marker}
	var recovered any
	var prepared *PreparedEncryptInput
	var prepareErr error
	func() {
		defer func() { recovered = recover() }()
		prepared, prepareErr = PrepareEncryptInput(context.Background(), EncryptInputRequest{
			InputFile: paths[0], OutputFile: filepath.Join(dir, "output.pcv"), Compress: true, Reporter: reporter,
		})
	}()
	if prepared != nil {
		defer prepared.Close()
	}
	if recovered != marker || !reporter.called || prepared != nil || prepareErr != nil { //nolint:errorlint // Only this exact panic sentinel demonstrates the callback path.
		t.Fatalf("probe did not reach expected panic: recovered=%v called=%v prepared=%v err=%v", recovered, reporter.called, prepared, prepareErr)
	}
	t.Log("RECOVERED expected callback panic; exported call did not transfer an owner")
	for i, path := range paths {
		data, readErr := os.ReadFile(path)
		info, statErr := os.Stat(path)
		if readErr != nil || statErr != nil {
			t.Fatalf("protected fixture changed: file=%s read=%v stat=%v", filepath.Base(path), readErr, statErr)
		}
		hash := sha256.Sum256(data)
		if hash != beforeHashes[i] || !os.SameFile(beforeInfos[i], info) {
			t.Fatalf("protected file identity/content changed: %s", filepath.Base(path))
		}
		t.Logf("AFTER file=%s bytes=%d mode=%#o sha256=%x same_inode=true", filepath.Base(path), info.Size(), info.Mode().Perm(), hash)
	}
	afterEntries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	residuals := 0
	for _, entry := range afterEntries {
		if entry.Name() == "input.txt" || entry.Name() == "unrelated.txt" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("AFTER unexpected_file=%s bytes=%d mode=%#o", entry.Name(), info.Size(), info.Mode().Perm())
		if !strings.HasPrefix(entry.Name(), ".picocrypt-") || !info.Mode().IsRegular() {
			t.Fatalf("unexpected non-stage fixture result: %s", entry.Name())
		}
		residuals++
	}
	if residuals != 0 {
		t.Fatalf("callback panic leaked %d operation-owned temporary ZIP stage(s); original and unrelated sibling retained", residuals)
	}
}

func TestPrepareInputPanicCleanupFailurePreservesWarningAndOriginals(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission fault requires an unprivileged POSIX process")
	}
	dir := t.TempDir()
	defer os.Chmod(dir, 0o700)
	source := filepath.Join(dir, "input")
	foreign := filepath.Join(dir, "unrelated")
	body := []byte("original secret input")
	for _, p := range []string{source, foreign} {
		if e := os.WriteFile(p, body, 0o600); e != nil {
			t.Fatal(e)
		}
	}
	before, e := os.Stat(source)
	if e != nil {
		t.Fatal(e)
	}
	marker := errors.New("private panic content /private/cleanup/path")
	var stage string
	reporter := &tempZipDesignPanicReporter{marker: marker, before: func() {
		entries, e := os.ReadDir(dir)
		if e != nil {
			t.Fatal(e)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".picocrypt-") {
				stage = filepath.Join(dir, entry.Name())
			}
		}
		if stage == "" {
			t.Fatal("panic seam lacks owned stage")
		}
		if e = os.Chmod(dir, 0o500); e != nil {
			t.Fatal(e)
		}
	}}
	var recovered any
	var owner *PreparedEncryptInput
	func() {
		defer func() { recovered = recover() }()
		owner, e = PrepareEncryptInput(context.Background(), EncryptInputRequest{InputFile: source, OutputFile: filepath.Join(dir, "output.pcv"), Compress: true, Reporter: reporter})
	}()
	if e = os.Chmod(dir, 0o700); e != nil {
		t.Fatal(e)
	}
	if owner != nil {
		owner.Close()
		t.Fatal("panic transferred an input owner")
	}
	if recovered == nil {
		t.Fatal("callback panic was swallowed")
	}
	if !fileops.PanicCleanupIncomplete(recovered) {
		t.Fatal("cleanup warning was lost across preparation panic boundary")
	}
	// A cleanup-warning panic must be redacted even when passed directly to a
	// frontend formatter; the original panic marker cannot be the public value.
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		rendered := fmt.Sprintf(format, recovered)
		if strings.Contains(rendered, "private") || strings.Contains(rendered, dir) {
			t.Fatalf("panic exposed private diagnostic through %s", format)
		}
	}
	if _, e = os.Stat(filepath.Join(dir, "output.pcv")); !os.IsNotExist(e) {
		t.Fatal("panic published output")
	}
	if _, e = os.Stat(stage); e != nil {
		t.Fatalf("cleanup failure did not retain identified residue: %v", e)
	}
	if e = os.Remove(stage); e != nil {
		t.Fatal(e)
	}
	after, e := os.Stat(source)
	if e != nil || !os.SameFile(before, after) {
		t.Fatal("panic changed original identity")
	}
	for _, p := range []string{source, foreign} {
		got, e := os.ReadFile(p)
		if e != nil || string(got) != string(body) {
			t.Fatal("panic changed protected input")
		}
	}
}

type legacyPreparedPanicReporter struct {
	GoldenTestReporter
	before func()
	marker error
}

func (r *legacyPreparedPanicReporter) SetStatus(status string) {
	if status == "Generating values..." {
		r.before()
		panic(r.marker)
	}
}

// A panic after successful archive preparation is owned by the legacy outer
// operation defer, rather than CreateTempZip's pre-transfer defer.
func TestLegacyPreparedPanicCleanupFailureRemainsWarningWithoutPublication(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission fault requires an unprivileged POSIX process")
	}
	dir := t.TempDir()
	defer os.Chmod(dir, 0o700)
	source := filepath.Join(dir, "input")
	body := []byte("original after prepared panic")
	if e := os.WriteFile(source, body, 0o600); e != nil {
		t.Fatal(e)
	}
	before, e := os.Stat(source)
	if e != nil {
		t.Fatal(e)
	}
	var stage string
	marker := errors.New("private prepared panic")
	reporter := &legacyPreparedPanicReporter{marker: marker, before: func() {
		entries, e := os.ReadDir(dir)
		if e != nil {
			t.Fatal(e)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".picocrypt-") {
				stage = filepath.Join(dir, entry.Name())
			}
		}
		if stage == "" {
			t.Fatal("missing prepared stage")
		}
		if e = os.Chmod(dir, 0o500); e != nil {
			t.Fatal(e)
		}
	}}
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		e = Encrypt(context.Background(), &EncryptRequest{InputFile: source, OutputFile: filepath.Join(dir, "out.pcv"), Compress: true, Password: []byte("test password"), Reporter: reporter})
	}()
	if restore := os.Chmod(dir, 0o700); restore != nil {
		t.Fatal(restore)
	}
	if !fileops.PanicCleanupIncomplete(recovered) {
		t.Fatalf("outer prepared panic lost cleanup warning: error=%v", e)
	}
	if strings.Contains(fmt.Sprintf("%#v", recovered), "private") {
		t.Fatal("outer panic exposed private value")
	}
	if _, e = os.Stat(filepath.Join(dir, "out.pcv")); !os.IsNotExist(e) {
		t.Fatal("outer panic published output")
	}
	if e = os.Remove(stage); e != nil {
		t.Fatal(e)
	}
	after, e := os.Stat(source)
	got, readErr := os.ReadFile(source)
	if e != nil || readErr != nil || !os.SameFile(before, after) || string(got) != string(body) {
		t.Fatal("outer panic changed source")
	}
}
