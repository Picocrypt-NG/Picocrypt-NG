//go:build linux && !android

package volume

import (
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3publication"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDesktopCanceledEncryptOrphanWorker(t *testing.T) {
	parent := os.Getenv("PICOCRYPT_VOLUME_CANCEL_ORPHAN_PARENT")
	if parent == "" {
		return
	}
	stage, err := pcv3publication.Create(filepath.Join(parent, "abandoned-output"), nil, pcv3publication.PolicyNoReplace)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stage.File().WriteString("private data from interrupted operation"); err != nil {
		t.Fatal(err)
	}
	if err := stage.PersistLeasedCleanupJournal(); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}

func TestDesktopPreCancelledEncryptPreservesValidOrphanBeforePreparation(t *testing.T) {
	parent := t.TempDir()
	worker := exec.Command(os.Args[0], "-test.run=^TestDesktopCanceledEncryptOrphanWorker$")
	worker.Env = append(os.Environ(), "PICOCRYPT_VOLUME_CANCEL_ORPHAN_PARENT="+parent)
	if output, err := worker.CombinedOutput(); err != nil {
		t.Fatalf("seed orphan: %s %v", output, err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	var orphan string
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), ".picocrypt-pcv3-private-") {
			orphan = filepath.Join(parent, entry.Name())
		}
	}
	if orphan == "" {
		t.Fatal("worker did not leave its private operation directory")
	}
	type snapshot struct {
		info os.FileInfo
		data []byte
	}
	protected := make(map[string]snapshot)
	privateEntries, err := os.ReadDir(orphan)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range privateEntries {
		path := filepath.Join(orphan, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		protected[path] = snapshot{info: info, data: data}
	}
	source := filepath.Join(t.TempDir(), "source")
	plaintext := []byte("selected plaintext")
	if err := os.WriteFile(source, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reporter := &desktopCleanupReporter{}
	target := filepath.Join(parent, "output")
	result, err := EncryptWithResult(ctx, &EncryptRequest{
		InputFiles: []string{source}, OutputFile: target,
		Password: []byte("password"), PCV3: true, Compress: true, Reporter: reporter,
	}, pcv3operation.ExecutionOptions{LinuxDesktopCleanup: true})
	if !errors.Is(err, context.Canceled) || reporter.compressionStarted || result != nil {
		t.Errorf("pre-cancelled operation reached preparation: compressed=%v result=%v err=%v", reporter.compressionStarted, result, err)
	}
	for path, before := range protected {
		info, statErr := os.Lstat(path)
		data, readErr := os.ReadFile(path)
		if statErr != nil || readErr != nil || !os.SameFile(before.info, info) || !bytes.Equal(before.data, data) {
			t.Errorf("cancelled operation changed an existing orphan: %s stat=%v read=%v", filepath.Base(path), statErr, readErr)
		}
	}
	data, readErr := os.ReadFile(source)
	if readErr != nil || !bytes.Equal(data, plaintext) {
		t.Fatalf("cancelled operation changed the selected source: %q %v", data, readErr)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled operation published output: %v", err)
	}
}
