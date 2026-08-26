//go:build linux || android

package pcv3

import (
	"Picocrypt-NG/internal/pcv3publication"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const privateStageJournalName = ".picocrypt-pcv3-stage.journal"

func TestNativeReadPrivateStageJournalRecoversWrittenPlaintextAfterRestart(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "private-output.bin")
	payload := []byte("authenticated plaintext written through the production sink")
	var observed bytes.Buffer
	firstWriteBoundaryCalls := 0
	sink := &nativeReadSink{
		target:              target,
		journalPrivateStage: true,
		stageWriter: func(destination io.Writer) io.Writer {
			firstWriteBoundaryCalls++
			return io.MultiWriter(destination, &observed)
		},
	}
	defer sink.abortUncommitted()

	if err := sink.writeVerifiedRecord(context.Background(), 0, payload); err != nil {
		t.Fatalf("write verified plaintext through production sink: %v", err)
	}
	if firstWriteBoundaryCalls != 1 || !bytes.Equal(observed.Bytes(), payload) {
		t.Fatalf(
			"first-write observation = calls %d bytes %q; want one exact production write boundary",
			firstWriteBoundaryCalls, observed.Bytes(),
		)
	}
	stagePath := requireSinglePrivateStage(t, directory)
	stageBytes, err := os.ReadFile(stagePath)
	if err != nil || !bytes.Equal(stageBytes, payload) {
		t.Fatalf("private stage bytes = %q, %v; want exact authenticated plaintext", stageBytes, err)
	}

	state, err := pcv3publication.CleanupJournaledStage(directory)
	if err != nil || state != pcv3publication.CleanupJournalCleaned {
		t.Fatalf("restart cleanup = (%v, %v); want exact journaled stage cleanup", state, err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("restart cleanup published a target: %v", err)
	}
	requireNoPrivateStageEntries(t, directory, false)
}

func TestNativeReadPrivateJournalCollisionPrecedesFirstPlaintextWrite(t *testing.T) {
	directory := t.TempDir()
	journalPath := filepath.Join(directory, privateStageJournalName)
	foreign := []byte("foreign journal blocks plaintext before its first byte")
	if err := os.WriteFile(journalPath, foreign, 0o640); err != nil {
		t.Fatalf("seed foreign private-stage journal: %v", err)
	}
	foreignInfo, err := os.Lstat(journalPath)
	if err != nil {
		t.Fatalf("stat foreign private-stage journal: %v", err)
	}

	firstWriteBoundaryEntered := false
	target := filepath.Join(directory, "must-not-exist.bin")
	sink := &nativeReadSink{
		target:              target,
		journalPrivateStage: true,
		stageWriter: func(destination io.Writer) io.Writer {
			firstWriteBoundaryEntered = true
			return destination
		},
	}
	writeErr := sink.writeVerifiedRecord(
		context.Background(),
		0,
		[]byte("plaintext must not reach the first write boundary"),
	)
	sink.abortUncommitted()

	if !errors.Is(writeErr, pcv3publication.ErrCleanupIncomplete) {
		t.Fatalf("foreign journal write error = %v; want cleanup-incomplete refusal", writeErr)
	}
	if firstWriteBoundaryEntered {
		t.Fatal("ordinary read reached its first plaintext write before journal persistence")
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("foreign journal collision created a target: %v", err)
	}
	gotInfo, err := os.Lstat(journalPath)
	if err != nil {
		t.Fatalf("stat preserved foreign journal: %v", err)
	}
	gotBytes, err := os.ReadFile(journalPath)
	if err != nil || !bytes.Equal(gotBytes, foreign) || !os.SameFile(foreignInfo, gotInfo) ||
		gotInfo.Mode().Perm() != foreignInfo.Mode().Perm() {
		t.Fatalf(
			"foreign journal changed: bytes=%q error=%v same-inode=%v mode=%o",
			gotBytes, err, os.SameFile(foreignInfo, gotInfo), gotInfo.Mode().Perm(),
		)
	}
	requireNoPrivateStageEntries(t, directory, true)
}

func TestNativeReadRequestTransfersAndClearsPrivateJournalOption(t *testing.T) {
	request := &NativeReadRequest{
		Source:              bytes.NewReader(nil),
		SourceSize:          0,
		Target:              filepath.Join(t.TempDir(), "output.bin"),
		JournalPrivateStage: true,
	}

	result := RunNativeRead(context.Background(), request, func(*NativeReadOutput) error {
		t.Fatal("invalid pre-KDF request reached the output callback")
		return nil
	})
	if result == nil || result.Outcome() != OutcomeOperationFailed {
		t.Fatalf("invalid pre-KDF result = %#v; want closed operation failure", result)
	}
	if request.JournalPrivateStage {
		t.Fatal("native read request retained the transferred private-journal option")
	}
}

func requireSinglePrivateStage(t *testing.T, directory string) string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read private stage directory: %v", err)
	}
	var stagePath string
	journalFound := false
	for _, entry := range entries {
		switch {
		case entry.Name() == privateStageJournalName:
			journalFound = true
		case strings.HasPrefix(entry.Name(), ".picocrypt-pcv3-"):
			if stagePath != "" {
				t.Fatalf("multiple private PCV3 stage entries: %q and %q", filepath.Base(stagePath), entry.Name())
			}
			stagePath = filepath.Join(directory, entry.Name())
		}
	}
	if !journalFound || stagePath == "" {
		t.Fatalf("private stage directory entries = %v; want one stage and its fixed journal", entries)
	}
	return stagePath
}

func requireNoPrivateStageEntries(t *testing.T, directory string, allowJournal bool) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read private stage directory: %v", err)
	}
	for _, entry := range entries {
		if allowJournal && entry.Name() == privateStageJournalName {
			continue
		}
		if strings.HasPrefix(entry.Name(), ".picocrypt-pcv3-") {
			t.Fatalf("private PCV3 residue remains after cleanup: %q", entry.Name())
		}
	}
}
