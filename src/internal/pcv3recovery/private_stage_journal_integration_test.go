//go:build linux || android

package pcv3recovery

import (
	"Picocrypt-NG/internal/pcv3"
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

const recoveryPrivateStageJournalName = ".picocrypt-pcv3-stage.journal"

func TestRecoveryPrivateJournalCollisionPreventsStageWriterAndPlaintext(t *testing.T) {
	directory := t.TempDir()
	journalPath := filepath.Join(directory, recoveryPrivateStageJournalName)
	foreign := []byte("foreign fixed journal must remain byte-for-byte unchanged")
	if err := os.WriteFile(journalPath, foreign, 0o640); err != nil {
		t.Fatalf("seed foreign fixed journal: %v", err)
	}
	foreignInfo, err := os.Lstat(journalPath)
	if err != nil {
		t.Fatalf("stat foreign fixed journal: %v", err)
	}

	semantic, runner := journalIntegrationRecoveryFixture()
	stageWriterEntered := false
	target := filepath.Join(directory, "must-not-exist.bin")
	result := runWithCoreOptions(
		context.Background(),
		&Request{
			Target: target,
			stageWriter: func(io.Writer) io.Writer {
				stageWriterEntered = true
				return io.Discard
			},
		},
		runner,
		ExecutionOptions{JournalPrivateStage: true},
	)

	if stageWriterEntered {
		t.Fatal("recovery entered its plaintext writer before journal persistence succeeded")
	}
	if result == nil || result.Outcome() != semantic.outcome ||
		!result.PublicationAttempted() ||
		result.PublicationState() != pcv3publication.StateNotPublished ||
		!errors.Is(result, pcv3publication.ErrCleanupIncomplete) {
		t.Fatalf(
			"journal collision result = %#v outcome=%v attempted=%v state=%v cleanup=%v; want semantic result, not-published, cleanup-incomplete",
			result, result.Outcome(), result.PublicationAttempted(), result.PublicationState(),
			errors.Is(result, pcv3publication.ErrCleanupIncomplete),
		)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal collision created a target: %v", err)
	}
	requireForeignJournalUnchanged(t, journalPath, foreignInfo, foreign, foreignInfo.Mode())
	requireNoRecoveryPrivateStageResidue(t, directory)
}

func TestRecoveryDefaultOutputDoesNotAdoptPrivateJournalContract(t *testing.T) {
	directory := t.TempDir()
	journalPath := filepath.Join(directory, recoveryPrivateStageJournalName)
	foreign := []byte("foreign journal is outside default desktop custody")
	if err := os.WriteFile(journalPath, foreign, 0o640); err != nil {
		t.Fatalf("seed foreign fixed journal: %v", err)
	}
	foreignInfo, err := os.Lstat(journalPath)
	if err != nil {
		t.Fatalf("stat foreign fixed journal: %v", err)
	}

	_, runner := journalIntegrationRecoveryFixture()
	target := filepath.Join(directory, "default-output.bin")
	result := runWithCore(context.Background(), &Request{Target: target}, runner)
	if result == nil || result.PublicationState() != pcv3publication.StatePublishedDurable ||
		errors.Is(result, pcv3publication.ErrCleanupIncomplete) {
		t.Fatalf("default recovery = %#v state=%v; want unchanged durable publication", result, result.PublicationState())
	}
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("default recovery output = %q, %v; want exact plaintext", got, err)
	}
	requireForeignJournalUnchanged(t, journalPath, foreignInfo, foreign, foreignInfo.Mode())
	requireNoRecoveryPrivateStageResidue(t, directory)
}

func journalIntegrationRecoveryFixture() (operationSemantic, recoveryCoreRunner) {
	semantic := operationSemantic{
		outcome:         pcv3.OutcomeAuthenticatedDegraded,
		provenance:      pcv3.ForceProvenanceVerified,
		stage:           pcv3.StageWrapAuth,
		code:            pcv3.CodeAuthenticatedDegraded,
		plaintextLength: 5,
		ranges: []operationRange{{
			recordIndex: 0,
			start:       0,
			end:         5,
			state:       pcv3.RecoveryRangeVerified,
		}},
		final: pcv3.RecoveryFinalVerified,
	}
	return semantic, fixedCoreRunner(semantic, [][]byte{[]byte("hello")}, nil)
}

func requireForeignJournalUnchanged(
	t *testing.T,
	path string,
	wantInfo os.FileInfo,
	wantBytes []byte,
	wantMode os.FileMode,
) {
	t.Helper()
	gotInfo, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat preserved foreign journal: %v", err)
	}
	gotBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read preserved foreign journal: %v", err)
	}
	if !os.SameFile(wantInfo, gotInfo) || !bytes.Equal(gotBytes, wantBytes) ||
		gotInfo.Mode().Perm() != wantMode.Perm() {
		t.Fatalf(
			"foreign journal changed: same-inode=%v bytes=%q mode=%o; want true, %q, %o",
			os.SameFile(wantInfo, gotInfo), gotBytes, gotInfo.Mode().Perm(), wantBytes, wantMode.Perm(),
		)
	}
}

func requireNoRecoveryPrivateStageResidue(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read recovery stage directory: %v", err)
	}
	for _, entry := range entries {
		if entry.Name() != recoveryPrivateStageJournalName &&
			strings.HasPrefix(entry.Name(), ".picocrypt-pcv3-") {
			t.Fatalf("recovery left private stage residue: %q", entry.Name())
		}
	}
}
