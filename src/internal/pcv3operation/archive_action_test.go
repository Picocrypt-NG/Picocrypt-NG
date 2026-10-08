package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3publication"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

// These fixtures execute the production writer, authenticated reader, archive
// handoff, extractor, and fixed KDF with keyfile-only credentials.
func archiveActionFixture(t *testing.T, target string, plaintext []byte) *Result {
	t.Helper()
	return archiveActionReadFixture(t, target, archiveActionCiphertext(t, plaintext))
}

func archiveActionFactors() *FactorRequest {
	return &FactorRequest{
		Mode: CredentialModeKeyfilesOnly, ExpectedPolicy: FactorPolicyKeyfilesOnly, KeyfileMode: KeyfileModeUnordered,
		Keyfiles: []*KeyfileReader{OwnKeyfileReader(io.NopCloser(bytes.NewReader([]byte("public archive action factor"))))},
	}
}

func archiveActionCiphertext(t *testing.T, plaintext []byte) string {
	t.Helper()
	ciphertext := filepath.Join(t.TempDir(), "ciphertext.pcv")
	write := RunWrite(context.Background(), &WriteRequest{
		Mode: WriteModeNormal, Suite: SuiteStandard, PayloadKind: PayloadKindArchive,
		Source: bytes.NewReader(plaintext), PlaintextLength: uint64(len(plaintext)),
		Target: ciphertext, Factors: archiveActionFactors(), Comment: []byte("public archive action comment"),
	})
	requireNativeOperationPublication(t, write)
	return ciphertext
}

func archiveActionReadFixture(t *testing.T, target, ciphertext string) *Result {
	t.Helper()
	source, err := os.Open(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	result := Run(context.Background(), &Request{Mode: ModeReadNormal, Source: source, Target: target, Factors: archiveActionFactors()})
	followUp := result.ArchiveFollowUp()
	if followUp == nil {
		t.Fatalf("authenticated archive fixture has no authority: %v", result)
	}
	t.Cleanup(func() { followUp.Close() })
	return result
}

func archiveActionPayload(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.zip")
	pcv3BuildZipArchive(t, path, "payload.txt", []byte("archive action authenticated contents\n"))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestArchiveActionProductionSaveAndExtract(t *testing.T) {
	for _, action := range []ArchiveAction{ArchiveSave, ArchiveExtract, ArchiveExtractSameLevel} {
		t.Run(map[ArchiveAction]string{ArchiveSave: "save", ArchiveExtract: "new folder", ArchiveExtractSameLevel: "same level"}[action], func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, "Restored.ZiP")
			plan, err := newArchiveReadPlan(action, target)
			if err != nil {
				t.Fatal(err)
			}
			defer plan.close()
			plaintext := archiveActionPayload(t)
			read := archiveActionFixture(t, target, plaintext)
			result := plan.apply(context.Background(), read)
			requireNativeOperationPublication(t, result)
			if result.ArchiveFollowUp() != nil ||
				result.AuthenticatedComment() != "public archive action comment" || result.SourceDeletionAllowed() {
				t.Fatalf("archive action completion=%v", result)
			}
			wantPath := target
			wantBytes := plaintext
			if action != ArchiveSave {
				wantPath = filepath.Join(directory, "payload.txt")
				if action == ArchiveExtract {
					wantPath = filepath.Join(directory, "Restored", "payload.txt")
					info, err := os.Stat(filepath.Join(directory, "Restored"))
					if err != nil || !info.IsDir() || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o700) {
						t.Fatalf("extraction directory permissions: %v %v", info, err)
					}
				}
				wantBytes = []byte("archive action authenticated contents\n")
				if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("extraction also published raw ZIP: %v", err)
				}
			}
			got, err := os.ReadFile(wantPath)
			if err != nil || !bytes.Equal(got, wantBytes) {
				t.Fatalf("archive action output differs: %q %v", got, err)
			}
		})
	}
}

func TestArchiveActionReviewsAuthenticatedBudgetBeforeExtraction(t *testing.T) {
	archive, err := os.ReadFile(filepath.Join("..", "fileops", "testdata", "unpack_high_ratio_above_floor.zip"))
	if err != nil {
		t.Fatal(err)
	}
	for _, decision := range []string{"approve", "decline", "panic"} {
		t.Run(decision, func(t *testing.T) {
			parent := t.TempDir()
			target := filepath.Join(parent, "result.zip")
			plan, err := newArchiveReadPlan(ArchiveExtract, target)
			if err != nil {
				t.Fatal(err)
			}
			defer plan.close()
			calls := 0
			plan.review = func(ctx context.Context, summary ArchiveSummary) error {
				calls++
				if ctx.Err() != nil || summary.Files != 1 || summary.Directories != 0 || summary.UnpackedBytes != 2<<20 {
					t.Fatalf("review received incorrect archive budget: %+v (%v)", summary, ctx.Err())
				}
				entries, err := os.ReadDir(filepath.Join(parent, "result"))
				if err != nil || len(entries) != 0 {
					t.Fatalf("extraction started before review: %v", err)
				}
				switch decision {
				case "decline":
					return context.Canceled
				case "panic":
					panic("review callback failed")
				}
				return nil
			}
			read := archiveActionFixture(t, target, archive)
			result := plan.apply(context.Background(), read)
			if calls != 1 || result.ArchiveFollowUp() != nil || result.SourceDeletionAllowed() {
				t.Fatalf("review lifecycle mismatch: calls=%d result=%v", calls, result)
			}
			if decision == "approve" {
				requireNativeOperationPublication(t, result)
				entries, err := os.ReadDir(filepath.Join(parent, "result"))
				if err != nil || len(entries) != 1 {
					t.Fatalf("approved archive output missing: %v", err)
				}
				body, err := os.ReadFile(filepath.Join(parent, "result", entries[0].Name()))
				if err != nil || !bytes.Equal(body, bytes.Repeat([]byte("A"), 2<<20)) {
					t.Fatalf("approved output bytes differ: %v", err)
				}
				return
			}
			if result.PublicationState() != pcv3publication.StateNotPublished || len(result.Warnings()) != 0 {
				t.Fatalf("declined review did not cleanly refuse: %v", result)
			}
			if decision == "decline" && !errors.Is(result, context.Canceled) {
				t.Fatalf("declining review lost cancellation: %v", result)
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatalf("declined review left plaintext or temporary files: %v", err)
			}
		})
	}
}

func TestArchiveActionDefaultAndPrepareLeaveOneShotChoice(t *testing.T) {
	for _, action := range []ArchiveAction{ArchiveDefault, ArchivePrepare} {
		target := filepath.Join(t.TempDir(), "pending.zip")
		plan, err := newArchiveReadPlan(action, target)
		if err != nil {
			t.Fatal(err)
		}
		defer plan.close()
		read := archiveActionFixture(t, target, archiveActionPayload(t))
		if result := plan.apply(context.Background(), read); result != read || result.ArchiveFollowUp() == nil {
			t.Fatal("nonterminal archive choice was consumed")
		}
	}
}

func TestArchiveActionPreflightRejectsExistingExtractionDirectoryAndSymlink(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		directory := t.TempDir()
		leaf := filepath.Join(directory, "output")
		if symlink {
			if err := os.Symlink(t.TempDir(), leaf); err != nil {
				t.Fatal(err)
			}
		} else if err := os.Mkdir(leaf, 0o700); err != nil {
			t.Fatal(err)
		}
		if plan, err := newArchiveReadPlan(ArchiveExtract, leaf+".zip"); err == nil || plan != nil {
			if plan != nil {
				plan.close()
			}
			t.Fatal("preflight accepted an existing extraction destination")
		}
	}
}

func TestArchiveActionCompetingDirectoryCreationPreservesForeignContents(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "output.zip")
	plan, err := newArchiveReadPlan(ArchiveExtract, target)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()
	read := archiveActionFixture(t, target, archiveActionPayload(t))
	leaf := filepath.Join(directory, "output")
	if err := os.Mkdir(leaf, 0o700); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(leaf, "payload.txt")
	if err := os.WriteFile(foreign, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := plan.apply(context.Background(), read)
	if result.CompletionClass() != CompletionNoOutput || read.ArchiveFollowUp() != nil {
		t.Fatalf("competing creation was not rejected: %v", result)
	}
	got, err := os.ReadFile(foreign)
	if err != nil || string(got) != "foreign" {
		t.Fatalf("foreign extraction contents changed: %q %v", got, err)
	}
}

func TestArchiveActionParentReplacementDoesNotRedirectPlaintext(t *testing.T) {
	base := t.TempDir()
	directory := filepath.Join(base, "parent")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "output.zip")
	plan, err := newArchiveReadPlan(ArchiveExtract, target)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()
	read := archiveActionFixture(t, target, archiveActionPayload(t))
	moved := filepath.Join(base, "moved")
	if err := os.Rename(directory, moved); err != nil {
		var renameErr *os.LinkError
		if runtime.GOOS != "windows" || !errors.As(err, &renameErr) ||
			renameErr.Op != "rename" || renameErr.Old != directory || renameErr.New != moved ||
			(!errors.Is(renameErr.Err, syscall.Errno(5)) && !errors.Is(renameErr.Err, syscall.Errno(32))) {
			t.Fatal(err)
		}
		// Windows may prevent the attack while the pinned directory is open.
		// The admitted destination must still receive the exact plaintext.
		if _, movedErr := os.Lstat(moved); !errors.Is(movedErr, os.ErrNotExist) {
			t.Fatalf("failed parent replacement moved the original: %v", movedErr)
		}
		result := plan.apply(context.Background(), read)
		requireNativeOperationPublication(t, result)
		if result.ArchiveFollowUp() != nil || result.SourceDeletionAllowed() {
			t.Fatalf("blocked parent replacement retained authority: %v", result)
		}
		requireOperationFileBytes(t, filepath.Join(directory, "output", "payload.txt"), []byte("archive action authenticated contents\n"))
		entries, readErr := os.ReadDir(directory)
		if readErr != nil || len(entries) != 1 || entries[0].Name() != "output" {
			t.Fatalf("blocked parent replacement left unexpected output: %v %v", entries, readErr)
		}
		return
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	result := plan.apply(context.Background(), read)
	if result.CompletionClass() != CompletionNoOutput || read.ArchiveFollowUp() != nil {
		t.Fatalf("replaced parent accepted: %v", result)
	}
	for _, path := range []string{directory, moved} {
		entries, err := os.ReadDir(path)
		if err != nil || len(entries) != 0 {
			t.Fatalf("parent replacement left output: %s %v %v", path, entries, err)
		}
	}
}

func TestArchiveActionFailedExtractionRemovesOnlyItsEmptyDirectory(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "output.zip")
	plan, err := newArchiveReadPlan(ArchiveExtract, target)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()
	read := archiveActionFixture(t, target, []byte("authenticated but invalid ZIP"))
	result := plan.apply(context.Background(), read)
	if result.CompletionClass() != CompletionNoOutput || len(result.Warnings()) != 0 {
		t.Fatalf("malformed ZIP failure=%v", result)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed extraction retained its directory or ZIP: %v %v", entries, err)
	}
}

func TestArchiveActionParentSyncFailurePreservesExtractedFilesWithWarning(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "output.zip")
	plan, err := newArchiveReadPlan(ArchiveExtract, target)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()
	read := archiveActionFixture(t, target, archiveActionPayload(t))
	// A real closed sync descriptor injects only the late parent barrier fault.
	if err := plan.parentDirectory.Close(); err != nil {
		t.Fatal(err)
	}
	result := plan.apply(context.Background(), read)
	if result.PublicationState() != pcv3publication.StatePublishedDurabilityUncertain ||
		result.CompletionClass() != CompletionDurabilityUncertain || result.SourceDeletionAllowed() {
		t.Fatalf("missing parent barrier reported durable success: %v", result)
	}
	got, err := os.ReadFile(filepath.Join(directory, "output", "payload.txt"))
	if err != nil || string(got) != "archive action authenticated contents\n" {
		t.Fatalf("uncertain output was lost: %q %v", got, err)
	}
}
