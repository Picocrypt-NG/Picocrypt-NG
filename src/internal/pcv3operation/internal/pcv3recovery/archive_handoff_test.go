package pcv3recovery

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3publication"
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func recoveryArchiveBytes(t *testing.T) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	entry, err := writer.Create("payload.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("authenticated archive contents\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// The seam supplies authenticated core output; the stage, ZIP parser,
// publisher, extractor, and cleanup execute their production filesystem paths.
func recoveryArchiveCore(data []byte, after func() error) recoveryCoreRunner {
	return func(_ context.Context, _ *Request, output operationOutput) (operationSemantic, error) {
		semantic := operationSemantic{
			outcome: pcv3.OutcomeSuccess, stage: pcv3.StageNone, code: pcv3.CodeSuccess,
			provenance: pcv3.ForceProvenanceNone, d1Provenance: pcv3.D1BootstrapProvenanceFront,
		}
		if err := output(semantic, operationRoleD1Front, "", uint64(len(data)), func(sink operationSegmentSink) error {
			return sink(operationRange{recordIndex: 0, start: 0, end: uint64(len(data)), state: pcv3.RecoveryRangeVerified}, data)
		}); err != nil {
			return semantic, err
		}
		if after != nil {
			return semantic, after()
		}
		return semantic, nil
	}
}

func prepareRecoveryArchive(t *testing.T, after func() error) (*Result, string) {
	t.Helper()
	target := filepath.Join(t.TempDir(), "plaintext.zip")
	result := runWithCoreOptions(context.Background(), &Request{
		Target: target, Mode: pcv3.RecoveryModeNormalV3,
	}, recoveryArchiveCore(recoveryArchiveBytes(t), after), ExecutionOptions{PrepareArchive: true})
	return result, target
}

func TestD1ArchiveHandoffDefersPlaintextAndExtractsOnlyOnce(t *testing.T) {
	result, target := prepareRecoveryArchive(t, nil)
	handoff := result.TakeArchiveHandoff()
	if handoff == nil || !handoff.Live() || result.PublicationAttempted() || result.TakeArchiveHandoff() != nil {
		t.Fatalf("archive did not transfer exact unpublished custody: %v", result)
	}
	copied := *handoff
	defer handoff.Close()
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("archive published before follow-up: %v", err)
	}
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	extracted := handoff.Extract(context.Background(), root)
	if extracted == nil || extracted.State() != fileops.UnpackStatePublishedDurable || extracted.CleanupIncomplete() {
		t.Fatalf("extraction did not complete durably: %v", extracted)
	}
	assertFileBytesAndMode(t, filepath.Join(directory, "payload.txt"), []byte("authenticated archive contents\n"), 0o600)
	if _, err := root.Stat("."); err == nil {
		t.Fatal("extraction did not close its owned root")
	}
	if handoff.Live() || copied.Live() {
		t.Fatal("copied archive handoff remained live")
	}
	if publication, cleanup := copied.Publish(context.Background()); publication != nil || cleanup {
		t.Fatal("copied handoff published plaintext after extraction")
	}
	assertNoRecoveryStageResidue(t, filepath.Dir(target))
}

func TestD1ArchiveHandoffPublishPreservesZIPAndNoReplace(t *testing.T) {
	for _, collision := range []bool{false, true} {
		t.Run(map[bool]string{false: "publish", true: "collision"}[collision], func(t *testing.T) {
			result, target := prepareRecoveryArchive(t, nil)
			handoff := result.TakeArchiveHandoff()
			if handoff == nil {
				t.Fatal("archive handoff missing")
			}
			defer handoff.Close()
			if collision {
				if err := os.WriteFile(target, []byte("foreign"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			publication, cleanup := handoff.Publish(context.Background())
			wantState := pcv3publication.StatePublishedDurable
			wantBytes := recoveryArchiveBytes(t)
			if collision {
				wantState = pcv3publication.StateNotPublished
				wantBytes = []byte("foreign")
			}
			if publication == nil || publication.State() != wantState || cleanup {
				t.Fatalf("publication state=%v cleanup=%v", publication, cleanup)
			}
			assertFileBytesAndMode(t, target, wantBytes, 0o600)
			assertNoRecoveryStageResidue(t, filepath.Dir(target))
		})
	}
}

func TestD1ArchiveHandoffRejectsExtractionCollisionAndCancelledUse(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "collision", true: "cancelled"}[cancelled], func(t *testing.T) {
			result, target := prepareRecoveryArchive(t, nil)
			handoff := result.TakeArchiveHandoff()
			if handoff == nil {
				t.Fatal("archive handoff missing")
			}
			defer handoff.Close()
			directory := t.TempDir()
			if !cancelled {
				if err := os.WriteFile(filepath.Join(directory, "payload.txt"), []byte("foreign"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if cancelled {
				cancel()
			}
			extracted := handoff.Extract(ctx, root)
			if extracted == nil || extracted.State() != fileops.UnpackStateNotPublished || extracted.CleanupIncomplete() {
				t.Fatalf("failed extraction state=%v", extracted)
			}
			if cancelled {
				if _, err := os.Lstat(filepath.Join(directory, "payload.txt")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("cancelled extraction left plaintext: %v", err)
				}
			} else {
				assertFileBytesAndMode(t, filepath.Join(directory, "payload.txt"), []byte("foreign"), 0o600)
			}
			assertNoRecoveryStageResidue(t, filepath.Dir(target))
		})
	}
}

func TestD1ArchiveHandoffFinalCoreFailureCleansUnpublishedPlaintext(t *testing.T) {
	result, target := prepareRecoveryArchive(t, func() error { return errors.New("final core failure") })
	if handoff := result.TakeArchiveHandoff(); handoff != nil {
		defer handoff.Close()
		t.Fatal("failed core granted archive authority")
	}
	if result.Outcome() != pcv3.OutcomeOperationFailed {
		t.Fatalf("final core failure reported as success: %v", result.Outcome())
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("final core failure published plaintext: %v", err)
	}
	assertNoRecoveryStageResidue(t, filepath.Dir(target))
}

func TestD1ArchiveHandoffPanicAfterEmissionCleansPrivateStage(t *testing.T) {
	directory := t.TempDir()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("core panic did not propagate")
			}
		}()
		_ = runWithCoreOptions(context.Background(), &Request{
			Target: filepath.Join(directory, "plaintext.zip"), Mode: pcv3.RecoveryModeNormalV3,
		}, recoveryArchiveCore(recoveryArchiveBytes(t), func() error { panic("core failed") }), ExecutionOptions{PrepareArchive: true})
	}()
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("panic retained plaintext: entries=%v err=%v", entries, err)
	}
}

func TestD1ArchivePreparationRefusesForceAndRetainedCustodyBeforeKDF(t *testing.T) {
	for _, test := range []struct {
		name     string
		mode     pcv3.RecoveryMode
		retained bool
	}{
		{name: "force", mode: pcv3.RecoveryModeForce},
		{name: "unverified", mode: pcv3.RecoveryModeForceUnverified},
		{name: "retained output", mode: pcv3.RecoveryModeNormalV3, retained: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			factors := &pcv3credential.FactorRequest{
				Mode:           pcv3credential.CredentialModePasswordOnly,
				KeyfileMode:    pcv3credential.KeyfileModeNone,
				ExpectedPolicy: pcv3credential.FactorPolicyPasswordOnly,
				Password:       []byte("must be consumed before core admission"),
			}
			request := &Request{Mode: test.mode, Factors: factors, Target: filepath.Join(directory, "output")}
			result := RunD1WithOptions(context.Background(), request, ExecutionOptions{
				PrepareArchive: true, RetainDurableOutput: test.retained,
			})
			if result.Outcome() != pcv3.OutcomeOperationFailed || result.Stage() != pcv3.StageCredentialPolicy ||
				result.PublicationAttempted() || result.TakeArchiveHandoff() != nil || request.Factors != nil || len(factors.Password) != 0 {
				t.Fatal("incompatible archive custody did not fail before core entry and consume factors")
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 0 {
				t.Fatalf("rejected archive request created output: %v %v", entries, err)
			}
		})
	}
}

func TestD1ArchivePreparationPublishesAuthenticatedNonZIPAfterCoreSuccess(t *testing.T) {
	malformed := recoveryArchiveBytes(t)
	malformed[len(malformed)-2] = 0xff
	malformed[len(malformed)-1] = 0xff
	for name, data := range map[string][]byte{
		"ordinary plaintext": []byte("ordinary authenticated plaintext\n"),
		"malformed ZIP":      malformed,
	} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, "ordinary.txt")
			result := runWithCoreOptions(context.Background(), &Request{
				Target: target, Mode: pcv3.RecoveryModeNormalV3,
			}, recoveryArchiveCore(data, nil), ExecutionOptions{PrepareArchive: true})
			if result.TakeArchiveHandoff() != nil || result.Outcome() != pcv3.OutcomeSuccess ||
				!result.PublicationAttempted() || result.PublicationState() != pcv3publication.StatePublishedDurable {
				t.Fatalf("non-ZIP auto-unzip did not preserve ordinary publication: %v", result)
			}
			assertFileBytesAndMode(t, target, data, 0o600)
			assertNoRecoveryStageResidue(t, directory)
		})
	}
}

func TestD1ArchivePreparationCancellationAfterEmissionDropsCustody(t *testing.T) {
	directory := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := runWithCoreOptions(ctx, &Request{
		Target: filepath.Join(directory, "archive.zip"), Mode: pcv3.RecoveryModeNormalV3,
	}, recoveryArchiveCore(recoveryArchiveBytes(t), func() error { cancel(); return nil }), ExecutionOptions{PrepareArchive: true})
	if result.TakeArchiveHandoff() != nil || result.Outcome() != pcv3.OutcomeOperationFailed || result.Stage() != pcv3.StageCancellation {
		t.Fatal("cancellation after emission left archive authority")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("cancelled archive request left output: %v %v", entries, err)
	}
}

func TestD1ArchiveHandoffCloseAndNilContextConsumeWithoutOutput(t *testing.T) {
	for _, publish := range []bool{false, true} {
		t.Run(map[bool]string{false: "close", true: "nil publish context"}[publish], func(t *testing.T) {
			result, target := prepareRecoveryArchive(t, nil)
			handoff := result.TakeArchiveHandoff()
			if handoff == nil {
				t.Fatal("archive handoff missing")
			}
			if publish {
				publication, cleanup := handoff.Publish(nil) //nolint:staticcheck // SA1012: exercise fail-closed handling of an invalid context.
				if publication == nil || publication.State() != pcv3publication.StateNotPublished || cleanup {
					t.Fatalf("nil context publication=%v cleanup=%v", publication, cleanup)
				}
			} else if handoff.Close() {
				t.Fatal("unused handoff cleanup incomplete")
			}
			if handoff.Live() || handoff.Close() {
				t.Fatal("consumed handoff remained live")
			}
			entries, err := os.ReadDir(filepath.Dir(target))
			if err != nil || len(entries) != 0 {
				t.Fatalf("unused archive retained plaintext: %v %v", entries, err)
			}
		})
	}
}

func TestD1ArchiveHandoffReportsUnprovenCleanupAndPreservesForeignReplacement(t *testing.T) {
	result, target := prepareRecoveryArchive(t, nil)
	handoff := result.TakeArchiveHandoff()
	if handoff == nil {
		t.Fatal("archive handoff missing")
	}
	stagePath := handoff.state.stage.File().Name()
	movedPath := filepath.Join(filepath.Dir(target), "moved-private-stage")
	if err := os.Rename(stagePath, movedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stagePath, []byte("foreign replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !handoff.Close() || handoff.Live() {
		t.Fatal("uncertain cleanup was hidden or retained usable authority")
	}
	assertFileBytesAndMode(t, stagePath, []byte("foreign replacement"), 0o600)
	assertFileBytesAndMode(t, movedPath, recoveryArchiveBytes(t), 0o600)
}

func TestD1ArchivePreparationNeverGrantsDegradedArchiveAuthority(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "degraded.zip")
	data := recoveryArchiveBytes(t)
	degraded := operationSemantic{
		outcome: pcv3.OutcomeAuthenticatedDegraded, provenance: pcv3.ForceProvenanceNone,
		stage: pcv3.StageD1Bootstrap, code: pcv3.CodeAuthenticatedDegraded,
		d1Provenance: pcv3.D1BootstrapProvenanceTail,
	}
	runner := func(_ context.Context, _ *Request, output operationOutput) (operationSemantic, error) {
		err := output(degraded, operationRoleD1Tail, "", uint64(len(data)), func(sink operationSegmentSink) error {
			return sink(operationRange{recordIndex: 0, start: 0, end: uint64(len(data)), state: pcv3.RecoveryRangeVerified}, data)
		})
		return degraded, err
	}
	result := runWithCoreOptions(context.Background(), &Request{
		Target: target, Mode: pcv3.RecoveryModeNormalV3,
	}, runner, ExecutionOptions{PrepareArchive: true})
	if result.TakeArchiveHandoff() != nil || result.Outcome() != pcv3.OutcomeAuthenticatedDegraded ||
		result.PublicationState() != pcv3publication.StatePublishedDurable {
		t.Fatal("archive option altered degraded evidence or granted archive authority")
	}
	assertFileBytesAndMode(t, target, data, 0o600)
	assertNoRecoveryStageResidue(t, directory)
}
