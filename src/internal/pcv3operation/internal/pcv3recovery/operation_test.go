package pcv3recovery

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3artifact"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3ranges"
	"Picocrypt-NG/internal/pcv3publication"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type archiveHandoffAuthority interface {
	ArchiveHandoffAllowed() bool
}

func runWithCore(
	ctx context.Context,
	request *Request,
	run recoveryCoreRunner,
) *Result {
	return runWithCoreOptions(ctx, request, run, ExecutionOptions{})
}

type secondPassFault uint8

const (
	secondPassMutation secondPassFault = iota + 1
	secondPassInputError
	secondPassCancellation
)

var errSecondPassInput = errors.New("TEST ONLY second-pass input fault")

type failingStageWriter struct {
	cause            error
	calls            int
	firstRequestSize int
}

func (writer *failingStageWriter) Write(data []byte) (int, error) {
	writer.calls++
	if writer.calls == 1 {
		writer.firstRequestSize = len(data)
	}
	return 0, writer.cause
}

type secondPassReaderAt struct {
	source        io.ReaderAt
	fault         secondPassFault
	mutationByte  int64
	matchingReads int
	cancel        context.CancelFunc
}

func (reader *secondPassReaderAt) ReadAt(destination []byte, offset int64) (int, error) {
	containsMutation := offset <= reader.mutationByte &&
		reader.mutationByte < offset+int64(len(destination))
	if containsMutation {
		reader.matchingReads++
		if reader.matchingReads == 2 && reader.fault == secondPassInputError {
			return 0, errSecondPassInput
		}
	}
	read, err := reader.source.ReadAt(destination, offset)
	if !containsMutation || reader.matchingReads != 2 {
		return read, err
	}
	switch reader.fault {
	case secondPassMutation:
		destination[reader.mutationByte-offset] ^= 0xc1
	case secondPassCancellation:
		reader.cancel()
	}
	return read, err
}

type recoveryOperationAdmitter struct{}

func (recoveryOperationAdmitter) AdmitKDF(
	context.Context,
	pcv3credential.KDFProfile,
) (pcv3credential.KDFAdmission, error) {
	return pcv3credential.KDFAdmissionGranted, nil
}

func TestRunPublishesCompleteRecoveredPlaintextWithoutSemanticRelabelling(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "recovered.bin")
	semantic := operationSemantic{
		outcome: pcv3.OutcomeAuthenticatedDegraded, provenance: pcv3.ForceProvenanceVerified,
		stage: pcv3.StageWrapAuth, code: pcv3.CodeAuthenticatedDegraded, plaintextLength: 5,
		ranges: fixtureRangeMap([]operationRange{{recordIndex: 0, start: 0, end: 5, state: pcv3.RecoveryRangeVerified}}),
		final:  pcv3.RecoveryFinalVerified,
	}
	runner := fixedCoreRunner(semantic, [][]byte{[]byte("hello")}, nil)

	result := runWithCore(context.Background(), &Request{Target: target}, runner)
	if result.Outcome() != pcv3.OutcomeAuthenticatedDegraded ||
		result.ForceProvenance() != pcv3.ForceProvenanceVerified ||
		result.Stage() != pcv3.StageWrapAuth {
		t.Fatalf("semantic result = %v/%v/%v; durable publication must not relabel Force-verified recovery", result.Outcome(), result.ForceProvenance(), result.Stage())
	}
	requireNativeRecoveryPublication(t, result)
	assertFileBytesAndMode(t, target, []byte("hello"), 0o600)
	assertNoRecoveryStageResidue(t, directory)
	if authority, ok := any(result).(archiveHandoffAuthority); ok && authority.ArchiveHandoffAllowed() {
		t.Fatal("recovery result granted archive handoff authority")
	}
}

func TestRunNilContextConsumesTransferredFactorsWithoutOutput(t *testing.T) {
	password := []byte("TEST ONLY recovery password")
	request := &Request{
		Factors: &pcv3credential.FactorRequest{
			Mode:           pcv3credential.CredentialModePasswordOnly,
			ExpectedPolicy: pcv3credential.FactorPolicyPasswordOnly,
			Password:       password,
		},
		Target: filepath.Join(t.TempDir(), "must-not-exist"),
	}
	//nolint:staticcheck // A nil production context is the failure/cleanup case under test.
	result := Run(nil, request)
	if result.Outcome() != pcv3.OutcomeOperationFailed || result.PublicationAttempted() {
		t.Fatalf("nil-context result = %v/%v; want operation-failed without publication", result.Outcome(), result.PublicationAttempted())
	}
	if request.Factors != nil {
		t.Fatal("nil-context recovery retained transferred factors")
	}
	for _, value := range password {
		if value != 0 {
			t.Fatal("nil-context recovery did not zero the transferred password")
		}
	}
}

func TestRunRejectsZeroCoreSemantic(t *testing.T) {
	target := filepath.Join(t.TempDir(), "must-not-exist")
	result := runWithCore(
		context.Background(),
		&Request{Target: target},
		fixedCoreRunner(operationSemantic{}, nil, nil),
	)
	if result.Outcome() != pcv3.OutcomeOperationFailed || result.Stage() != pcv3.StageCredentialPolicy ||
		result.PublicationAttempted() {
		t.Fatalf("zero core semantic = %v/%v/%v; want fail-closed operation result", result.Outcome(), result.Stage(), result.PublicationAttempted())
	}
}

func TestRunPublishesOneCanonicalArtifactForPartialEvidence(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "evidence.pcv3-recovery")
	firstSegment := bytes.Repeat([]byte{0xa5}, int(recoveryRecordPlaintextMax))
	finalSegment := []byte("safe!")
	plaintextLength := 2*recoveryRecordPlaintextMax + uint64(len(finalSegment))
	semantic := operationSemantic{
		outcome: pcv3.OutcomeForcePartial, provenance: pcv3.ForceProvenancePartial,
		stage: pcv3.StageRecordAuth, code: pcv3.CodeForcePartial, plaintextLength: plaintextLength,
		ranges: fixtureRangeMap([]operationRange{
			{recordIndex: 0, start: 0, end: recoveryRecordPlaintextMax, state: pcv3.RecoveryRangeVerified},
			{recordIndex: 1, start: recoveryRecordPlaintextMax, end: 2 * recoveryRecordPlaintextMax, state: pcv3.RecoveryRangeMissing},
			{recordIndex: 2, start: 2 * recoveryRecordPlaintextMax, end: plaintextLength, state: pcv3.RecoveryRangeVerified},
		}),
		final: pcv3.RecoveryFinalVerified,
	}
	runner := fixedCoreRunner(semantic, [][]byte{firstSegment, finalSegment}, nil)

	result := runWithCore(context.Background(), &Request{Target: target}, runner)
	if result.Outcome() != pcv3.OutcomeForcePartial ||
		result.ForceProvenance() != pcv3.ForceProvenancePartial ||
		result.Stage() != pcv3.StageRecordAuth || result.Code() != pcv3.CodeForcePartial {
		t.Fatalf("semantic result = %v/%v/%v/%v; want exact Force-partial classification", result.Outcome(), result.ForceProvenance(), result.Stage(), result.Code())
	}
	requireNativeRecoveryPublication(t, result)
	contents, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read published artifact: %v", err)
	}
	artifact, err := pcv3artifact.Parse(context.Background(), bytes.NewReader(contents), int64(len(contents)))
	if err != nil {
		t.Fatalf("parse published artifact: %v", err)
	}
	metadata := artifact.Metadata()
	if metadata.State != pcv3artifact.StatePartial || metadata.Role != pcv3artifact.RoleNone ||
		metadata.Final != pcv3artifact.FinalVerified || metadata.PlaintextLength != plaintextLength ||
		metadata.RangeCount != 3 || metadata.EmittedSegmentCount != 2 ||
		metadata.TableOffset != 80 || metadata.DataOffset != 200 ||
		metadata.TotalLength != uint64(len(contents)) {
		t.Fatalf("artifact metadata = %#v; want exact partial map", metadata)
	}
	var entries []pcv3artifact.Entry
	var segments [][]byte
	if err := artifact.VisitRanges(context.Background(), func(entry pcv3artifact.Entry, segment io.Reader) error {
		entries = append(entries, entry)
		if segment != nil {
			data, readErr := io.ReadAll(segment)
			if readErr != nil {
				return readErr
			}
			segments = append(segments, data)
		}
		return nil
	}); err != nil {
		t.Fatalf("visit artifact ranges: %v", err)
	}
	if len(entries) != 3 || len(segments) != 2 ||
		entries[0].RecordIndex != 0 || entries[0].Start != 0 ||
		entries[0].End != recoveryRecordPlaintextMax || entries[0].Status != pcv3artifact.RangeVerified ||
		entries[0].SegmentOffset != 200 || entries[0].SegmentLength != uint32(len(firstSegment)) ||
		entries[1].RecordIndex != 1 || entries[1].Start != recoveryRecordPlaintextMax ||
		entries[1].End != 2*recoveryRecordPlaintextMax || entries[1].Status != pcv3artifact.RangeMissing ||
		entries[1].SegmentOffset != 0 || entries[1].SegmentLength != 0 ||
		entries[2].RecordIndex != 2 || entries[2].Start != 2*recoveryRecordPlaintextMax ||
		entries[2].End != plaintextLength || entries[2].Status != pcv3artifact.RangeVerified ||
		entries[2].SegmentOffset != 200+recoveryRecordPlaintextMax ||
		entries[2].SegmentLength != uint32(len(finalSegment)) ||
		!bytes.Equal(segments[0], firstSegment) || !bytes.Equal(segments[1], finalSegment) {
		t.Fatalf("artifact entries/segments do not preserve verified/missing/verified evidence: %#v", entries)
	}
	assertFileBytesAndMode(t, target, contents, 0o600)
	assertNoRecoveryStageResidue(t, directory)
}

func TestRunNoOutputStatesNeverCreateDestination(t *testing.T) {
	for _, outcome := range []pcv3.Outcome{
		pcv3.OutcomeCredentialsOrDamage,
		pcv3.OutcomeAmbiguousVolume,
		pcv3.OutcomeOperationFailed,
	} {
		t.Run(outcome.String(), func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, "must-not-exist")
			semantic := operationSemantic{outcome: outcome, stage: pcv3.StageWrapAuth}
			result := runWithCore(context.Background(), &Request{Target: target}, fixedCoreRunner(semantic, nil, nil))
			if result.PublicationAttempted() || result.PublicationState() != 0 {
				t.Fatalf("no-output publication = %v/%v; want not attempted", result.PublicationAttempted(), result.PublicationState())
			}
			if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("no-output target exists or cannot be classified: %v", err)
			}
			assertNoRecoveryStageResidue(t, directory)
		})
	}
}

func TestRunNoReplaceAndProtectedAliasesRetainForeignBytes(t *testing.T) {
	tests := []struct {
		name          string
		protectTarget bool
	}{
		{name: "existing destination"},
		{name: "protected source alias", protectTarget: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, "foreign.bin")
			foreign := []byte("FOREIGN-SOURCE-BYTES")
			foreignMode := seedFileWithMode(t, target, foreign, 0o640)
			request := &Request{Target: target}
			if test.protectTarget {
				request.Protected = []string{target}
			}
			semantic := operationSemantic{
				outcome: pcv3.OutcomeAuthenticatedDegraded, provenance: pcv3.ForceProvenanceVerified,
				stage: pcv3.StageWrapAuth, code: pcv3.CodeAuthenticatedDegraded, plaintextLength: 3,
				ranges: fixtureRangeMap([]operationRange{{recordIndex: 0, start: 0, end: 3, state: pcv3.RecoveryRangeVerified}}),
				final:  pcv3.RecoveryFinalVerified,
			}
			result := runWithCore(context.Background(), request, fixedCoreRunner(semantic, [][]byte{[]byte("new")}, nil))
			if !result.PublicationAttempted() || result.PublicationState() != pcv3publication.StateNotPublished {
				t.Fatalf("protected publication = %v/%v; want attempted/not-published", result.PublicationAttempted(), result.PublicationState())
			}
			assertFileBytesAndMode(t, target, foreign, foreignMode)
			assertNoRecoveryStageResidue(t, directory)
		})
	}
}

func TestRunCreateCleanupWarningPreservesSemanticAndPublicationResult(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source.pcv")
	sourceBytes := []byte("TEST ONLY encrypted source")
	if err := os.WriteFile(source, sourceBytes, 0o600); err != nil {
		t.Fatalf("seed protected recovery source: %v", err)
	}
	target := filepath.Join(directory, "missing-parent", "recovered.bin")
	semantic := operationSemantic{
		outcome: pcv3.OutcomeAuthenticatedDegraded, provenance: pcv3.ForceProvenanceVerified,
		stage: pcv3.StageWrapAuth, code: pcv3.CodeAuthenticatedDegraded, plaintextLength: 3,
		ranges: fixtureRangeMap([]operationRange{{recordIndex: 0, start: 0, end: 3, state: pcv3.RecoveryRangeVerified}}),
		final:  pcv3.RecoveryFinalVerified,
	}
	request := &Request{
		Target: target, Protected: []string{source},
		createStage: func(
			target string,
			protected []string,
			policy pcv3publication.Policy,
		) (*pcv3publication.Stage, error) {
			stage, createErr := pcv3publication.Create(target, protected, policy)
			if createErr == nil {
				if stage != nil {
					_ = stage.Cleanup()
				}
				return nil, errors.New("TEST ONLY expected real publication refusal")
			}
			return nil, errors.Join(createErr, pcv3publication.ErrCleanupIncomplete)
		},
	}

	result := runWithCore(
		context.Background(),
		request,
		fixedCoreRunner(semantic, [][]byte{[]byte("new")}, nil),
	)
	if result.Outcome() != pcv3.OutcomeAuthenticatedDegraded ||
		result.ForceProvenance() != pcv3.ForceProvenanceVerified || result.Stage() != pcv3.StageWrapAuth {
		t.Fatalf("cleanup warning changed semantic result = %v/%v/%v", result.Outcome(), result.ForceProvenance(), result.Stage())
	}
	if !result.PublicationAttempted() || result.PublicationState() != pcv3publication.StateNotPublished ||
		result.PublicationStage() != pcv3.StageOutputPublication ||
		result.PublicationCode() != pcv3publication.CodeStageFailure {
		t.Fatalf("cleanup warning changed publication result = %v/%v/%v/%v", result.PublicationAttempted(), result.PublicationState(), result.PublicationStage(), result.PublicationCode())
	}
	assertFileBytesAndMode(t, source, sourceBytes, 0o600)
	if _, statErr := os.Lstat(filepath.Dir(target)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed recovery create changed missing destination parent: %v", statErr)
	}
	assertNoRecoveryStageResidue(t, directory)
	if strings.Contains(result.Error(), directory) ||
		strings.Contains(result.Error(), "TEST ONLY expected real publication refusal") {
		t.Fatalf("recovery cleanup diagnostic disclosed a path or raw error: %q", result.Error())
	}
	if !errors.Is(result, pcv3publication.ErrCleanupIncomplete) {
		t.Fatalf("recovery result = %v; want observable ErrCleanupIncomplete", result)
	}
}

func TestRunEmitterFailureCleansOnlyOwnedStageAndRetainsSource(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source.pcv")
	target := filepath.Join(directory, "evidence.pcv3-recovery")
	sourceBytes := []byte("TEST ONLY encrypted source")
	if err := os.WriteFile(source, sourceBytes, 0o600); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	semantic := operationSemantic{
		outcome: pcv3.OutcomeForcePartial, provenance: pcv3.ForceProvenancePartial,
		stage: pcv3.StageRecordAuth, code: pcv3.CodeForcePartial, plaintextLength: 4,
		ranges: fixtureRangeMap([]operationRange{{recordIndex: 0, start: 0, end: 4, state: pcv3.RecoveryRangeVerified}}),
		final:  pcv3.RecoveryFinalMissing,
	}
	emitErr := errors.New("TEST ONLY sink fault")
	result := runWithCore(
		context.Background(),
		&Request{Target: target, Protected: []string{source}},
		fixedCoreRunner(semantic, nil, emitErr),
	)
	if !result.PublicationAttempted() || result.PublicationState() != pcv3publication.StateNotPublished {
		t.Fatalf("failed emission publication = %v/%v; want attempted/not-published", result.PublicationAttempted(), result.PublicationState())
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed emission left target: %v", err)
	}
	assertFileBytesAndMode(t, source, sourceBytes, 0o600)
	assertNoRecoveryStageResidue(t, directory)
}

func TestRunDestinationWriteFailureRetainsOutputWriteClassificationAndCleansStage(t *testing.T) {
	fixture, err := os.ReadFile("../pcv3/testdata/normal/volumes/normal-degraded-capsule.pcv")
	if err != nil {
		t.Fatalf("read frozen recovery fixture: %v", err)
	}
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "source.pcv")
	target := filepath.Join(directory, "recovered.bin")
	if err := os.WriteFile(sourcePath, fixture, 0o600); err != nil {
		t.Fatalf("seed frozen recovery source: %v", err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatalf("open frozen recovery source: %v", err)
	}
	t.Cleanup(func() { _ = source.Close() })
	writeFailure := errors.New("TEST ONLY destination write fault")
	factors := &pcv3credential.FactorRequest{
		Mode:           pcv3credential.CredentialModePasswordAndKeyfiles,
		KeyfileMode:    pcv3credential.KeyfileModeOrdered,
		ExpectedPolicy: pcv3credential.FactorPolicyPasswordAndKeyfiles,
		Password:       []byte("mix"),
		Keyfiles: []*pcv3credential.KeyfileReader{
			pcv3credential.OwnKeyfileReader(io.NopCloser(bytes.NewReader([]byte("red")))),
			pcv3credential.OwnKeyfileReader(io.NopCloser(bytes.NewReader([]byte("blue")))),
		},
	}
	request := &Request{
		Source: source, SourceSize: int64(len(fixture)), Factors: factors,
		Admitter: recoveryOperationAdmitter{}, Mode: pcv3.RecoveryModeNormalV3,
		Target: target, Protected: []string{sourcePath},
		stageWriter: func(destination io.Writer) io.Writer {
			stage, ok := destination.(*os.File)
			if !ok {
				t.Fatalf("production stage writer = %T; want real file", destination)
			}
			if err := stage.Close(); err != nil {
				t.Fatalf("close real stage before injected write failure: %v", err)
			}
			return &failingStageWriter{cause: writeFailure}
		},
	}

	result := Run(context.Background(), request)
	if result.Outcome() != pcv3.OutcomeOperationFailed || result.Stage() != pcv3.StageOutputWrite ||
		result.Code() != pcv3.CodeOperationFailed {
		t.Fatalf("destination-write semantic = %v/%v/%v; want operation-failed/output-write/operation-failed", result.Outcome(), result.Stage(), result.Code())
	}
	if !result.PublicationAttempted() || result.PublicationState() != pcv3publication.StateNotPublished ||
		result.PublicationStage() != pcv3.StageOutputWrite ||
		result.PublicationCode() != pcv3publication.CodeStageFailure {
		t.Fatalf("destination-write publication = %v/%v/%v/%v; want attempted/not-published/output-write/stage-failure", result.PublicationAttempted(), result.PublicationState(), result.PublicationStage(), result.PublicationCode())
	}
	if !errors.Is(result, pcv3publication.ErrCleanupIncomplete) {
		t.Fatalf("destination-write cleanup result = %v; want observable ErrCleanupIncomplete", result)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination-write failure left durable target: %v", err)
	}
	assertFileBytesAndMode(t, sourcePath, fixture, 0o600)
	assertNoRecoveryStageResidue(t, directory)
}

func TestRunForceArtifactHeaderWriteFailureRetainsOutputWriteClassificationAndCleansStage(t *testing.T) {
	fixture, err := os.ReadFile("../pcv3/testdata/normal/volumes/normal-negative-record.pcv")
	if err != nil {
		t.Fatalf("read frozen Force fixture: %v", err)
	}
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "source.pcv")
	target := filepath.Join(directory, "evidence.pcv3-recovery")
	if err := os.WriteFile(sourcePath, fixture, 0o600); err != nil {
		t.Fatalf("seed frozen Force source: %v", err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatalf("open frozen Force source: %v", err)
	}
	t.Cleanup(func() { _ = source.Close() })
	writeFailure := errors.New("TEST ONLY artifact header write fault")
	writer := &failingStageWriter{cause: writeFailure}
	factors := &pcv3credential.FactorRequest{
		Mode:           pcv3credential.CredentialModePasswordAndKeyfiles,
		KeyfileMode:    pcv3credential.KeyfileModeOrdered,
		ExpectedPolicy: pcv3credential.FactorPolicyPasswordAndKeyfiles,
		Password:       []byte("mix"),
		Keyfiles: []*pcv3credential.KeyfileReader{
			pcv3credential.OwnKeyfileReader(io.NopCloser(bytes.NewReader([]byte("red")))),
			pcv3credential.OwnKeyfileReader(io.NopCloser(bytes.NewReader([]byte("blue")))),
		},
	}
	request := &Request{
		Source: source, SourceSize: int64(len(fixture)), Factors: factors,
		Admitter: recoveryOperationAdmitter{}, Mode: pcv3.RecoveryModeForce,
		Target: target, Protected: []string{sourcePath},
		stageWriter: func(io.Writer) io.Writer {
			return writer
		},
	}

	result := Run(context.Background(), request)
	if writer.calls != 1 || writer.firstRequestSize != 80 {
		t.Fatalf("Force artifact writes = %d calls, first request %d bytes; want failure on the single 80-byte fixed header write", writer.calls, writer.firstRequestSize)
	}
	if result.Outcome() != pcv3.OutcomeOperationFailed || result.Stage() != pcv3.StageOutputWrite ||
		result.Code() != pcv3.CodeOperationFailed {
		t.Fatalf("artifact-header semantic = %v/%v/%v; want operation-failed/output-write/operation-failed", result.Outcome(), result.Stage(), result.Code())
	}
	if !result.PublicationAttempted() || result.PublicationState() != pcv3publication.StateNotPublished ||
		result.PublicationStage() != pcv3.StageOutputWrite ||
		result.PublicationCode() != pcv3publication.CodeStageFailure {
		t.Fatalf("artifact-header publication = %v/%v/%v/%v; want attempted/not-published/output-write/stage-failure", result.PublicationAttempted(), result.PublicationState(), result.PublicationStage(), result.PublicationCode())
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("artifact-header failure left durable target: %v", err)
	}
	assertFileBytesAndMode(t, sourcePath, fixture, 0o600)
	assertNoRecoveryStageResidue(t, directory)
}

func TestRunSecondPassFailuresRetainCoreClassificationAndPublishNothing(t *testing.T) {
	fixture, err := os.ReadFile("../pcv3/testdata/normal/volumes/normal-degraded-capsule.pcv")
	if err != nil {
		t.Fatalf("read frozen recovery fixture: %v", err)
	}
	tests := []struct {
		name    string
		fault   secondPassFault
		outcome pcv3.Outcome
		stage   pcv3.Stage
		code    pcv3.Code
	}{
		{name: "record authentication drift", fault: secondPassMutation, outcome: pcv3.OutcomeAuthenticationFailed, stage: pcv3.StageRecordAuth, code: pcv3.CodeAuthenticationFailed},
		{name: "non-EOF input failure", fault: secondPassInputError, outcome: pcv3.OutcomeOperationFailed, stage: pcv3.StageInputIO, code: pcv3.CodeOperationFailed},
		{name: "cancellation", fault: secondPassCancellation, outcome: pcv3.OutcomeOperationFailed, stage: pcv3.StageCancellation, code: pcv3.CodeOperationFailed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			sourcePath := filepath.Join(directory, "source.pcv")
			target := filepath.Join(directory, "recovered.bin")
			if err := os.WriteFile(sourcePath, fixture, 0o600); err != nil {
				t.Fatalf("seed frozen recovery source: %v", err)
			}
			source, err := os.Open(sourcePath)
			if err != nil {
				t.Fatalf("open frozen recovery source: %v", err)
			}
			t.Cleanup(func() { _ = source.Close() })
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			reader := &secondPassReaderAt{
				source: source, fault: test.fault, mutationByte: 1160, cancel: cancel,
			}
			factors := &pcv3credential.FactorRequest{
				Mode:           pcv3credential.CredentialModePasswordAndKeyfiles,
				KeyfileMode:    pcv3credential.KeyfileModeOrdered,
				ExpectedPolicy: pcv3credential.FactorPolicyPasswordAndKeyfiles,
				Password:       []byte("mix"),
				Keyfiles: []*pcv3credential.KeyfileReader{
					pcv3credential.OwnKeyfileReader(io.NopCloser(bytes.NewReader([]byte("red")))),
					pcv3credential.OwnKeyfileReader(io.NopCloser(bytes.NewReader([]byte("blue")))),
				},
			}

			result := Run(ctx, &Request{
				Source: reader, SourceSize: int64(len(fixture)), Factors: factors,
				Admitter: recoveryOperationAdmitter{}, Mode: pcv3.RecoveryModeNormalV3,
				Target: target, Protected: []string{sourcePath},
			})
			if result.Outcome() != test.outcome || result.Stage() != test.stage || result.Code() != test.code {
				t.Fatalf("second-pass result = %v/%v/%v; want %v/%v/%v", result.Outcome(), result.Stage(), result.Code(), test.outcome, test.stage, test.code)
			}
			if reader.matchingReads != 2 {
				t.Fatalf("record-body reads = %d; want one analysis and one output pass", reader.matchingReads)
			}
			if !result.PublicationAttempted() || result.PublicationState() != pcv3publication.StateNotPublished {
				t.Fatalf("second-pass publication = %v/%v; want attempted/not-published", result.PublicationAttempted(), result.PublicationState())
			}
			if result.PublicationStage() != test.stage {
				t.Fatalf("second-pass publication stage = %v; want exact non-output stage %v", result.PublicationStage(), test.stage)
			}
			if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("second-pass failure left durable destination: %v", err)
			}
			assertFileBytesAndMode(t, sourcePath, fixture, 0o600)
			assertNoRecoveryStageResidue(t, directory)
		})
	}
}

func TestD1ForceArtifactFilesystemContract(t *testing.T) {
	rawOuter := []byte("PCVOUT3\x00TEST ONLY raw inner volume")
	semantic := operationSemantic{
		outcome: pcv3.OutcomeForceUnverified, provenance: pcv3.ForceProvenanceUnverified,
		stage: pcv3.StageD1Body, code: pcv3.CodeForceUnverified,
		d1Provenance:    pcv3.D1BootstrapProvenanceTail,
		plaintextLength: uint64(len(rawOuter)),
		ranges: fixtureRangeMap([]operationRange{{
			recordIndex: 0, start: 0, end: uint64(len(rawOuter)), state: pcv3.RecoveryRangeUnverified,
		}}),
		final: pcv3.RecoveryFinalUnverified,
	}

	t.Run("native exact-owner artifact", func(t *testing.T) {
		directory := t.TempDir()
		source := filepath.Join(directory, "source.d1")
		target := filepath.Join(directory, "evidence.pcv3-recovery")
		sourceBytes := []byte("TEST ONLY encrypted D1 source")
		if err := os.WriteFile(source, sourceBytes, 0o600); err != nil {
			t.Fatalf("seed D1 source: %v", err)
		}

		var observedStage string
		runner := func(
			_ context.Context,
			_ *Request,
			output operationOutput,
		) (operationSemantic, error) {
			err := output(semantic, operationRoleD1Tail, "", semantic.plaintextLength, func(sink operationSegmentSink) error {
				entries, readErr := os.ReadDir(directory)
				if readErr != nil {
					return readErr
				}
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), ".picocrypt-pcv3-") {
						if observedStage != "" {
							return errors.New("TEST ONLY multiple recovery stages")
						}
						observedStage = filepath.Join(directory, entry.Name())
					}
				}
				if observedStage == "" {
					return errors.New("TEST ONLY missing recovery stage")
				}
				info, statErr := os.Stat(observedStage)
				if statErr != nil {
					return statErr
				}
				if !recoveryFileModeMatches(info, 0o600) {
					return fmt.Errorf("TEST ONLY stage mode = %v", info.Mode())
				}
				if _, statErr := os.Lstat(target); statErr == nil {
					return errors.New("TEST ONLY destination existed before publish")
				} else if !errors.Is(statErr, os.ErrNotExist) {
					return fmt.Errorf("TEST ONLY inspect destination before publish: %w", statErr)
				}
				return sink(fixtureOperationRange(semantic.ranges, 0), rawOuter)
			})
			return semantic, err
		}

		result := runWithCore(
			context.Background(),
			&Request{Target: target, Protected: []string{source}},
			runner,
		)
		if result.Outcome() != pcv3.OutcomeForceUnverified ||
			result.D1BootstrapProvenance() != pcv3.D1BootstrapProvenanceTail ||
			result.PublicationState() != nativeRecoveryPublicationState() {
			t.Fatalf("D1 operation = %v/%v/%v; want Force-unverified/tail/durable", result.Outcome(), result.D1BootstrapProvenance(), result.PublicationState())
		}
		if observedStage == "" || observedStage == target {
			t.Fatalf("observed stage = %q; want distinct private sibling", observedStage)
		}
		contents, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("read D1 recovery artifact: %v", err)
		}
		artifact, err := pcv3artifact.Parse(context.Background(), bytes.NewReader(contents), int64(len(contents)))
		if err != nil {
			t.Fatalf("parse D1 recovery artifact: %v", err)
		}
		metadata := artifact.Metadata()
		if metadata.State != pcv3artifact.StateUnverifiedForensic ||
			metadata.Role != pcv3artifact.RoleD1Tail || metadata.Final != pcv3artifact.FinalUnverified {
			t.Fatalf("D1 artifact metadata = %#v; want exact unverified tail evidence", metadata)
		}
		visits := 0
		if err := artifact.VisitRanges(context.Background(), func(entry pcv3artifact.Entry, reader io.Reader) error {
			visits++
			got, readErr := io.ReadAll(reader)
			if readErr != nil {
				return readErr
			}
			if entry.Status != pcv3artifact.RangeUnverified || !bytes.Equal(got, rawOuter) {
				return errors.New("D1 artifact changed raw outer evidence")
			}
			return nil
		}); err != nil {
			t.Fatalf("visit D1 recovery artifact: %v", err)
		}
		if visits != 1 {
			t.Fatalf("D1 artifact visits = %d; want 1", visits)
		}
		assertFileBytesAndMode(t, source, sourceBytes, 0o600)
		assertFileBytesAndMode(t, target, contents, 0o600)
		assertNoRecoveryStageResidue(t, directory)
	})

	t.Run("collision preserves foreign destination", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "foreign.bin")
		foreign := []byte("FOREIGN DESTINATION")
		foreignMode := seedFileWithMode(t, target, foreign, 0o640)
		result := runWithCore(
			context.Background(),
			&Request{Target: target},
			fixedRoleCoreRunner(semantic, operationRoleD1Tail, [][]byte{rawOuter}, nil),
		)
		if result.Outcome() != pcv3.OutcomeForceUnverified ||
			result.PublicationState() != pcv3publication.StateNotPublished {
			t.Fatalf("collision result = %v/%v; want retained Force-unverified/not-published", result.Outcome(), result.PublicationState())
		}
		assertFileBytesAndMode(t, target, foreign, foreignMode)
		assertNoRecoveryStageResidue(t, directory)
	})

	t.Run("cancellation and emitter failure leave no artifact", func(t *testing.T) {
		tests := []struct {
			name    string
			context func() context.Context
			emitErr error
		}{
			{
				name: "cancelled publication",
				context: func() context.Context {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					return ctx
				},
			},
			{name: "emitter failure", context: context.Background, emitErr: errors.New("TEST ONLY D1 emitter failure")},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				directory := t.TempDir()
				target := filepath.Join(directory, "must-not-exist")
				result := runWithCore(
					test.context(),
					&Request{Target: target},
					fixedRoleCoreRunner(semantic, operationRoleD1Tail, [][]byte{rawOuter}, test.emitErr),
				)
				if result.PublicationState() != pcv3publication.StateNotPublished {
					t.Fatalf("failed D1 publication state = %v; want not-published", result.PublicationState())
				}
				if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("failed D1 operation left destination: %v", err)
				}
				assertNoRecoveryStageResidue(t, directory)
			})
		}
	})

	t.Run("invalid D1 ownership cannot create an artifact", func(t *testing.T) {
		tests := []struct {
			name     string
			semantic operationSemantic
			role     operationPhysicalRole
		}{
			{
				name:     "tail semantic as front artifact",
				semantic: semantic,
				role:     operationRoleD1Front,
			},
			{
				name: "unverified matching provenance",
				semantic: func() operationSemantic {
					invalid := semantic
					invalid.d1Provenance = pcv3.D1BootstrapProvenanceMatching
					return invalid
				}(),
				role: operationRoleD1Tail,
			},
			{
				name: "tail-only success without bootstrap degradation",
				semantic: operationSemantic{
					outcome: pcv3.OutcomeSuccess, provenance: pcv3.ForceProvenanceNone,
					stage: pcv3.StageNone, code: pcv3.CodeSuccess,
					d1Provenance: pcv3.D1BootstrapProvenanceTail,
				},
				role: operationRoleD1Tail,
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				directory := t.TempDir()
				source := filepath.Join(directory, "source.d1")
				target := filepath.Join(directory, "must-not-exist")
				sourceBytes := []byte("TEST ONLY protected encrypted D1 source")
				if err := os.WriteFile(source, sourceBytes, 0o600); err != nil {
					t.Fatalf("seed protected D1 source: %v", err)
				}
				result := runWithCore(
					context.Background(),
					&Request{Target: target, Protected: []string{source}},
					fixedRoleCoreRunner(test.semantic, test.role, [][]byte{rawOuter}, nil),
				)
				if result.Outcome() != pcv3.OutcomeOperationFailed ||
					result.Stage() != pcv3.StageCredentialPolicy ||
					result.Code() != pcv3.CodeOperationFailed || result.PublicationAttempted() {
					t.Fatalf(
						"invalid D1 ownership = %v/%v/%v publication %v; want fail-closed operation failure",
						result.Outcome(), result.Stage(), result.Code(), result.PublicationAttempted(),
					)
				}
				if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("invalid D1 ownership created destination: %v", err)
				}
				assertFileBytesAndMode(t, source, sourceBytes, 0o600)
				assertNoRecoveryStageResidue(t, directory)
			})
		}
	})
}

func TestD1PublicationCannotLaunderOutcome(t *testing.T) {
	const plaintextLength = recoveryRecordPlaintextMax + 5
	semantic := operationSemantic{
		outcome: pcv3.OutcomeForcePartial, provenance: pcv3.ForceProvenancePartial,
		stage: pcv3.StageInnerVolume, code: pcv3.CodeForcePartial,
		d1Provenance: pcv3.D1BootstrapProvenanceTail,
		detailStage:  pcv3.StageRecordAuth, plaintextLength: plaintextLength,
		ranges: fixtureRangeMap([]operationRange{
			{recordIndex: 0, start: 0, end: recoveryRecordPlaintextMax, state: pcv3.RecoveryRangeMissing},
			{recordIndex: 1, start: recoveryRecordPlaintextMax, end: plaintextLength, state: pcv3.RecoveryRangeVerified},
		}),
		final: pcv3.RecoveryFinalMissing,
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "foreign.bin")
	foreign := []byte("FOREIGN DESTINATION")
	foreignMode := seedFileWithMode(t, target, foreign, 0o640)

	result := runWithCore(
		context.Background(),
		&Request{Target: target},
		fixedRoleCoreRunner(semantic, operationRoleD1Tail, [][]byte{[]byte("safe!")}, nil),
	)
	if result.Outcome() != pcv3.OutcomeForcePartial ||
		result.ForceProvenance() != pcv3.ForceProvenancePartial ||
		result.Stage() != pcv3.StageInnerVolume || result.DetailStage() != pcv3.StageRecordAuth ||
		result.D1BootstrapProvenance() != pcv3.D1BootstrapProvenanceTail {
		t.Fatalf(
			"D1 semantic after publication failure = %v/%v/%v detail %v provenance %v; want unchanged nested Force-partial",
			result.Outcome(), result.ForceProvenance(), result.Stage(), result.DetailStage(), result.D1BootstrapProvenance(),
		)
	}
	if !result.PublicationAttempted() || result.PublicationState() != pcv3publication.StateNotPublished {
		t.Fatalf("D1 publication = %v/%v; want attempted/not-published", result.PublicationAttempted(), result.PublicationState())
	}
	assertFileBytesAndMode(t, target, foreign, foreignMode)
	assertNoRecoveryStageResidue(t, directory)
}

func TestArtifactInspectionRequiresDurabilityAndPagesWithoutReopeningArtifact(t *testing.T) {
	const rangeCount = uint64(260)
	plaintextLength := rangeCount * recoveryRecordPlaintextMax
	ranges := make([]operationRange, rangeCount)
	for recordIndex := range rangeCount {
		state := pcv3.RecoveryRangeMissing
		if recordIndex == 0 {
			state = pcv3.RecoveryRangeVerified
		}
		ranges[recordIndex] = operationRange{
			recordIndex: recordIndex,
			start:       recordIndex * recoveryRecordPlaintextMax,
			end:         (recordIndex + 1) * recoveryRecordPlaintextMax,
			state:       state,
		}
	}
	semantic := operationSemantic{
		outcome: pcv3.OutcomeForcePartial, provenance: pcv3.ForceProvenancePartial,
		stage: pcv3.StageRecordAuth, code: pcv3.CodeForcePartial,
		plaintextLength: plaintextLength,
		ranges:          fixtureRangeMap(ranges),
		final:           pcv3.RecoveryFinalMissing,
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "large-evidence.pcv3-recovery")
	result := runWithCore(
		context.Background(),
		&Request{Target: target},
		fixedCoreRunner(
			semantic,
			[][]byte{bytes.Repeat([]byte{0xa5}, int(recoveryRecordPlaintextMax))},
			nil,
		),
	)
	requireNativeRecoveryPublication(t, result)
	inspection := result.ArtifactInspection()
	if runtime.GOOS == "windows" {
		if inspection != nil {
			t.Fatal("uncertain Force publication granted durable inspection authority")
		}
		contents, err := os.ReadFile(target)
		if err != nil {
			t.Fatal(err)
		}
		artifact, err := pcv3artifact.Parse(context.Background(), bytes.NewReader(contents), int64(len(contents)))
		if err != nil {
			t.Fatal(err)
		}
		metadata := artifact.Metadata()
		if metadata.State != pcv3artifact.StatePartial || metadata.Role != pcv3artifact.RoleNone || metadata.Final != pcv3artifact.FinalMissing || metadata.PlaintextLength != plaintextLength || metadata.RangeCount != rangeCount || metadata.EmittedSegmentCount != 1 {
			t.Fatalf("uncertain artifact metadata changed: %+v", metadata)
		}
		visits := 0
		if err := artifact.VisitRanges(context.Background(), func(entry pcv3artifact.Entry, reader io.Reader) error {
			want := ranges[visits]
			wantStatus := pcv3artifact.RangeMissing
			if visits == 0 {
				wantStatus = pcv3artifact.RangeVerified
			}
			if entry.Status != wantStatus || entry.RecordIndex != want.recordIndex || entry.Start != want.start || entry.End != want.end || (reader != nil) != (visits == 0) {
				t.Fatalf("uncertain artifact range %d changed: %+v", visits, entry)
			}
			if reader != nil {
				data, err := io.ReadAll(reader)
				if err != nil || !bytes.Equal(data, bytes.Repeat([]byte{0xa5}, int(recoveryRecordPlaintextMax))) {
					t.Fatalf("uncertain artifact payload changed: %v", err)
				}
			}
			visits++
			return nil
		}); err != nil || visits != int(rangeCount) {
			t.Fatalf("uncertain artifact ranges=%d err=%v", visits, err)
		}
		assertNoRecoveryStageResidue(t, directory)
		return
	}
	if inspection == nil {
		t.Fatal("durable Force-partial result did not expose artifact inspection")
	}
	metadata := inspection.Metadata()
	if metadata.Kind != pcv3artifact.StatePartial || metadata.Role != pcv3artifact.RoleNone ||
		metadata.PlaintextLength != plaintextLength || metadata.Final != pcv3artifact.FinalMissing ||
		metadata.RangeCount != 260 || metadata.VerifiedRangeCount != 1 ||
		metadata.UnverifiedRangeCount != 0 || metadata.MissingRangeCount != 259 {
		t.Fatalf("inspection metadata = %#v; want exact frozen Force-partial summary", metadata)
	}

	if err := os.Remove(target); err != nil {
		t.Fatalf("remove published test artifact before path-free inspection: %v", err)
	}
	first, ok := inspection.Page(0, 128)
	if !ok || len(first) != 128 || first[0] != (pcv3artifact.Range{
		RecordIndex: 0,
		Start:       0,
		End:         recoveryRecordPlaintextMax,
		Status:      pcv3artifact.RangeVerified,
	}) || first[127] != (pcv3artifact.Range{
		RecordIndex: 127,
		Start:       127 * recoveryRecordPlaintextMax,
		End:         128 * recoveryRecordPlaintextMax,
		Status:      pcv3artifact.RangeMissing,
	}) {
		t.Fatalf("first page = ok %v length %d endpoints %#v/%#v; want exact records 0..127", ok, len(first), first[0], first[len(first)-1])
	}
	middle, ok := inspection.Page(128, 128)
	if !ok || len(middle) != 128 || middle[0].RecordIndex != 128 ||
		middle[127].RecordIndex != 255 || middle[0].Status != pcv3artifact.RangeMissing ||
		middle[127].Status != pcv3artifact.RangeMissing {
		t.Fatalf("middle page = ok %v length %d endpoints %#v/%#v; want exact records 128..255", ok, len(middle), middle[0], middle[len(middle)-1])
	}
	final, ok := inspection.Page(256, 128)
	if !ok || len(final) != 4 || final[0].RecordIndex != 256 ||
		final[3] != (pcv3artifact.Range{
			RecordIndex: 259,
			Start:       259 * recoveryRecordPlaintextMax,
			End:         plaintextLength,
			Status:      pcv3artifact.RangeMissing,
		}) {
		t.Fatalf("final page = ok %v length %d endpoints %#v/%#v; want exact records 256..259", ok, len(final), final[0], final[len(final)-1])
	}

	first[0] = pcv3artifact.Range{RecordIndex: math.MaxUint64, Status: pcv3artifact.RangeUnverified}
	metadata.Kind = pcv3artifact.StateUnverifiedForensic
	again, ok := inspection.Page(0, 1)
	if !ok || len(again) != 1 || again[0].RecordIndex != 0 ||
		again[0].Status != pcv3artifact.RangeVerified ||
		inspection.Metadata().Kind != pcv3artifact.StatePartial {
		t.Fatalf("caller mutation changed sealed inspection: page=%#v metadata=%#v", again, inspection.Metadata())
	}

	invalidPages := []struct {
		name   string
		offset uint64
		limit  uint64
	}{
		{name: "zero limit", offset: 0, limit: 0},
		{name: "over maximum limit", offset: 0, limit: 129},
		{name: "offset at range count", offset: 260, limit: 1},
		{name: "overflowing end", offset: math.MaxUint64, limit: 2},
	}
	for _, test := range invalidPages {
		t.Run(test.name, func(t *testing.T) {
			page, ok := inspection.Page(test.offset, test.limit)
			if ok || page != nil {
				t.Fatalf("invalid page (%d, %d) = %#v/%v; want nil/false", test.offset, test.limit, page, ok)
			}
		})
	}
	var nilInspection *ArtifactInspection
	if page, ok := nilInspection.Page(0, 1); ok || page != nil {
		t.Fatalf("nil inspection page = %#v/%v; want nil/false", page, ok)
	}
	assertNoRecoveryStageResidue(t, directory)
}

func TestArtifactInspectionRequiresDurableForceResultTuple(t *testing.T) {
	forceSemantic := operationSemantic{
		outcome: pcv3.OutcomeForceUnverified, provenance: pcv3.ForceProvenanceUnverified,
		stage: pcv3.StageRecordAuth, code: pcv3.CodeForceUnverified, plaintextLength: 5,
		ranges: fixtureRangeMap([]operationRange{{
			recordIndex: 0, start: 0, end: 5, state: pcv3.RecoveryRangeUnverified,
		}}),
		final: pcv3.RecoveryFinalUnverified,
	}
	durableDirectory := t.TempDir()
	durable := runWithCore(
		context.Background(),
		&Request{Target: filepath.Join(durableDirectory, "unverified.pcv3-recovery")},
		fixedRoleCoreRunner(
			forceSemantic,
			operationRoleCapsuleBackup,
			[][]byte{[]byte("raw!!")},
			nil,
		),
	)
	requireNativeRecoveryPublication(t, durable)
	contents, err := os.ReadFile(filepath.Join(durableDirectory, "unverified.pcv3-recovery"))
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := pcv3artifact.Parse(context.Background(), bytes.NewReader(contents), int64(len(contents)))
	if err != nil {
		t.Fatal(err)
	}
	artifactMetadata := artifact.Metadata()
	if artifactMetadata.State != pcv3artifact.StateUnverifiedForensic || artifactMetadata.Role != pcv3artifact.RoleBackup || artifactMetadata.Final != pcv3artifact.FinalUnverified || artifactMetadata.PlaintextLength != 5 || artifactMetadata.RangeCount != 1 {
		t.Fatalf("native unverified artifact changed: %+v", artifactMetadata)
	}
	visits := 0
	if err := artifact.VisitRanges(context.Background(), func(entry pcv3artifact.Entry, reader io.Reader) error {
		visits++
		if entry.RecordIndex != 0 || entry.Start != 0 || entry.End != 5 || entry.Status != pcv3artifact.RangeUnverified || reader == nil {
			t.Fatalf("native unverified range changed: %+v", entry)
		}
		data, err := io.ReadAll(reader)
		if err != nil || string(data) != "raw!!" {
			t.Fatalf("native unverified payload changed: %q %v", data, err)
		}
		return nil
	}); err != nil || visits != 1 {
		t.Fatalf("native unverified ranges=%d err=%v", visits, err)
	}
	assertNoRecoveryStageResidue(t, durableDirectory)
	inspection := durable.ArtifactInspection()
	if (inspection != nil) != (runtime.GOOS != "windows") {
		t.Fatal("Force-unverified inspection differs from proven native durability")
	}
	if inspection != nil {
		metadata := inspection.Metadata()
		if metadata.Kind != pcv3artifact.StateUnverifiedForensic || metadata.Role != pcv3artifact.RoleBackup ||
			metadata.PlaintextLength != 5 || metadata.Final != pcv3artifact.FinalUnverified ||
			metadata.RangeCount != 1 || metadata.VerifiedRangeCount != 0 ||
			metadata.UnverifiedRangeCount != 1 || metadata.MissingRangeCount != 0 {
			t.Fatalf("unverified inspection metadata = %#v; want exact backup-role summary", metadata)
		}

		for _, state := range []pcv3publication.State{
			pcv3publication.StatePublishedDurabilityUncertain,
			pcv3publication.StatePublicationIndeterminate,
		} {
			changed := *durable
			changed.publicationState = state
			if changed.ArtifactInspection() != nil {
				t.Fatalf("publication state %v retained inspection; want fail-closed nil", state)
			}
		}
	}

	collisionDirectory := t.TempDir()
	collisionTarget := filepath.Join(collisionDirectory, "foreign.bin")
	if err := os.WriteFile(collisionTarget, []byte("FOREIGN"), 0o600); err != nil {
		t.Fatalf("seed colliding destination: %v", err)
	}
	nonDurable := runWithCore(
		context.Background(),
		&Request{Target: collisionTarget},
		fixedRoleCoreRunner(
			forceSemantic,
			operationRoleCapsuleBackup,
			[][]byte{[]byte("raw!!")},
			nil,
		),
	)
	if nonDurable.PublicationState() != pcv3publication.StateNotPublished ||
		nonDurable.ArtifactInspection() != nil {
		t.Fatalf("non-durable Force result = %v inspection %#v; want not-published/nil", nonDurable.PublicationState(), nonDurable.ArtifactInspection())
	}

	nonForceSemantic := operationSemantic{
		outcome: pcv3.OutcomeAuthenticatedDegraded, provenance: pcv3.ForceProvenanceVerified,
		stage: pcv3.StageWrapAuth, code: pcv3.CodeAuthenticatedDegraded, plaintextLength: 5,
		ranges: fixtureRangeMap([]operationRange{{
			recordIndex: 0, start: 0, end: 5, state: pcv3.RecoveryRangeVerified,
		}}),
		final: pcv3.RecoveryFinalVerified,
	}
	nonForceDirectory := t.TempDir()
	nonForce := runWithCore(
		context.Background(),
		&Request{Target: filepath.Join(nonForceDirectory, "recovered.bin")},
		fixedCoreRunner(nonForceSemantic, [][]byte{[]byte("clear")}, nil),
	)
	requireNativeRecoveryPublication(t, nonForce)
	if nonForce.PublicationState() != nativeRecoveryPublicationState() ||
		nonForce.ArtifactInspection() != nil {
		t.Fatalf("durable non-Force result = %v inspection %#v; want durable/nil", nonForce.PublicationState(), nonForce.ArtifactInspection())
	}
}

func fixedCoreRunner(
	semantic operationSemantic,
	segments [][]byte,
	emitErr error,
) recoveryCoreRunner {
	return fixedRoleCoreRunner(semantic, operationRoleCapsulePrimary, segments, emitErr)
}

func fixedRoleCoreRunner(
	semantic operationSemantic,
	role operationPhysicalRole,
	segments [][]byte,
	emitErr error,
) recoveryCoreRunner {
	return func(
		_ context.Context,
		_ *Request,
		output operationOutput,
	) (operationSemantic, error) {
		if !semantic.outputCapable() {
			return semantic, nil
		}
		err := output(semantic, role, "", semantic.plaintextLength, func(sink operationSegmentSink) error {
			if emitErr != nil {
				return emitErr
			}
			segmentIndex := 0
			for mapRange := range semantic.ranges.All() {
				recoveryRange := operationRange{recordIndex: mapRange.Index, start: mapRange.Start, end: mapRange.End, state: pcv3.RecoveryRangeState(mapRange.State)}
				if recoveryRange.state == pcv3.RecoveryRangeMissing {
					continue
				}
				if segmentIndex >= len(segments) {
					return errors.New("TEST ONLY missing segment")
				}
				if err := sink(recoveryRange, segments[segmentIndex]); err != nil {
					return err
				}
				segmentIndex++
			}
			if segmentIndex != len(segments) {
				return errors.New("TEST ONLY extra segment")
			}
			return nil
		})
		return semantic, err
	}
}

func assertFileBytesAndMode(t *testing.T, path string, want []byte, wantMode os.FileMode) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Base(path), err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s bytes = %q; want %q", filepath.Base(path), got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", filepath.Base(path), err)
	}
	if !recoveryFileModeMatches(info, wantMode) {
		t.Fatalf("%s mode = %04o; want %04o", filepath.Base(path), info.Mode().Perm(), wantMode)
	}
}

func seedFileWithMode(t *testing.T, path string, contents []byte, mode os.FileMode) os.FileMode {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("seed %s: %v", filepath.Base(path), err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("set %s mode: %v", filepath.Base(path), err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", filepath.Base(path), err)
	}
	return info.Mode().Perm()
}

func assertNoRecoveryStageResidue(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read destination directory: %v", err)
	}
	for _, entry := range entries {
		if len(entry.Name()) >= len(".picocrypt-pcv3-") &&
			entry.Name()[:len(".picocrypt-pcv3-")] == ".picocrypt-pcv3-" {
			t.Fatalf("owned recovery stage residue remains: %s", entry.Name())
		}
	}
}

func fixtureRangeMap(ranges []operationRange) *pcv3ranges.Map {
	length := uint64(0)
	if len(ranges) > 0 {
		length = ranges[len(ranges)-1].end
	}
	builder, err := pcv3ranges.NewBuilder(length, nil)
	if err != nil {
		panic(err)
	}
	defer builder.Close()
	for _, r := range ranges {
		if err := builder.Append(pcv3ranges.State(r.state)); err != nil {
			panic(err)
		}
	}
	result, err := builder.Seal()
	if err != nil {
		panic(err)
	}
	return result
}

func fixtureOperationRange(m *pcv3ranges.Map, index uint64) operationRange {
	r, ok := m.At(index)
	if !ok {
		panic("fixture range absent")
	}
	return operationRange{recordIndex: r.Index, start: r.Start, end: r.End, state: pcv3.RecoveryRangeState(r.State)}
}
