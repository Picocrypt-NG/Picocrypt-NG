package pcv3recovery

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRecoveryRetainsOnlyOptInDurableOutputCapability(t *testing.T) {
	semantic := operationSemantic{
		outcome: pcv3.OutcomeAuthenticatedDegraded, provenance: pcv3.ForceProvenanceVerified,
		stage: pcv3.StageWrapAuth, code: pcv3.CodeAuthenticatedDegraded, plaintextLength: 5,
		ranges: fixtureRangeMap([]operationRange{{
			recordIndex: 0, start: 0, end: 5, state: pcv3.RecoveryRangeVerified,
		}}),
		final: pcv3.RecoveryFinalVerified,
	}
	runner := fixedCoreRunner(semantic, [][]byte{[]byte("hello")}, nil)

	t.Run("default publication remains terminal", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "recovered.bin")
		result := runWithCore(context.Background(), &Request{Target: target}, runner)
		retained := result.TakeRetainedOutput()
		if result.PublicationState() != pcv3publication.StatePublishedDurable ||
			retained != nil {
			t.Fatalf(
				"default recovery = state %v retained=%v; want durable terminal publication",
				result.PublicationState(), retained,
			)
		}
		assertFileBytesAndMode(t, target, []byte("hello"), 0o600)
	})

	t.Run("explicit retention transfers exact output", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "recovered.bin")
		result := runWithCoreOptions(
			context.Background(),
			&Request{Target: target},
			runner,
			ExecutionOptions{RetainDurableOutput: true},
		)
		retained := result.TakeRetainedOutput()
		if result.PublicationState() != pcv3publication.StatePublishedDurable ||
			retained == nil || !retained.Live() {
			t.Fatalf(
				"opt-in recovery = state %v retained=%v; want durable exact capability",
				result.PublicationState(), retained,
			)
		}
		if result.TakeRetainedOutput() != nil {
			t.Fatal("recovery result transferred retained output more than once")
		}
		assertFileBytesAndMode(t, target, []byte("hello"), 0o600)
		if err := retained.RemoveExact(); err != nil {
			t.Fatalf("remove exact retained recovery output: %v", err)
		}
		if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("retained recovery output still exists: %v", err)
		}
	})

	t.Run("destination collision grants nothing", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "foreign.bin")
		foreign := []byte("foreign output")
		if err := os.WriteFile(target, foreign, 0o640); err != nil {
			t.Fatalf("seed collision: %v", err)
		}
		foreignInfo, err := os.Lstat(target)
		if err != nil {
			t.Fatalf("stat seeded collision: %v", err)
		}
		result := runWithCoreOptions(
			context.Background(),
			&Request{Target: target},
			runner,
			ExecutionOptions{RetainDurableOutput: true},
		)
		retained := result.TakeRetainedOutput()
		if result.PublicationState() != pcv3publication.StateNotPublished ||
			retained != nil {
			t.Fatalf(
				"collision recovery = state %v retained=%v; want not-published/no authority",
				result.PublicationState(), retained,
			)
		}
		assertFileBytesAndMode(t, target, foreign, foreignInfo.Mode())
	})
}

func TestRecoveryCleansRetainedOutputIfCoreLaterWithdrawsOutputSemantic(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "must-not-remain.bin")
	outputSemantic := operationSemantic{
		outcome: pcv3.OutcomeAuthenticatedDegraded, provenance: pcv3.ForceProvenanceVerified,
		stage: pcv3.StageWrapAuth, code: pcv3.CodeAuthenticatedDegraded, plaintextLength: 5,
		ranges: fixtureRangeMap([]operationRange{{
			recordIndex: 0, start: 0, end: 5, state: pcv3.RecoveryRangeVerified,
		}}),
		final: pcv3.RecoveryFinalVerified,
	}
	terminalSemantic := operationSemantic{
		outcome: pcv3.OutcomeOperationFailed,
		stage:   pcv3.StageInputIO,
		code:    pcv3.CodeOperationFailed,
	}
	runner := func(
		_ context.Context,
		_ *Request,
		output operationOutput,
	) (operationSemantic, error) {
		err := output(
			outputSemantic,
			operationRoleCapsulePrimary,
			"",
			5,
			func(sink operationSegmentSink) error {
				return sink(fixtureOperationRange(outputSemantic.ranges, 0), []byte("hello"))
			},
		)
		if err != nil {
			return operationSemantic{}, err
		}
		return terminalSemantic, errors.New("TEST ONLY terminal core failure after output callback")
	}

	result := runWithCoreOptions(
		context.Background(),
		&Request{Target: target},
		runner,
		ExecutionOptions{RetainDurableOutput: true},
	)
	retained := result.TakeRetainedOutput()
	if result.Outcome() != pcv3.OutcomeOperationFailed ||
		result.Stage() != pcv3.StageInputIO ||
		result.PublicationState() != pcv3publication.StateNotPublished ||
		retained != nil || result.cleanupIncomplete {
		t.Fatalf(
			"withdrawn output = %v/%v publication=%v retained=%v cleanup=%v; want no-output core failure",
			result.Outcome(), result.Stage(), result.PublicationState(),
			retained, result.cleanupIncomplete,
		)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("withdrawn output semantic orphaned plaintext: %v", err)
	}
}

func TestRecoveryPanicAfterRetainedPublicationRemovesInternalPlaintext(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "panic-must-not-orphan.bin")
	semantic := operationSemantic{
		outcome: pcv3.OutcomeAuthenticatedDegraded, provenance: pcv3.ForceProvenanceVerified,
		stage: pcv3.StageWrapAuth, code: pcv3.CodeAuthenticatedDegraded, plaintextLength: 5,
		ranges: fixtureRangeMap([]operationRange{{
			recordIndex: 0, start: 0, end: 5, state: pcv3.RecoveryRangeVerified,
		}}),
		final: pcv3.RecoveryFinalVerified,
	}
	runner := func(
		_ context.Context,
		_ *Request,
		output operationOutput,
	) (operationSemantic, error) {
		err := output(
			semantic,
			operationRoleCapsulePrimary,
			"",
			5,
			func(sink operationSegmentSink) error {
				return sink(fixtureOperationRange(semantic.ranges, 0), []byte("hello"))
			},
		)
		if err != nil {
			return semantic, err
		}
		panic("TEST ONLY core panic after retained publication")
	}

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		_ = runWithCoreOptions(
			context.Background(),
			&Request{Target: target},
			runner,
			ExecutionOptions{RetainDurableOutput: true},
		)
	}()
	if recovered == nil {
		t.Fatal("core panic was unexpectedly swallowed")
	}
	if cleanupErr, ok := recovered.(error); ok &&
		errors.Is(cleanupErr, pcv3publication.ErrCleanupIncomplete) {
		t.Fatalf("panic cleanup reported uncertainty after exact removal: %v", cleanupErr)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("core panic orphaned retained plaintext: %v", err)
	}
}
