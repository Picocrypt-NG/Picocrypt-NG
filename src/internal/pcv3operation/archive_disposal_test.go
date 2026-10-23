package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

type archiveDisposalFixture struct {
	active      bool
	closeResult func() *Result
}

func (state *archiveDisposalFixture) live() bool { return state.active }

func (state *archiveDisposalFixture) extract(context.Context, *os.Root, func(ArchiveSummary) error) *Result {
	panic("unexpected extraction")
}

func (state *archiveDisposalFixture) close() *Result {
	state.active = false
	return state.closeResult()
}

func TestArchiveDisposalPreservesCloseCleanupFacts(t *testing.T) {
	for _, both := range []bool{false, true} {
		for _, finalize := range []bool{false, true} {
			t.Run(fmt.Sprintf("both=%v/finalize=%v", both, finalize), func(t *testing.T) {
				closed := archiveNoOutput(DiagnosticNone, both)
				closed.WithCleanupDurabilityWarning()
				state := &archiveDisposalFixture{active: true, closeResult: func() *Result { return closed }}
				result := closedFailure(OutcomeOperationFailed, StageOutputPublication, CodeOperationFailed, DiagnosticCoreFailure)
				result.archiveFollowUp = &ArchiveFollowUp{state: state}
				var failure *Result
				if finalize {
					failure = finalizeOperationResult(context.Background(), result, &operationOwner{}, nil, nil, nil)
				} else {
					failure = (&operationOwner{reporterFailed: true}).finishReportedResult(result)
				}
				if !failure.hasWarning(WarningCleanupDurabilityUncertain) || failure.hasWarning(WarningCleanupIncomplete) != both {
					t.Fatalf("both=%v finalize=%v: archive Close cleanup facts lost: %v", both, finalize, failure.Warnings())
				}
				if state.live() || result.archiveFollowUp != nil || failure.SourceDeletionAllowed() || failure.ArchiveFollowUp() != nil {
					t.Fatal("disposal retained or granted operation authority")
				}
			})
		}
	}
}

func TestArchiveDisposalUnknownCloseRemainsIncompleteAndRedacted(t *testing.T) {
	const canary = "TEST ONLY unknown private close details"
	for _, panicClose := range []bool{false, true} {
		state := &archiveDisposalFixture{active: true, closeResult: func() *Result {
			if panicClose {
				panic(canary)
			}
			return nil
		}}
		result := closedFailure(OutcomeOperationFailed, StageOutputPublication, CodeOperationFailed, DiagnosticCoreFailure)
		result.archiveFollowUp = &ArchiveFollowUp{state: state}
		var failure *Result
		var recovered any
		func() {
			defer func() { recovered = recover() }()
			failure = (&operationOwner{reporterFailed: true}).finishReportedResult(result)
		}()
		if recovered != nil || failure == nil || !errors.Is(failure, pcv3publication.ErrCleanupIncomplete) || failure.SourceDeletionAllowed() {
			t.Fatalf("unknown archive Close did not fail closed: result=%v recovered=%v", failure, recovered)
		}
		if strings.Contains(fmt.Sprint(failure), canary) || result.archiveFollowUp != nil || state.live() {
			t.Fatal("unknown archive Close disclosed details or retained authority")
		}
	}
}
