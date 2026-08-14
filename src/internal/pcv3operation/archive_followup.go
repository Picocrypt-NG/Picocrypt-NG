package pcv3operation

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3publication"
	"os"
	"sync"
)

type nativeArchiveFollowUpState struct {
	mu      sync.Mutex
	active  bool
	handoff *pcv3.NativeArchiveHandoff
}

func newArchiveFollowUp(handoff *pcv3.NativeArchiveHandoff) *ArchiveFollowUp {
	if handoff == nil || !handoff.Live() {
		return nil
	}
	return &ArchiveFollowUp{state: &nativeArchiveFollowUpState{
		active: true, handoff: handoff,
	}}
}

func (state *nativeArchiveFollowUpState) live() bool {
	if state == nil {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.active && state.handoff != nil && state.handoff.Live()
}

func (state *nativeArchiveFollowUpState) extract(root *os.Root) *Result {
	handoff := state.consume()
	if handoff == nil {
		return archiveNoOutput(DiagnosticInvalidRequest, closeExtractionRoot(root))
	}
	return resultFromArchiveExtraction(handoff.Extract(root))
}

func (state *nativeArchiveFollowUpState) close() *Result {
	handoff := state.consume()
	if handoff == nil {
		return archiveNoOutput(DiagnosticInvalidRequest, false)
	}
	return archiveNoOutput(DiagnosticNone, handoff.Close())
}

func (state *nativeArchiveFollowUpState) consume() *pcv3.NativeArchiveHandoff {
	if state == nil {
		return nil
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.active || state.handoff == nil {
		return nil
	}
	state.active = false
	handoff := state.handoff
	state.handoff = nil
	return handoff
}

// Extract consumes the follow-up before effects and takes ownership of the
// caller-opened, pre-existing extraction root.
func (followUp *ArchiveFollowUp) Extract(root *os.Root) *Result {
	if followUp == nil || followUp.state == nil {
		return archiveNoOutput(DiagnosticInvalidRequest, closeExtractionRoot(root))
	}
	return followUp.state.extract(root)
}

// Close consumes the follow-up without publishing or extracting plaintext.
func (followUp *ArchiveFollowUp) Close() *Result {
	if followUp == nil || followUp.state == nil {
		return archiveNoOutput(DiagnosticInvalidRequest, false)
	}
	return followUp.state.close()
}

type archiveExtractionResult interface {
	State() fileops.UnpackState
	CleanupIncomplete() bool
}

func resultFromArchiveExtraction(extraction archiveExtractionResult) *Result {
	if extraction == nil {
		return archiveNoOutput(DiagnosticInvalidRequest, false)
	}
	data := resultData{
		outcome:              pcv3.OutcomeSuccess,
		stage:                pcv3.StageNone,
		code:                 pcv3.CodeSuccess,
		publicationAttempted: true,
	}
	switch extraction.State() {
	case fileops.UnpackStateNotPublished:
		data.outcome = pcv3.OutcomeOperationFailed
		data.stage = pcv3.StageOutputPublication
		data.code = pcv3.CodeOperationFailed
		data.publicationState = pcv3publication.StateNotPublished
		data.publicationStage = pcv3.StageOutputPublication
		data.publicationCode = pcv3publication.CodeAtomicFailed
	case fileops.UnpackStatePublishedDurable:
		data.publicationState = pcv3publication.StatePublishedDurable
		data.publicationCode = pcv3publication.CodePublishedDurable
	case fileops.UnpackStatePublishedDurabilityUncertain:
		data.publicationState = pcv3publication.StatePublishedDurabilityUncertain
		data.publicationStage = pcv3.StageDirectorySync
		data.publicationCode = pcv3publication.CodeDurabilityUncertain
	case fileops.UnpackStatePublicationIndeterminate:
		data.publicationState = pcv3publication.StatePublicationIndeterminate
		data.publicationStage = pcv3.StageOutputPublication
		data.publicationCode = pcv3publication.CodePublicationIndeterminate
	default:
		return archiveNoOutput(DiagnosticCoreFailure, extraction.CleanupIncomplete())
	}
	result := newResult(data)
	if extraction.CleanupIncomplete() {
		result.appendWarning(WarningCleanupIncomplete)
	}
	return result
}

func archiveNoOutput(diagnostic Diagnostic, cleanupIncomplete bool) *Result {
	result := newResult(resultData{
		outcome:    pcv3.OutcomeOperationFailed,
		stage:      pcv3.StageOutputPublication,
		code:       pcv3.CodeOperationFailed,
		diagnostic: diagnostic,
	})
	if cleanupIncomplete {
		result.appendWarning(WarningCleanupIncomplete)
	}
	return result
}

func closeExtractionRoot(root *os.Root) bool {
	return root != nil && root.Close() != nil
}
