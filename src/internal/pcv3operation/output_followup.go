package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
)

// OutputActionCode is the closed terminal state of one retained-output action.
type OutputActionCode uint8

const (
	OutputActionSaved OutputActionCode = iota + 1
	OutputActionSavedCleanupIncomplete
	OutputActionSaveFailed
	OutputActionSaveFailedCleanupIncomplete
	OutputActionDiscarded
	OutputActionDiscardCleanupIncomplete
	OutputActionExpired
	OutputActionSavedCleanupDurabilityUncertain
	OutputActionSaveFailedCleanupDurabilityUncertain
	OutputActionDiscardCleanupDurabilityUncertain
)

// OutputActionResult is path-free and carries only custody-relevant truth.
type OutputActionResult struct {
	code                       OutputActionCode
	cleanupIncomplete          bool
	cleanupDurabilityUncertain bool
}

func (result OutputActionResult) Code() OutputActionCode { return result.code }

func (result OutputActionResult) CleanupIncomplete() bool { return result.cleanupIncomplete }

func (result OutputActionResult) CleanupDurabilityUncertain() bool {
	return result.cleanupDurabilityUncertain
}

func outputActionWithCleanup(code OutputActionCode, incomplete, uncertain bool) OutputActionResult {
	if incomplete {
		switch code {
		case OutputActionSaved:
			code = OutputActionSavedCleanupIncomplete
		case OutputActionSaveFailed:
			code = OutputActionSaveFailedCleanupIncomplete
		case OutputActionDiscarded:
			code = OutputActionDiscardCleanupIncomplete
		}
	} else if uncertain {
		switch code {
		case OutputActionSaved:
			code = OutputActionSavedCleanupDurabilityUncertain
		case OutputActionSaveFailed:
			code = OutputActionSaveFailedCleanupDurabilityUncertain
		case OutputActionDiscarded:
			code = OutputActionDiscardCleanupDurabilityUncertain
		}
	}
	return OutputActionResult{code: code, cleanupIncomplete: incomplete, cleanupDurabilityUncertain: uncertain}
}

func (result OutputActionResult) String() string { return result.code.String() }

func (result OutputActionResult) GoString() string { return result.String() }

func (result OutputActionResult) Format(state fmt.State, verb rune) {
	value := result.String()
	if verb == 'q' {
		value = strconv.Quote(value)
	}
	_, _ = state.Write([]byte(value))
}

func (code OutputActionCode) String() string {
	switch code {
	case OutputActionSaved:
		return "saved"
	case OutputActionSavedCleanupIncomplete:
		return "saved-cleanup-incomplete"
	case OutputActionSaveFailed:
		return "save-failed"
	case OutputActionSaveFailedCleanupIncomplete:
		return "save-failed-cleanup-incomplete"
	case OutputActionDiscarded:
		return "discarded"
	case OutputActionDiscardCleanupIncomplete:
		return "discard-cleanup-incomplete"
	case OutputActionExpired:
		return "expired"
	case OutputActionSavedCleanupDurabilityUncertain:
		return "saved-cleanup-durability-uncertain"
	case OutputActionSaveFailedCleanupDurabilityUncertain:
		return "save-failed-cleanup-durability-uncertain"
	case OutputActionDiscardCleanupDurabilityUncertain:
		return "discard-cleanup-durability-uncertain"
	default:
		return "unknown-output-action"
	}
}

type outputFollowUpState struct {
	mu        sync.Mutex
	active    bool
	retryCopy bool
	retained  *pcv3publication.RetainedFile
}

// OutputFollowUp is a Go-minted capability for retained non-archive output.
// Plaintext requires durable publication; ciphertext may retain an uncertain
// directory barrier. Copies share custody and consumption state. Failed
// ciphertext SaveTo retains custody for deliberate retry.
type OutputFollowUp struct {
	state *outputFollowUpState
}

func newOutputFollowUp(retained *pcv3publication.RetainedFile) *OutputFollowUp {
	if retained == nil || !retained.Live() {
		return nil
	}
	return &OutputFollowUp{state: &outputFollowUpState{
		active: true, retained: retained,
	}}
}

func newWriteOutputFollowUp(retained *pcv3publication.RetainedFile) *OutputFollowUp {
	followUp := newOutputFollowUp(retained)
	if followUp != nil {
		followUp.state.retryCopy = true
	}
	return followUp
}

func (followUp *OutputFollowUp) live() bool {
	if followUp == nil || followUp.state == nil {
		return false
	}
	followUp.state.mu.Lock()
	defer followUp.state.mu.Unlock()
	return followUp.state.active && followUp.state.retained != nil &&
		followUp.state.retained.Live()
}

func (followUp *OutputFollowUp) consume() *pcv3publication.RetainedFile {
	if followUp == nil || followUp.state == nil {
		return nil
	}
	followUp.state.mu.Lock()
	defer followUp.state.mu.Unlock()
	if !followUp.state.active || followUp.state.retained == nil ||
		!followUp.state.retained.Live() {
		followUp.state.active = false
		followUp.state.retained = nil
		return nil
	}
	followUp.state.active = false
	retained := followUp.state.retained
	followUp.state.retained = nil
	return retained
}

func cleanupOutputExact(result *Result) error {
	var streamErr error
	if cleanupEncryptedOutput(result) {
		streamErr = pcv3publication.ErrCleanupIncomplete
	}
	if result == nil || result.outputFollowUp == nil {
		return streamErr
	}
	retained := result.outputFollowUp.consume()
	result.outputFollowUp = nil
	return errors.Join(cleanupRetainedExact(&retained), streamErr)
}

func cleanupRetainedExact(retained **pcv3publication.RetainedFile) error {
	if retained == nil || *retained == nil {
		return nil
	}
	owned := *retained
	*retained = nil
	return owned.RemoveExact()
}

// SaveTo takes ownership of destination. Plaintext consumes the action before
// effects and removes its exact internal owner even on failure. Ciphertext
// consumes only after successful transport; failure retains the live capability
// for deliberate retry. Neither transport grants source-deletion authority.
func (followUp *OutputFollowUp) SaveTo(destination *os.File) OutputActionResult {
	if followUp != nil && followUp.state != nil && followUp.state.retryCopy {
		return followUp.saveWriteTo(destination)
	}
	retained := followUp.consume()
	if retained == nil {
		if destination != nil {
			_ = destination.Close()
		}
		return OutputActionResult{code: OutputActionExpired}
	}
	copyResult := retained.CopyTo(destination)
	incomplete, uncertain := cleanupErrorFacts(retained.RemoveExact())
	incomplete = incomplete || copyResult.CleanupIncomplete()
	uncertain = uncertain || copyResult.CleanupDurabilityUncertain()
	if !copyResult.Copied() {
		return outputActionWithCleanup(OutputActionSaveFailed, incomplete, uncertain)
	}
	return outputActionWithCleanup(OutputActionSaved, incomplete, uncertain)
}

// StreamTo consumes both plaintext and ciphertext actions, including on failure,
// and streams from the retained descriptor. The destination remains open after
// a successful copy and is closed on cancel.
func (followUp *OutputFollowUp) StreamTo(
	ctx context.Context,
	destination *os.File,
) OutputActionResult {
	retained := followUp.consume()
	if retained == nil {
		return OutputActionResult{code: OutputActionExpired}
	}
	copyResult := retained.StreamTo(ctx, destination)
	code := OutputActionSaved
	if !copyResult.Copied() {
		code = OutputActionSaveFailed
	}
	return outputActionWithCleanup(code, copyResult.CleanupIncomplete(), copyResult.CleanupDurabilityUncertain())
}

// Discard consumes the action before effects and removes only the exact
// retained identity. Replacement or cleanup uncertainty preserves the
// observed name and is reported as cleanup uncertainty.
func (followUp *OutputFollowUp) Discard() OutputActionResult {
	retained := followUp.consume()
	if retained == nil {
		return OutputActionResult{code: OutputActionExpired}
	}
	incomplete, uncertain := cleanupErrorFacts(retained.RemoveExact())
	return outputActionWithCleanup(OutputActionDiscarded, incomplete, uncertain)
}

func (followUp *OutputFollowUp) String() string { return "pcv3 output follow-up" }

func (followUp *OutputFollowUp) GoString() string { return followUp.String() }

func (followUp *OutputFollowUp) Format(state fmt.State, verb rune) {
	value := followUp.String()
	if verb == 'q' {
		value = strconv.Quote(value)
	}
	_, _ = state.Write([]byte(value))
}

// Failed ciphertext transport retains the exact original for a deliberate retry.
func (followUp *OutputFollowUp) saveWriteTo(destination *os.File) OutputActionResult {
	state := followUp.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.active || state.retained == nil || !state.retained.Live() {
		if destination != nil {
			_ = destination.Close()
		}
		return OutputActionResult{code: OutputActionExpired}
	}
	copied := state.retained.CopyTo(destination)
	if !copied.Copied() {
		return outputActionWithCleanup(OutputActionSaveFailed, copied.CleanupIncomplete(), copied.CleanupDurabilityUncertain())
	}
	state.active = false
	retained := state.retained
	state.retained = nil
	incomplete, uncertain := cleanupErrorFacts(retained.RemoveExact())
	return outputActionWithCleanup(OutputActionSaved, incomplete || copied.CleanupIncomplete(), uncertain || copied.CleanupDurabilityUncertain())
}
