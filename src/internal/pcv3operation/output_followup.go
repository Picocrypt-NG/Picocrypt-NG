package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3publication"
	"context"
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
)

// OutputActionResult is path-free and carries only custody-relevant truth.
type OutputActionResult struct {
	code              OutputActionCode
	cleanupIncomplete bool
}

func (result OutputActionResult) Code() OutputActionCode { return result.code }

func (result OutputActionResult) CleanupIncomplete() bool { return result.cleanupIncomplete }

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

func cleanupOutputExact(result *Result) bool {
	if result == nil || result.outputFollowUp == nil {
		return false
	}
	retained := result.outputFollowUp.consume()
	result.outputFollowUp = nil
	return cleanupRetainedExact(&retained)
}

func cleanupRetainedExact(retained **pcv3publication.RetainedFile) bool {
	if retained == nil || *retained == nil {
		return false
	}
	owned := *retained
	*retained = nil
	return owned.RemoveExact() != nil
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
	if !copyResult.Copied() {
		cleanupIncomplete := retained.RemoveExact() != nil || copyResult.CleanupIncomplete()
		code := OutputActionSaveFailed
		if cleanupIncomplete {
			code = OutputActionSaveFailedCleanupIncomplete
		}
		return OutputActionResult{
			code:              code,
			cleanupIncomplete: cleanupIncomplete,
		}
	}
	if err := retained.RemoveExact(); err != nil {
		return OutputActionResult{
			code:              OutputActionSavedCleanupIncomplete,
			cleanupIncomplete: true,
		}
	}
	return OutputActionResult{code: OutputActionSaved}
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
	if copyResult.CleanupIncomplete() {
		if copyResult.Copied() {
			code = OutputActionSavedCleanupIncomplete
		} else {
			code = OutputActionSaveFailedCleanupIncomplete
		}
	}
	return OutputActionResult{code: code, cleanupIncomplete: copyResult.CleanupIncomplete()}
}

// Discard consumes the action before effects and removes only the exact
// retained identity. Replacement or cleanup uncertainty preserves the
// observed name and is reported as cleanup uncertainty.
func (followUp *OutputFollowUp) Discard() OutputActionResult {
	retained := followUp.consume()
	if retained == nil {
		return OutputActionResult{code: OutputActionExpired}
	}
	if err := retained.RemoveExact(); err != nil {
		return OutputActionResult{
			code:              OutputActionDiscardCleanupIncomplete,
			cleanupIncomplete: true,
		}
	}
	return OutputActionResult{code: OutputActionDiscarded}
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
		code := OutputActionSaveFailed
		if copied.CleanupIncomplete() {
			code = OutputActionSaveFailedCleanupIncomplete
		}
		return OutputActionResult{code: code, cleanupIncomplete: copied.CleanupIncomplete()}
	}
	state.active = false
	retained := state.retained
	state.retained = nil
	if retained.RemoveExact() != nil {
		return OutputActionResult{code: OutputActionSavedCleanupIncomplete, cleanupIncomplete: true}
	}
	return OutputActionResult{code: OutputActionSaved}
}
