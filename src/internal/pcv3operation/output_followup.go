package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3publication"
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
	mu       sync.Mutex
	active   bool
	retained *pcv3publication.RetainedFile
}

// OutputFollowUp is a one-shot Go-minted capability for a retained durable
// non-archive output. Copies share one consumption state.
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

// SaveTo consumes the action before effects and takes ownership of destination.
// A failed transport immediately removes the exact internal owner because the
// one-shot action cannot safely leave plaintext with no remaining authority.
func (followUp *OutputFollowUp) SaveTo(destination *os.File) OutputActionResult {
	retained := followUp.consume()
	if retained == nil {
		if destination != nil {
			_ = destination.Close()
		}
		return OutputActionResult{code: OutputActionExpired}
	}
	copyResult := retained.CopyTo(destination)
	if !copyResult.Copied() {
		cleanupIncomplete := copyResult.CleanupIncomplete() || retained.RemoveExact() != nil
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
