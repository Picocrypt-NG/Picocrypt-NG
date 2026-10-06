// Package cli provides command-line interface functionality for Picocrypt-NG.
package cli

import (
	"Picocrypt-NG/internal/pcv3operation"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Reporter implements volume.ProgressReporter for terminal output.
// It displays progress updates on a single line that gets overwritten.
type Reporter struct {
	mu              sync.Mutex
	status          string
	progress        float32
	info            string
	quiet           bool
	cancelled       atomic.Bool
	lastLine        int // Length of last printed line (for clearing)
	cancelOperation atomic.Pointer[context.CancelFunc]
}

// NewReporter creates a new CLI progress reporter.
// If quiet is true, only errors are printed.
func NewReporter(quiet bool) *Reporter {
	return &Reporter{
		quiet: quiet,
	}
}

// SetStatus updates the status message.
func (r *Reporter) SetStatus(text string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status = text
}

// SetProgress updates the progress bar and info text.
func (r *Reporter) SetProgress(fraction float32, info string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.progress = fraction
	r.info = info
}

// SetCanCancel enables/disables cancellation (no-op for CLI, always cancellable via Ctrl+C).
func (r *Reporter) SetCanCancel(can bool) {
	// No-op for CLI - cancellation is handled via OS signals
}

// Update triggers a UI refresh - prints current status to terminal.
func (r *Reporter) Update() {
	if r.quiet {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Build progress bar
	barWidth := 30
	filled := min(int(r.progress*float32(barWidth)), barWidth)
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	// Format: [████████░░░░░░░░░░░░░░░░░░░░░░] 25.00% | Encrypting at 150.00 MiB/s (ETA: 0:05)
	line := fmt.Sprintf("\r[%s] %s | %s", bar, r.info, r.status)

	// Clear previous line if it was longer
	if len(line) < r.lastLine {
		line += strings.Repeat(" ", r.lastLine-len(line))
	}
	r.lastLine = len(line)

	fmt.Fprint(os.Stderr, line)
}

// IsCancelled checks if the operation was cancelled.
func (r *Reporter) IsCancelled() bool {
	return r.cancelled.Load()
}

// Cancel marks the operation as cancelled.
func (r *Reporter) Cancel() {
	r.cancelled.Store(true)
	cancel := r.cancelOperation.Load()
	if cancel != nil {
		(*cancel)()
	}
}

func (r *Reporter) setCancel(cancel context.CancelFunc) {
	if cancel == nil {
		r.cancelOperation.Store(nil)
		return
	}
	r.cancelOperation.Store(&cancel)
	if r.cancelled.Load() {
		cancel()
	}
}

// Finish prints a newline to move past the progress line.
func (r *Reporter) Finish() {
	if !r.quiet {
		fmt.Fprintln(os.Stderr)
	}
}

// PrintError prints an error message.
func (r *Reporter) PrintError(format string, args ...any) {
	// Move to new line if we were showing progress
	if !r.quiet && r.lastLine > 0 {
		fmt.Fprintln(os.Stderr)
	}
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
}

// PrintSuccess prints a success message.
func (r *Reporter) PrintSuccess(format string, args ...any) {
	if r.quiet {
		return
	}
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// PrintPCV3Status renders only operation-owned stable codes and bounded
// numeric arguments. Quiet mode suppresses progress, never terminal warnings.
func (r *Reporter) PrintPCV3Status(status pcv3operation.Status) error {
	if r.quiet {
		return nil
	}

	message := "Working…"
	switch status.Code() {
	case pcv3operation.StatusCheckingRequest:
		message = "Checking operation…"
	case pcv3operation.StatusCheckingFactors:
		message = "Checking credential policy…"
	case pcv3operation.StatusCheckingResources:
		message = "Checking device resources…"
	case pcv3operation.StatusDerivingKey:
		message = "Deriving key…"
	case pcv3operation.StatusEncrypting:
		message = "Encrypting volume…"
	case pcv3operation.StatusSplitting:
		message = "Splitting encrypted output…"
	case pcv3operation.StatusAuthenticating:
		message = "Authenticating…"
	case pcv3operation.StatusRecovering:
		message = "Recovering…"
	case pcv3operation.StatusPreparingArtifact:
		message = "Preparing recovery artifact…"
	case pcv3operation.StatusPublishing:
		message = "Publishing output…"
	case pcv3operation.StatusConfirmingDurability:
		message = "Confirming output durability…"
	}

	var line strings.Builder
	line.WriteString(message)
	args := status.Args()
	if len(args) > 4 {
		args = args[:4]
	}
	if len(args) > 0 {
		line.WriteString(" [")
		for index, value := range args {
			if index > 0 {
				line.WriteString(", ")
			}
			line.WriteString(strconv.FormatUint(value, 10))
		}
		line.WriteByte(']')
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	_, err := fmt.Fprintln(os.Stderr, line.String())
	return err
}

func renderPCV3CLIResult(output io.Writer, result pcv3CLIResult) int {
	if output == nil {
		return ExitGeneralError
	}
	outcome := "unknown-outcome"
	publication := "not-attempted"
	var warnings []pcv3operation.Warning
	if result != nil {
		outcome = result.Outcome().String()
		if result.PublicationAttempted() {
			publication = result.PublicationState().String()
		}
		warnings = result.Warnings()
	}
	if _, err := fmt.Fprintf(output, "Outcome: %s\nPublication: %s\n", outcome, publication); err != nil {
		return ExitGeneralError
	}
	if result != nil && result.Stage() == pcv3operation.StageResourceBudget {
		if _, err := fmt.Fprintln(output, "Resource limit reached: the operation exceeded its processing resource budget."); err != nil {
			return ExitGeneralError
		}
	}
	if commented, ok := result.(interface{ AuthenticatedComment() string }); ok {
		if comment := commented.AuthenticatedComment(); comment != "" {
			if _, err := fmt.Fprintf(output, "Comment: %s\n", strconv.Quote(comment)); err != nil {
				return ExitGeneralError
			}
		}
	}
	if split, ok := result.(interface{ SplitOutputUncertain() bool }); ok && split.SplitOutputUncertain() {
		if _, err := fmt.Fprintln(output, "All parts were created. Write durability could not be confirmed, so the complete encrypted file and source files were kept."); err != nil {
			return ExitGeneralError
		}
	}
	if len(warnings) > 8 {
		warnings = warnings[:8]
	}
	for _, warning := range warnings {
		if _, err := fmt.Fprintln(output, pcv3CLIWarningText(warning)); err != nil {
			return ExitGeneralError
		}
	}
	return pcv3ExitCode(result)
}

func pcv3CLIWarningText(warning pcv3operation.Warning) string {
	switch warning {
	case pcv3operation.WarningAuthenticatedDegraded:
		return "Warning: output is authenticated but recovery redundancy is damaged"
	case pcv3operation.WarningForcePartial:
		return "Warning: partial recovery output is not a complete plaintext file"
	case pcv3operation.WarningForceUnverified:
		return "Warning: recovered bytes are unverified and may be unsafe"
	case pcv3operation.WarningDurabilityUncertain:
		return "Warning: output durability was not confirmed; keep source and destination unchanged"
	case pcv3operation.WarningPublicationIndeterminate:
		return "Warning: output state is unknown; keep source and destination unchanged"
	case pcv3operation.WarningCleanupIncomplete:
		return "Warning: cleanup of operation-owned temporary files could not be confirmed"
	case pcv3operation.WarningCallbackFailure:
		return "Warning: an operation callback failed; clean completion was not confirmed"
	default:
		return "Warning: operation completed with a caution"
	}
}
