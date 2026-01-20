// Package cli provides command-line interface functionality for Picocrypt-NG.
package cli

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// Reporter implements volume.ProgressReporter for terminal output.
// It displays progress updates on a single line that gets overwritten.
type Reporter struct {
	mu        sync.Mutex
	status    string
	progress  float32
	info      string
	quiet     bool
	cancelled atomic.Bool
	lastLine  int // Length of last printed line (for clearing)
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
