// Package app provides application state management and operations orchestration.
package app

import (
	"sync"

	"Picocrypt-NG/internal/volume"
)

// Ensure UIReporter implements volume.ProgressReporter
var _ volume.ProgressReporter = (*UIReporter)(nil)

// UIReporter bridges the volume module with the main UI.
// It implements volume.ProgressReporter and updates UI state.
type UIReporter struct {
	mu sync.RWMutex

	// Callbacks for UI updates (set by main)
	OnStatus    func(text string)
	OnProgress  func(fraction float32, info string)
	OnCanCancel func(can bool)
	OnUpdate    func()
	CheckCancel func() bool

	// Internal state
	cancelled bool
}

// NewUIReporter creates a new UI reporter with the given callbacks.
func NewUIReporter(
	onStatus func(string),
	onProgress func(float32, string),
	onCanCancel func(bool),
	onUpdate func(),
	checkCancel func() bool,
) *UIReporter {
	return &UIReporter{
		OnStatus:    onStatus,
		OnProgress:  onProgress,
		OnCanCancel: onCanCancel,
		OnUpdate:    onUpdate,
		CheckCancel: checkCancel,
	}
}

// SetStatus implements volume.ProgressReporter.
func (r *UIReporter) SetStatus(text string) {
	if r.OnStatus != nil {
		r.OnStatus(text)
	}
}

// SetProgress implements volume.ProgressReporter.
func (r *UIReporter) SetProgress(fraction float32, info string) {
	if r.OnProgress != nil {
		r.OnProgress(fraction, info)
	}
}

// SetCanCancel implements volume.ProgressReporter.
func (r *UIReporter) SetCanCancel(can bool) {
	if r.OnCanCancel != nil {
		r.OnCanCancel(can)
	}
}

// Update implements volume.ProgressReporter.
func (r *UIReporter) Update() {
	if r.OnUpdate != nil {
		r.OnUpdate()
	}
}

// IsCancelled implements volume.ProgressReporter.
func (r *UIReporter) IsCancelled() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.cancelled {
		return true
	}
	if r.CheckCancel != nil {
		return r.CheckCancel()
	}
	return false
}

// Cancel marks the operation as cancelled.
func (r *UIReporter) Cancel() {
	r.mu.Lock()
	r.cancelled = true
	r.mu.Unlock()
}

// Reset resets the cancelled state.
func (r *UIReporter) Reset() {
	r.mu.Lock()
	r.cancelled = false
	r.mu.Unlock()
}
