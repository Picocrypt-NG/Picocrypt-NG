// Package app provides application state management with optional Fyne data binding support.
package app

import (
	"fyne.io/fyne/v2/data/binding"
)

// BoundProgress provides Fyne data bindings for progress-related UI elements.
// This enables automatic UI updates without manual widget.SetText() calls.
type BoundProgress struct {
	// Progress bar value (0.0 to 1.0)
	Progress binding.Float

	// Progress info text (e.g., "50.00%")
	ProgressInfo binding.String

	// Status text (e.g., "Encrypting at 100 MiB/s (ETA: 1m30s)")
	Status binding.String

	// Main status text with color
	MainStatus binding.String

	// Can cancel flag
	CanCancel binding.Bool
}

// NewBoundProgress creates a new BoundProgress with default values.
func NewBoundProgress() *BoundProgress {
	return &BoundProgress{
		Progress:     binding.NewFloat(),
		ProgressInfo: binding.NewString(),
		Status:       binding.NewString(),
		MainStatus:   binding.NewString(),
		CanCancel:    binding.NewBool(),
	}
}

// SetProgress updates the progress binding.
func (b *BoundProgress) SetProgress(fraction float64) {
	_ = b.Progress.Set(fraction)
}

// SetProgressInfo updates the progress info binding.
func (b *BoundProgress) SetProgressInfo(info string) {
	_ = b.ProgressInfo.Set(info)
}

// SetStatus updates the status binding.
func (b *BoundProgress) SetStatus(text string) {
	_ = b.Status.Set(text)
}

// SetMainStatus updates the main status binding.
func (b *BoundProgress) SetMainStatus(text string) {
	_ = b.MainStatus.Set(text)
}

// SetCanCancel updates the can cancel binding.
func (b *BoundProgress) SetCanCancel(can bool) {
	_ = b.CanCancel.Set(can)
}

// Reset resets all bindings to default values.
func (b *BoundProgress) Reset() {
	_ = b.Progress.Set(0)
	_ = b.ProgressInfo.Set("")
	_ = b.Status.Set("Ready")
	_ = b.MainStatus.Set("Ready")
	_ = b.CanCancel.Set(false)
}

// BoundInput provides Fyne data bindings for input-related UI elements.
type BoundInput struct {
	// Input label text
	InputLabel binding.String

	// Output file path display
	OutputFile binding.String

	// Comments text
	Comments binding.String

	// Keyfile label
	KeyfileLabel binding.String
}

// NewBoundInput creates a new BoundInput with default values.
func NewBoundInput() *BoundInput {
	b := &BoundInput{
		InputLabel:   binding.NewString(),
		OutputFile:   binding.NewString(),
		Comments:     binding.NewString(),
		KeyfileLabel: binding.NewString(),
	}
	_ = b.InputLabel.Set("Drop files and folders into this window")
	_ = b.KeyfileLabel.Set("None selected")
	return b
}

// BoundOptions provides Fyne data bindings for option checkboxes.
type BoundOptions struct {
	Paranoid    binding.Bool
	ReedSolomon binding.Bool
	Deniability binding.Bool
	Compress    binding.Bool
	Split       binding.Bool
	Delete      binding.Bool
	Recursively binding.Bool

	// Decrypt options
	ForceDecrypt binding.Bool
	VerifyFirst  binding.Bool
	AutoUnzip    binding.Bool
	SameLevel    binding.Bool
}

// NewBoundOptions creates a new BoundOptions with default values.
func NewBoundOptions() *BoundOptions {
	return &BoundOptions{
		Paranoid:     binding.NewBool(),
		ReedSolomon:  binding.NewBool(),
		Deniability:  binding.NewBool(),
		Compress:     binding.NewBool(),
		Split:        binding.NewBool(),
		Delete:       binding.NewBool(),
		Recursively:  binding.NewBool(),
		ForceDecrypt: binding.NewBool(),
		VerifyFirst:  binding.NewBool(),
		AutoUnzip:    binding.NewBool(),
		SameLevel:    binding.NewBool(),
	}
}

// BoundState provides all Fyne data bindings for the application.
// This can be used alongside the traditional State struct for gradual migration.
type BoundState struct {
	Progress *BoundProgress
	Input    *BoundInput
	Options  *BoundOptions
}

// NewBoundState creates a new BoundState with all bindings initialized.
func NewBoundState() *BoundState {
	return &BoundState{
		Progress: NewBoundProgress(),
		Input:    NewBoundInput(),
		Options:  NewBoundOptions(),
	}
}

// SyncFromState copies values from a traditional State to the bindings.
// Call this after modifying State to update bound widgets.
func (b *BoundState) SyncFromState(s *State) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Progress
	_ = b.Progress.Progress.Set(float64(s.Progress))
	_ = b.Progress.ProgressInfo.Set(s.ProgressInfo)
	_ = b.Progress.Status.Set(s.PopupStatus)
	_ = b.Progress.MainStatus.Set(s.MainStatus)
	_ = b.Progress.CanCancel.Set(s.CanCancel)

	// Input
	_ = b.Input.InputLabel.Set(s.InputLabel)
	_ = b.Input.OutputFile.Set(s.OutputFile)
	_ = b.Input.Comments.Set(s.Comments)
	_ = b.Input.KeyfileLabel.Set(s.KeyfileLabel)

	// Options
	_ = b.Options.Paranoid.Set(s.Paranoid)
	_ = b.Options.ReedSolomon.Set(s.ReedSolomon)
	_ = b.Options.Deniability.Set(s.Deniability)
	_ = b.Options.Compress.Set(s.Compress)
	_ = b.Options.Split.Set(s.Split)
	_ = b.Options.Delete.Set(s.Delete)
	_ = b.Options.Recursively.Set(s.Recursively)
	_ = b.Options.ForceDecrypt.Set(s.Keep)
	_ = b.Options.VerifyFirst.Set(s.VerifyFirst)
	_ = b.Options.AutoUnzip.Set(s.AutoUnzip)
	_ = b.Options.SameLevel.Set(s.SameLevel)
}

// SyncToState copies values from bindings to a traditional State.
// Call this before starting operations to get user input values.
func (b *BoundState) SyncToState(s *State) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Options (these are the most commonly modified by users)
	s.Paranoid, _ = b.Options.Paranoid.Get()
	s.ReedSolomon, _ = b.Options.ReedSolomon.Get()
	s.Deniability, _ = b.Options.Deniability.Get()
	s.Compress, _ = b.Options.Compress.Get()
	s.Split, _ = b.Options.Split.Get()
	s.Delete, _ = b.Options.Delete.Get()
	s.Recursively, _ = b.Options.Recursively.Get()
	s.Keep, _ = b.Options.ForceDecrypt.Get()
	s.VerifyFirst, _ = b.Options.VerifyFirst.Get()
	s.AutoUnzip, _ = b.Options.AutoUnzip.Get()
	s.SameLevel, _ = b.Options.SameLevel.Get()

	// Comments
	s.Comments, _ = b.Input.Comments.Get()
}
