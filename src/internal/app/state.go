// Package app provides centralized application state and operation orchestration.
//
// This package serves two main purposes:
//
//  1. State Management (state.go):
//     The State struct centralizes all UI state variables that were previously
//     global variables in the original Picocrypt implementation. This includes
//     file paths, credentials, options, progress tracking, and status display.
//     All state access is thread-safe via sync.RWMutex.
//
//  2. Progress Reporting (reporter.go):
//     The UIReporter implements volume.ProgressReporter to bridge between the
//     core encryption/decryption operations and the UI. It translates operation
//     status updates into UI state changes and triggers redraws.
//
// This separation allows the core crypto code in internal/volume to remain
// UI-agnostic while still providing rich progress feedback.
package app

import (
	"image/color"
	"sync"
	"time"

	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/util"

	"github.com/Picocrypt/infectious"
)

// Version is the application version string.
const Version = "v2.04"

// PasswordInputMode represents the visibility state of password inputs.
type PasswordInputMode int

const (
	PasswordModeHidden PasswordInputMode = iota
	PasswordModeVisible
)

// State holds the application state that persists across operations.
// This centralizes all the global variables from the original implementation.
type State struct {
	mu sync.RWMutex

	// DPI scaling factor
	DPI float32

	// Operation mode
	Mode     string // "encrypt" or "decrypt"
	Working  bool   // Operation in progress
	Scanning bool   // Scanning files

	// Modal state
	ModalID       int
	ShowPassgen   bool
	ShowKeyfile   bool
	ShowOverwrite bool
	ShowProgress  bool

	// Input/Output files
	InputFile    string
	InputFileOld string // For recombine cleanup
	OutputFile   string
	OnlyFiles    []string
	OnlyFolders  []string
	AllFiles     []string
	InputLabel   string

	// Credentials
	Password           string
	CPassword          string // Confirm password
	PasswordStrength   int
	PasswordMode       PasswordInputMode
	PasswordStateLabel string

	// Password generator
	PassgenLength  int32
	PassgenUpper   bool
	PassgenLower   bool
	PassgenNums    bool
	PassgenSymbols bool
	PassgenCopy    bool

	// Keyfiles
	Keyfiles       []string
	KeyfileOrdered bool
	KeyfileLabel   string
	Keyfile        bool // Whether keyfiles are required (from header)

	// Comments
	Comments         string
	CommentsLabel    string
	CommentsDisabled bool

	// Encryption options
	Paranoid    bool
	ReedSolomon bool
	Deniability bool
	Compress    bool

	// Decryption options
	Keep        bool // Force decrypt despite errors
	Kept        bool // File was kept despite errors
	VerifyFirst bool // Two-pass mode: verify MAC before decryption (slower, more secure)
	AutoUnzip   bool
	SameLevel   bool

	// Split options
	Split         bool
	SplitSize     string
	SplitUnits    []string
	SplitSelected int32

	// Processing options
	Recursively bool
	Delete      bool
	Recombine   bool

	// Status
	StartLabel      string
	MainStatus      string
	MainStatusColor color.RGBA
	PopupStatus     string

	// Progress
	Progress     float32
	ProgressInfo string
	Speed        float64
	ETA          string
	CanCancel    bool
	FastDecode   bool

	// Reed-Solomon codecs
	RSCodecs                                *encoding.RSCodecs
	RS1, RS5, RS16, RS24, RS32, RS64, RS128 *infectious.FEC

	// Size tracking
	RequiredFreeSpace int64
	CompressTotal     int64
	CompressDone      int64
	CompressStart     time.Time

	// Clipboard callback (set by UI)
	SetClipboard func(text string)
}

// NewState creates a new application state with default values.
func NewState() *State {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		panic(err)
	}

	return &State{
		// Defaults
		InputLabel:         "Drop files and folders into this window",
		KeyfileLabel:       "None selected",
		CommentsLabel:      "Comments:",
		StartLabel:         "Start",
		MainStatus:         "Ready",
		MainStatusColor:    util.WHITE,
		PasswordMode:       PasswordModeHidden,
		PasswordStateLabel: "Show",
		PassgenLength:      32,
		SplitSelected:      1, // Default to MiB
		SplitUnits:         []string{"KiB", "MiB", "GiB", "TiB", "Total"},
		FastDecode:         true,
		DPI:                1.0,

		// Reed-Solomon codecs
		RSCodecs: rs,
		RS1:      rs.RS1,
		RS5:      rs.RS5,
		RS16:     rs.RS16,
		RS24:     rs.RS24,
		RS32:     rs.RS32,
		RS64:     rs.RS64,
		RS128:    rs.RS128,
	}
}

// Reset clears the state to initial values (full reset for Clear button).
// This resets EVERYTHING including progress state.
func (s *State) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Reset progress-related state (NOT reset by original resetUI)
	s.Working = false
	s.Scanning = false
	s.ShowProgress = false
	s.CanCancel = false

	// Reset everything else (same as ResetUI)
	s.resetUILocked()
}

// ResetUI resets UI state but preserves progress-related flags.
// This matches the original Picocrypt's resetUI() behavior (lines 2635-2692).
// It does NOT reset: Working, ShowProgress, CanCancel, Scanning, ModalID
func (s *State) ResetUI() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resetUILocked()
}

// resetUILocked performs the actual reset (must be called with lock held).
// Matches original resetUI() - does NOT reset progress-related fields.
func (s *State) resetUILocked() {
	s.Mode = ""

	s.ShowPassgen = false
	s.ShowKeyfile = false
	s.ShowOverwrite = false
	// NOTE: ShowProgress is NOT reset here (matches original)

	s.InputFile = ""
	s.InputFileOld = ""
	s.OutputFile = ""
	s.OnlyFiles = nil
	s.OnlyFolders = nil
	s.AllFiles = nil
	s.InputLabel = "Drop files and folders into this window"

	s.Password = ""
	s.CPassword = ""
	s.PasswordStrength = 0
	s.PasswordMode = PasswordModeHidden
	s.PasswordStateLabel = "Show"

	s.Keyfiles = nil
	s.KeyfileOrdered = false
	s.KeyfileLabel = "None selected"
	s.Keyfile = false

	s.Comments = ""
	s.CommentsLabel = "Comments:"
	s.CommentsDisabled = false

	s.Paranoid = false
	s.ReedSolomon = false
	s.Deniability = false
	s.Compress = false

	s.Keep = false
	s.Kept = false
	s.VerifyFirst = false
	s.AutoUnzip = false
	s.SameLevel = false

	s.Split = false
	s.SplitSize = ""
	s.SplitSelected = 1

	// Password generator defaults (must be true after reset, like original)
	s.PassgenLength = 32
	s.PassgenUpper = true
	s.PassgenLower = true
	s.PassgenNums = true
	s.PassgenSymbols = true
	s.PassgenCopy = true

	s.Recursively = false
	s.Delete = false
	s.Recombine = false

	s.StartLabel = "Start"
	s.MainStatus = "Ready"
	s.MainStatusColor = util.WHITE
	s.PopupStatus = ""

	// Progress values are reset, but not the progress FLAGS
	s.Progress = 0
	s.ProgressInfo = ""
	s.Speed = 0
	s.ETA = ""
	// NOTE: CanCancel is NOT reset here (matches original)
	s.FastDecode = true

	s.RequiredFreeSpace = 0
	s.CompressTotal = 0
	s.CompressDone = 0
}

// ResetAfterOperation resets state after an encryption/decryption operation.
func (s *State) ResetAfterOperation() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Working = false
	s.ShowProgress = false
	s.CanCancel = false
	s.Progress = 0
	s.ProgressInfo = ""
}

// IsEncrypting returns true if in encrypt mode.
func (s *State) IsEncrypting() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Mode == "encrypt"
}

// IsDecrypting returns true if in decrypt mode.
func (s *State) IsDecrypting() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Mode == "decrypt"
}

// CanStart returns true if the operation can be started.
func (s *State) CanStart() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Need either password or keyfiles
	hasCredentials := len(s.Keyfiles) > 0 || s.Password != ""
	if !hasCredentials {
		return false
	}

	// For encryption, passwords must match
	if s.Mode == "encrypt" && s.Password != s.CPassword {
		return false
	}

	return true
}

// TogglePasswordVisibility toggles password show/hide.
func (s *State) TogglePasswordVisibility() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.PasswordStateLabel == "Show" {
		s.PasswordMode = PasswordModeVisible
		s.PasswordStateLabel = "Hide"
	} else {
		s.PasswordMode = PasswordModeHidden
		s.PasswordStateLabel = "Show"
	}
}

// IsPasswordHidden returns true if password should be hidden.
func (s *State) IsPasswordHidden() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.PasswordMode == PasswordModeHidden
}

// UpdateKeyfileLabel updates the keyfile label based on current keyfiles.
func (s *State) UpdateKeyfileLabel() {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := len(s.Keyfiles)
	switch count {
	case 0:
		if s.Keyfile {
			s.KeyfileLabel = "Keyfiles required"
		} else {
			s.KeyfileLabel = "None selected"
		}
	case 1:
		s.KeyfileLabel = "Using 1 keyfile"
	default:
		s.KeyfileLabel = "Using multiple keyfiles"
	}
}

// SetStatus updates the main status display.
func (s *State) SetStatus(text string, c color.RGBA) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.MainStatus = text
	s.MainStatusColor = c
}

// SetPopupStatus updates the popup status display.
func (s *State) SetPopupStatus(text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PopupStatus = text
}

// SetProgress updates the progress display.
func (s *State) SetProgress(fraction float32, info string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Progress = fraction
	s.ProgressInfo = info
}

// SetCanCancel updates whether cancel is allowed.
func (s *State) SetCanCancel(can bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CanCancel = can
}

// GenPassword generates a password using current passgen settings.
// Returns empty string if generation fails (extremely rare crypto/rand failure).
func (s *State) GenPassword() string {
	s.mu.RLock()
	opts := util.PassgenOptions{
		Length:  int(s.PassgenLength),
		Upper:   s.PassgenUpper,
		Lower:   s.PassgenLower,
		Numbers: s.PassgenNums,
		Symbols: s.PassgenSymbols,
	}
	copyToClipboard := s.PassgenCopy
	clipboardFunc := s.SetClipboard
	s.mu.RUnlock()

	password, err := util.GenPassword(opts)
	if err != nil {
		// crypto/rand failure is extremely rare and indicates a broken system
		// Return empty string - UI will show no password was generated
		return ""
	}
	if copyToClipboard && clipboardFunc != nil {
		clipboardFunc(password)
	}
	return password
}
