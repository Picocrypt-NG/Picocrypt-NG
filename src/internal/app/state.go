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
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/util"
	"fmt"
	"image/color"
	"sync"
	"time"

	"github.com/Picocrypt/infectious"
)

// newRSCodecs is the Reed-Solomon codec constructor used by NewState. It is a
// package-level seam (mirroring the Phase 3/4 RekeyThreshold / deriveVolumeKey
// pattern) so tests can inject a failing constructor to exercise the RS-init
// error path without a real failure (see TestNewStateRSInitFailure).
var newRSCodecs = encoding.NewRSCodecs

// Version is the application version string.
const Version = "v2.18"

// PasswordInputMode represents the visibility state of password inputs.
type PasswordInputMode int

const (
	PasswordModeHidden PasswordInputMode = iota
	PasswordModeVisible
)

// MainStatusKind identifies whether MainStatus is the UI-owned ready state or a
// caller-provided status message. Render logic must not infer this from text.
type MainStatusKind int

const (
	MainStatusCustom MainStatusKind = iota
	MainStatusReady
)

type InputSummaryKind int

const (
	InputSummaryDropPrompt InputSummaryKind = iota
	InputSummaryScanning
	InputSummarySelection
	InputSummaryDecryptVolume
)

type InputSummary struct {
	Kind      InputSummaryKind
	Files     int
	Folders   int
	SizeBytes int64
	ShowSize  bool
}

type StartAction int

const (
	StartActionStart StartAction = iota
	StartActionEncrypt
	StartActionZipAndEncrypt
	StartActionDecrypt
)

type StatusKind int

const (
	StatusCustom StatusKind = iota
	StatusReady
	StatusCancelledByUser
	StatusCompleted
	StatusNoFilesToProcess
	StatusProcessingFile
	StatusRecursiveCompleted
	StatusRecursiveFailedAll
	StatusRecursiveCompletedFailed
	StatusInvalidSplitSize
	StatusCompletedSomeDeleteFailed
	StatusKeptOutputUnverified
	StatusCompletedVolumeDeleteFailed
	StatusStartupPathAccessFailed
	StatusStartupPathPartialAccessFailed
	StatusOpenedPathsPreparing
	StatusOpenedPathsTimeout
	StatusDropFailedWalk
	StatusDropFailedStatItem
	StatusDropFailedStatItems
	StatusDropReadAccessDenied
	StatusDropHeaderMayBeDeniable
	StatusDropHeaderDamaged
	StatusDropFailedSplitPath
	StatusKeyfileReadAccessDenied
	StatusKeyfileGenerateFailed
	StatusKeyfileWriteFailed
	StatusMobileAppStorageCreateFailed
	StatusMobileAppStorageReadFailed
	StatusMobileAppStoragePathCopied
	StatusMobileAppStorageNoFiles
	StatusMobileFileAccessFailed
	StatusMobileFileAccessUnsafeName
)

type StatusArgs struct {
	Count  int
	OK     int
	Failed int
	Index  int
	Total  int
	Error  string
}

type StatusMessage struct {
	Kind  StatusKind
	Args  StatusArgs
	Text  string
	Color color.RGBA
}

// CommentsPreviewState identifies whether decrypt-preview comments are usable.
// Comments remains the header comment payload only; it must not carry display
// sentinels such as "Comments are corrupted".
type CommentsPreviewState int

const (
	CommentsPreviewNormal CommentsPreviewState = iota
	CommentsPreviewUnavailable
	CommentsPreviewCorrupted
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
	InputFile                 string
	InputFileOld              string // For recombine cleanup
	OutputFile                string
	OutputChosenViaSaveDialog bool
	OnlyFiles                 []string
	OnlyFolders               []string
	AllFiles                  []string
	InputLabel                string

	// Credentials
	//
	// SECURITY (SEC-05, GUI residual): Password and CPassword are immutable Go
	// strings sourced from Fyne widget.Entry. Strings cannot be zeroed in place
	// (immutable + freely copied/relocated by the GC), so resetUILocked only sets
	// them to "" — the prior contents may linger in memory until GC. The request
	// layer no longer carries the password as a string: volume.EncryptRequest/
	// DecryptRequest.Password are owned []byte, and ui/operations.go converts this
	// string to an owned []byte at request-build and zeros that copy. This one GUI
	// string is the documented residual — guaranteed zeroing of it is intentionally
	// out of scope (CONCERNS 3.1; ROADMAP "Out of Scope: Guaranteed password
	// zeroing"); all []byte key material derived from it is zeroed (see
	// OperationContext.Close).
	Password  string
	CPassword string // Confirm password

	PasswordStrength int
	PasswordMode     PasswordInputMode

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
	Keyfile        bool // Whether keyfiles are required (from header)

	// Comments
	Comments             string
	CommentsPreviewState CommentsPreviewState

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
	InputSummary    InputSummary
	StartAction     StartAction
	Status          StatusMessage
	Popup           StatusMessage
	StartLabel      string
	MainStatus      string
	MainStatusKind  MainStatusKind
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
//
// It returns an error (rather than panicking) when the Reed-Solomon codecs
// cannot be initialized, so callers can surface a recoverable, user-visible
// startup failure instead of crashing the process (APP-01/D-05).
func NewState() (*State, error) {
	rs, err := newRSCodecs()
	if err != nil {
		return nil, fmt.Errorf("init RS codecs: %w", err)
	}

	return &State{
		// Defaults
		InputLabel:           "Drop files and folders into this window",
		InputSummary:         InputSummary{Kind: InputSummaryDropPrompt},
		StartAction:          StartActionStart,
		Status:               StatusMessage{Kind: StatusReady, Color: util.WHITE},
		Popup:                StatusMessage{Kind: StatusCustom},
		StartLabel:           "Start",
		MainStatus:           "Ready",
		MainStatusKind:       MainStatusReady,
		MainStatusColor:      util.WHITE,
		PasswordMode:         PasswordModeHidden,
		CommentsPreviewState: CommentsPreviewNormal,
		// Password generator defaults must match resetUILocked(): all character
		// classes ON (so the generator works before any reset) and PassgenCopy
		// OFF (do not auto-copy a generated password to the OS clipboard).
		PassgenLength:  32,
		PassgenUpper:   true,
		PassgenLower:   true,
		PassgenNums:    true,
		PassgenSymbols: true,
		PassgenCopy:    false,
		SplitSelected:  1, // Default to MiB
		SplitUnits:     []string{"KiB", "MiB", "GiB", "TiB", "Total"},
		FastDecode:     true,
		DPI:            1.0,

		// Reed-Solomon codecs
		RSCodecs: rs,
		RS1:      rs.RS1,
		RS5:      rs.RS5,
		RS16:     rs.RS16,
		RS24:     rs.RS24,
		RS32:     rs.RS32,
		RS64:     rs.RS64,
		RS128:    rs.RS128,
	}, nil
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
	s.OutputChosenViaSaveDialog = false
	s.OnlyFiles = nil
	s.OnlyFolders = nil
	s.AllFiles = nil
	s.InputLabel = "Drop files and folders into this window"

	s.Password = ""
	s.CPassword = ""
	s.PasswordStrength = 0
	s.PasswordMode = PasswordModeHidden

	s.Keyfiles = nil
	s.KeyfileOrdered = false
	s.Keyfile = false

	s.Comments = ""
	s.CommentsPreviewState = CommentsPreviewNormal

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

	// Password generator defaults. PassgenCopy defaults OFF: do not auto-copy a
	// generated password to the OS clipboard (sync/history leak); user can opt in.
	s.PassgenLength = 32
	s.PassgenUpper = true
	s.PassgenLower = true
	s.PassgenNums = true
	s.PassgenSymbols = true
	s.PassgenCopy = false

	s.Recursively = false
	s.Delete = false
	s.Recombine = false

	s.InputSummary = InputSummary{Kind: InputSummaryDropPrompt}
	s.StartAction = StartActionStart
	s.Status = StatusMessage{Kind: StatusReady, Color: util.WHITE}
	s.Popup = StatusMessage{Kind: StatusCustom}
	s.StartLabel = "Start"
	s.MainStatus = "Ready"
	s.MainStatusKind = MainStatusReady
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

// IsScanning returns true if file scanning is in progress.
func (s *State) IsScanning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Scanning
}

// SetScanning updates whether file scanning is in progress.
func (s *State) SetScanning(scanning bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Scanning = scanning
}

// canStart is the single source of truth for the start-gate condition, shared by
// the live State.CanStart() and the render-path UISnapshot.CanStart() (DRY).
func canStart(mode, password, cpassword string, keyfileCount int) bool {
	// Need either password or keyfiles
	hasCredentials := keyfileCount > 0 || password != ""
	if !hasCredentials {
		return false
	}

	// For encryption, passwords must match
	if mode == "encrypt" && password != cpassword {
		return false
	}

	return true
}

// CanStart returns true if the operation can be started.
func (s *State) CanStart() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return canStart(s.Mode, s.Password, s.CPassword, len(s.Keyfiles))
}

// CanStart returns true if the operation can be started, evaluated against this
// render-path snapshot. UI code uses this so the start-gate boolean lives in
// exactly one place (canStart) shared with State.CanStart.
func (snap UISnapshot) CanStart() bool {
	return canStart(snap.Mode, snap.Password, snap.CPassword, snap.KeyfileCount)
}

// TogglePasswordVisibility toggles password show/hide.
func (s *State) TogglePasswordVisibility() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.PasswordMode == PasswordModeHidden {
		s.PasswordMode = PasswordModeVisible
	} else {
		s.PasswordMode = PasswordModeHidden
	}
}

// IsPasswordHidden returns true if password should be hidden.
func (s *State) IsPasswordHidden() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.PasswordMode == PasswordModeHidden
}

// SetStatus updates the main status display.
func (s *State) SetStatus(text string, c color.RGBA) {
	s.SetCustomStatus(text, c)
}

// SetReadyStatus restores the UI-owned ready status.
func (s *State) SetReadyStatus() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Status = StatusMessage{Kind: StatusReady, Color: util.WHITE}
	s.MainStatus = "Ready"
	s.MainStatusKind = MainStatusReady
	s.MainStatusColor = util.WHITE
}

func (s *State) SetInputPrompt() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.InputSummary = InputSummary{Kind: InputSummaryDropPrompt}
}

func (s *State) SetInputScanning(sizeBytes int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.InputSummary = InputSummary{Kind: InputSummaryScanning, SizeBytes: sizeBytes}
}

func (s *State) SetInputSelection(files, folders int, sizeBytes int64, showSize bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.InputSummary = InputSummary{
		Kind:      InputSummarySelection,
		Files:     files,
		Folders:   folders,
		SizeBytes: sizeBytes,
		ShowSize:  showSize,
	}
}

func (s *State) SetInputDecryptVolume() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.InputSummary = InputSummary{Kind: InputSummaryDecryptVolume}
}

func (s *State) SetStartAction(action StartAction) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.StartAction = action
}

func (s *State) SetStatusMessage(kind StatusKind, c color.RGBA, args StatusArgs) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Status = StatusMessage{Kind: kind, Args: args, Color: c}
	s.MainStatusKind = MainStatusCustom
	s.MainStatusColor = c
}

func (s *State) SetCustomStatus(text string, c color.RGBA) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Status = StatusMessage{Kind: StatusCustom, Text: text, Color: c}
	s.MainStatus = text
	s.MainStatusKind = MainStatusCustom
	s.MainStatusColor = c
}

func (s *State) SetPopupStatusMessage(kind StatusKind, args StatusArgs) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Popup = StatusMessage{Kind: kind, Args: args}
}

func (s *State) SetPopupStatusText(text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Popup = StatusMessage{Kind: StatusCustom, Text: text}
	s.PopupStatus = text
}

// SetPopupStatus updates the popup status display.
func (s *State) SetPopupStatus(text string) {
	s.SetPopupStatusText(text)
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

// Snapshot is a value-copy of the State fields the encrypt/decrypt worker
// reads to build a volume.EncryptRequest / volume.DecryptRequest. Taking one
// Snapshot under a single RLock lets the worker's request-building hot path
// read every field consistently without touching State unlocked (APP-02/D-06).
//
// It holds exactly the fields doEncrypt/doDecrypt build their request from;
// no UI/widget or progress fields belong here.
type Snapshot struct {
	Mode string

	// Inputs / outputs
	InputFile   string
	InputFiles  []string // mirrors State.AllFiles
	OnlyFiles   []string
	OnlyFolders []string
	OutputFile  string

	// Credentials
	Password       string
	Keyfiles       []string
	KeyfileOrdered bool

	// Metadata + encryption options
	Comments    string
	Paranoid    bool
	ReedSolomon bool
	Deniability bool
	Compress    bool

	// Decryption options
	Keep        bool
	VerifyFirst bool
	AutoUnzip   bool
	SameLevel   bool
	Recombine   bool

	// Split options
	Split         bool
	SplitSize     string
	SplitSelected int32

	// Post-operation file handling
	Delete bool
}

// UISnapshot is a value-copy of State fields the Fyne render path reads while
// enabling/disabling widgets and refreshing labels. It deliberately contains no
// widget references, so callers can release State.mu before touching Fyne.
type UISnapshot struct {
	Mode     string
	Scanning bool
	Working  bool

	AllFileCount    int
	OnlyFileCount   int
	OnlyFolderCount int
	KeyfileCount    int

	Password             string
	CPassword            string
	PasswordMode         PasswordInputMode
	Keyfile              bool
	Deniability          bool
	Comments             string
	CommentsPreviewState CommentsPreviewState
	StartLabel           string
	Recursively          bool
	OutputFile           string
	InputFile            string
	Split                bool
	SplitSize            string
	MainStatus           string
	MainStatusKind       MainStatusKind
	MainStatusColor      color.RGBA
	RequiredFreeSpace    int64
	ShowProgress         bool
	Recombine            bool
	AutoUnzip            bool
	InputLabel           string
	InputSummary         InputSummary
	StartAction          StartAction
	Status               StatusMessage
	PopupStatus          StatusMessage
	PopupStatusMessage   StatusMessage
}

// RecursiveSnapshot is a value-copy of the State fields the recursive (batch)
// worker captures once and re-applies before each file. Like Snapshot/UISnapshot,
// taking one copy under a single RLock keeps the recursive worker off unlocked
// State access (APP-02). It carries credential/option fields only; no
// progress/widget/display-label fields belong here.
type RecursiveSnapshot struct {
	Password       string
	Keyfile        bool
	Keyfiles       []string
	KeyfileOrdered bool
	Comments       string
	Paranoid       bool
	ReedSolomon    bool
	Deniability    bool
	Split          bool
	SplitSize      string
	SplitSelected  int32
	Delete         bool
}

// Snapshot returns a consistent value-copy of the request-building fields under
// a single read lock. Slice fields are deep-copied so the worker never aliases
// State's backing arrays after the lock is released (APP-02).
func (s *State) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Snapshot{
		Mode:           s.Mode,
		InputFile:      s.InputFile,
		InputFiles:     append([]string(nil), s.AllFiles...),
		OnlyFiles:      append([]string(nil), s.OnlyFiles...),
		OnlyFolders:    append([]string(nil), s.OnlyFolders...),
		OutputFile:     s.OutputFile,
		Password:       s.Password,
		Keyfiles:       append([]string(nil), s.Keyfiles...),
		KeyfileOrdered: s.KeyfileOrdered,
		Comments:       s.Comments,
		Paranoid:       s.Paranoid,
		ReedSolomon:    s.ReedSolomon,
		Deniability:    s.Deniability,
		Compress:       s.Compress,
		Keep:           s.Keep,
		VerifyFirst:    s.VerifyFirst,
		AutoUnzip:      s.AutoUnzip,
		SameLevel:      s.SameLevel,
		Recombine:      s.Recombine,
		Split:          s.Split,
		SplitSize:      s.SplitSize,
		SplitSelected:  s.SplitSelected,
		Delete:         s.Delete,
	}
}

// UISnapshot returns a consistent value-copy of render-path fields under a
// single read lock. UI code must not hold State.mu while calling Fyne widgets.
func (s *State) UISnapshot() UISnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return UISnapshot{
		Mode:                 s.Mode,
		Scanning:             s.Scanning,
		Working:              s.Working,
		AllFileCount:         len(s.AllFiles),
		OnlyFileCount:        len(s.OnlyFiles),
		OnlyFolderCount:      len(s.OnlyFolders),
		KeyfileCount:         len(s.Keyfiles),
		Password:             s.Password,
		CPassword:            s.CPassword,
		PasswordMode:         s.PasswordMode,
		Keyfile:              s.Keyfile,
		Deniability:          s.Deniability,
		Comments:             s.Comments,
		CommentsPreviewState: s.CommentsPreviewState,
		StartLabel:           s.StartLabel,
		Recursively:          s.Recursively,
		OutputFile:           s.OutputFile,
		InputFile:            s.InputFile,
		Split:                s.Split,
		SplitSize:            s.SplitSize,
		MainStatus:           s.MainStatus,
		MainStatusKind:       s.MainStatusKind,
		MainStatusColor:      s.MainStatusColor,
		RequiredFreeSpace:    s.RequiredFreeSpace,
		ShowProgress:         s.ShowProgress,
		Recombine:            s.Recombine,
		AutoUnzip:            s.AutoUnzip,
		InputLabel:           s.InputLabel,
		InputSummary:         s.InputSummary,
		StartAction:          s.StartAction,
		Status:               s.Status,
		PopupStatus:          s.Popup,
		PopupStatusMessage:   s.Popup,
	}
}

// RecursiveSnapshot returns a consistent value-copy of the fields the recursive
// worker captures before processing a batch, under a single read lock. Keyfiles
// is deep-copied so the worker never aliases State's backing array (APP-02).
func (s *State) RecursiveSnapshot() RecursiveSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return RecursiveSnapshot{
		Password:       s.Password,
		Keyfile:        s.Keyfile,
		Keyfiles:       append([]string(nil), s.Keyfiles...),
		KeyfileOrdered: s.KeyfileOrdered,
		Comments:       s.Comments,
		Paranoid:       s.Paranoid,
		ReedSolomon:    s.ReedSolomon,
		Deniability:    s.Deniability,
		Split:          s.Split,
		SplitSize:      s.SplitSize,
		SplitSelected:  s.SplitSelected,
		Delete:         s.Delete,
	}
}

// ApplyRecursiveSelection restores a captured RecursiveSnapshot onto the State
// before the next file in a recursive batch, under a single write lock (APP-02:
// replaces the recursive worker's bare cross-goroutine field writes). CPassword
// mirrors Password (recursive mode never re-confirms), and Keyfiles is deep-copied
// so the State never aliases the snapshot's backing array. Deniability is an
// encrypt-only option, so it is left untouched when the just-dropped file put the
// State into decrypt mode (preserves the prior inline guard).
func (s *State) ApplyRecursiveSelection(rs RecursiveSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Password = rs.Password
	s.CPassword = rs.Password
	s.Keyfile = rs.Keyfile
	s.Keyfiles = append([]string(nil), rs.Keyfiles...)
	s.KeyfileOrdered = rs.KeyfileOrdered
	s.Comments = rs.Comments
	s.Paranoid = rs.Paranoid
	s.ReedSolomon = rs.ReedSolomon
	if s.Mode != "decrypt" {
		s.Deniability = rs.Deniability
	}
	s.Split = rs.Split
	s.SplitSize = rs.SplitSize
	s.SplitSelected = rs.SplitSelected
	s.Delete = rs.Delete
}

// SetShowProgress sets whether the progress dialog/state should be visible.
func (s *State) SetShowProgress(show bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ShowProgress = show
}

// SetMode sets the current operation mode ("encrypt", "decrypt", or "").
// Reads of Mode go through IsEncrypting/IsDecrypting or Snapshot (the field name
// is unchanged per D-06, so it cannot also be a getter method name).
func (s *State) SetMode(mode string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Mode = mode
}

// IsWorking reports whether an operation is in progress.
func (s *State) IsWorking() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Working
}

// SetWorking sets whether an operation is in progress.
func (s *State) SetWorking(working bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Working = working
}

// SetInputFile sets the current input file path.
func (s *State) SetInputFile(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.InputFile = path
}

// SetOutputFile sets the current output file path.
func (s *State) SetOutputFile(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.OutputFile = path
}

// SetComments sets the current header comments.
func (s *State) SetComments(comments string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Comments = comments
}

// SetDeniability sets whether deniability is enabled.
func (s *State) SetDeniability(deniable bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Deniability = deniable
}

// SetKeep sets whether force-decrypt-despite-errors is enabled.
func (s *State) SetKeep(keep bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Keep = keep
}

// WasKept reports whether the input file was kept despite errors.
// (Named WasKept because the field Kept is unchanged per D-06.)
func (s *State) WasKept() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Kept
}

// SetKept sets whether the input file was kept despite errors.
func (s *State) SetKept(kept bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Kept = kept
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
