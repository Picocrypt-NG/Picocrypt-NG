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
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/util"
	"fmt"
	"image/color"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Picocrypt/infectious"
)

// newRSCodecs is the Reed-Solomon codec constructor used by NewState. It is a
// package-level seam (mirroring the RekeyThreshold / deriveVolumeKey
// pattern) so tests can inject a failing constructor to exercise the RS-init
// error path without a real failure (see TestNewStateRSInitFailure).
var newRSCodecs = encoding.NewRSCodecs

// Version is the application version string.
const Version = "v3.0"

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

// PCV3RouteState is the closed state of content routing for one selected file.
// D1 is never inferred by this state; it is selected explicitly through
// SelectPCV3D1.
type PCV3RouteState uint8

const (
	PCV3RouteNone PCV3RouteState = iota
	PCV3RouteChecking
	PCV3RouteReady
	PCV3RouteTransferred
	PCV3RouteFailed
)

type PCV3Format uint8

const (
	PCV3FormatNone PCV3Format = iota
	PCV3FormatNormal
	PCV3FormatD1
)

type PCV3Action uint8

const (
	PCV3ActionNone PCV3Action = iota
	PCV3ActionDecrypt
	PCV3ActionRecovery
	PCV3ActionForce
	PCV3ActionForceUnverified
)

type PCV3FactorPolicy uint8

const (
	PCV3FactorPolicyUnset PCV3FactorPolicy = iota
	PCV3FactorPolicyPassword
	PCV3FactorPolicyKeyfiles
	PCV3FactorPolicyCombined
)

type PCV3KeyfileOrder uint8

const (
	PCV3KeyfileOrderUnset PCV3KeyfileOrder = iota
	PCV3KeyfileOrderSelected
	PCV3KeyfileOrderAny
)

// PCV3OperationIntent is the single mutable-to-owned handoff from application
// state to the native operation boundary. Source and Password transfer exactly
// once; Keyfiles preserves the user's selection order and duplicates.
type PCV3OperationIntent struct {
	Format       PCV3Format
	Action       PCV3Action
	FactorPolicy PCV3FactorPolicy
	KeyfileOrder PCV3KeyfileOrder
	Source       *os.File
	SplitBase    string
	Target       string
	Password     []byte
	Keyfiles     []string
	AutoUnzip    bool
	SameLevel    bool
}

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
	StatusPCVUnavailable
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
	Mode           string // "encrypt" or "decrypt"
	PCVUnavailable bool   // Selected PCV content is terminal until clear/replacement
	Working        bool   // Operation in progress
	Scanning       bool   // Scanning files
	PCV3Route      PCV3RouteState
	PCV3Format     PCV3Format
	PCV3Action     PCV3Action
	PCV3Factor     PCV3FactorPolicy
	PCV3Order      PCV3KeyfileOrder
	PCV3Result     pcv3operation.Presentation
	PCV3Progress   pcv3operation.StatusCode
	// PCV3CleanupIncomplete is UI-only process-lifetime truth. It records that
	// a released archive follow-up could not confirm cleanup; it never carries
	// a capability, path, plaintext, or raw error.
	PCV3CleanupIncomplete bool
	pcv3Source            *os.File
	pcv3ReadyTicket       uint64

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
	// string is the documented residual; all []byte key material derived from it
	// is zeroed (see OperationContext.Close).
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
	CreatePCV3  bool

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
	RecursiveD1 bool
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
		CreatePCV3:           true,
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
	source := s.pcv3Source
	s.pcv3Source = nil

	// Reset progress-related state (NOT reset by original resetUI)
	s.Working = false
	s.Scanning = false
	s.ShowProgress = false
	s.CanCancel = false

	// Reset everything else (same as ResetUI)
	s.resetUILocked()
	s.mu.Unlock()
	if source != nil {
		_ = source.Close()
	}
}

// ResetUI resets UI state but preserves progress-related flags.
// This matches the original Picocrypt's resetUI() behavior (lines 2635-2692).
// It does NOT reset: Working, ShowProgress, CanCancel, Scanning, ModalID
func (s *State) ResetUI() {
	s.mu.Lock()
	source := s.pcv3Source
	s.pcv3Source = nil
	s.resetUILocked()
	s.mu.Unlock()
	if source != nil {
		_ = source.Close()
	}
}

// ClosePCV3Source releases only the retained PCV3 input descriptor. Shutdown
// uses it while workers drain so the visible selection and status remain
// stable until the window closes.
func (s *State) ClosePCV3Source() {
	s.mu.Lock()
	source := s.pcv3Source
	s.pcv3Source = nil
	s.mu.Unlock()
	if source != nil {
		_ = source.Close()
	}
}

// resetUILocked performs the actual reset (must be called with lock held).
// Matches original resetUI() - does NOT reset progress-related fields.
func (s *State) resetUILocked() {
	s.Mode = ""
	s.PCVUnavailable = false
	s.PCV3Route = PCV3RouteNone
	s.PCV3Format = PCV3FormatNone
	s.PCV3Action = PCV3ActionNone
	s.PCV3Factor = PCV3FactorPolicyUnset
	s.PCV3Order = PCV3KeyfileOrderUnset
	s.PCV3Result = pcv3operation.Presentation{}
	s.PCV3Progress = 0

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
	s.CreatePCV3 = true

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
	s.RecursiveD1 = false
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

// SetPCV3RoutingChecking replaces the previous selection and records the only
// in-flight route state. The caller remains responsible for the newly opened
// descriptor until SetPCV3Ready transfers it.
func (s *State) SetPCV3RoutingChecking(path string, size int64) {
	s.mu.Lock()
	old := s.pcv3Source
	s.pcv3Source = nil
	s.Mode = "decrypt"
	s.PCVUnavailable = false
	s.PCV3Route = PCV3RouteChecking
	s.PCV3Format = PCV3FormatNone
	s.PCV3Action = PCV3ActionNone
	s.PCV3Factor = PCV3FactorPolicyUnset
	s.PCV3Order = PCV3KeyfileOrderUnset
	s.PCV3Result = pcv3operation.Presentation{}
	s.PCV3Progress = 0
	s.InputFile = path
	s.OutputFile = ""
	s.InputSummary = InputSummary{Kind: InputSummarySelection, Files: 1, SizeBytes: size, ShowSize: true}
	s.Scanning = true
	s.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
}

// SetPCV3RoutingFailed records a bounded terminal route failure. Raw detector
// errors never enter State.
func (s *State) SetPCV3RoutingFailed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PCV3Route = PCV3RouteFailed
	s.PCV3Format = PCV3FormatNone
	s.PCV3Action = PCV3ActionNone
	s.PCV3Factor = PCV3FactorPolicyUnset
	s.PCV3Order = PCV3KeyfileOrderUnset
	s.Scanning = false
}

// SetPCV3LegacyEligible completes content routing without selecting PCV3.
// The retained descriptor, if any, is only a candidate for a later explicit
// SelectPCV3D1 call.
func (s *State) SetPCV3LegacyEligible() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PCV3Route = PCV3RouteNone
	s.PCV3Format = PCV3FormatNone
	s.PCV3Action = PCV3ActionNone
	s.PCV3Factor = PCV3FactorPolicyUnset
	s.PCV3Order = PCV3KeyfileOrderUnset
	s.PCV3Result = pcv3operation.Presentation{}
	s.PCV3Progress = 0
	s.Scanning = false
}

// SetPCV3Ready transfers one already-opened regular-file descriptor to State.
// Only the content detector may select Normal; D1 uses SelectPCV3D1.
func (s *State) SetPCV3Ready(source *os.File, format PCV3Format, path, target string, size int64) bool {
	if source == nil || (format != PCV3FormatNormal && format != PCV3FormatD1) {
		return false
	}
	s.mu.Lock()
	old := s.pcv3Source
	s.pcv3Source = source
	s.Mode = "decrypt"
	s.PCVUnavailable = false
	s.PCV3Route = PCV3RouteReady
	s.pcv3ReadyTicket++
	s.PCV3Format = format
	s.PCV3Action = PCV3ActionNone
	s.PCV3Factor = PCV3FactorPolicyUnset
	s.PCV3Order = PCV3KeyfileOrderUnset
	s.PCV3Result = pcv3operation.Presentation{}
	s.PCV3Progress = 0
	s.InputFile = path
	s.OutputFile = target
	s.OnlyFiles = []string{path}
	s.AllFiles = nil
	s.InputSummary = InputSummary{Kind: InputSummarySelection, Files: 1, SizeBytes: size, ShowSize: true}
	s.StartAction = StartActionStart
	s.Scanning = false
	s.mu.Unlock()
	if old != nil && old != source {
		_ = old.Close()
	}
	return true
}

// RetainPCV3D1Candidate pins the descriptor of one legacy-eligible regular
// selection. It does not select D1 and leaves the legacy UI unchanged.
func (s *State) RetainPCV3D1Candidate(source *os.File) bool {
	if source == nil {
		return false
	}
	s.mu.Lock()
	old := s.pcv3Source
	s.pcv3Source = source
	s.mu.Unlock()
	if old != nil && old != source {
		_ = old.Close()
	}
	return true
}

// SelectPCV3D1 explicitly switches the retained regular selection to D1.
func (s *State) SelectPCV3D1() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pcv3Source == nil || s.Working || s.Scanning {
		return false
	}
	s.Mode = "decrypt"
	s.PCVUnavailable = false
	s.PCV3Route = PCV3RouteReady
	s.pcv3ReadyTicket++
	s.PCV3Format = PCV3FormatD1
	s.PCV3Action = PCV3ActionNone
	s.PCV3Factor = PCV3FactorPolicyUnset
	s.PCV3Order = PCV3KeyfileOrderUnset
	s.PCV3Result = pcv3operation.Presentation{}
	s.PCV3Progress = 0
	s.Comments = ""
	s.CommentsPreviewState = CommentsPreviewUnavailable
	s.StartAction = StartActionStart
	return true
}

// PCV3ReadyOutputSelection returns the ticket and output for one current Ready
// selection. Callers must present this ticket back to SetPCV3OutputForReady;
// that setter rejects callbacks from an earlier selection atomically.
func (s *State) PCV3ReadyOutputSelection() (uint64, string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.PCV3Route != PCV3RouteReady {
		return 0, "", false
	}
	return s.pcv3ReadyTicket, s.OutputFile, true
}

// IsPCV3ReadyOutputSelection reports whether ticket still names the current
// Ready selection. It lets UI callbacks avoid displaying an obsolete form;
// SetPCV3OutputForReady remains the atomic authority for any state mutation.
func (s *State) IsPCV3ReadyOutputSelection(ticket uint64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.PCV3Route == PCV3RouteReady && s.pcv3ReadyTicket == ticket
}

// SetPCV3OutputForReady atomically updates the output and Ready status only
// when ticket still identifies the same Ready selection.
func (s *State) SetPCV3OutputForReady(ticket uint64, path string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.PCV3Route != PCV3RouteReady || s.pcv3ReadyTicket != ticket {
		return false
	}
	s.OutputFile = path
	s.Status = StatusMessage{Kind: StatusReady, Color: util.WHITE}
	s.MainStatus = "Ready"
	s.MainStatusKind = MainStatusReady
	s.MainStatusColor = util.WHITE
	return true
}

func (s *State) SetPCV3Intent(action PCV3Action, factor PCV3FactorPolicy, order PCV3KeyfileOrder) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PCV3Action = action
	s.PCV3Factor = factor
	if factor == PCV3FactorPolicyPassword {
		order = PCV3KeyfileOrderUnset
	}
	s.PCV3Order = order
}

func (s *State) SetAutoUnzip(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AutoUnzip = enabled
	if !enabled {
		s.SameLevel = false
	}
}

func (s *State) SetSameLevel(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.SameLevel = enabled && s.AutoUnzip
}

func (s *State) SetPCV3Progress(code pcv3operation.StatusCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PCV3Progress = code
}

func (s *State) SetPCV3Result(presentation pcv3operation.Presentation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PCV3Result = presentation
	s.PCV3Progress = 0
}

// LatchPCV3CleanupIncomplete retains bounded cleanup uncertainty for this
// State lifetime. Reset and selection replacement deliberately do not clear it.
func (s *State) LatchPCV3CleanupIncomplete() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PCV3CleanupIncomplete = true
}

func pcv3IntentReady(
	route PCV3RouteState,
	format PCV3Format,
	action PCV3Action,
	factor PCV3FactorPolicy,
	order PCV3KeyfileOrder,
	password, output string,
	keyfileCount int,
) bool {
	if route != PCV3RouteReady ||
		(format != PCV3FormatNormal && format != PCV3FormatD1) ||
		(action != PCV3ActionDecrypt && action != PCV3ActionRecovery &&
			action != PCV3ActionForce && action != PCV3ActionForceUnverified) || output == "" {
		return false
	}
	hasPassword := password != ""
	hasKeyfiles := keyfileCount != 0
	switch factor {
	case PCV3FactorPolicyPassword:
		return hasPassword && !hasKeyfiles && order == PCV3KeyfileOrderUnset
	case PCV3FactorPolicyKeyfiles:
		return !hasPassword && hasKeyfiles &&
			(order == PCV3KeyfileOrderSelected || order == PCV3KeyfileOrderAny)
	case PCV3FactorPolicyCombined:
		return hasPassword && hasKeyfiles &&
			(order == PCV3KeyfileOrderSelected || order == PCV3KeyfileOrderAny)
	default:
		return false
	}
}

func pcv3IntentReadyLocked(s *State) bool {
	return s.pcv3Source != nil && pcv3IntentReady(
		s.PCV3Route, s.PCV3Format, s.PCV3Action, s.PCV3Factor, s.PCV3Order,
		s.Password, s.OutputFile, len(s.Keyfiles),
	)
}

// BeginPCV3ArchiveFollowUp atomically consumes the UI start gate for one
// archive follow-up. The Go-owned ArchiveFollowUp remains the effect authority.
func (s *State) BeginPCV3ArchiveFollowUp() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Working || s.PCV3Route != PCV3RouteTransferred ||
		!s.PCV3Result.ArchivePending() {
		return false
	}
	s.Working = true
	return true
}

// TakePCV3OperationIntent atomically validates and transfers the operation-local
// intent. Credentials are cleared at the caller boundary even if subsequent
// descriptor preparation fails.
func (s *State) TakePCV3OperationIntent() (PCV3OperationIntent, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Working || s.Scanning || !pcv3IntentReadyLocked(s) {
		return PCV3OperationIntent{}, false
	}
	return s.takePCV3OperationIntentLocked(), true
}

// TakePCV3RecursiveOperationIntent transfers one decrypt selection inside an
// already-running batch. D1 requires the batch's explicit format selection;
// neither batch format grants recovery authority.
func (s *State) TakePCV3RecursiveOperationIntent() (PCV3OperationIntent, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	format := PCV3FormatNormal
	if s.RecursiveD1 {
		format = PCV3FormatD1
	}
	if !s.Working || !s.Recursively || s.Scanning ||
		s.PCV3Format != format || s.PCV3Action != PCV3ActionDecrypt ||
		!pcv3IntentReadyLocked(s) {
		return PCV3OperationIntent{}, false
	}
	return s.takePCV3OperationIntentLocked(), true
}

// SetRecursiveD1 records explicit format intent for the complete batch. The
// selection's original mode is unchanged so disabling it restores that choice.
func (s *State) SetRecursiveD1(enabled bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Working || s.Scanning || (enabled && !s.Recursively) {
		return false
	}
	s.RecursiveD1 = enabled
	return true
}

func (s *State) takePCV3OperationIntentLocked() PCV3OperationIntent {
	intent := PCV3OperationIntent{
		Format:       s.PCV3Format,
		Action:       s.PCV3Action,
		FactorPolicy: s.PCV3Factor,
		KeyfileOrder: s.PCV3Order,
		Source:       s.pcv3Source,
		Target:       s.OutputFile,
		Password:     []byte(s.Password),
		Keyfiles:     append([]string(nil), s.Keyfiles...),
		AutoUnzip:    s.AutoUnzip,
		SameLevel:    s.SameLevel,
	}
	if s.Recombine {
		intent.SplitBase = s.InputFile
	}
	s.pcv3Source = nil
	s.PCV3Route = PCV3RouteTransferred
	s.Password = ""
	s.CPassword = ""
	for index := range s.Keyfiles {
		s.Keyfiles[index] = ""
	}
	s.Keyfiles = nil
	return intent
}

// canStart is the single source of truth for the start-gate condition, shared by
// the live State.CanStart() and the render-path UISnapshot.CanStart() (DRY).
func canStart(mode, password, cpassword string, keyfileCount int, deniability, createPCV3 bool) bool {
	// Legacy v2 creation cannot use keyfiles; explicit PCV3 creation can.
	if mode == "encrypt" && keyfileCount > 0 && !createPCV3 {
		return false
	}

	// Need either password or keyfiles
	hasCredentials := keyfileCount > 0 || password != ""
	if !hasCredentials {
		return false
	}

	// In the legacy format, keyfiles protect the inner volume but not the
	// password-derived deniability wrapper. PCV3 D1 binds the complete factor
	// transcript to both layers.
	if mode == "encrypt" && deniability && !createPCV3 && password == "" {
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
	if s.Recursively && s.RecursiveD1 {
		return !s.PCVUnavailable && !s.Working && !s.Scanning &&
			canStart("decrypt", s.Password, s.CPassword, len(s.Keyfiles), false, true)
	}
	if s.PCV3Route != PCV3RouteNone {
		return !s.PCVUnavailable && !s.Working && !s.Scanning && pcv3IntentReadyLocked(s)
	}
	return !s.PCVUnavailable && canStart(s.Mode, s.Password, s.CPassword, len(s.Keyfiles), s.Deniability, s.CreatePCV3)
}

// CanStart returns true if the operation can be started, evaluated against this
// render-path snapshot. UI code uses this so the start-gate boolean lives in
// exactly one place (canStart) shared with State.CanStart.
func (snap UISnapshot) CanStart() bool {
	if snap.Recursively && snap.RecursiveD1 {
		return !snap.PCVUnavailable && !snap.Working && !snap.Scanning &&
			canStart("decrypt", snap.Password, snap.CPassword, snap.KeyfileCount, false, true)
	}
	if snap.PCV3Route != PCV3RouteNone {
		return !snap.PCVUnavailable && !snap.Working && !snap.Scanning && pcv3IntentReady(
			snap.PCV3Route, snap.PCV3Format, snap.PCV3Action, snap.PCV3Factor, snap.PCV3Order,
			snap.Password, snap.OutputFile, snap.KeyfileCount,
		)
	}
	return !snap.PCVUnavailable && canStart(snap.Mode, snap.Password, snap.CPassword, snap.KeyfileCount, snap.Deniability, snap.CreatePCV3)
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

// SetPCVUnavailable atomically replaces the current selection with a terminal,
// non-startable PCV selection while retaining only its path and input summary.
func (s *State) SetPCVUnavailable(path string, sizeBytes int64) {
	s.mu.Lock()
	source := s.pcv3Source
	s.pcv3Source = nil
	s.resetUILocked()
	s.Working = false
	s.Scanning = false
	s.ShowProgress = false
	s.CanCancel = false
	s.PCVUnavailable = true
	s.InputFile = path
	s.InputSummary = InputSummary{
		Kind:      InputSummarySelection,
		Files:     1,
		SizeBytes: sizeBytes,
		ShowSize:  true,
	}
	s.Status = StatusMessage{Kind: StatusPCVUnavailable, Color: util.RED}
	s.MainStatusKind = MainStatusCustom
	s.MainStatusColor = util.RED
	s.mu.Unlock()
	if source != nil {
		_ = source.Close()
	}
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
	CreatePCV3  bool

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
	Mode           string
	PCVUnavailable bool
	Scanning       bool
	Working        bool

	AllFileCount    int
	OnlyFileCount   int
	OnlyFolderCount int
	KeyfileCount    int

	Password              string
	CPassword             string
	PasswordMode          PasswordInputMode
	Keyfile               bool
	KeyfileOrdered        bool
	Deniability           bool
	CreatePCV3            bool
	Comments              string
	CommentsPreviewState  CommentsPreviewState
	StartLabel            string
	Recursively           bool
	RecursiveD1           bool
	OutputFile            string
	InputFile             string
	Split                 bool
	SplitSize             string
	MainStatus            string
	MainStatusKind        MainStatusKind
	MainStatusColor       color.RGBA
	RequiredFreeSpace     int64
	ShowProgress          bool
	CanCancel             bool
	Recombine             bool
	AutoUnzip             bool
	SameLevel             bool
	InputLabel            string
	InputSummary          InputSummary
	StartAction           StartAction
	Status                StatusMessage
	PopupStatus           StatusMessage
	PopupStatusMessage    StatusMessage
	PCV3Route             PCV3RouteState
	PCV3Format            PCV3Format
	PCV3Action            PCV3Action
	PCV3Factor            PCV3FactorPolicy
	PCV3Order             PCV3KeyfileOrder
	PCV3Result            pcv3operation.Presentation
	PCV3Progress          pcv3operation.StatusCode
	PCV3CleanupIncomplete bool
	PCV3KeyfileNames      []string
}

// RecursiveSnapshot is a value-copy of the State fields the recursive (batch)
// worker captures once and re-applies before each file. Like Snapshot/UISnapshot,
// taking one copy under a single RLock keeps the recursive worker off unlocked
// State access (APP-02). It carries credential/option fields only; no
// progress/widget/display-label fields belong here.
type RecursiveSnapshot struct {
	RecursiveD1    bool
	Password       string
	Keyfile        bool
	Keyfiles       []string
	KeyfileOrdered bool
	Comments       string
	Paranoid       bool
	ReedSolomon    bool
	Deniability    bool
	CreatePCV3     bool
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
		CreatePCV3:     s.CreatePCV3,
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
	var pcv3KeyfileNames []string
	if s.PCV3Route == PCV3RouteReady || s.PCV3Route == PCV3RouteTransferred {
		pcv3KeyfileNames = make([]string, len(s.Keyfiles))
		for index, path := range s.Keyfiles {
			pcv3KeyfileNames[index] = filepath.Base(path)
		}
	}
	return UISnapshot{
		Mode:                  s.Mode,
		PCVUnavailable:        s.PCVUnavailable,
		Scanning:              s.Scanning,
		Working:               s.Working,
		AllFileCount:          len(s.AllFiles),
		OnlyFileCount:         len(s.OnlyFiles),
		OnlyFolderCount:       len(s.OnlyFolders),
		KeyfileCount:          len(s.Keyfiles),
		Password:              s.Password,
		CPassword:             s.CPassword,
		PasswordMode:          s.PasswordMode,
		Keyfile:               s.Keyfile,
		KeyfileOrdered:        s.KeyfileOrdered,
		Deniability:           s.Deniability,
		CreatePCV3:            s.CreatePCV3,
		Comments:              s.Comments,
		CommentsPreviewState:  s.CommentsPreviewState,
		StartLabel:            s.StartLabel,
		Recursively:           s.Recursively,
		RecursiveD1:           s.RecursiveD1,
		OutputFile:            s.OutputFile,
		InputFile:             s.InputFile,
		Split:                 s.Split,
		SplitSize:             s.SplitSize,
		MainStatus:            s.MainStatus,
		MainStatusKind:        s.MainStatusKind,
		MainStatusColor:       s.MainStatusColor,
		RequiredFreeSpace:     s.RequiredFreeSpace,
		ShowProgress:          s.ShowProgress,
		CanCancel:             s.CanCancel,
		Recombine:             s.Recombine,
		AutoUnzip:             s.AutoUnzip,
		SameLevel:             s.SameLevel,
		InputLabel:            s.InputLabel,
		InputSummary:          s.InputSummary,
		StartAction:           s.StartAction,
		Status:                s.Status,
		PopupStatus:           s.Popup,
		PopupStatusMessage:    s.Popup,
		PCV3Route:             s.PCV3Route,
		PCV3Format:            s.PCV3Format,
		PCV3Action:            s.PCV3Action,
		PCV3Factor:            s.PCV3Factor,
		PCV3Order:             s.PCV3Order,
		PCV3Result:            s.PCV3Result,
		PCV3Progress:          s.PCV3Progress,
		PCV3CleanupIncomplete: s.PCV3CleanupIncomplete,
		PCV3KeyfileNames:      pcv3KeyfileNames,
	}
}

// RecursiveSnapshot returns a consistent value-copy of the fields the recursive
// worker captures before processing a batch, under a single read lock. Keyfiles
// is deep-copied so the worker never aliases State's backing array (APP-02).
func (s *State) RecursiveSnapshot() RecursiveSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return RecursiveSnapshot{
		RecursiveD1:    s.RecursiveD1,
		Password:       s.Password,
		Keyfile:        s.Keyfile,
		Keyfiles:       append([]string(nil), s.Keyfiles...),
		KeyfileOrdered: s.KeyfileOrdered,
		Comments:       s.Comments,
		Paranoid:       s.Paranoid,
		ReedSolomon:    s.ReedSolomon,
		Deniability:    s.Deniability,
		CreatePCV3:     s.CreatePCV3,
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
	s.RecursiveD1 = rs.RecursiveD1
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
		s.CreatePCV3 = true
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
