package app

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/util"
	"errors"
	"image/color"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// mustNewState builds a *State for tests, failing the test if RS-codec
// initialization returns an error. Centralizes the (*State, error) call so the
// many table tests below stay readable after APP-01 changed NewState's signature.
func mustNewState(t *testing.T) *State {
	t.Helper()
	s, err := NewState()
	if err != nil {
		t.Fatalf("NewState() returned error: %v", err)
	}
	return s
}

// TestNewStateRSInitFailure proves APP-01/D-05: when the RS-codec constructor
// fails, NewState returns a non-nil error (wrapping the cause) and a nil *State,
// and never panics. The newRSCodecs package-level seam is overridden to force
// the failure, mirroring the Phase 3/4 var-seam override+restore pattern.
func TestNewStateRSInitFailure(t *testing.T) {
	orig := newRSCodecs
	t.Cleanup(func() { newRSCodecs = orig })

	forced := errors.New("forced RS init failure")
	newRSCodecs = func() (*encoding.RSCodecs, error) {
		return nil, forced
	}

	// Must not panic; recover only to surface a clearer failure if it does.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("NewState() panicked instead of returning an error: %v", r)
		}
	}()

	state, err := NewState()
	if err == nil {
		t.Fatal("NewState() error = nil; want non-nil on RS-init failure")
	}
	if state != nil {
		t.Errorf("NewState() state = %v; want nil on error", state)
	}
	if !errors.Is(err, forced) {
		t.Errorf("NewState() error = %v; want wrapping %v", err, forced)
	}
	if !strings.Contains(err.Error(), "init RS codecs") {
		t.Errorf("NewState() error = %q; want it to mention 'init RS codecs'", err.Error())
	}
}

func TestNewState(t *testing.T) {
	state := mustNewState(t)

	// Check defaults
	if state.InputLabel != "Drop files and folders into this window" {
		t.Errorf("InputLabel = %q; want default", state.InputLabel)
	}
	if state.StartLabel != "Start" {
		t.Errorf("StartLabel = %q; want 'Start'", state.StartLabel)
	}
	if state.MainStatus != "Ready" {
		t.Errorf("MainStatus = %q; want 'Ready'", state.MainStatus)
	}
	if state.MainStatusKind != MainStatusReady {
		t.Errorf("MainStatusKind = %v; want MainStatusReady", state.MainStatusKind)
	}
	if state.MainStatusColor != util.WHITE {
		t.Error("MainStatusColor should be WHITE")
	}
	if state.PasswordMode != PasswordModeHidden {
		t.Error("PasswordMode should be Hidden")
	}
	if state.CommentsPreviewState != CommentsPreviewNormal {
		t.Errorf("CommentsPreviewState = %v; want CommentsPreviewNormal", state.CommentsPreviewState)
	}
	if state.PassgenLength != 32 {
		t.Errorf("PassgenLength = %d; want 32", state.PassgenLength)
	}
	if state.SplitSelected != 1 {
		t.Errorf("SplitSelected = %d; want 1 (MiB)", state.SplitSelected)
	}
	if !state.FastDecode {
		t.Error("FastDecode should be true by default")
	}
	if state.DPI != 1.0 {
		t.Errorf("DPI = %f; want 1.0", state.DPI)
	}

	// Check RS codecs are initialized
	if state.RSCodecs == nil {
		t.Error("RSCodecs should be initialized")
	}
	if state.RS1 == nil || state.RS128 == nil {
		t.Error("RS codecs should be initialized")
	}
}

func TestStateReset(t *testing.T) {
	state := mustNewState(t)

	// Modify state
	state.Mode = "encrypt"
	state.Working = true
	state.Password = "secret"
	state.Keyfiles = []string{"key1", "key2"}
	state.Paranoid = true
	state.ShowProgress = true

	// Reset
	state.Reset()

	// Check all fields are reset
	if state.Mode != "" {
		t.Errorf("Mode = %q; want empty", state.Mode)
	}
	if state.Working {
		t.Error("Working should be false")
	}
	if state.Password != "" {
		t.Error("Password should be empty")
	}
	if len(state.Keyfiles) != 0 {
		t.Error("Keyfiles should be empty")
	}
	if state.Paranoid {
		t.Error("Paranoid should be false")
	}
	if state.ShowProgress {
		t.Error("ShowProgress should be false")
	}

	// Check defaults are restored
	if state.MainStatus != "Ready" {
		t.Errorf("MainStatus = %q; want 'Ready'", state.MainStatus)
	}
	if state.MainStatusKind != MainStatusReady {
		t.Errorf("MainStatusKind = %v; want MainStatusReady", state.MainStatusKind)
	}
	if state.CommentsPreviewState != CommentsPreviewNormal {
		t.Errorf("CommentsPreviewState = %v; want CommentsPreviewNormal", state.CommentsPreviewState)
	}
}

func TestStateResetUI(t *testing.T) {
	state := mustNewState(t)

	// Set progress-related flags that ResetUI must PRESERVE (the delta vs Reset).
	state.Working = true
	state.ShowProgress = true
	state.CanCancel = true

	// Set other state that ResetUI must clear.
	state.Mode = "encrypt"
	state.Password = "secret"

	// ResetUI preserves the progress flags; Reset clears them.
	// Swapping this call to state.Reset() must turn the assertions below RED.
	state.ResetUI()

	// Progress-related flags: ResetUI must NOT touch these.
	if !state.Working {
		t.Error("Working should be preserved by ResetUI (Reset clears it; ResetUI does not)")
	}
	if !state.ShowProgress {
		t.Error("ShowProgress should be preserved by ResetUI (Reset clears it; ResetUI does not)")
	}
	if !state.CanCancel {
		t.Error("CanCancel should be preserved by ResetUI (Reset clears it; ResetUI does not)")
	}

	// Other state should be reset by both Reset and ResetUI.
	if state.Mode != "" {
		t.Errorf("Mode = %q; want empty", state.Mode)
	}
	if state.Password != "" {
		t.Error("Password should be empty")
	}
}

// TestStateResetUIVsReset asserts the exact behavioral delta between ResetUI and
// Reset: Reset clears Working, ShowProgress, CanCancel, and Scanning; ResetUI
// preserves all four. A test that passes whether we call Reset or ResetUI is not
// a real test (Rule 9). This test pins the delta so swapping Reset↔ResetUI
// makes it FAIL. ModalID is preserved by both; it is not part of the delta.
func TestStateResetUIVsReset(t *testing.T) {
	// Verify Reset DOES clear the progress flags (control group).
	t.Run("Reset clears progress flags", func(t *testing.T) {
		s := mustNewState(t)
		s.Working = true
		s.ShowProgress = true
		s.CanCancel = true
		s.Scanning = true

		s.Reset()

		if s.Working {
			t.Error("Reset: Working should be false after Reset")
		}
		if s.ShowProgress {
			t.Error("Reset: ShowProgress should be false after Reset")
		}
		if s.CanCancel {
			t.Error("Reset: CanCancel should be false after Reset")
		}
		if s.Scanning {
			t.Error("Reset: Scanning should be false after Reset")
		}
	})

	// Verify ResetUI does NOT clear the same flags.
	t.Run("ResetUI preserves progress flags", func(t *testing.T) {
		s := mustNewState(t)
		s.Working = true
		s.ShowProgress = true
		s.CanCancel = true
		s.Scanning = true

		s.ResetUI()

		if !s.Working {
			t.Error("ResetUI: Working should remain true (only Reset clears it)")
		}
		if !s.ShowProgress {
			t.Error("ResetUI: ShowProgress should remain true (only Reset clears it)")
		}
		if !s.CanCancel {
			t.Error("ResetUI: CanCancel should remain true (only Reset clears it)")
		}
		if !s.Scanning {
			t.Error("ResetUI: Scanning should remain true (only Reset clears it)")
		}
	})
}

func TestStateResetAfterOperation(t *testing.T) {
	state := mustNewState(t)

	state.Working = true
	state.ShowProgress = true
	state.CanCancel = true
	state.Progress = 0.75
	state.ProgressInfo = "75%"

	state.ResetAfterOperation()

	if state.Working {
		t.Error("Working should be false")
	}
	if state.ShowProgress {
		t.Error("ShowProgress should be false")
	}
	if state.CanCancel {
		t.Error("CanCancel should be false")
	}
	if state.Progress != 0 {
		t.Errorf("Progress = %f; want 0", state.Progress)
	}
	if state.ProgressInfo != "" {
		t.Errorf("ProgressInfo = %q; want empty", state.ProgressInfo)
	}
}

func TestIsEncryptingDecrypting(t *testing.T) {
	state := mustNewState(t)

	// Initially neither
	if state.IsEncrypting() {
		t.Error("Should not be encrypting initially")
	}
	if state.IsDecrypting() {
		t.Error("Should not be decrypting initially")
	}

	// Set encrypt mode
	state.Mode = "encrypt"
	if !state.IsEncrypting() {
		t.Error("Should be encrypting")
	}
	if state.IsDecrypting() {
		t.Error("Should not be decrypting in encrypt mode")
	}

	// Set decrypt mode
	state.Mode = "decrypt"
	if state.IsEncrypting() {
		t.Error("Should not be encrypting in decrypt mode")
	}
	if !state.IsDecrypting() {
		t.Error("Should be decrypting")
	}
}

func TestCanStart(t *testing.T) {
	state := mustNewState(t)

	// No credentials
	if state.CanStart() {
		t.Error("Should not be able to start without credentials")
	}

	// With password only
	state.Password = "secret"
	if !state.CanStart() {
		t.Error("Should be able to start with password")
	}

	// New v2 encryption with keyfiles is frozen until the reviewed v3 writer.
	state.Mode = "encrypt"
	state.Password = ""
	state.CPassword = ""
	state.Keyfiles = []string{"keyfile.bin"}
	if state.CanStart() {
		t.Error("Should not be able to start new encryption with keyfiles only")
	}
	state.Password = "secret"
	state.CPassword = "secret"
	if state.CanStart() {
		t.Error("Should not be able to start new encryption with password and keyfiles")
	}

	// Legacy v1/v2 keyfile volumes remain decryptable.
	state.Mode = "decrypt"
	state.Password = ""
	if !state.CanStart() {
		t.Error("Decrypt mode should accept legacy keyfile-only credentials")
	}

	// Encrypt mode with mismatched passwords
	state.Mode = "encrypt"
	state.Keyfiles = nil
	state.Password = "secret"
	state.CPassword = "different"
	if state.CanStart() {
		t.Error("Should not be able to start with mismatched passwords")
	}

	// Encrypt mode with matching passwords
	state.CPassword = "secret"
	if !state.CanStart() {
		t.Error("Should be able to start with matching passwords")
	}

	// Decrypt mode ignores CPassword
	state.Mode = "decrypt"
	state.CPassword = "different"
	if !state.CanStart() {
		t.Error("Decrypt mode should not check password confirmation")
	}
}

func TestCanStartPreservesLegacyKeyfileDecryptionButFreezesV2Writer(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode string
		want bool
	}{
		{
			name: "new encryption is rejected",
			mode: "encrypt",
			want: false,
		},
		{
			name: "legacy decryption remains available",
			mode: "decrypt",
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := mustNewState(t)
			state.Mode = tc.mode
			state.Deniability = true
			state.Password = ""
			state.CPassword = ""
			state.Keyfiles = []string{"keyfile.bin"}

			if got := state.CanStart(); got != tc.want {
				t.Fatalf("State.CanStart() = %v; want %v for %s with a legacy keyfile credential", got, tc.want, tc.mode)
			}
			if got := state.UISnapshot().CanStart(); got != tc.want {
				t.Fatalf("UISnapshot.CanStart() = %v; want %v for %s with a legacy keyfile credential", got, tc.want, tc.mode)
			}
		})
	}
}

func TestTogglePasswordVisibility(t *testing.T) {
	state := mustNewState(t)

	// Initially hidden
	if state.PasswordMode != PasswordModeHidden {
		t.Error("Should start hidden")
	}

	// Toggle to visible
	state.TogglePasswordVisibility()
	if state.PasswordMode != PasswordModeVisible {
		t.Error("Should be visible after toggle")
	}

	// Toggle back to hidden
	state.TogglePasswordVisibility()
	if state.PasswordMode != PasswordModeHidden {
		t.Error("Should be hidden after second toggle")
	}
}

func TestTogglePasswordVisibilityIgnoresLegacyDisplayLabel(t *testing.T) {
	state := mustNewState(t)
	state.PasswordMode = PasswordModeHidden

	// A localized or stale display label must not control password visibility.
	// Use reflection so the regression guard survives removal of the legacy field.
	if label := reflect.ValueOf(state).Elem().FieldByName("PasswordStateLabel"); label.IsValid() && label.CanSet() {
		label.SetString("localized-show")
	}

	state.TogglePasswordVisibility()

	if state.PasswordMode != PasswordModeVisible {
		t.Fatalf("PasswordMode = %v; want PasswordModeVisible when toggling from hidden regardless of display label", state.PasswordMode)
	}
}

func TestIsPasswordHidden(t *testing.T) {
	state := mustNewState(t)

	if !state.IsPasswordHidden() {
		t.Error("Password should be hidden initially")
	}

	state.PasswordMode = PasswordModeVisible
	if state.IsPasswordHidden() {
		t.Error("Password should not be hidden when visible")
	}
}

func TestKeyfileSemanticState(t *testing.T) {
	state := mustNewState(t)

	state.Keyfile = false
	state.Keyfiles = nil
	if state.Keyfile {
		t.Fatal("Keyfile should be false before a required-keyfile header is seen")
	}
	if len(state.Keyfiles) != 0 {
		t.Fatalf("Keyfiles = %v; want none", state.Keyfiles)
	}

	state.Keyfile = true
	if !state.Keyfile {
		t.Fatal("Keyfile should hold the required-keyfile semantic flag")
	}

	state.Keyfiles = []string{"key1.bin"}
	if len(state.Keyfiles) != 1 {
		t.Fatalf("Keyfiles = %v; want one selected keyfile", state.Keyfiles)
	}

	state.Keyfiles = []string{"key1.bin", "key2.bin", "key3.bin"}
	if len(state.Keyfiles) != 3 {
		t.Fatalf("Keyfiles = %v; want three selected keyfiles", state.Keyfiles)
	}
}

// TestSetStatus pins the binding between SetStatus's two args and the two fields it
// writes. Two DISTINCT non-default rows ({text, color} pairs that differ in BOTH
// components) are required so the test fails if SetStatus ignores an arg, writes a
// constant, or swaps text↔color (a single row that happened to match a default could
// not catch a no-op). Both fields are asserted independently per row.
func TestSetStatus(t *testing.T) {
	tests := []struct {
		name  string
		text  string
		color color.RGBA
	}{
		{name: "working/red", text: "Working…", color: util.RED},
		{name: "done/green", text: "Done", color: util.GREEN},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := mustNewState(t)
			state.SetStatus(tt.text, tt.color)

			if state.MainStatus != tt.text {
				t.Errorf("MainStatus = %q; want %q", state.MainStatus, tt.text)
			}
			if state.MainStatusKind != MainStatusCustom {
				t.Errorf("MainStatusKind = %v; want MainStatusCustom after SetStatus", state.MainStatusKind)
			}
			if state.MainStatusColor != tt.color {
				t.Errorf("MainStatusColor = %v; want %v", state.MainStatusColor, tt.color)
			}
		})
	}
}

func TestSetReadyStatusMarksReadySemanticKind(t *testing.T) {
	state := mustNewState(t)
	state.SetStatus("Working", util.RED)

	state.SetReadyStatus()

	if state.MainStatusKind != MainStatusReady {
		t.Fatalf("MainStatusKind = %v; want MainStatusReady", state.MainStatusKind)
	}
	if state.MainStatus != "Ready" {
		t.Fatalf("MainStatus = %q; want Ready display fallback", state.MainStatus)
	}
	if state.MainStatusColor != util.WHITE {
		t.Fatalf("MainStatusColor = %v; want WHITE", state.MainStatusColor)
	}
}

// TestSetPopupStatus pins that SetPopupStatus writes its arg AND that a later call
// overwrites an earlier value. The second sequential write ("B" after "A") is the
// load-bearing assertion: a set-once mutation (writing only when empty) or one that
// ignores its arg would keep "A" and fail here, where a single write could not tell
// "stored the arg" from "stored a constant that happened to match".
func TestSetPopupStatus(t *testing.T) {
	state := mustNewState(t)

	state.SetPopupStatus("A")
	if state.PopupStatus != "A" {
		t.Errorf("PopupStatus = %q; want %q", state.PopupStatus, "A")
	}

	state.SetPopupStatus("B")
	if state.PopupStatus != "B" {
		t.Errorf("PopupStatus = %q after second write; want %q (the setter must overwrite, not set-once)", state.PopupStatus, "B")
	}
}

func TestSemanticDisplayDefaultsAndReset(t *testing.T) {
	state := mustNewState(t)

	snap := state.UISnapshot()
	if snap.InputSummary.Kind != InputSummaryDropPrompt {
		t.Fatalf("InputSummary.Kind = %v; want InputSummaryDropPrompt", snap.InputSummary.Kind)
	}
	if snap.StartAction != StartActionStart {
		t.Fatalf("StartAction = %v; want StartActionStart", snap.StartAction)
	}
	if snap.Status.Kind != StatusReady {
		t.Fatalf("Status.Kind = %v; want StatusReady", snap.Status.Kind)
	}

	state.SetInputSelection(2, 1, 4096, true)
	state.SetStartAction(StartActionEncrypt)
	state.SetStatusMessage(StatusCompleted, util.GREEN, StatusArgs{})
	state.ResetUI()

	snap = state.UISnapshot()
	if snap.InputSummary.Kind != InputSummaryDropPrompt {
		t.Fatalf("InputSummary.Kind after ResetUI = %v; want InputSummaryDropPrompt", snap.InputSummary.Kind)
	}
	if snap.StartAction != StartActionStart {
		t.Fatalf("StartAction after ResetUI = %v; want StartActionStart", snap.StartAction)
	}
	if snap.Status.Kind != StatusReady {
		t.Fatalf("Status.Kind after ResetUI = %v; want StatusReady", snap.Status.Kind)
	}
}

func TestSemanticDisplaySettersReachUISnapshot(t *testing.T) {
	state := mustNewState(t)

	state.SetInputSelection(3, 2, 12345, true)
	state.SetStartAction(StartActionZipAndEncrypt)
	state.SetStatusMessage(StatusProcessingFile, util.YELLOW, StatusArgs{Index: 2, Total: 5})
	state.SetPopupStatusMessage(StatusRecursiveCompleted, StatusArgs{Count: 4})

	snap := state.UISnapshot()
	if snap.InputSummary != (InputSummary{Kind: InputSummarySelection, Files: 3, Folders: 2, SizeBytes: 12345, ShowSize: true}) {
		t.Fatalf("InputSummary = %#v; want selection summary", snap.InputSummary)
	}
	if snap.StartAction != StartActionZipAndEncrypt {
		t.Fatalf("StartAction = %v; want StartActionZipAndEncrypt", snap.StartAction)
	}
	if snap.Status.Kind != StatusProcessingFile || snap.Status.Args.Index != 2 || snap.Status.Args.Total != 5 {
		t.Fatalf("Status = %#v; want processing file 2/5", snap.Status)
	}
	if snap.PopupStatus.Kind != StatusRecursiveCompleted || snap.PopupStatus.Args.Count != 4 {
		t.Fatalf("PopupStatus = %#v; want recursive completed count 4", snap.PopupStatus)
	}
}

func TestCustomStatusRemainsRawText(t *testing.T) {
	state := mustNewState(t)

	state.SetCustomStatus("volume error from lower layer", util.RED)
	state.SetPopupStatusText("Encrypting...")

	snap := state.UISnapshot()
	if snap.Status.Kind != StatusCustom || snap.Status.Text != "volume error from lower layer" {
		t.Fatalf("Status = %#v; want custom lower-layer text", snap.Status)
	}
	if snap.PopupStatus.Kind != StatusCustom || snap.PopupStatus.Text != "Encrypting..." {
		t.Fatalf("PopupStatus = %#v; want custom reporter text", snap.PopupStatus)
	}
}

// TestSetProgress pins both args of SetProgress to their fields. Two rows with
// distinct fraction AND info (0.0/"0%" and 1.0/"100%") catch an arg-swap (fraction
// vs info are different types so a swap won't compile, but a constant fraction or a
// dropped info would slip past a single row), a constant return, or a dropped write.
func TestSetProgress(t *testing.T) {
	tests := []struct {
		name     string
		fraction float32
		info     string
	}{
		{name: "zero", fraction: 0.0, info: "0%"},
		{name: "full", fraction: 1.0, info: "100%"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := mustNewState(t)
			state.SetProgress(tt.fraction, tt.info)

			if state.Progress != tt.fraction {
				t.Errorf("Progress = %f; want %f", state.Progress, tt.fraction)
			}
			if state.ProgressInfo != tt.info {
				t.Errorf("ProgressInfo = %q; want %q", state.ProgressInfo, tt.info)
			}
		})
	}
}

func TestGenPassword(t *testing.T) {
	state := mustNewState(t)

	// Set passgen options
	state.PassgenLength = 20
	state.PassgenUpper = true
	state.PassgenLower = true
	state.PassgenNums = true
	state.PassgenSymbols = false
	state.PassgenCopy = false

	password := state.GenPassword()

	if len(password) != 20 {
		t.Errorf("Password length = %d; want 20", len(password))
	}

	// Should not contain symbols
	for _, ch := range password {
		if ch == '-' || ch == '=' || ch == '_' || ch == '+' || ch == '!' {
			t.Error("Password should not contain symbols")
		}
	}
}

func TestGenPasswordNoOptions(t *testing.T) {
	state := mustNewState(t)

	// No character sets enabled
	state.PassgenLength = 10
	state.PassgenUpper = false
	state.PassgenLower = false
	state.PassgenNums = false
	state.PassgenSymbols = false
	state.PassgenCopy = false

	password := state.GenPassword()

	if password != "" {
		t.Errorf("Password = %q; want empty when no char sets", password)
	}
}

func TestStateConcurrency(t *testing.T) {
	state := mustNewState(t)

	var wg sync.WaitGroup
	iterations := 100

	// Concurrent reads
	wg.Add(iterations)
	for range iterations {
		go func() {
			defer wg.Done()
			_ = state.IsEncrypting()
			_ = state.IsDecrypting()
			_ = state.CanStart()
			_ = state.IsPasswordHidden()
		}()
	}

	// Concurrent writes
	wg.Add(iterations)
	for i := range iterations {
		go func(i int) {
			defer wg.Done()
			state.SetStatus("Test", util.WHITE)
			state.SetPopupStatus("Status")
			state.SetProgress(float32(i)/float32(iterations), "")
			state.SetCanCancel(i%2 == 0)
			state.TogglePasswordVisibility()
		}(i)
	}

	wg.Wait()
	t.Log("Concurrent access completed without deadlock")
}

// TestPasswordInputModeConstants verifies the named PasswordInputMode constants
// are wired correctly into their consumers, rather than asserting the trivial
// iota distinctness (0 != 1). It pins two bindings: NewState initializes
// PasswordMode to PasswordModeHidden, and IsPasswordHidden tracks the named
// constant at each value. This catches a consumer that hard-codes a literal or
// returns a constant answer.
//
// Residual overlap with TestIsPasswordHidden is minimal and intentional: that
// test exercises IsPasswordHidden in isolation, while this one ties the named
// constants to both the constructor default and the predicate together — the
// binding the original tautology failed to assert.
func TestPasswordInputModeConstants(t *testing.T) {
	state := mustNewState(t)

	// Constructor default is bound to the named constant, not a bare literal.
	if state.PasswordMode != PasswordModeHidden {
		t.Errorf("NewState PasswordMode = %d; want PasswordModeHidden (%d)", state.PasswordMode, PasswordModeHidden)
	}
	if !state.IsPasswordHidden() {
		t.Error("IsPasswordHidden() = false at PasswordModeHidden; want true")
	}

	// One toggle flips to the visible constant; the predicate must follow it.
	state.TogglePasswordVisibility()
	if state.PasswordMode != PasswordModeVisible {
		t.Errorf("after toggle PasswordMode = %d; want PasswordModeVisible (%d)", state.PasswordMode, PasswordModeVisible)
	}
	if state.IsPasswordHidden() {
		t.Error("IsPasswordHidden() = true at PasswordModeVisible; want false")
	}
}

// TestPassgenCopyDefaultsOff asserts PassgenCopy defaults to false both on
// construction and after Reset, so generated passwords are NOT auto-copied to
// the OS clipboard (clipboard sync / history is a strong-secret leak). The
// Copy buttons remain for explicit user action; only the default is changed.
func TestPassgenCopyDefaultsOff(t *testing.T) {
	t.Run("NewState", func(t *testing.T) {
		s := mustNewState(t)
		if s.PassgenCopy {
			t.Fatal("PassgenCopy must default to false — do not auto-copy generated passwords to the clipboard")
		}
	})
	t.Run("after Reset", func(t *testing.T) {
		s := mustNewState(t)
		s.PassgenCopy = true // simulate user enabling it
		s.Reset()
		if s.PassgenCopy {
			t.Fatal("PassgenCopy must be false after Reset — Reset must not restore the old auto-copy default")
		}
	})
}

// TestPassgenCharClassesDefaultOn asserts the four password-generator character
// classes default to ON, and — crucially — that NewState() agrees with Reset().
// resetUILocked() sets all four true, but a freshly-constructed State (before any
// ResetUI) must too: otherwise the generator dialog opens with every class
// unchecked and Generate is a no-op (dialogs.go guards against zero classes).
// This is a desync tripwire between the construction literal and the reset path,
// mirroring TestPassgenCopyDefaultsOff for the opposite-default sibling field.
func TestPassgenCharClassesDefaultOn(t *testing.T) {
	classes := func(s *State) [4]bool {
		return [4]bool{s.PassgenUpper, s.PassgenLower, s.PassgenNums, s.PassgenSymbols}
	}
	want := [4]bool{true, true, true, true}

	t.Run("NewState", func(t *testing.T) {
		if got := classes(mustNewState(t)); got != want {
			t.Fatalf("NewState passgen classes = %v; want %v — a fresh State must have all classes ON so the generator works before any reset", got, want)
		}
	})
	t.Run("agrees with Reset", func(t *testing.T) {
		s := mustNewState(t)
		s.PassgenUpper, s.PassgenLower, s.PassgenNums, s.PassgenSymbols = false, false, false, false
		s.Reset()
		if got := classes(s); got != want {
			t.Fatalf("after Reset passgen classes = %v; want %v", got, want)
		}
	})
}
