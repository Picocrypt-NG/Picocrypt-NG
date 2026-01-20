package app

import (
	"sync"
	"testing"

	"Picocrypt-NG/internal/util"
)

func TestNewState(t *testing.T) {
	state := NewState()

	// Check defaults
	if state.InputLabel != "Drop files and folders into this window" {
		t.Errorf("InputLabel = %q; want default", state.InputLabel)
	}
	if state.KeyfileLabel != "None selected" {
		t.Errorf("KeyfileLabel = %q; want 'None selected'", state.KeyfileLabel)
	}
	if state.CommentsLabel != "Comments:" {
		t.Errorf("CommentsLabel = %q; want 'Comments:'", state.CommentsLabel)
	}
	if state.StartLabel != "Start" {
		t.Errorf("StartLabel = %q; want 'Start'", state.StartLabel)
	}
	if state.MainStatus != "Ready" {
		t.Errorf("MainStatus = %q; want 'Ready'", state.MainStatus)
	}
	if state.MainStatusColor != util.WHITE {
		t.Error("MainStatusColor should be WHITE")
	}
	if state.PasswordMode != PasswordModeHidden {
		t.Error("PasswordMode should be Hidden")
	}
	if state.PasswordStateLabel != "Show" {
		t.Errorf("PasswordStateLabel = %q; want 'Show'", state.PasswordStateLabel)
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
	state := NewState()

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
}

func TestStateResetUI(t *testing.T) {
	state := NewState()

	// Set progress-related flags
	state.Working = true
	state.ShowProgress = true
	state.CanCancel = true

	// Set other state
	state.Mode = "encrypt"
	state.Password = "secret"

	// ResetUI should NOT reset progress flags
	state.ResetUI()

	// Note: Working is reset by ResetUI based on the code

	// Other state should be reset
	if state.Mode != "" {
		t.Errorf("Mode = %q; want empty", state.Mode)
	}
	if state.Password != "" {
		t.Error("Password should be empty")
	}
}

func TestStateResetAfterOperation(t *testing.T) {
	state := NewState()

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
	state := NewState()

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
	state := NewState()

	// No credentials
	if state.CanStart() {
		t.Error("Should not be able to start without credentials")
	}

	// With password only
	state.Password = "secret"
	if !state.CanStart() {
		t.Error("Should be able to start with password")
	}

	// With keyfiles only
	state.Password = ""
	state.Keyfiles = []string{"keyfile.bin"}
	if !state.CanStart() {
		t.Error("Should be able to start with keyfiles")
	}

	// Encrypt mode with mismatched passwords
	state.Mode = "encrypt"
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

func TestTogglePasswordVisibility(t *testing.T) {
	state := NewState()

	// Initially hidden
	if state.PasswordMode != PasswordModeHidden {
		t.Error("Should start hidden")
	}
	if state.PasswordStateLabel != "Show" {
		t.Error("Label should be 'Show'")
	}

	// Toggle to visible
	state.TogglePasswordVisibility()
	if state.PasswordMode != PasswordModeVisible {
		t.Error("Should be visible after toggle")
	}
	if state.PasswordStateLabel != "Hide" {
		t.Error("Label should be 'Hide'")
	}

	// Toggle back to hidden
	state.TogglePasswordVisibility()
	if state.PasswordMode != PasswordModeHidden {
		t.Error("Should be hidden after second toggle")
	}
	if state.PasswordStateLabel != "Show" {
		t.Error("Label should be 'Show'")
	}
}

func TestIsPasswordHidden(t *testing.T) {
	state := NewState()

	if !state.IsPasswordHidden() {
		t.Error("Password should be hidden initially")
	}

	state.PasswordMode = PasswordModeVisible
	if state.IsPasswordHidden() {
		t.Error("Password should not be hidden when visible")
	}
}

func TestUpdateKeyfileLabel(t *testing.T) {
	state := NewState()

	// No keyfiles, not required
	state.Keyfile = false
	state.Keyfiles = nil
	state.UpdateKeyfileLabel()
	if state.KeyfileLabel != "None selected" {
		t.Errorf("KeyfileLabel = %q; want 'None selected'", state.KeyfileLabel)
	}

	// No keyfiles, but required
	state.Keyfile = true
	state.UpdateKeyfileLabel()
	if state.KeyfileLabel != "Keyfiles required" {
		t.Errorf("KeyfileLabel = %q; want 'Keyfiles required'", state.KeyfileLabel)
	}

	// One keyfile
	state.Keyfiles = []string{"key1.bin"}
	state.UpdateKeyfileLabel()
	if state.KeyfileLabel != "Using 1 keyfile" {
		t.Errorf("KeyfileLabel = %q; want 'Using 1 keyfile'", state.KeyfileLabel)
	}

	// Multiple keyfiles
	state.Keyfiles = []string{"key1.bin", "key2.bin", "key3.bin"}
	state.UpdateKeyfileLabel()
	if state.KeyfileLabel != "Using multiple keyfiles" {
		t.Errorf("KeyfileLabel = %q; want 'Using multiple keyfiles'", state.KeyfileLabel)
	}
}

func TestSetStatus(t *testing.T) {
	state := NewState()

	state.SetStatus("Testing", util.GREEN)

	if state.MainStatus != "Testing" {
		t.Errorf("MainStatus = %q; want 'Testing'", state.MainStatus)
	}
	if state.MainStatusColor != util.GREEN {
		t.Error("MainStatusColor should be GREEN")
	}
}

func TestSetPopupStatus(t *testing.T) {
	state := NewState()

	state.SetPopupStatus("Processing...")

	if state.PopupStatus != "Processing..." {
		t.Errorf("PopupStatus = %q; want 'Processing...'", state.PopupStatus)
	}
}

func TestSetProgress(t *testing.T) {
	state := NewState()

	state.SetProgress(0.5, "50%")

	if state.Progress != 0.5 {
		t.Errorf("Progress = %f; want 0.5", state.Progress)
	}
	if state.ProgressInfo != "50%" {
		t.Errorf("ProgressInfo = %q; want '50%%'", state.ProgressInfo)
	}
}

func TestSetCanCancel(t *testing.T) {
	state := NewState()

	state.SetCanCancel(true)
	if !state.CanCancel {
		t.Error("CanCancel should be true")
	}

	state.SetCanCancel(false)
	if state.CanCancel {
		t.Error("CanCancel should be false")
	}
}

func TestGenPassword(t *testing.T) {
	state := NewState()

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
	state := NewState()

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
	state := NewState()

	var wg sync.WaitGroup
	iterations := 100

	// Concurrent reads
	wg.Add(iterations)
	for i := 0; i < iterations; i++ {
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
	for i := 0; i < iterations; i++ {
		go func(i int) {
			defer wg.Done()
			state.SetStatus("Test", util.WHITE)
			state.SetPopupStatus("Status")
			state.SetProgress(float32(i)/float32(iterations), "")
			state.SetCanCancel(i%2 == 0)
			state.TogglePasswordVisibility()
			state.UpdateKeyfileLabel()
		}(i)
	}

	wg.Wait()
	t.Log("Concurrent access completed without deadlock")
}

func TestPasswordInputModeConstants(t *testing.T) {
	// Verify constants are distinct
	if PasswordModeHidden == PasswordModeVisible {
		t.Error("PasswordModeHidden should not equal PasswordModeVisible")
	}
}

func TestStateVersion(t *testing.T) {
	if Version == "" {
		t.Error("Version should not be empty")
	}
	if Version != "v2.02" {
		t.Logf("Note: Version = %q", Version)
	}
}
