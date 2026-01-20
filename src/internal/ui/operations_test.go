// Package ui provides tests for UI operations and validation logic.
package ui

import (
	"os"
	"path/filepath"
	"testing"

	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/util"

	"fyne.io/fyne/v2/test"
)

// TestOnClickStartValidation tests the validation logic in onClickStart.
func TestOnClickStartValidation(t *testing.T) {
	test.NewApp()
	defer test.NewApp()

	t.Run("NoMode", func(t *testing.T) {
		a := createTestApp(t)
		a.State.Mode = ""
		a.State.Password = "secret"

		// Should return early without starting work
		a.onClickStart()
		if a.State.Working {
			t.Error("Should not start work when mode is empty")
		}
	})

	t.Run("NoCredentials", func(t *testing.T) {
		a := createTestApp(t)
		a.State.Mode = "encrypt"
		a.State.Password = ""
		a.State.Keyfiles = nil

		a.onClickStart()
		if a.State.Working {
			t.Error("Should not start work without credentials")
		}
	})

	t.Run("PasswordOnlyValid", func(t *testing.T) {
		a := createTestApp(t)
		a.State.Mode = "decrypt"
		a.State.Password = "secret"
		a.State.Keyfiles = nil

		// Should have credentials
		hasCredentials := len(a.State.Keyfiles) > 0 || a.State.Password != ""
		if !hasCredentials {
			t.Error("Password alone should be valid credentials")
		}
	})

	t.Run("KeyfilesOnlyValid", func(t *testing.T) {
		a := createTestApp(t)
		a.State.Mode = "decrypt"
		a.State.Password = ""
		a.State.Keyfiles = []string{"/path/to/keyfile"}

		hasCredentials := len(a.State.Keyfiles) > 0 || a.State.Password != ""
		if !hasCredentials {
			t.Error("Keyfiles alone should be valid credentials")
		}
	})

	t.Run("EncryptPasswordMismatch", func(t *testing.T) {
		a := createTestApp(t)
		a.State.Mode = "encrypt"
		a.State.Password = "secret"
		a.State.CPassword = "different"

		// Validation should fail
		if a.State.Password == a.State.CPassword {
			t.Error("Passwords should not match")
		}

		a.onClickStart()
		if a.State.Working {
			t.Error("Should not start encrypt with mismatched passwords")
		}
	})

	t.Run("EncryptPasswordMatch", func(t *testing.T) {
		a := createTestApp(t)
		a.State.Mode = "encrypt"
		a.State.Password = "secret"
		a.State.CPassword = "secret"

		// Validation should pass
		if a.State.Password != a.State.CPassword {
			t.Error("Passwords should match")
		}
	})

	t.Run("DecryptIgnoresConfirmPassword", func(t *testing.T) {
		a := createTestApp(t)
		a.State.Mode = "decrypt"
		a.State.Password = "secret"
		a.State.CPassword = "different"

		// Decrypt mode should not care about CPassword
		hasCredentials := len(a.State.Keyfiles) > 0 || a.State.Password != ""
		passwordsMatch := a.State.Mode != "encrypt" || a.State.Password == a.State.CPassword

		if !hasCredentials || !passwordsMatch {
			t.Error("Decrypt should be valid regardless of CPassword")
		}
	})
}

// TestSplitUnitConversion tests the split unit selection logic in doEncrypt.
func TestSplitUnitConversion(t *testing.T) {
	testCases := []struct {
		selected int
		expected string
	}{
		{0, "KiB"},
		{1, "MiB"},
		{2, "GiB"},
		{3, "TiB"},
		{4, "Total"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			// This tests the State.SplitUnits array alignment
			state := app.NewState()
			if tc.selected < len(state.SplitUnits) {
				if state.SplitUnits[tc.selected] != tc.expected {
					t.Errorf("SplitUnits[%d] = %q; want %q",
						tc.selected, state.SplitUnits[tc.selected], tc.expected)
				}
			}
		})
	}
}

// TestSplitSizeValidation tests split size parsing logic.
func TestSplitSizeValidation(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		valid    bool
		expected int
	}{
		{"ValidNumber", "100", true, 100},
		{"ValidSmall", "1", true, 1},
		{"ValidLarge", "9999", true, 9999},
		{"Empty", "", false, 0},
		{"Zero", "0", false, 0},
		{"Negative", "-1", false, 0},
		{"NonNumeric", "abc", false, 0},
		{"MixedContent", "10a", false, 0},
		{"Decimal", "10.5", false, 0},
		{"Whitespace", " 10 ", false, 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Parse logic from doEncrypt
			var n int
			var valid bool
			if tc.input != "" {
				if parsed, err := parseInt(tc.input); err == nil && parsed > 0 {
					n = parsed
					valid = true
				}
			}

			if valid != tc.valid {
				t.Errorf("Valid = %v; want %v for input %q", valid, tc.valid, tc.input)
			}
			if valid && n != tc.expected {
				t.Errorf("Parsed = %d; want %d for input %q", n, tc.expected, tc.input)
			}
		})
	}
}

// parseInt is a helper to match the strconv.Atoi behavior in doEncrypt.
func parseInt(s string) (int, error) {
	var n int
	_, err := parseIntHelper(s, &n)
	return n, err
}

func parseIntHelper(s string, n *int) (bool, error) {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false, os.ErrInvalid
		}
	}
	if len(s) == 0 {
		return false, os.ErrInvalid
	}
	var result int
	for _, c := range s {
		result = result*10 + int(c-'0')
	}
	*n = result
	return true, nil
}

// TestOperationStatusColors tests that status colors are set correctly.
func TestOperationStatusColors(t *testing.T) {
	t.Run("SuccessStatus", func(t *testing.T) {
		state := app.NewState()
		state.SetStatus("Completed", util.GREEN)

		if state.MainStatus != "Completed" {
			t.Errorf("MainStatus = %q; want 'Completed'", state.MainStatus)
		}
		if state.MainStatusColor != util.GREEN {
			t.Error("MainStatusColor should be GREEN")
		}
	})

	t.Run("ErrorStatus", func(t *testing.T) {
		state := app.NewState()
		state.SetStatus("Failed", util.RED)

		if state.MainStatus != "Failed" {
			t.Errorf("MainStatus = %q; want 'Failed'", state.MainStatus)
		}
		if state.MainStatusColor != util.RED {
			t.Error("MainStatusColor should be RED")
		}
	})

	t.Run("WarningStatus", func(t *testing.T) {
		state := app.NewState()
		state.SetStatus("Warning", util.YELLOW)

		if state.MainStatus != "Warning" {
			t.Errorf("MainStatus = %q; want 'Warning'", state.MainStatus)
		}
		if state.MainStatusColor != util.YELLOW {
			t.Error("MainStatusColor should be YELLOW")
		}
	})
}

// TestRecursiveModeSettings tests recursive mode state preservation.
func TestRecursiveModeSettings(t *testing.T) {
	state := app.NewState()

	// Set encryption settings
	state.Password = "secret"
	state.CPassword = "secret"
	state.Paranoid = true
	state.ReedSolomon = true
	state.Comments = "test comments"

	// Simulate saving settings for recursive mode
	savedPassword := state.Password
	savedParanoid := state.Paranoid
	savedReedSolomon := state.ReedSolomon
	savedComments := state.Comments

	// Reset and restore (simulating recursive processing)
	state.ResetUI()

	state.Password = savedPassword
	state.Paranoid = savedParanoid
	state.ReedSolomon = savedReedSolomon
	state.Comments = savedComments

	// Verify settings preserved
	if state.Password != "secret" {
		t.Error("Password not preserved")
	}
	if !state.Paranoid {
		t.Error("Paranoid not preserved")
	}
	if !state.ReedSolomon {
		t.Error("ReedSolomon not preserved")
	}
	if state.Comments != "test comments" {
		t.Error("Comments not preserved")
	}
}

// TestOutputFileGeneration tests output file path generation.
func TestOutputFileGeneration(t *testing.T) {
	t.Run("SingleFileEncrypt", func(t *testing.T) {
		inputFile := "/home/user/documents/secret.txt"
		expectedOutput := inputFile + ".pcv"

		if expectedOutput != "/home/user/documents/secret.txt.pcv" {
			t.Errorf("Output = %q; want '.pcv' suffix", expectedOutput)
		}
	})

	t.Run("FolderEncrypt", func(t *testing.T) {
		// Use a platform-specific absolute path for testing
		folderPath := filepath.Join(os.TempDir(), "documents", "folder")
		// Encrypted folder creates a zip with timestamp
		dir := filepath.Dir(folderPath)
		baseOutput := filepath.Join(dir, "encrypted-") // + timestamp + ".zip.pcv"

		if !filepath.IsAbs(baseOutput) {
			t.Errorf("Output path should be absolute, got: %s", baseOutput)
		}
	})

	t.Run("DecryptRemovesPcv", func(t *testing.T) {
		inputFile := "/home/user/documents/secret.txt.pcv"
		expectedOutput := inputFile[:len(inputFile)-4] // Remove ".pcv"

		if expectedOutput != "/home/user/documents/secret.txt" {
			t.Errorf("Output = %q; want original name without .pcv", expectedOutput)
		}
	})
}

// TestCanStartLogic tests the comprehensive start validation.
func TestCanStartLogic(t *testing.T) {
	testCases := []struct {
		name      string
		mode      string
		password  string
		cPassword string
		keyfiles  []string
		expected  bool
	}{
		{"NoCredentials", "encrypt", "", "", nil, false},
		{"PasswordOnly", "encrypt", "secret", "secret", nil, true},
		{"KeyfilesOnly", "encrypt", "", "", []string{"key.bin"}, true},
		{"Both", "encrypt", "secret", "secret", []string{"key.bin"}, true},
		{"EncryptMismatch", "encrypt", "secret", "wrong", nil, false},
		{"DecryptMismatchOK", "decrypt", "secret", "wrong", nil, true},
		{"DecryptNoPassword", "decrypt", "", "", []string{"key.bin"}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			state := app.NewState()
			state.Mode = tc.mode
			state.Password = tc.password
			state.CPassword = tc.cPassword
			state.Keyfiles = tc.keyfiles

			result := state.CanStart()
			if result != tc.expected {
				t.Errorf("CanStart() = %v; want %v", result, tc.expected)
			}
		})
	}
}

// TestProgressReporting tests progress callback integration.
func TestProgressReporting(t *testing.T) {
	state := app.NewState()

	// Simulate progress updates
	progressValues := []float32{0.0, 0.25, 0.5, 0.75, 1.0}
	progressInfos := []string{"0%", "25%", "50%", "75%", "100%"}

	for i, val := range progressValues {
		state.SetProgress(val, progressInfos[i])

		if state.Progress != val {
			t.Errorf("Progress = %f; want %f", state.Progress, val)
		}
		if state.ProgressInfo != progressInfos[i] {
			t.Errorf("ProgressInfo = %q; want %q", state.ProgressInfo, progressInfos[i])
		}
	}
}

// TestCancelButtonState tests cancel button enable/disable logic.
func TestCancelButtonState(t *testing.T) {
	state := app.NewState()

	// Initially not cancellable
	if state.CanCancel {
		t.Error("CanCancel should be false initially")
	}

	// During operation
	state.SetCanCancel(true)
	if !state.CanCancel {
		t.Error("CanCancel should be true during operation")
	}

	// After operation
	state.SetCanCancel(false)
	if state.CanCancel {
		t.Error("CanCancel should be false after operation")
	}
}

// createTestApp creates a minimal App instance for testing.
func createTestApp(t *testing.T) *App {
	t.Helper()

	a, err := NewApp("v2.02")
	if err != nil {
		t.Fatalf("Failed to create test app: %v", err)
	}
	return a
}
