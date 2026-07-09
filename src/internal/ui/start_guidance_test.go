package ui

import (
	"os"
	"path/filepath"
	"testing"

	"fyne.io/fyne/v2"
)

func TestStartHintExplainsNoFiles(t *testing.T) {
	newTestFyneApp(t)

	a := createTestApp(t)
	a.State.Mode = "encrypt"

	got := a.startReadinessHint(a.State.UISnapshot())
	want := tr("start.hint.noFiles", "Add files or folders to continue.")
	if got != want {
		t.Fatalf("startReadinessHint() = %q; want %q", got, want)
	}
}

func TestStartHintExplainsScanning(t *testing.T) {
	newTestFyneApp(t)

	a := createTestApp(t)
	a.State.Mode = "encrypt"
	a.State.InputFile = "input.txt"
	a.State.Scanning = true

	got := a.startReadinessHint(a.State.UISnapshot())
	want := tr("start.hint.scanning", "Scanning files; wait before starting.")
	if got != want {
		t.Fatalf("startReadinessHint() = %q; want %q", got, want)
	}
}

func TestStartHintExplainsMissingCredentials(t *testing.T) {
	newTestFyneApp(t)

	a := createTestApp(t)
	a.State.Mode = "encrypt"
	a.State.InputFile = "input.txt"
	a.State.AllFiles = []string{"input.txt"}
	a.State.OnlyFiles = []string{"input.txt"}

	got := a.startReadinessHint(a.State.UISnapshot())
	want := tr("start.hint.enterPasswordOrKeyfiles", "Enter a password or add keyfiles.")
	if got != want {
		t.Fatalf("startReadinessHint() = %q; want %q", got, want)
	}
}

func TestStartHintExplainsPasswordMismatch(t *testing.T) {
	newTestFyneApp(t)

	a := createTestApp(t)
	a.State.Mode = "encrypt"
	a.State.InputFile = "input.txt"
	a.State.AllFiles = []string{"input.txt"}
	a.State.OnlyFiles = []string{"input.txt"}
	a.State.Password = "secret"
	a.State.CPassword = "different"

	got := a.startReadinessHint(a.State.UISnapshot())
	want := tr("start.hint.passwordMismatch", "Passwords do not match.")
	if got != want {
		t.Fatalf("startReadinessHint() = %q; want %q", got, want)
	}
}

func TestStartHintExplainsInvalidSplitSize(t *testing.T) {
	newTestFyneApp(t)

	a := createTestApp(t)
	a.State.Mode = "encrypt"
	a.State.InputFile = "input.txt"
	a.State.AllFiles = []string{"input.txt"}
	a.State.OnlyFiles = []string{"input.txt"}
	a.State.Password = "secret"
	a.State.CPassword = "secret"
	a.State.Split = true
	a.State.SplitSize = "0"

	got := a.startReadinessHint(a.State.UISnapshot())
	want := tr("start.hint.invalidSplitSize", "Choose a positive split size.")
	if got != want {
		t.Fatalf("startReadinessHint() = %q; want %q", got, want)
	}
}

func TestOnClickStartDoesNotRunWhenDisabled(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	outputFile := filepath.Join(t.TempDir(), "output.pcv")
	if err := os.WriteFile(outputFile, []byte("existing output"), 0o600); err != nil {
		t.Fatalf("write output: %v", err)
	}

	a.State.Mode = "encrypt"
	a.State.InputFile = "input.txt"
	a.State.AllFiles = []string{"input.txt"}
	a.State.OnlyFiles = []string{"input.txt"}
	a.State.OutputFile = outputFile

	fyne.DoAndWait(func() {
		a.updateAdvancedSection()
		a.updateUIState()
		a.onClickStart()
	})

	if a.State.ShowOverwrite {
		t.Fatal("onClickStart() should not open the overwrite modal when Start is disabled")
	}
	if a.State.Working || a.State.ShowProgress {
		t.Fatal("onClickStart() should not start work when Start is disabled")
	}
}

func TestOutputChangeEnabledBeforeCredentialsAfterFileSelection(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	a.State.Mode = "encrypt"
	a.State.InputFile = "a.txt"
	a.State.AllFiles = []string{"a.txt", "b.txt"}
	a.State.OnlyFiles = []string{"a.txt", "b.txt"}
	a.State.OutputFile = "a.txt.pcv"

	fyne.DoAndWait(func() {
		a.updateAdvancedSection()
		a.updateUIState()
	})

	if a.changeBtn == nil || a.changeBtn.Disabled() {
		t.Fatal("Change output button should stay enabled once input is selected, even before credentials")
	}
	for _, tc := range []struct {
		name     string
		disabled func() bool
	}{
		{"Paranoid mode", a.paranoidCheck.Disabled},
		{"Compress files", a.compressCheck.Disabled},
		{"Reed-Solomon", a.reedSolomonCheck.Disabled},
		{"Deniability", a.deniabilityCheck.Disabled},
		{"Recursively", a.recursivelyCheck.Disabled},
		{"Split", a.splitCheck.Disabled},
		{"Split size", a.splitSizeEntry.Disabled},
		{"Split units", a.splitUnitSelect.Disabled},
	} {
		if tc.disabled() {
			t.Fatalf("%s should stay enabled once input is selected, even before credentials", tc.name)
		}
	}
	if a.startButton == nil || !a.startButton.Disabled() {
		t.Fatal("Start button should remain disabled until credentials are ready")
	}
	if a.startHintLabel == nil {
		t.Fatal("startHintLabel was not built")
	}
	wantHint := tr("start.hint.enterPasswordOrKeyfiles", "Enter a password or add keyfiles.")
	if got := a.startHintLabel.Text; got != wantHint {
		t.Fatalf("startHintLabel.Text = %q; want %q", got, wantHint)
	}
}
