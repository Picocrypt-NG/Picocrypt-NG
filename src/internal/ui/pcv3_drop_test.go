package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"fyne.io/fyne/v2"
)

const pcv3DesktopUnavailable = "This PCV volume is not supported by this version. Keep the original file; no output was created."

func loadPCV3DropFixture(t *testing.T) []byte {
	t.Helper()
	fixture, err := os.ReadFile(filepath.Join("..", "pcv3", "testdata", "schema1-minimal.pcv"))
	if err != nil {
		t.Fatalf("read literal PCV3 fixture: %v", err)
	}
	return fixture
}

func pcv3DropDirectoryNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read drop directory: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

func primePCV3DropWidgets(t *testing.T, a *App) {
	t.Helper()
	fyne.DoAndWait(func() {
		a.State.Mode = "decrypt"
		a.State.InputFile = "previous.zip.pcv"
		a.State.OnlyFiles = []string{"previous.zip.pcv"}
		a.State.Password = "stale-password"
		a.State.Comments = "stale-comment"
		a.State.Keyfile = true
		a.State.Keyfiles = []string{"stale-keyfile"}
		a.State.Deniability = false
		a.State.Keep = true
		a.State.OutputFile = "previous.zip"
		a.State.SetInputDecryptVolume()
		a.State.SetStartAction(app.StartActionDecrypt)
		a.refreshAdvanced()
		a.updateUIState()
		// Leave stale state that the atomic unavailable setter must clear, while
		// keeping the already-built Force widget observably enabled beforehand.
		a.State.Deniability = true
	})
	if a.forceDecryptCheck == nil {
		t.Fatal("failed to build real Force decrypt widget")
	}
	if a.forceDecryptCheck.Disabled() {
		t.Fatal("Force decrypt widget precondition is disabled")
	}
}

func assertPCV3UnavailableDrop(t *testing.T, a *App, input string, size int64) {
	t.Helper()
	fyne.DoAndWait(func() {
		snap := a.State.UISnapshot()
		if !snap.PCVUnavailable {
			t.Fatal("PCVUnavailable = false; claimed selection must be terminal")
		}
		if snap.Mode != "" || snap.OutputFile != "" || snap.Comments != "" || snap.Keyfile || snap.KeyfileCount != 0 {
			t.Fatalf("mode/output/metadata survived unavailable state: mode=%q output=%q comments=%q keyfile=%v count=%d",
				snap.Mode, snap.OutputFile, snap.Comments, snap.Keyfile, snap.KeyfileCount)
		}
		if snap.InputFile != input {
			t.Fatalf("InputFile = %q; want retained selected path %q", snap.InputFile, input)
		}
		if snap.InputSummary.Kind != app.InputSummarySelection || snap.InputSummary.Files != 1 ||
			snap.InputSummary.Folders != 0 || snap.InputSummary.SizeBytes != size || !snap.InputSummary.ShowSize {
			t.Fatalf("selected summary = %#v; want one selected file with size %d", snap.InputSummary, size)
		}
		if snap.Deniability || a.State.Keep || a.State.VerifyFirst || a.State.AutoUnzip || a.State.SameLevel {
			t.Fatalf("decrypt options survived unavailable state: deniability=%v force=%v verify=%v unzip=%v same=%v",
				snap.Deniability, a.State.Keep, a.State.VerifyFirst, a.State.AutoUnzip, a.State.SameLevel)
		}
		if snap.StartAction != app.StartActionStart || snap.CanStart() || a.State.CanStart() {
			t.Fatalf("start state = action %v snapshotCanStart=%v stateCanStart=%v; want terminal Start/false/false",
				snap.StartAction, snap.CanStart(), a.State.CanStart())
		}
		if snap.Scanning || snap.Working || snap.ShowProgress || a.State.Progress != 0 || a.State.CanCancel {
			t.Fatalf("progress state survived unavailable selection: scanning=%v working=%v shown=%v progress=%v cancel=%v",
				snap.Scanning, snap.Working, snap.ShowProgress, a.State.Progress, a.State.CanCancel)
		}
		if got := renderStatus(snap.Status, snap); got != pcv3DesktopUnavailable {
			t.Fatalf("rendered status = %q; want %q", got, pcv3DesktopUnavailable)
		}
		if a.statusLabel == nil {
			t.Fatal("status widget is nil")
		}
		if a.statusLabel.text != pcv3DesktopUnavailable {
			t.Fatalf("status widget = %q; want canonical unavailable copy", a.statusLabel.text)
		}
		if a.inputLabel == nil {
			t.Fatal("input summary widget is nil")
		}
		if a.inputLabel.Text != renderInputSummary(snap.InputSummary) {
			t.Fatalf("input summary widget = %q; want %q", a.inputLabel.Text, renderInputSummary(snap.InputSummary))
		}
		if a.startButton == nil || !a.startButton.Disabled() {
			t.Fatal("Start button is enabled for unavailable PCV selection")
		}
		if a.forceDecryptCheck == nil || !a.forceDecryptCheck.Disabled() {
			t.Fatal("Force decrypt widget is enabled for unavailable PCV selection")
		}
		if a.passwordEntry == nil || !a.passwordEntry.Disabled() {
			t.Fatal("credential input is enabled for unavailable PCV selection")
		}
		if a.startHintLabel != nil && a.startHintLabel.Visible() {
			t.Fatalf("unavailable selection shows unrelated start hint %q", a.startHintLabel.Text)
		}
	})
}

func TestPCV3DropRoutesBeforeFilenameClassification(t *testing.T) {
	previousLanguage := activeLanguage()
	if err := setActiveLanguage("en"); err != nil {
		t.Fatalf("set English language: %v", err)
	}
	t.Cleanup(func() { _ = setActiveLanguage(previousLanguage) })

	previousPreview := previewDroppedHeader
	previousDeniability := isDroppedVolumeDeniable
	previewCalls := 0
	deniabilityCalls := 0
	previewDroppedHeader = func(reader io.Reader, codecs *encoding.RSCodecs) (*header.ReadResult, error) {
		previewCalls++
		return previousPreview(reader, codecs)
	}
	isDroppedVolumeDeniable = func(path string, codecs *encoding.RSCodecs) bool {
		deniabilityCalls++
		return previousDeniability(path, codecs)
	}
	t.Cleanup(func() {
		previewDroppedHeader = previousPreview
		isDroppedVolumeDeniable = previousDeniability
	})

	fixture := loadPCV3DropFixture(t)

	t.Run("misleading txt name owns the unavailable state", func(t *testing.T) {
		fyneApp := newTestFyneApp(t)
		a := createUIReadyDropTestApp(t, fyneApp)
		primePCV3DropWidgets(t, a)

		dir := t.TempDir()
		input := filepath.Join(dir, "looks-like-plaintext.txt")
		potentialOutput := input + ".pcv"
		originalOutput := []byte("existing output sentinel")
		if err := os.WriteFile(input, fixture, 0o600); err != nil {
			t.Fatalf("write claimed input: %v", err)
		}
		if err := os.WriteFile(potentialOutput, originalOutput, 0o600); err != nil {
			t.Fatalf("write output sentinel: %v", err)
		}
		beforePreview, beforeDeniability := previewCalls, deniabilityCalls

		fyne.DoAndWait(func() { a.onDrop([]string{input}) })
		waitForDropProcessing(t, a)
		assertPCV3UnavailableDrop(t, a, input, int64(len(fixture)))
		if previewCalls != beforePreview || deniabilityCalls != beforeDeniability {
			t.Fatalf("claimed .txt reached legacy preview: preview=%d deniability=%d; want %d/%d",
				previewCalls, deniabilityCalls, beforePreview, beforeDeniability)
		}
		gotInput, err := os.ReadFile(input)
		if err != nil || !bytes.Equal(gotInput, fixture) {
			t.Fatalf("claimed input changed: len=%d err=%v", len(gotInput), err)
		}
		gotOutput, err := os.ReadFile(potentialOutput)
		if err != nil || !bytes.Equal(gotOutput, originalOutput) {
			t.Fatalf("existing output changed: %q err=%v", gotOutput, err)
		}
		if names := pcv3DropDirectoryNames(t, dir); len(names) != 2 {
			t.Fatalf("drop created filesystem artifacts: %v", names)
		}

		fyne.DoAndWait(func() {
			if err := a.SwitchLanguage("ru"); err != nil {
				t.Fatalf("switch language: %v", err)
			}
			snap := a.State.UISnapshot()
			if !snap.PCVUnavailable || snap.Status.Kind != app.StatusPCVUnavailable {
				t.Fatalf("language refresh cleared unavailable state: %#v", snap)
			}
			want := "Этот том PCV не поддерживается этой версией. Сохраните исходный файл; выходной файл не был создан."
			if got := renderStatus(snap.Status, snap); got != want || a.statusLabel.text != want {
				t.Fatalf("Russian unavailable status = %q / %q; want %q", got, a.statusLabel.text, want)
			}
			if err := a.SwitchLanguage("en"); err != nil {
				t.Fatalf("restore English: %v", err)
			}
		})

		legacy := filepath.Join(dir, "replacement.txt")
		if err := os.WriteFile(legacy, []byte("legacy eligible"), 0o600); err != nil {
			t.Fatalf("write replacement: %v", err)
		}
		fyne.DoAndWait(func() { a.onDrop([]string{legacy}) })
		waitForDropProcessing(t, a)
		fyne.DoAndWait(func() {
			snap := a.State.UISnapshot()
			if snap.PCVUnavailable || snap.Mode != "encrypt" || snap.InputFile != legacy {
				t.Fatalf("legacy replacement state = unavailable %v mode %q input %q", snap.PCVUnavailable, snap.Mode, snap.InputFile)
			}
		})

		fyne.DoAndWait(func() { a.onDrop([]string{input}) })
		waitForDropProcessing(t, a)
		fyne.DoAndWait(func() { a.clearButton.OnTapped() })
		fyne.DoAndWait(func() {
			snap := a.State.UISnapshot()
			if snap.PCVUnavailable || snap.InputSummary.Kind != app.InputSummaryDropPrompt || snap.InputFile != "" {
				t.Fatalf("clear left unavailable selection: unavailable=%v summary=%#v input=%q", snap.PCVUnavailable, snap.InputSummary, snap.InputFile)
			}
		})
	})

	t.Run("legacy-looking filename cannot reach legacy preview", func(t *testing.T) {
		fyneApp := newTestFyneApp(t)
		a := createUIReadyDropTestApp(t, fyneApp)
		primePCV3DropWidgets(t, a)
		dir := t.TempDir()
		input := filepath.Join(dir, "looks-like-legacy.pcv")
		if err := os.WriteFile(input, fixture, 0o600); err != nil {
			t.Fatalf("write claimed input: %v", err)
		}
		beforePreview, beforeDeniability := previewCalls, deniabilityCalls
		fyne.DoAndWait(func() { a.onDrop([]string{input}) })
		waitForDropProcessing(t, a)
		assertPCV3UnavailableDrop(t, a, input, int64(len(fixture)))
		if previewCalls != beforePreview || deniabilityCalls != beforeDeniability {
			t.Fatalf("claimed .pcv reached legacy preview: preview=%d deniability=%d; want %d/%d",
				previewCalls, deniabilityCalls, beforePreview, beforeDeniability)
		}
	})

	t.Run("partial and mismatched inputs keep legacy routing", func(t *testing.T) {
		for _, test := range []struct {
			name        string
			filename    string
			data        []byte
			wantMode    string
			wantPreview bool
		}{
			{name: "partial pcv filename", filename: "partial.pcv", data: []byte{'P', 'C', 'V'}, wantMode: "decrypt", wantPreview: true},
			{name: "mismatched txt filename", filename: "mismatch.txt", data: []byte{'P', 'C', 'X', 0}, wantMode: "encrypt"},
		} {
			t.Run(test.name, func(t *testing.T) {
				fyneApp := newTestFyneApp(t)
				a := createUIReadyDropTestApp(t, fyneApp)
				dir := t.TempDir()
				input := filepath.Join(dir, test.filename)
				if err := os.WriteFile(input, test.data, 0o600); err != nil {
					t.Fatalf("write legacy-eligible input: %v", err)
				}
				beforePreview := previewCalls
				fyne.DoAndWait(func() { a.onDrop([]string{input}) })
				waitForDropProcessing(t, a)
				fyne.DoAndWait(func() {
					snap := a.State.UISnapshot()
					if snap.PCVUnavailable || snap.Mode != test.wantMode {
						t.Fatalf("legacy-eligible route = unavailable %v mode %q; want false/%q", snap.PCVUnavailable, snap.Mode, test.wantMode)
					}
				})
				if got := previewCalls > beforePreview; got != test.wantPreview {
					t.Fatalf("legacy preview called = %v; want %v", got, test.wantPreview)
				}
			})
		}
	})

	t.Run("valid legacy volume still reaches both legacy probes", func(t *testing.T) {
		fyneApp := newTestFyneApp(t)
		a := createUIReadyDropTestApp(t, fyneApp)
		legacy, err := filepath.Abs(filepath.Join("..", "..", "testdata", "golden", "pico_test_v2.txt.pcv"))
		if err != nil {
			t.Fatalf("resolve legacy fixture: %v", err)
		}
		beforePreview, beforeDeniability := previewCalls, deniabilityCalls
		fyne.DoAndWait(func() { a.onDrop([]string{legacy}) })
		waitForDropProcessing(t, a)
		fyne.DoAndWait(func() {
			snap := a.State.UISnapshot()
			if snap.PCVUnavailable || snap.Mode != "decrypt" {
				t.Fatalf("legacy volume route = unavailable %v mode %q; want false/decrypt", snap.PCVUnavailable, snap.Mode)
			}
		})
		if previewCalls != beforePreview+1 || deniabilityCalls != beforeDeniability+1 {
			t.Fatalf("legacy probes = preview %d deniability %d; want %d/%d",
				previewCalls, deniabilityCalls, beforePreview+1, beforeDeniability+1)
		}
	})
}
