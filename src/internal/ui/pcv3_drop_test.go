package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/pcv3operation"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	fynetest "fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
)

func loadPCV3DropFixture(t *testing.T) []byte {
	t.Helper()
	fixture, err := os.ReadFile(filepath.Join("..", "pcv3operation", "internal", "pcv3", "testdata", "schema1-minimal.pcv"))
	if err != nil {
		t.Fatalf("read literal PCV3 fixture: %v", err)
	}
	return fixture
}

func TestPCV3DropAcceptsNormalSplitFromAnyChunk(t *testing.T) {
	resetLocalizationForTest(t)
	dir := t.TempDir()
	base := filepath.Join(dir, "normal.pcv")
	if err := os.WriteFile(base, loadPCV3DropFixture(t), 0o600); err != nil {
		t.Fatalf("write normal PCV3 fixture: %v", err)
	}
	chunks, err := fileops.Split(fileops.SplitOptions{
		InputPath: base,
		ChunkSize: 1,
		Unit:      fileops.SplitUnitKiB,
	})
	if err != nil || len(chunks) < 2 {
		t.Fatalf("split normal PCV3 fixture: chunks=%d err=%v", len(chunks), err)
	}
	if err := os.Remove(base); err != nil {
		t.Fatalf("remove unsplit fixture: %v", err)
	}

	a := createUIReadyDropTestApp(t, newTestFyneApp(t))
	t.Cleanup(func() {
		a.workers.wait()
		fyne.DoAndWait(func() { a.State.Reset() })
	})
	fyne.DoAndWait(func() { a.onDrop([]string{chunks[1]}) })
	waitForDropProcessing(t, a)
	snap := a.State.UISnapshot()
	if snap.PCV3Route != app.PCV3RouteReady || snap.PCV3Format != app.PCV3FormatNormal ||
		!snap.Recombine || snap.InputFile != base || snap.OutputFile != strings.TrimSuffix(base, ".pcv") {
		t.Fatalf("normal PCV3 split route = %#v", snap)
	}
}

func TestPCV3DropKeepsExplicitD1OverrideForNormalLookingSplit(t *testing.T) {
	resetLocalizationForTest(t)
	dir := t.TempDir()
	base := filepath.Join(dir, "collision.pcv")
	if err := os.WriteFile(base+".0", []byte{'P', 'C', 'V', 0, 1, 2, 3, 4}, 0o600); err != nil {
		t.Fatalf("write normal-looking D1 chunk zero: %v", err)
	}
	if err := os.WriteFile(base+".1", []byte{5, 6, 7, 8}, 0o600); err != nil {
		t.Fatalf("write D1 chunk one: %v", err)
	}

	a := createUIReadyDropTestApp(t, newTestFyneApp(t))
	t.Cleanup(func() {
		a.workers.wait()
		fyne.DoAndWait(func() { a.State.Reset() })
	})
	fyne.DoAndWait(func() { a.onDrop([]string{base + ".1"}) })
	waitForDropProcessing(t, a)

	fyne.DoAndWait(func() {
		snap := a.State.UISnapshot()
		if snap.PCV3Route != app.PCV3RouteReady || snap.PCV3Format != app.PCV3FormatNormal || !snap.Recombine {
			t.Fatalf("normal-looking split route = %#v", snap)
		}
		if findPCV3Button(a.advancedContainer, tr("pcv3.format.d1_action", "Open as PCV3 D1")) != nil {
			t.Fatal("recognized Normal volume exposes D1 as a primary action")
		}
		menu := openPCV3FormatMenu(t, a)
		menu.TypedKey(&fyne.KeyEvent{Name: fyne.KeyDown})
		menu.TypedKey(&fyne.KeyEvent{Name: fyne.KeyReturn})
		snap = a.State.UISnapshot()
		if snap.PCV3Format != app.PCV3FormatD1 || !snap.Recombine || snap.InputFile != base ||
			snap.OutputFile != strings.TrimSuffix(base, ".pcv") || snap.PCV3Action != app.PCV3ActionDecrypt {
			t.Fatalf("explicit D1 override changed split intent: %#v", snap)
		}
	})
}

func TestPCV3FormatMenuRejectsStaleSelection(t *testing.T) {
	a := newPCV3ReadUI(t, app.PCV3FormatNormal)
	input := filepath.Join(t.TempDir(), "new-input.txt")
	if err := os.WriteFile(input, []byte("new public selection"), 0o600); err != nil {
		t.Fatal(err)
	}
	var menu *widget.PopUpMenu
	fyne.DoAndWait(func() {
		a.setAdvancedDisclosureOpen(true)
		menu = openPCV3FormatMenu(t, a)
		a.onDrop([]string{input})
	})
	waitForDropProcessing(t, a)
	fyne.DoAndWait(func() {
		menu.TypedKey(&fyne.KeyEvent{Name: fyne.KeyDown})
		menu.TypedKey(&fyne.KeyEvent{Name: fyne.KeyReturn})
		snap := a.State.UISnapshot()
		if snap.Mode != "encrypt" || snap.PCV3Format != app.PCV3FormatNone || snap.InputFile != input {
			t.Error("old format menu changed the newly selected file")
		}
	})
}

func TestExplicitD1ClearsLegacyHeaderNoticeAndPreservesCleanupWarning(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "pcv3operation", "internal", "pcv3", "testdata", "d1", "independent", "d1.pcv"))
	if err != nil {
		t.Fatal(err)
	}
	a := createUIReadyDropTestApp(t, newTestFyneApp(t))
	t.Cleanup(func() { fyne.DoAndWait(a.State.Reset) })
	input := filepath.Join(t.TempDir(), "input.pcv")
	if err := os.WriteFile(input, data, 0o600); err != nil {
		t.Fatal(err)
	}
	fyne.DoAndWait(func() { a.onDrop([]string{input}) })
	waitForDropProcessing(t, a)
	fyne.DoAndWait(func() {
		kind := a.State.UISnapshot().Status.Kind
		if kind != app.StatusDropHeaderMayBeDeniable && kind != app.StatusDropHeaderDamaged {
			t.Fatalf("D1 did not reach the legacy header notice: %v", kind)
		}
		a.State.LatchPCV3CleanupIncomplete()
		a.updateUIState()
		a.setAdvancedDisclosureOpen(true)
		button := findPCV3Button(a.advancedContainer, tr("pcv3.format.d1_action", "Open as PCV3 D1"))
		if button == nil {
			t.Fatal("unidentified file lost the explicit D1 action")
		}
		fynetest.Tap(button)
		snap := a.State.UISnapshot()
		if snap.PCV3Format != app.PCV3FormatD1 || snap.Status.Kind != app.StatusReady || !snap.PCV3CleanupIncomplete {
			t.Error("explicit D1 did not replace the obsolete header notice while preserving cleanup state")
		}
		requirePCV3Text(t, a.pcv3Container, "Cleanup could not be confirmed")
	})
}

func waitForPCV3UI(t *testing.T, condition func() bool, failure string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		matched := false
		fyne.DoAndWait(func() { matched = condition() })
		if matched {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(failure)
}

func findPCV3Button(object fyne.CanvasObject, text string) *widget.Button {
	if button, ok := object.(*widget.Button); ok && button.Text == text {
		return button
	}
	if popup, ok := object.(*widget.PopUp); ok {
		return findPCV3Button(popup.Content, text)
	}
	if container, ok := object.(*fyne.Container); ok {
		for _, child := range container.Objects {
			if button := findPCV3Button(child, text); button != nil {
				return button
			}
		}
	}
	return nil
}

func TestPCV3FyneDefaultsToDecryptAndRequiresLiveConsent(t *testing.T) {
	resetLocalizationForTest(t)

	t.Run("content routing stays pending then defaults to ordinary decryption", func(t *testing.T) {
		previousProbe := probeDroppedPCVInput
		previousPreview := previewDroppedHeader
		entered := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		var legacyPreviewCalls atomic.Int32
		probeDroppedPCVInput = func(source io.ReaderAt, size int64) (pcv3operation.Route, error) {
			once.Do(func() { close(entered) })
			<-release
			return previousProbe(source, size)
		}
		previewDroppedHeader = func(reader io.Reader, codecs *encoding.RSCodecs) (*header.ReadResult, error) {
			legacyPreviewCalls.Add(1)
			return previousPreview(reader, codecs)
		}
		t.Cleanup(func() {
			probeDroppedPCVInput = previousProbe
			previewDroppedHeader = previousPreview
		})

		dir := t.TempDir()
		input := filepath.Join(dir, "misleading.txt")
		if err := os.WriteFile(input, loadPCV3DropFixture(t), 0o600); err != nil {
			t.Fatalf("write PCV3 input: %v", err)
		}
		fyneApp := newTestFyneApp(t)
		a := createUIReadyDropTestApp(t, fyneApp)
		fyne.DoAndWait(func() { a.onDrop([]string{input}) })
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("content detector did not run asynchronously")
		}
		fyne.DoAndWait(func() {
			snap := a.State.UISnapshot()
			if snap.PCV3Route != app.PCV3RouteChecking || !snap.Scanning || !a.startButton.Disabled() {
				t.Fatalf("pending route = route %v scanning %v startDisabled %v", snap.PCV3Route, snap.Scanning, a.startButton.Disabled())
			}
			if a.pcv3Container == nil || len(a.pcv3Container.Objects) != 1 {
				t.Fatal("pending route did not render one bounded checking state")
			}
		})
		close(release)
		waitForPCV3UI(t, func() bool {
			return a.State.UISnapshot().PCV3Route == app.PCV3RouteReady
		}, "content-routed PCV3 did not become ready")
		fyne.DoAndWait(func() {
			snap := a.State.UISnapshot()
			if snap.PCV3Format != app.PCV3FormatNormal || snap.PCV3Action != app.PCV3ActionDecrypt ||
				snap.PCV3Factor != app.PCV3FactorPolicyUnset || !a.startButton.Disabled() {
				t.Fatalf("ordinary read defaults: %#v", snap)
			}
			if !a.State.SelectPCV3D1() {
				t.Fatal("explicit D1 action refused retained descriptor")
			}
			a.updateAdvancedSection()
			a.updateUIState()
			if got := a.State.UISnapshot().PCV3Format; got != app.PCV3FormatD1 {
				t.Fatalf("explicit D1 format = %v", got)
			}
		})
		if legacyPreviewCalls.Load() != 0 {
			t.Fatalf("content-claimed PCV3 reached legacy preview %d times", legacyPreviewCalls.Load())
		}
	})

	t.Run("dismissal refuses the one live core consent without KDF or output", func(t *testing.T) {
		dir := t.TempDir()
		input := filepath.Join(dir, "d1-input.bin")
		output := filepath.Join(dir, "recovery.pcv3-recovery")
		if err := os.WriteFile(input, nil, 0o600); err != nil {
			t.Fatalf("write D1 input: %v", err)
		}
		source, err := os.Open(input)
		if err != nil {
			t.Fatalf("open D1 input: %v", err)
		}
		fyneApp := newTestFyneApp(t)
		a := createUIReadyDropTestApp(t, fyneApp)
		fyne.DoAndWait(func() {
			if !a.State.SetPCV3Ready(source, app.PCV3FormatD1, input, output, 0) {
				t.Fatal("set D1 selection")
			}
			a.State.Password = "consent-only password"
			a.State.SetPCV3Intent(app.PCV3ActionForceUnverified, app.PCV3FactorPolicyPassword, app.PCV3KeyfileOrderUnset)
			a.refreshAdvanced()
			a.updateUIState()
			a.startPCV3Work()
		})
		var cancel *widget.Button
		waitForPCV3UI(t, func() bool {
			focused, ok := a.Window.Canvas().Focused().(*widget.Button)
			if !ok || focused.Text != tr("pcv3.consent.cancel", "Cancel recovery") {
				return false
			}
			cancel = focused
			return true
		}, "live consent did not focus its safe-default cancellation")
		fyne.DoAndWait(func() { fynetest.Tap(cancel) })
		waitForPCV3UI(t, func() bool { return !a.State.IsWorking() }, "consent dismissal did not terminate operation")
		fyne.DoAndWait(func() {
			snap := a.State.UISnapshot()
			if snap.PCV3Result.Diagnostic() != pcv3operation.DiagnosticCredentialPolicy ||
				snap.PCV3Result.PublicationAttempted() {
				t.Fatalf("dismissed consent result = diagnostic %v attempted %v", snap.PCV3Result.Diagnostic(), snap.PCV3Result.PublicationAttempted())
			}
			if !a.startButton.Disabled() {
				t.Fatal("dismissed consent restored start authority")
			}
		})
		if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("dismissed consent created output: %v", err)
		}
	})
}

func TestPCV3DropKeepsRoutedDescriptorAcrossPathReplacement(t *testing.T) {
	resetLocalizationForTest(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "input.pcv")
	backup := filepath.Join(dir, "original.pcv")
	replacement := filepath.Join(dir, "replacement.pcv")
	legacy, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "pico_test_v2.txt.pcv"))
	if err != nil {
		t.Fatalf("read legacy fixture: %v", err)
	}
	if err := os.WriteFile(input, legacy, 0o600); err != nil {
		t.Fatalf("write legacy input: %v", err)
	}
	if err := os.WriteFile(replacement, loadPCV3DropFixture(t), 0o600); err != nil {
		t.Fatalf("write replacement: %v", err)
	}

	previousOpen := openDroppedPCVInput
	var openCalls atomic.Int32
	openDroppedPCVInput = func(path string, split bool) (*os.File, error) {
		file, openErr := previousOpen(path, split)
		if openErr != nil {
			return nil, openErr
		}
		openCalls.Add(1)
		if renameErr := os.Rename(path, backup); renameErr != nil {
			_ = file.Close()
			return nil, renameErr
		}
		if renameErr := os.Rename(replacement, path); renameErr != nil {
			_ = file.Close()
			return nil, renameErr
		}
		return file, nil
	}
	t.Cleanup(func() { openDroppedPCVInput = previousOpen })

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	fyne.DoAndWait(func() { a.onDrop([]string{input}) })
	waitForDropProcessing(t, a)
	if openCalls.Load() != 1 {
		t.Fatalf("selection opened %d descriptors; want exactly one", openCalls.Load())
	}
	fyne.DoAndWait(func() {
		snap := a.State.UISnapshot()
		if runtime.GOOS == "windows" && snap.PCV3Route == app.PCV3RouteFailed {
			t.Skip("Windows denied replacement of an open descriptor")
		}
		if snap.PCV3Route != app.PCV3RouteNone || snap.Mode != "decrypt" {
			t.Fatalf("routed original changed family after pathname replacement: %#v", snap)
		}
		if !a.State.SelectPCV3D1() {
			t.Fatal("legacy-eligible descriptor was not retained for explicit D1")
		}
	})
	got, readErr := os.ReadFile(backup)
	if readErr != nil || !bytes.Equal(got, legacy) {
		t.Fatalf("original selection changed: len=%d err=%v", len(got), readErr)
	}
}

// TestPCV3DropSplitRoutingPreservesLegacyCompatibility protects a real legacy
// split and a user-selected chunk-zero symlink through legacy routing.
func TestPCV3DropSplitRoutingPreservesLegacyCompatibility(t *testing.T) {
	resetLocalizationForTest(t)
	legacy, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "pico_test_v2.txt.pcv"))
	if err != nil {
		t.Fatalf("read frozen legacy volume: %v", err)
	}
	if len(legacy) <= 800 {
		t.Fatalf("frozen legacy volume is too small for a complete header chunk: %d", len(legacy))
	}

	t.Run("regular chunks", func(t *testing.T) {
		dir := t.TempDir()
		base := filepath.Join(dir, "legacy.pcv")
		if err := os.WriteFile(base+".0", legacy[:800], 0o600); err != nil {
			t.Fatalf("write legacy chunk zero: %v", err)
		}
		selected := base + ".1"
		if err := os.WriteFile(selected, legacy[800:], 0o600); err != nil {
			t.Fatalf("write legacy chunk one: %v", err)
		}
		a := createUIReadyDropTestApp(t, newTestFyneApp(t))
		t.Cleanup(func() { a.State.Reset() })

		fyne.DoAndWait(func() { a.onDrop([]string{selected}) })
		waitForDropProcessing(t, a)
		var snap app.UISnapshot
		fyne.DoAndWait(func() { snap = a.State.UISnapshot() })
		if snap.PCV3Route != app.PCV3RouteNone || snap.Mode != "decrypt" || !snap.Recombine ||
			snap.InputFile != base || snap.OutputFile != trimPCVSuffix(base) {
			t.Fatalf("legacy split compatibility route changed: %#v", snap)
		}
	})

	t.Run("selected chunk-zero symlink", func(t *testing.T) {
		dir := t.TempDir()
		base := filepath.Join(dir, "legacy-link.pcv")
		selected := base + ".0"
		target, err := filepath.Abs(filepath.Join("..", "..", "testdata", "golden", "pico_test_v2.txt.pcv"))
		if err != nil {
			t.Fatalf("resolve frozen legacy volume: %v", err)
		}
		if err := os.Symlink(target, selected); err != nil {
			t.Skipf("chunk-zero symlinks unavailable: %v", err)
		}
		if err := os.WriteFile(base+".1", nil, 0o600); err != nil {
			t.Fatalf("write later chunk: %v", err)
		}
		a := createUIReadyDropTestApp(t, newTestFyneApp(t))
		t.Cleanup(func() { a.State.Reset() })

		fyne.DoAndWait(func() { a.onDrop([]string{selected}) })
		waitForDropProcessing(t, a)
		var snap app.UISnapshot
		var retainedD1 bool
		fyne.DoAndWait(func() {
			snap = a.State.UISnapshot()
			retainedD1 = a.State.SelectPCV3D1()
		})
		if snap.PCV3Route != app.PCV3RouteNone || snap.Mode != "decrypt" || !snap.Recombine ||
			snap.InputFile != base || snap.OutputFile != trimPCVSuffix(base) {
			t.Fatalf("chunk-zero symlink compatibility route changed: %#v", snap)
		}
		if retainedD1 {
			t.Fatal("legacy-compatible chunk-zero symlink retained explicit D1 authority")
		}
	})
}
