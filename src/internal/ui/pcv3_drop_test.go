package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3operation"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
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
	fixture, err := os.ReadFile(filepath.Join("..", "pcv3", "testdata", "schema1-minimal.pcv"))
	if err != nil {
		t.Fatalf("read literal PCV3 fixture: %v", err)
	}
	return fixture
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

func TestPCV3FyneRequiresExplicitModeAndLiveConsent(t *testing.T) {
	resetLocalizationForTest(t)

	t.Run("content routing stays pending and never infers operation intent", func(t *testing.T) {
		previousProbe := probeDroppedPCVInput
		previousPreview := previewDroppedHeader
		entered := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		var legacyPreviewCalls atomic.Int32
		probeDroppedPCVInput = func(source io.ReaderAt, size int64) (pcv3.Route, pcv3.Structure, error) {
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
			if snap.PCV3Format != app.PCV3FormatNormal || snap.PCV3Action != app.PCV3ActionNone ||
				snap.PCV3Factor != app.PCV3FactorPolicyUnset || !a.startButton.Disabled() {
				t.Fatalf("detector inferred intent: %#v", snap)
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
			a.State.SetPCV3Intent(app.PCV3ActionForce, app.PCV3FactorPolicyPassword, app.PCV3KeyfileOrderUnset)
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

// TestPCV3DropRejectsNormalFormatInLegacySplitSelection protects the split
// authority boundary. Chunk zero classifies a legacy split, but its descriptor
// must never authorize a normal PCV3 operation whose visible input and target
// are derived from a different selected chunk.
func TestPCV3DropRejectsNormalFormatInLegacySplitSelection(t *testing.T) {
	resetLocalizationForTest(t)
	dir := t.TempDir()
	base := filepath.Join(dir, "claimed.pcv")
	chunkZero := base + ".0"
	selected := base + ".1"
	if err := os.WriteFile(chunkZero, loadPCV3DropFixture(t), 0o600); err != nil {
		t.Fatalf("write normal PCV3 chunk zero: %v", err)
	}
	if err := os.WriteFile(selected, []byte("legacy-looking later chunk"), 0o600); err != nil {
		t.Fatalf("write selected later chunk: %v", err)
	}

	previousOpen := openDroppedPCVInput
	opened := make(chan *os.File, 1)
	var openCalls atomic.Int32
	openDroppedPCVInput = func(path string, split bool) (*os.File, error) {
		source, err := previousOpen(path, split)
		if err == nil {
			openCalls.Add(1)
			select {
			case opened <- source:
			default:
			}
		}
		return source, err
	}
	t.Cleanup(func() { openDroppedPCVInput = previousOpen })

	a := createUIReadyDropTestApp(t, newTestFyneApp(t))
	t.Cleanup(func() { a.State.Reset() })
	fyne.DoAndWait(func() { a.onDrop([]string{selected}) })
	waitForDropProcessing(t, a)

	var routed *os.File
	select {
	case routed = <-opened:
	default:
		t.Fatal("drop did not open authoritative chunk zero")
	}
	if got := openCalls.Load(); got != 1 {
		t.Fatalf("drop opened %d routing descriptors; want one authoritative chunk-zero descriptor", got)
	}
	var snap app.UISnapshot
	var startDisabled, retainedD1 bool
	fyne.DoAndWait(func() {
		snap = a.State.UISnapshot()
		startDisabled = a.startButton.Disabled()
		retainedD1 = a.State.SelectPCV3D1()
	})
	if snap.PCV3Route != app.PCV3RouteFailed || snap.PCV3Format != app.PCV3FormatNone ||
		snap.OutputFile != "" || snap.CanStart() || !startDisabled {
		t.Fatalf("split normal-PCV3 route retained operation authority: %#v", snap)
	}
	if retainedD1 {
		t.Fatal("rejected split normal-PCV3 route retained explicit D1 authority")
	}
	if _, err := routed.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("rejected chunk-zero descriptor remains open: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read split directory: %v", err)
	}
	if len(entries) != 2 || entries[0].Name() != filepath.Base(chunkZero) || entries[1].Name() != filepath.Base(selected) {
		t.Fatalf("rejected split selection created filesystem artifacts: %v", entries)
	}
}

// TestPCV3DropSplitRoutingPreservesLegacyCompatibility protects the paths that
// remain valid after the normal-PCV3 split rejection: a real legacy split and
// a user-selected chunk-zero symlink both continue through legacy routing.
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
