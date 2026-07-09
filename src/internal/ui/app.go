// Package ui provides the Picocrypt NG graphical user interface using Fyne.
//
// The UI is designed to match the original audited Picocrypt layout exactly, ensuring
// users familiar with the original application can transition seamlessly. Key features:
//
//   - Drag-and-drop file/folder selection
//   - Password strength indicator (using zxcvbn algorithm)
//   - Keyfile management (ordered and unordered modes)
//   - Advanced options: paranoid mode, Reed-Solomon, deniability, compression
//   - Real-time progress reporting with speed and ETA
//   - Automatic output file naming and format detection
//
// The UI state is managed by internal/app.State, which centralizes all application
// state in a thread-safe manner. Encryption/decryption operations run in goroutines
// with progress reported via the ProgressReporter interface.
//
// Code organization:
//   - app.go: Core UI setup, main layout, state updates
//   - password_section.go: Password input and strength indicator
//   - keyfile_section.go: Keyfile management
//   - advanced_section.go: Encrypt/decrypt options
//   - dialogs.go: Modal dialogs (passgen, progress, overwrite)
//   - operations.go: Encryption/decryption operations
//   - widgets.go: Custom Fyne widgets
//   - drop.go: Drag-and-drop handling
//   - mobile.go: Mobile-specific UI
//   - theme.go: Custom theme
package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/util"
	"context"
	_ "embed"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	fyneApp "fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	fynetooltip "github.com/dweymouth/fyne-tooltip"
	ttwidget "github.com/dweymouth/fyne-tooltip/widget"
)

//go:embed key.png
var appIconData []byte

// UI dimensions matching original giu implementation
const (
	windowWidth         = 340
	windowHeightEncrypt = 512 // Full height for encrypt mode (more options)
	windowHeightDecrypt = 430 // Reduced height for decrypt mode (fewer options)
	windowHeightInitial = 350 // Compact height for initial state (no advanced options)
	buttonWidth         = 54
	padding             = 4 // Reduced from 8 to match compact theme
	contentWidth        = windowWidth - padding*2
)

// App represents the main UI application.
type App struct {
	fyneApp fyne.App
	Window  fyne.Window
	Version string
	DPI     float32

	// Application state
	State *app.State

	// Reed-Solomon codecs
	rsCodecs *encoding.RSCodecs

	// Cancellation flag (atomic for thread safety across goroutines)
	cancelled atomic.Bool

	// macOS opened-path readiness session. It is used for Finder/Dock-opened
	// paths that may point at iCloud placeholders. It is separate from the global
	// AppleEvent buffer in macos_open.go.
	openReadinessMu            sync.Mutex
	openReadinessGeneration    uint64
	openReadinessCancel        context.CancelFunc
	openReadinessPaths         []string
	openReadinessCollectLate   bool
	openReadinessLastAppend    time.Time
	openReadinessSuppressUntil time.Time
	openReadinessAppliedPaths  []string
	openReadinessAppliedAt     time.Time

	// UI widgets that need to be updated
	inputLabel         *widget.Label
	clearButton        *widget.Button
	aboutButton        *widget.Button
	languageSelector   *languageSelector
	aboutVersionLabel  *widget.Label
	mainContent        *fyne.Container
	passwordLabel      *widget.Label
	passwordEntry      *PasswordEntry
	cPasswordEntry     *PasswordEntry
	strengthIndicator  *PasswordStrengthIndicator
	validIndicator     *ValidationIndicator
	keyfilesTitleLabel *widget.Label
	keyfileLabel       *widget.Label
	commentsLabel      *widget.Label
	commentsEntry      *widget.Entry
	advancedLabel      *widget.Label
	advancedContainer  *fyne.Container
	advancedToggleBtn  *widget.Button
	advancedDetail     fyne.CanvasObject
	advancedOpen       bool
	advancedOverridden bool
	outputLabel        *widget.Label
	outputEntry        interface{ SetText(string) }
	startButton        *widget.Button
	startHintLabel     *widget.Label
	statusLabel        *ColoredLabel

	// Confirm password section (hidden in decrypt mode)
	confirmLabel *widget.Label
	confirmRow   *fyne.Container

	// Advisory shown in encrypt mode when the password contains non-ASCII
	// characters (#19): normalized for cross-platform decryption, but the user
	// should be able to reproduce the same characters on other devices.
	nonASCIIHint *widget.Label

	// Password buttons
	showHideBtn *ttwidget.Button
	clearPwdBtn *ttwidget.Button
	copyBtn     *ttwidget.Button
	pasteBtn    *ttwidget.Button
	createBtn   *ttwidget.Button

	// Keyfile buttons
	keyfileEditBtn   *ttwidget.Button
	keyfileCreateBtn *ttwidget.Button

	// Output section
	changeBtn *widget.Button

	// Mobile file-selection controls
	mobileSelectFilesBtn  *widget.Button
	mobileSelectFolderBtn *widget.Button
	mobileAppStorageBtn   *widget.Button
	mobileAppStorageHelp  *widget.Label

	// Advanced options (encrypt mode)
	paranoidCheck    *ttwidget.Check
	compressCheck    *ttwidget.Check
	reedSolomonCheck *ttwidget.Check
	deleteCheck      *ttwidget.Check
	deniabilityCheck *ttwidget.Check
	recursivelyCheck *ttwidget.Check
	splitCheck       *ttwidget.Check
	splitSizeEntry   *widget.Entry
	splitUnitSelect  *widget.Select

	// Advanced options (decrypt mode)
	forceDecryptCheck *ttwidget.Check
	verifyFirstCheck  *ttwidget.Check
	deleteVolumeCheck *ttwidget.Check
	autoUnzipCheck    *ttwidget.Check
	sameLevelCheck    *ttwidget.Check

	// Modals
	passgenModal   dialog.Dialog
	keyfileModal   dialog.Dialog
	overwriteModal dialog.Dialog
	progressModal  dialog.Dialog
	aboutModal     dialog.Dialog

	// Keyfile modal widgets (moved from package-level to avoid global state)
	keyfileListContainer *fyne.Container
	keyfileListScroll    *container.Scroll
	keyfileSeparator     *widget.Separator
	keyfileOrderCheck    *widget.Check

	// Progress widgets
	progressBar    *widget.ProgressBar
	progressStatus *widget.Label
	cancelButton   *widget.Button

	// Data bindings for reactive UI updates
	boundProgress binding.Float  // Progress bar value (0.0-1.0)
	boundStatus   binding.String // Status text (e.g., "Encrypting at 100 MiB/s")
}

// NewApp creates a new UI application.
func NewApp(version string) (*App, error) {
	// NewState builds the Reed-Solomon codecs once and returns an error on
	// RS-init failure (APP-01). Reuse those codecs here instead of constructing
	// a second, redundant set.
	state, err := app.NewState()
	if err != nil {
		return nil, fmt.Errorf("init app state: %w", err)
	}
	if err := loadTranslations(); err != nil {
		return nil, fmt.Errorf("load translations: %w", err)
	}

	return &App{
		Version:  version,
		State:    state,
		rsCodecs: state.RSCodecs,
		DPI:      1.0,
		// Initialize data bindings
		boundProgress: binding.NewFloat(),
		boundStatus:   binding.NewString(),
	}, nil
}

func (a *App) loadPreferredLanguage(p fyne.Preferences) error {
	code := LanguageCode(p.StringWithFallback(languagePreferenceKey, string(activeLanguage())))
	if code == "" {
		code = "en"
	}
	return setActiveLanguage(code)
}

func (a *App) SwitchLanguage(code LanguageCode) error {
	if err := setActiveLanguage(code); err != nil {
		return err
	}
	if a.fyneApp != nil {
		a.fyneApp.Preferences().SetString(languagePreferenceKey, string(code))
	}
	a.refreshLocalizedText()
	return nil
}

func (a *App) refreshLocalizedText() {
	if a.languageSelector != nil {
		a.languageSelector.refresh()
	}
	if a.clearButton != nil {
		a.clearButton.SetText(tr("action.clear", "Clear"))
	}
	if a.State != nil && a.showHideBtn != nil {
		configureToolbarButton(a.showHideBtn, passwordVisibilityLabel(a.State.PasswordMode), passwordVisibilityIcon(a.State.PasswordMode))
	}
	if a.clearPwdBtn != nil {
		configureToolbarButton(a.clearPwdBtn, tr("action.clear", "Clear"), theme.ContentClearIcon())
	}
	if a.copyBtn != nil {
		configureToolbarButton(a.copyBtn, tr("action.copy", "Copy"), theme.ContentCopyIcon())
	}
	if a.pasteBtn != nil {
		configureToolbarButton(a.pasteBtn, tr("action.paste", "Paste"), theme.ContentPasteIcon())
	}
	if a.createBtn != nil {
		configureToolbarButton(a.createBtn, tr("action.create", "Create"), theme.DocumentCreateIcon())
	}
	if a.keyfileEditBtn != nil {
		configureToolbarButton(a.keyfileEditBtn, tr("action.edit", "Edit"), theme.FolderOpenIcon())
	}
	if a.keyfileCreateBtn != nil {
		configureToolbarButton(a.keyfileCreateBtn, tr("action.create", "Create"), theme.DocumentCreateIcon())
	}
	if a.changeBtn != nil {
		a.changeBtn.SetText(tr("action.change", "Change"))
	}
	setLabelText(a.passwordLabel, tr("password.label", "Password:"))
	setEntryPlaceholder(a.passwordEntry, tr("password.placeholder", "Password"))
	setEntryPlaceholder(a.cPasswordEntry, tr("password.confirm_placeholder", "Confirm password"))
	setLabelText(a.confirmLabel, tr("password.confirm_label", "Confirm password:"))
	setLabelText(a.nonASCIIHint, tr("password.non_ascii_hint",
		"Non-ASCII password: it is normalized so the volume decrypts on any "+
			"platform, but make sure you can type the same characters on every "+
			"device where you'll decrypt it."))
	setLabelText(a.keyfilesTitleLabel, tr("keyfiles.label", "Keyfiles:"))
	setLabelText(a.commentsLabel, tr("comments.label", "Comments:"))
	setEntryPlaceholder(a.commentsEntry, tr("comments.placeholder", "Public note; not encrypted."))
	setLabelText(a.advancedLabel, tr("advanced.label", "Advanced:"))
	a.refreshAdvancedDisclosureButton()
	setLabelText(a.outputLabel, tr("output.label", "Save output as:"))
	setButtonText(a.mobileSelectFilesBtn, tr("mobile.select_files", "Select Files"))
	setButtonText(a.mobileSelectFolderBtn, tr("mobile.select_folder", "Select Folder"))
	setButtonText(a.mobileAppStorageBtn, tr("mobile.app_storage.button", "App Storage (large files)"))
	setLabelText(a.mobileAppStorageHelp, tr("mobile.app_storage.tip", "Tip: For large files, copy them to App Storage first"))
	a.refreshAdvancedLocalizedText()
	if a.State != nil {
		a.updateUIState()
	}
}

type localizedPlaceholder interface {
	SetPlaceHolder(string)
}

func setLabelText(label *widget.Label, text string) {
	if label != nil {
		label.SetText(text)
	}
}

func setButtonText(button *widget.Button, text string) {
	if button != nil {
		button.SetText(text)
	}
}

func setEntryPlaceholder(entry localizedPlaceholder, text string) {
	if entry == nil {
		return
	}
	if value := reflect.ValueOf(entry); value.Kind() == reflect.Pointer && value.IsNil() {
		return
	}
	entry.SetPlaceHolder(text)
}

func setCheckText(check *ttwidget.Check, text string) {
	if check != nil {
		check.SetText(text)
	}
}

func setCheckTooltip(check *ttwidget.Check, text string) {
	if check != nil {
		check.SetToolTip(text)
	}
}

func (a *App) refreshAdvancedLocalizedText() {
	setCheckText(a.paranoidCheck, tr("advanced.paranoid.label", "Paranoid mode"))
	setCheckTooltip(a.paranoidCheck, tr("advanced.paranoid.tooltip", "Adds Serpent and stronger checks"))
	setCheckText(a.compressCheck, tr("advanced.compress.label", "Compress files"))
	setCheckTooltip(a.compressCheck, tr("advanced.compress.tooltip", "Compress before encrypting"))
	setCheckText(a.reedSolomonCheck, tr("advanced.reed_solomon.label", "Reed-Solomon"))
	setCheckTooltip(a.reedSolomonCheck, tr("advanced.reed_solomon.tooltip", "Add recovery data"))
	if a.State != nil && a.State.Mode == "decrypt" {
		setCheckText(a.deleteCheck, tr("advanced.delete_encrypted.label", "Delete encrypted"))
	} else {
		setCheckText(a.deleteCheck, tr("advanced.delete_files.label", "Delete files"))
		setCheckTooltip(a.deleteCheck, tr("advanced.delete_files.tooltip", "Delete source files after encryption"))
	}
	setCheckText(a.deniabilityCheck, tr("advanced.deniability.label", "Deniability"))
	setCheckTooltip(a.deniabilityCheck, tr("advanced.deniability.tooltip", "No readable Picocrypt header. Keep password/keyfiles."))
	setCheckText(a.recursivelyCheck, tr("advanced.recursively.label", "Recursively"))
	setCheckTooltip(a.recursivelyCheck, tr("advanced.recursively.tooltip", "Process each file separately"))
	setCheckText(a.splitCheck, tr("advanced.split.label", "Split:"))
	setCheckTooltip(a.splitCheck, tr("advanced.split.tooltip", "Split output into parts"))
	setEntryPlaceholder(a.splitSizeEntry, tr("advanced.split.size_placeholder", "Size"))
	if a.splitUnitSelect != nil {
		a.splitUnitSelect.Options = localizedSplitUnits(a.State.SplitUnits)
		a.splitUnitSelect.SetSelectedIndex(int(a.State.SplitSelected))
	}
	setCheckText(a.forceDecryptCheck, tr("advanced.force_decrypt.label", "Force decrypt"))
	setCheckTooltip(a.forceDecryptCheck, tr("advanced.force_decrypt.tooltip", "Keep damaged or unverified output"))
	setCheckText(a.verifyFirstCheck, tr("advanced.verify_first.label", "Verify first"))
	setCheckTooltip(a.verifyFirstCheck, tr("advanced.verify_first.tooltip", "Verify before decrypting"))
	setCheckText(a.deleteVolumeCheck, tr("advanced.delete_volume.label", "Delete volume"))
	setCheckTooltip(a.deleteVolumeCheck, tr("advanced.delete_volume.tooltip", "Delete volume after decryption"))
	setCheckText(a.autoUnzipCheck, tr("advanced.auto_unzip.label", "Auto unzip"))
	setCheckTooltip(a.autoUnzipCheck, tr("advanced.auto_unzip.tooltip", "Extract {{.Extension}}; may overwrite files", map[string]any{
		"Extension": ".zip",
	}))
	setCheckText(a.sameLevelCheck, tr("advanced.same_level.label", "Same level"))
	setCheckTooltip(a.sameLevelCheck, tr("advanced.same_level.tooltip", "Extract {{.Extension}} beside the volume", map[string]any{
		"Extension": ".zip",
	}))
}

// Run starts the UI application and optionally loads files passed at startup.
func (a *App) Run(startupPaths []string) {
	// Create Fyne app with unique ID for preferences API support
	a.fyneApp = fyneApp.NewWithID(runtimeAppID())
	if err := a.loadPreferredLanguage(a.fyneApp.Preferences()); err != nil {
		_ = setActiveLanguage("en")
		a.fyneApp.Preferences().SetString(languagePreferenceKey, "en")
	}

	// Clean up any leftover temp files from previous sessions (mobile only)
	// Must be called AFTER Fyne app is initialized (isMobile() requires it)
	if isMobile() {
		a.CleanupMobileTempFiles()
	}

	// Apply compact theme to match original Picocrypt look
	a.fyneApp.Settings().SetTheme(NewCompactTheme())

	// Set application icon (embedded PNG)
	appIcon := fyne.NewStaticResource("key.png", appIconData)
	a.fyneApp.SetIcon(appIcon)

	// Create main window. The title intentionally carries no version (#133):
	// taskbars/docks show the .desktop Name or WM_CLASS, and mixing in the
	// version made the user-visible name inconsistent across DEs. The version
	// stays available via the CLI and the packaged file metadata.
	a.Window = a.fyneApp.NewWindow("Picocrypt NG")
	// NewWindow initializes the GLFW driver; native window creation happens on Show.
	prepareWindowIdentity()
	a.Window.SetIcon(appIcon)

	// On desktop: fixed size window; on mobile: flexible size
	if !isMobile() {
		a.Window.SetFixedSize(true)
		a.Window.Resize(fyne.NewSize(windowWidth, windowHeightEncrypt))
	}

	// Set clipboard callback for state
	// Must use fyne.Do() since this may be called from goroutines (e.g., GenPassword)
	a.State.SetClipboard = func(text string) {
		fyne.Do(func() {
			a.fyneApp.Clipboard().SetContent(text)
		})
	}

	// Set close callback to prevent closing during operations
	a.Window.SetCloseIntercept(func() {
		snap := a.State.UISnapshot()
		if !snap.Working && !snap.ShowProgress {
			if !isMobile() {
				fynetooltip.DestroyWindowToolTipLayer(a.Window.Canvas())
			}
			a.Window.Close()
		}
	})

	// Build UI - use mobile layout on mobile devices
	var content fyne.CanvasObject
	if isMobile() {
		content = a.buildMobileUI()
	} else {
		content = a.buildUI()

		// Set up drag and drop (desktop only)
		a.Window.SetOnDropped(func(pos fyne.Position, uris []fyne.URI) {
			paths := make([]string, len(uris))
			for i, uri := range uris {
				paths[i] = uri.Path()
			}
			a.cancelOpenedPathReadiness()
			a.onDrop(paths)
		})
	}

	// Set up Enter key handler
	if deskCanvas, ok := a.Window.Canvas().(desktop.Canvas); ok {
		deskCanvas.SetOnKeyDown(func(event *fyne.KeyEvent) {
			if event.Name == fyne.KeyReturn || event.Name == fyne.KeyEnter {
				a.onClickStart()
			}
		})
	}

	a.scheduleStartupPaths(startupPaths)

	if !isMobile() {
		content = fynetooltip.AddWindowToolTipLayer(content, a.Window.Canvas())
	}
	a.Window.SetContent(content)
	a.resizeDesktopWindowForContent(content, preferredDesktopWindowHeight(a.State.Mode))
	a.Window.ShowAndRun()
}

func (a *App) scheduleStartupPaths(startupPaths []string) {
	// applyOpened drains paths buffered by the macOS open-file bridge and feeds
	// them through the normal drop handler. It is the notify handler for cold and
	// warm openURLs events after the bridge debounce window goes idle.
	applyOpened := func() {
		fyne.Do(func() {
			opened := drainOpenedPaths()
			if len(opened) == 0 {
				return
			}
			a.applyOpenedPaths(opened)
		})
	}

	// Always wire SetOnStarted: even if startupPaths is empty, AppleEvent paths
	// from a Finder cold launch may have been buffered by the cgo handler before
	// Go's main() ran (drainOpenedPaths returns nothing on non-darwin).
	a.fyneApp.Lifecycle().SetOnStarted(func() {
		// Register the notify handler before checking for cold-launch AppleEvent
		// batches so Finder/Dock opens use the same debounce window as warm opens.
		setOpenedPathsNotify(applyOpened)
		if hasOpenedPaths() {
			flushOpenedPaths()
		}
		if len(startupPaths) > 0 {
			fyne.Do(func() {
				a.applyStartupPaths(startupPaths)
			})
		}
	})
}

// showFileDialogWithResize temporarily resizes the window to accommodate file dialogs.
// This is necessary because Fyne file dialogs are constrained by the parent window size
// when using fixed-size windows. The window is restored after the dialog closes.
func (a *App) showFileDialogWithResize(d dialog.Dialog, dialogSize fyne.Size) {
	// Skip resize handling on mobile - windows are flexible there
	if isMobile() {
		d.Resize(dialogSize)
		d.Show()
		return
	}

	// Calculate current window size to restore later
	originalHeight := preferredDesktopWindowHeight(a.State.Mode)

	// Temporarily allow window resizing and make room for dialog
	a.Window.SetFixedSize(false)
	a.Window.Resize(fyne.NewSize(dialogSize.Width+50, dialogSize.Height+50))

	d.SetOnClosed(func() {
		a.resizeDesktopWindowForCurrentContent(originalHeight)
		a.Window.SetFixedSize(true)
	})

	d.Resize(dialogSize)
	d.Show()
}

// fixedWidthLayout is a layout that forces a fixed width (used in tests).
//
//nolint:unused // used by widgets_test.go
type fixedWidthLayout struct {
	width float32
}

//nolint:unused // used by widgets_test.go
func (f *fixedWidthLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	if len(objects) == 0 {
		return fyne.NewSize(f.width, 0)
	}
	min := objects[0].MinSize()
	return fyne.NewSize(f.width, min.Height)
}

//nolint:unused // used by widgets_test.go
func (f *fixedWidthLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	for _, obj := range objects {
		obj.Resize(fyne.NewSize(f.width, size.Height))
		obj.Move(fyne.NewPos(0, 0))
	}
}

// buildUI creates the main UI layout.
func (a *App) buildUI() fyne.CanvasObject {
	snap := a.State.UISnapshot()

	// Input label with Clear button
	a.inputLabel = widget.NewLabel(renderInputSummary(snap.InputSummary))
	a.inputLabel.Wrapping = fyne.TextWrapWord
	a.clearButton = widget.NewButton(tr("action.clear", "Clear"), func() {
		a.cancelOpenedPathReadiness()
		a.resetUI()
	})
	// MediumImportance gives the button a visible border
	a.clearButton.Importance = widget.MediumImportance

	// Icon-only About button: keeps the fixed-size window unchanged while
	// giving the GUI a version indicator (the title carries none, #133).
	a.aboutButton = widget.NewButtonWithIcon("", theme.InfoIcon(), func() {
		a.showAboutModal()
	})
	a.aboutButton.Importance = widget.LowImportance

	a.languageSelector = newLanguageSelector(a)
	headerLeft := container.NewHBox(a.aboutButton, a.languageSelector.object())
	headerRow := container.NewBorder(nil, nil, headerLeft, a.clearButton, a.inputLabel)

	// Password section (from password_section.go)
	passwordSection := a.buildPasswordSection()

	// Keyfiles section (from keyfile_section.go)
	keyfilesSection := a.buildKeyfilesSection()

	// Comments section
	commentsSection := a.buildCommentsSection()

	// Advanced section (from advanced_section.go)
	a.advancedContainer = container.NewVBox()
	a.advancedLabel = nil
	a.updateAdvancedSection()

	// Output section
	outputSection := a.buildOutputSection()

	// Start button and status
	a.startButton = widget.NewButton(renderStartAction(snap.StartAction, snap.Recursively), a.onClickStart)
	a.startButton.Importance = widget.HighImportance
	a.startHintLabel = widget.NewLabel("")
	a.startHintLabel.Importance = widget.LowImportance
	a.startHintLabel.Wrapping = fyne.TextWrapWord
	a.startHintLabel.Hide()

	a.statusLabel = NewColoredLabel(renderStatus(snap.Status, snap), snap.Status.Color)

	// Main content container
	a.mainContent = container.NewVBox(
		passwordSection,
		keyfilesSection,
		widget.NewSeparator(),
		commentsSection,
		a.advancedContainer,
		outputSection,
		widget.NewSeparator(),
		container.NewVBox(
			a.startButton,
			a.startHintLabel,
		),
		a.statusLabel,
	)

	// Full layout with padding
	fullLayout := container.NewVBox(
		headerRow,
		widget.NewSeparator(),
		a.mainContent,
	)

	// Add padding
	padded := container.NewPadded(fullLayout)

	a.updateUIState()

	return padded
}

func preferredDesktopWindowHeight(mode string) float32 {
	switch mode {
	case "encrypt":
		return windowHeightEncrypt
	case "decrypt":
		return windowHeightDecrypt
	default:
		return windowHeightInitial
	}
}

func (a *App) resizeDesktopWindowForCurrentContent(preferredHeight float32) {
	var content fyne.CanvasObject
	if a.Window != nil {
		content = a.Window.Content()
	}
	a.resizeDesktopWindowForContent(content, preferredHeight)
}

func (a *App) resizeDesktopWindowForContent(content fyne.CanvasObject, preferredHeight float32) {
	if isMobile() || a.Window == nil {
		return
	}
	if content == nil && preferredHeight <= 0 {
		return
	}
	size := fyne.NewSize(windowWidth, preferredHeight)
	if content != nil {
		size = size.Max(content.MinSize())
	}
	if size.Height == 0 {
		size.Height = preferredHeight
	}
	a.Window.Resize(size)
}

func commentsLabelText(mode string) string {
	if mode == "decrypt" {
		return tr("comments.read_only", "Comments (read-only):")
	}
	return tr("comments.label", "Comments:")
}

func commentsDisplayText(mode, comments string, state app.CommentsPreviewState) string {
	if mode != "decrypt" {
		return comments
	}
	switch state {
	case app.CommentsPreviewCorrupted:
		return tr("comments.corrupted", "Comments are corrupted")
	case app.CommentsPreviewUnavailable:
		return ""
	default:
		return comments
	}
}

func renderInputSummary(input app.InputSummary) string {
	switch input.Kind {
	case app.InputSummaryScanning:
		return selectionScanningLabel(input.SizeBytes)
	case app.InputSummarySelection:
		label := selectionSummary(input.Files, input.Folders)
		if input.ShowSize {
			return selectionWithSize(label, input.SizeBytes)
		}
		return label
	case app.InputSummaryDecryptVolume:
		return tr("selection.volume_for_decryption", "Volume for decryption")
	default:
		return dropPromptLabel()
	}
}

func renderStartAction(action app.StartAction, recursively bool) string {
	if recursively {
		return tr("action.process", "Process")
	}
	switch action {
	case app.StartActionEncrypt:
		return tr("action.encrypt", "Encrypt")
	case app.StartActionZipAndEncrypt:
		return tr("action.zip_and_encrypt", "Zip and Encrypt")
	case app.StartActionDecrypt:
		return tr("action.decrypt", "Decrypt")
	default:
		return tr("action.start", "Start")
	}
}

func hasSelectedInput(snap app.UISnapshot) bool {
	return snap.AllFileCount > 0 || snap.OnlyFileCount > 0 || snap.OnlyFolderCount > 0 || snap.InputFile != ""
}

func (a *App) startReadinessHint(snap app.UISnapshot) string {
	if !hasSelectedInput(snap) {
		return tr("start.hint.noFiles", "Add files or folders to continue.")
	}
	if snap.Scanning {
		return tr("start.hint.scanning", "Scanning files; wait before starting.")
	}
	if snap.KeyfileCount == 0 && snap.Password == "" {
		return tr("start.hint.enterPasswordOrKeyfiles", "Enter a password or add keyfiles.")
	}
	if snap.Mode == "encrypt" {
		if snap.Password != "" && snap.CPassword == "" {
			return tr("start.hint.repeatPassword", "Repeat the password to continue.")
		}
		if snap.Password != snap.CPassword {
			return tr("start.hint.passwordMismatch", "Passwords do not match.")
		}
	}
	if !splitSizeReady(snap) {
		return tr("start.hint.invalidSplitSize", "Choose a positive split size.")
	}
	return ""
}

func (a *App) startDisabled(snap app.UISnapshot) bool {
	configureDisabled := snap.Scanning || !hasSelectedInput(snap)
	return configureDisabled || !snap.CanStart() || !splitSizeReady(snap)
}

func renderStatus(msg app.StatusMessage, snap app.UISnapshot) string {
	if msg.Kind == app.StatusCustom {
		return msg.Text
	}
	switch msg.Kind {
	case app.StatusCompleted:
		return tr("status.completed", "Completed")
	case app.StatusCancelledByUser:
		return tr("status.cancelled_by_user", "Operation cancelled by user")
	case app.StatusNoFilesToProcess:
		return tr("status.no_files_to_process", "No files to process")
	case app.StatusProcessingFile:
		return tr("status.processing_file", "Processing file {{.Index}}/{{.Total}}...", map[string]any{
			"Index": msg.Args.Index,
			"Total": msg.Args.Total,
		})
	case app.StatusRecursiveCompleted:
		return recursiveStatusCompleted(msg.Args.Count)
	case app.StatusRecursiveFailedAll:
		return recursiveStatusFailedAll(msg.Args.Count)
	case app.StatusRecursiveCompletedFailed:
		return recursiveStatusCompletedFailed(msg.Args.OK, msg.Args.Failed)
	case app.StatusInvalidSplitSize:
		return tr("status.invalid_split_size", "Invalid split size")
	case app.StatusCompletedSomeDeleteFailed:
		return tr("status.completed_some_delete_failed", "Completed (some files couldn't be deleted)")
	case app.StatusKeptOutputUnverified:
		return tr("status.kept_output_unverified", "Integrity check failed; kept output is unverified and may be corrupted")
	case app.StatusCompletedVolumeDeleteFailed:
		return tr("status.completed_volume_delete_failed", "Completed (volume couldn't be deleted)")
	case app.StatusStartupPathAccessFailed:
		return startupPathAccessStatus()
	case app.StatusStartupPathPartialAccessFailed:
		return startupPathPartialAccessStatus()
	case app.StatusOpenedPathsPreparing:
		return openedPathsPreparingStatus()
	case app.StatusOpenedPathsTimeout:
		return openedPathsTimeoutStatus()
	case app.StatusDropFailedWalk:
		return tr("drop.failed_walk", "Failed to walk through dropped items")
	case app.StatusDropFailedStatItem:
		return tr("drop.failed_stat_item", "Failed to stat dropped item")
	case app.StatusDropFailedStatItems:
		return tr("drop.failed_stat_items", "Failed to stat dropped items")
	case app.StatusDropReadAccessDenied:
		return tr("drop.read_access_denied", "Read access denied")
	case app.StatusDropHeaderMayBeDeniable:
		return tr("drop.header_may_be_deniable", "Cannot read header, volume may be deniable")
	case app.StatusDropHeaderDamaged:
		return tr("drop.header_damaged", "The volume header is damaged")
	case app.StatusDropFailedSplitPath:
		return tr("drop.failed_split_path", "Failed to derive split volume path")
	case app.StatusKeyfileReadAccessDenied:
		return tr("keyfiles.read_access_denied", "Cannot read keyfile")
	case app.StatusKeyfileGenerateFailed:
		return tr("keyfiles.generate_failed", "Failed to create keyfile")
	case app.StatusKeyfileWriteFailed:
		return tr("keyfiles.write_failed", "Failed to save keyfile")
	case app.StatusMobileAppStorageCreateFailed:
		return tr("mobile.app_storage.create_failed", "Failed to create app storage")
	case app.StatusMobileAppStorageReadFailed:
		return tr("mobile.app_storage.read_failed", "Failed to read app storage")
	case app.StatusMobileAppStoragePathCopied:
		return tr("mobile.app_storage.path_copied", "Path copied to clipboard")
	case app.StatusMobileAppStorageNoFiles:
		return tr("mobile.app_storage.no_files", "No files in app storage")
	case app.StatusMobileFileAccessFailed:
		return tr("mobile.file_access_failed", "Failed to access file: {{.Error}}", map[string]any{"Error": msg.Args.Error})
	case app.StatusMobileFileAccessUnsafeName:
		return tr("mobile.file_access_failed_unsafe_name", "Failed to access file: unsafe file name")
	default:
		statusText := tr("status.ready", "Ready")
		if snap.RequiredFreeSpace > 0 {
			multiplier := 1
			if snap.AllFileCount > 1 || snap.OnlyFolderCount > 0 {
				multiplier++
			}
			if snap.Deniability {
				multiplier++
			}
			if snap.Split {
				multiplier++
			}
			if snap.Recombine {
				multiplier++
			}
			if snap.AutoUnzip {
				multiplier++
			}
			statusText = tr("status.ready_free_space", "Ready (ensure >{{.Size}} free)", map[string]any{
				"Size": util.Sizeify(snap.RequiredFreeSpace * int64(multiplier)),
			})
		}
		return statusText
	}
}

// buildCommentsSection creates the comments input section.
func (a *App) buildCommentsSection() fyne.CanvasObject {
	a.commentsLabel = widget.NewLabel(commentsLabelText(a.State.Mode))
	a.commentsLabel.TextStyle = fyne.TextStyle{Bold: true}

	a.commentsEntry = widget.NewEntry()
	a.commentsEntry.SetPlaceHolder(tr("comments.placeholder", "Public note; not encrypted."))
	a.commentsEntry.OnChanged = func(text string) {
		// In decrypt mode, comments are read-only - revert any changes
		if a.State.Mode == "decrypt" {
			snap := a.State.UISnapshot()
			displayText := commentsDisplayText(snap.Mode, snap.Comments, snap.CommentsPreviewState)
			if text != displayText {
				a.commentsEntry.SetText(displayText)
			}
			return
		}
		a.State.Comments = text
	}

	return container.NewVBox(
		a.commentsLabel,
		a.commentsEntry,
	)
}

// buildOutputSection creates the output file section.
func (a *App) buildOutputSection() fyne.CanvasObject {
	outputEntry := NewOutputDisplay()
	a.outputEntry = outputEntry

	a.changeBtn = widget.NewButton(tr("action.change", "Change"), func() {
		a.changeOutputFile()
	})

	row := container.NewBorder(nil, nil, nil, a.changeBtn, outputEntry)

	// Create bold label for better visual hierarchy
	a.outputLabel = widget.NewLabel(tr("output.label", "Save output as:"))
	a.outputLabel.TextStyle = fyne.TextStyle{Bold: true}

	return container.NewVBox(
		a.outputLabel,
		row,
	)
}

// refreshUI updates all UI elements to reflect current state.
// This is the main entry point for UI updates from the main thread.
func (a *App) refreshUI() {
	a.updateUIState()
}

// refreshAdvanced rebuilds the advanced section for the current mode.
func (a *App) refreshAdvanced() {
	a.updateAdvancedSection()
}

// updateUIState updates the enabled/disabled state of all UI elements.
// This mirrors the exact logic from the original giu implementation.
func (a *App) updateUIState() {
	snap := a.State.UISnapshot()
	configureDisabled := snap.Scanning || !hasSelectedInput(snap)
	startDisabled := a.startDisabled(snap)

	// Clear button
	if a.clearButton != nil {
		if configureDisabled {
			a.clearButton.Disable()
		} else {
			a.clearButton.Enable()
		}
	}

	// Password section state (from password_section.go)
	a.updatePasswordUIState(configureDisabled, snap)

	// Keyfile section state (from keyfile_section.go)
	a.updateKeyfileUIState(configureDisabled, snap)

	// Comments section - complex nested logic
	commentsOuterDisabled := (snap.Mode != "decrypt" &&
		((snap.KeyfileCount == 0 && snap.Password == "") ||
			(snap.Password != snap.CPassword))) ||
		snap.Deniability
	commentsInnerDisabled := snap.Mode == "decrypt" &&
		snap.CommentsPreviewState != app.CommentsPreviewNormal

	if a.commentsEntry != nil {
		if snap.Mode == "decrypt" {
			displayText := commentsDisplayText(snap.Mode, snap.Comments, snap.CommentsPreviewState)
			if a.commentsEntry.Text != displayText {
				a.commentsEntry.SetText(displayText)
			}
		}
		// In decrypt mode with valid comments, keep entry enabled but read-only
		// (OnChanged will prevent actual changes). This keeps text visible, not pale.
		if snap.Mode == "decrypt" && snap.CommentsPreviewState == app.CommentsPreviewNormal && snap.Comments != "" {
			a.commentsEntry.Enable() // Keep text visible (not pale)
		} else if configureDisabled || commentsOuterDisabled || commentsInnerDisabled {
			a.commentsEntry.Disable()
		} else {
			a.commentsEntry.Enable()
		}
	}

	// Update advanced section checkboxes/inputs (from advanced_section.go)
	a.updateAdvancedDisableStateFromSnapshot(snap, configureDisabled)

	if a.startButton != nil {
		a.startButton.SetText(renderStartAction(snap.StartAction, snap.Recursively))
		if startDisabled {
			a.startButton.Disable()
		} else {
			a.startButton.Enable()
		}
	}
	if a.startHintLabel != nil {
		hint := a.startReadinessHint(snap)
		a.startHintLabel.SetText(hint)
		if hint == "" {
			a.startHintLabel.Hide()
		} else {
			a.startHintLabel.Show()
		}
	}

	// Update output display
	if a.outputEntry != nil {
		outputDisplay := ""
		if snap.OutputFile != "" {
			outputDisplay = filepath.Base(snap.OutputFile)
			if snap.Split {
				outputDisplay += ".*"
			}
			if snap.Recursively {
				outputDisplay = tr("output.multiple_values", "(multiple values)")
			}
		}
		a.outputEntry.SetText(outputDisplay)
	}

	// Change button - disabled when recursively
	if a.changeBtn != nil {
		if configureDisabled || snap.Recursively {
			a.changeBtn.Disable()
		} else {
			a.changeBtn.Enable()
		}
	}

	// Update status
	if a.statusLabel != nil {
		a.statusLabel.SetText(renderStatus(snap.Status, snap))
		a.statusLabel.SetColor(snap.Status.Color)
	}

	// Update labels
	if a.inputLabel != nil {
		a.inputLabel.SetText(renderInputSummary(snap.InputSummary))
	}

	if a.keyfileLabel != nil {
		a.keyfileLabel.SetText(keyfileDisplayLabel(
			snap.Keyfile,
			snap.KeyfileCount,
			keyfileApplicable(snap.Mode, snap.Keyfile, snap.Deniability),
		))
	}

	if a.commentsLabel != nil {
		a.commentsLabel.SetText(commentsLabelText(snap.Mode))
	}

	a.resizeDesktopWindowForCurrentContent(0)
}

// resetUI clears UI state but preserves progress flags.
func (a *App) resetUI() {
	a.State.ResetUI()
	if a.passwordEntry != nil {
		a.passwordEntry.SetText("")
	}
	if a.cPasswordEntry != nil {
		a.cPasswordEntry.SetText("")
	}
	if a.commentsEntry != nil {
		a.commentsEntry.SetText("")
	}
	a.updateAdvancedSection()
	a.updatePasswordStrength()
	a.updateValidation()
	a.updateUIState()
}
