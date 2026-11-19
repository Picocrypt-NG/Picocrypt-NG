// Package ui provides the Picocrypt NG graphical user interface using Fyne.
package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/pcv3publication"
	"Picocrypt-NG/internal/secret"
	"Picocrypt-NG/internal/util"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

const (
	keyfileDialogWidth      = windowWidth - 8
	keyfileDialogListWidth  = windowWidth - 40
	keyfileDialogListHeight = 88
	keyfileDialogHeight     = 260
)

func keyfileApplicable(mode string, required bool, deniable bool) bool {
	return mode == "decrypt" && (required || deniable)
}

func keyfileApplicableForSnapshot(snap app.UISnapshot) bool {
	return recursiveD1Selected(snap) || snap.PCV3Route == app.PCV3RouteReady ||
		snap.Mode == "encrypt" ||
		keyfileApplicable(snap.Mode, snap.Keyfile, snap.Deniability)
}

func keyfileDisplayLabel(required bool, count int, applicable bool) string {
	switch {
	case !applicable:
		return tr("keyfiles.not_applicable", "Not applicable")
	case count == 0 && required:
		return tr("keyfiles.required", "Keyfiles required")
	case count == 0:
		return tr("keyfiles.none_selected", "None selected")
	case count == 1:
		return trn("keyfiles.count", "{{.Count}} keyfile", count, map[string]any{
			"Count": count,
		})
	default:
		return trn("keyfiles.count", "{{.Count}} keyfiles", count, map[string]any{
			"Count": count,
		})
	}
}

// buildKeyfilesSection creates the keyfiles input section.
func (a *App) buildKeyfilesSection() fyne.CanvasObject {
	a.keyfileEditBtn = newToolbarButton(tr("action.edit", "Edit"), theme.FolderOpenIcon(), func() {
		a.showKeyfileModal()
	})

	a.keyfileCreateBtn = newToolbarButton(tr("action.create", "Create"), theme.DocumentCreateIcon(), func() {
		a.createKeyfile()
	})

	a.keyfileLabel = widget.NewLabel(keyfileDisplayLabel(
		a.State.Keyfile,
		len(a.State.Keyfiles),
		keyfileApplicable(a.State.Mode, a.State.Keyfile, a.State.Deniability),
	))
	a.keyfileLabel.Wrapping = fyne.TextWrapWord

	// Create bold label for better visual hierarchy
	a.keyfilesTitleLabel = widget.NewLabel(tr("keyfiles.label", "Keyfiles:"))
	a.keyfilesTitleLabel.TextStyle = fyne.TextStyle{Bold: true}

	buttonRow := container.NewHBox(
		a.keyfileEditBtn,
		a.keyfileCreateBtn,
	)
	headerRow := container.NewBorder(nil, nil, nil, buttonRow, a.keyfilesTitleLabel)

	return container.NewVBox(
		headerRow,
		a.keyfileLabel,
	)
}

// showKeyfileModal shows the keyfile manager dialog.
func (a *App) showKeyfileModal() {
	// Create order checkbox/label based on mode
	var orderWidget fyne.CanvasObject
	if a.State.Mode != "decrypt" || a.State.UISnapshot().PCV3Route == app.PCV3RouteReady {
		a.keyfileOrderCheck = widget.NewCheck(tr("keyfiles.require_order", "Use order"), func(checked bool) {
			a.State.KeyfileOrdered = checked
			a.updateUIState()
		})
		a.keyfileOrderCheck.SetChecked(a.State.KeyfileOrdered)
		orderWidget = a.keyfileOrderCheck
	} else if a.State.KeyfileOrdered {
		orderWidget = widget.NewLabel(tr("keyfiles.order_required", "Order matters"))
	} else {
		orderWidget = widget.NewLabel("") // Empty placeholder
	}

	// Separator (only visible when keyfiles exist)
	a.keyfileSeparator = widget.NewSeparator()

	// Container for keyfile labels (dynamic)
	a.keyfileListContainer = container.NewVBox()
	a.keyfileListScroll = container.NewScroll(a.keyfileListContainer)
	a.keyfileListScroll.SetMinSize(fyne.NewSize(keyfileDialogListWidth, keyfileDialogListHeight))
	a.updateKeyfileList()

	// Buttons
	clearBtn := widget.NewButton(tr("action.clear", "Clear"), func() {
		a.State.Keyfiles = nil
		a.State.ModalID++
		a.updateKeyfileList()
		a.updateUIState()
	})

	doneBtn := widget.NewButton(tr("action.done", "Done"), func() {
		a.keyfileModal.Hide()
		a.State.ShowKeyfile = false
		a.updateUIState()
	})
	doneBtn.Importance = widget.HighImportance

	buttonRow := container.NewGridWithColumns(2, clearBtn, doneBtn)

	content := container.NewVBox(
		widget.NewLabel(tr("keyfiles.drop_hint", "Drop keyfiles here")),
		orderWidget,
		a.keyfileSeparator,
		a.keyfileListScroll,
		buttonRow,
	)

	a.keyfileModal = dialog.NewCustomWithoutButtons(tr("keyfiles.manage_title", "Keyfiles"), content, a.Window)
	a.keyfileModal.Resize(fyne.NewSize(keyfileDialogWidth, keyfileDialogHeight))
	a.State.ShowKeyfile = true
	a.State.ModalID++
	a.keyfileModal.Show()
}

// updateKeyfileList updates the keyfile list in the modal.
func (a *App) updateKeyfileList() {
	if a.keyfileListContainer == nil {
		return
	}

	// Clear existing items
	a.keyfileListContainer.RemoveAll()

	// Show/hide separator based on keyfile count
	if a.keyfileSeparator != nil {
		if len(a.State.Keyfiles) > 0 {
			a.keyfileSeparator.Show()
		} else {
			a.keyfileSeparator.Hide()
		}
	}
	if a.keyfileListScroll != nil {
		if len(a.State.Keyfiles) > 0 {
			a.keyfileListScroll.Show()
		} else {
			a.keyfileListScroll.Hide()
		}
	}

	// Add label for each keyfile
	for _, kf := range a.State.Keyfiles {
		label := newKeyfileNameLabel(filepath.Base(kf))
		a.keyfileListContainer.Add(label)
	}

	a.keyfileListContainer.Refresh()
}

func newKeyfileNameLabel(name string) *widget.Label {
	label := widget.NewLabel(name)
	label.Truncation = fyne.TextTruncateEllipsis
	return label
}

// createKeyfile creates a new random keyfile.
func (a *App) createKeyfile() {
	picker := dialog.NewFolderOpen(func(folder fyne.ListableURI, err error) {
		if err != nil {
			a.showKeyfileCreationError(err)
			return
		}
		if folder == nil {
			return
		}
		if folder.Scheme() != "file" || !filepath.IsAbs(folder.Path()) {
			dialog.ShowInformation(tr("keyfiles.label", "Keyfiles"),
				tr("keyfiles.choose_local_folder", "Choose a local folder that supports private files."), a.Window)
			return
		}
		a.showKeyfileNameForm(folder.Path())
	}, a.Window)

	// Set start directory if we have files selected
	startDir := ""
	if len(a.State.OnlyFiles) > 0 {
		startDir = filepath.Dir(a.State.OnlyFiles[0])
	} else if len(a.State.OnlyFolders) > 0 {
		startDir = filepath.Dir(a.State.OnlyFolders[0])
	}
	if startDir != "" {
		uri := storage.NewFileURI(startDir)
		if listable, err := storage.ListerForURI(uri); err == nil {
			picker.SetLocation(listable)
		}
	}

	a.showFileDialogWithResize(picker, fyne.NewSize(600, 450))
}

func (a *App) showKeyfileNameForm(folder string) {
	filename := widget.NewEntry()
	defaultName := "keyfile-" + strconv.FormatInt(time.Now().Unix(), 10) + ".bin"
	filename.SetText(defaultName)
	filename.Validator = func(name string) error {
		if !filepath.IsLocal(name) {
			return errUnsafePCV3OutputFilename
		}
		if runtime.GOOS == "windows" && (strings.TrimRight(name, ". ") != name ||
			strings.ContainsAny(name, `<>:"|?*`) || strings.IndexFunc(name, func(r rune) bool { return r < 32 }) >= 0) {
			return errUnsafePCV3OutputFilename
		}
		return validatePCV3OutputFilename(name)
	}
	dialog.ShowForm(
		tr("keyfiles.create_title", "Create keyfile"), tr("action.create", "Create"), tr("action.cancel", "Cancel"),
		[]*widget.FormItem{widget.NewFormItem(tr("output.label", "Save output as:"), filename)},
		func(confirmed bool) {
			if !confirmed || filename.Validate() != nil {
				return
			}
			if err := writeGeneratedKeyfile(context.Background(), filepath.Join(folder, filename.Text)); err != nil {
				a.showKeyfileCreationError(err)
				return
			}
			a.State.SetReadyStatus()
			a.updateUIState()
		}, a.Window,
	)
}

func (a *App) showKeyfileCreationError(err error) {
	status := app.StatusKeyfileWriteFailed
	var publication pcv3publication.Result
	if errors.As(err, &publication) {
		switch {
		case publication.Code() == pcv3publication.CodeDestinationExists || errors.Is(err, os.ErrExist):
			dialog.ShowInformation(tr("keyfiles.label", "Keyfiles"),
				tr("keyfiles.destination_exists", "A file already exists at this location. Choose a different name."), a.Window)
		case publication.Code() == pcv3publication.CodePolicyUnsupported:
			dialog.ShowInformation(tr("keyfiles.label", "Keyfiles"),
				tr("keyfiles.choose_local_folder", "Choose a local folder that supports private files."), a.Window)
		case publication.State() != pcv3publication.StateNotPublished:
			dialog.ShowInformation(tr("keyfiles.label", "Keyfiles"),
				tr("keyfiles.check_destination", "The keyfile may have been saved. Check the destination before trying again."), a.Window)
		}
	}
	if errors.Is(err, errGenerateKeyfileRandom) {
		status = app.StatusKeyfileGenerateFailed
	}
	a.State.SetStatusMessage(status, util.RED, app.StatusArgs{})
	a.updateUIState()
}

var errGenerateKeyfileRandom = errors.New("keyfile randomness unavailable")

func writeGeneratedKeyfile(ctx context.Context, target string) (retErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	stage, err := pcv3publication.Create(target, nil, pcv3publication.PolicyNoReplace)
	if err != nil {
		return err
	}
	var publication pcv3publication.Result
	defer func() {
		if err := stage.Cleanup(); err != nil {
			if retErr == nil && publication != nil {
				retErr = publication
			}
			retErr = errors.Join(retErr, err)
		}
	}()
	file, err := stage.PrivateFile()
	if err != nil {
		return err
	}
	var key [32]byte
	defer secret.SecureZero(key[:])
	if _, err := rand.Read(key[:]); err != nil {
		return errGenerateKeyfileRandom
	}
	n, err := file.Write(key[:])
	if err != nil {
		return err
	}
	if n != len(key) {
		return io.ErrShortWrite
	}
	publication = stage.Publish(ctx)
	if publication.State() != pcv3publication.StatePublishedDurable {
		if publication.Code() == pcv3publication.CodeAtomicFailed {
			if _, err := os.Lstat(target); err == nil {
				return errors.Join(publication, os.ErrExist)
			}
		}
		return publication
	}
	return nil
}

// updateKeyfileUIState updates the enabled/disabled state of keyfile controls.
func (a *App) updateKeyfileUIState(mainDisabled bool, snap app.UISnapshot) {
	// Native creation and supported reads can use keyfiles.
	keyfileDisabled := mainDisabled || !keyfileApplicableForSnapshot(snap)
	if a.keyfileEditBtn != nil {
		if keyfileDisabled {
			a.keyfileEditBtn.Disable()
		} else {
			a.keyfileEditBtn.Enable()
		}
	}
	// Keyfile creation is available only for PCV3 creation.
	if a.keyfileCreateBtn != nil {
		if mainDisabled || snap.Mode == "decrypt" {
			a.keyfileCreateBtn.Disable()
		} else {
			a.keyfileCreateBtn.Enable()
		}
	}
}
