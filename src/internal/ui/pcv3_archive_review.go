package ui

import (
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/util"
	"context"
	"errors"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

func pcv3ArchiveSummaryText(summary pcv3operation.ArchiveSummary) string {
	return tr("pcv3.archive.summary", "Size after extraction: {{.Size}} · Files: {{.Files}} · Folders: {{.Folders}}", map[string]any{
		"Size": util.Sizeify(summary.UnpackedBytes), "Files": summary.Files, "Folders": summary.Directories,
	})
}

func (a *App) pcv3ArchiveReview(session *operationSession) func(context.Context, pcv3operation.ArchiveSummary) error {
	return func(ctx context.Context, summary pcv3operation.ArchiveSummary) error {
		if ctx == nil || session == nil || !session.gate.canApply() || !a.isCurrentOperation(session) || ctx.Err() != nil {
			return context.Canceled
		}
		if summary.Files < 0 || summary.Directories < 0 || summary.UnpackedBytes < 0 {
			return errors.New("invalid archive summary")
		}
		// Count directory entries too, without adding potentially overflowing ints.
		large := summary.UnpackedBytes >= util.GiB || summary.Files >= 10000 || summary.Directories >= 10000-summary.Files
		chosen := make(chan bool, 1)
		var once sync.Once
		send := func(approved bool) { once.Do(func() { chosen <- approved }) }
		var reviewDialog dialog.Dialog
		valid := false
		fyne.DoAndWait(func() {
			if a.Window == nil || ctx.Err() != nil || !session.gate.canApply() || !a.isCurrentOperation(session) {
				return
			}
			valid = true
			a.pcv3ArchiveSummary = &summary
			a.updateUIState()
			if !large {
				send(true)
				return
			}
			cancel := widget.NewButton(tr("action.cancel", "Cancel"), func() {
				send(false)
				reviewDialog.Hide()
			})
			confirm := widget.NewButton(tr("pcv3.archive.extract", "Extract archive"), func() {
				send(true)
				reviewDialog.Hide()
			})
			content := container.NewVBox(
				wrappedPCV3Label(pcv3ArchiveSummaryText(summary)),
				wrappedPCV3Label(tr("pcv3.archive.review.body", "This archive is large. Continue extracting?")),
				container.NewGridWithColumns(2, cancel, confirm),
			)
			reviewDialog = dialog.NewCustomWithoutButtons(tr("pcv3.archive.review.title", "Extract large archive?"), content, a.Window)
			reviewDialog.SetOnClosed(func() { send(false) })
			a.pcv3ArchiveReviewModal = reviewDialog
			reviewDialog.Show()
			a.Window.Canvas().Focus(cancel)
		})
		if !valid {
			return context.Canceled
		}
		if reviewDialog != nil {
			defer fyne.Do(func() {
				reviewDialog.Hide()
				if a.pcv3ArchiveReviewModal == reviewDialog {
					a.pcv3ArchiveReviewModal = nil
				}
			})
		}
		select {
		case approved := <-chosen:
			if !approved || ctx.Err() != nil || !session.gate.canApply() || !a.isCurrentOperation(session) {
				return context.Canceled
			}
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-session.ctx.Done():
			return context.Canceled
		}
	}
}
