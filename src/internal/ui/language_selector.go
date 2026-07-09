package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

type languageSelector struct {
	owner  *App
	button *widget.Button
}

func newLanguageSelector(owner *App) *languageSelector {
	selector := &languageSelector{owner: owner}
	selector.button = widget.NewButton(string(activeLanguage()), func() {
		if owner == nil || owner.Window == nil {
			return
		}
		popup := widget.NewPopUpMenu(selector.menu(), owner.Window.Canvas())
		popup.ShowAtRelativePosition(fyne.NewPos(0, selector.button.Size().Height), selector.button)
	})
	selector.button.Importance = widget.LowImportance
	return selector
}

func (s *languageSelector) object() fyne.CanvasObject {
	if s == nil || s.button == nil {
		return container.NewHBox()
	}
	return s.button
}

func (s *languageSelector) refresh() {
	if s == nil || s.button == nil {
		return
	}
	s.button.SetText(string(activeLanguage()))
	s.button.Refresh()
}

func (s *languageSelector) menu() *fyne.Menu {
	options := bundledLanguageOptions()
	items := make([]*fyne.MenuItem, 0, len(options))
	for _, option := range options {
		code := option.Code
		items = append(items, fyne.NewMenuItem(option.Name, func() {
			if s.owner == nil {
				_ = setActiveLanguage(code)
				s.refresh()
				return
			}
			_ = s.owner.SwitchLanguage(code)
		}))
	}
	return fyne.NewMenu(tr("language.menu", "Language"), items...)
}
