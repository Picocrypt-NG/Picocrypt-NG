// Package ui provides the Picocrypt NG graphical user interface using Fyne.
package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"

	ttwidget "github.com/dweymouth/fyne-tooltip/widget"
)

func newToolbarButton(label string, icon fyne.Resource, tapped func()) *ttwidget.Button {
	button := ttwidget.NewButtonWithIcon("", icon, nil)
	button.OnTapped = func() {
		button.MouseOut()
		if tapped != nil {
			tapped()
		}
	}
	configureToolbarButton(button, label, icon)
	return button
}

func configureToolbarButton(button *ttwidget.Button, label string, icon fyne.Resource) {
	if button == nil {
		return
	}
	if isMobile() {
		button.SetText(label)
		button.SetIcon(nil)
		button.SetToolTip("")
		return
	}
	button.Importance = widget.MediumImportance
	button.SetText("")
	button.SetIcon(icon)
	button.SetToolTip(label)
}
