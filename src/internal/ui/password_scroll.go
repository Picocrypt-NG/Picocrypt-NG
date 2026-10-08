package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
)

// CreateRenderer keeps Entry's renderer and editing behavior intact. Fyne 2.8 exposes its
// native viewport as a public Scroll among the renderer's objects.
func (e *PasswordEntry) CreateRenderer() fyne.WidgetRenderer {
	delegate := e.Entry.CreateRenderer()
	for _, object := range delegate.Objects() {
		if viewport, ok := object.(*container.Scroll); ok {
			e.viewport = viewport
			previous := viewport.OnScrolled
			viewport.OnScrolled = func(position fyne.Position) {
				if previous != nil {
					previous(position)
				}
				if e.viewport == viewport && e.onViewportChanged != nil {
					e.onViewportChanged(true)
				}
			}
			break
		}
	}
	return &passwordEntryRenderer{WidgetRenderer: delegate, entry: e, viewport: e.viewport}
}

type passwordEntryRenderer struct {
	fyne.WidgetRenderer
	entry    *PasswordEntry
	viewport *container.Scroll
}

func (r *passwordEntryRenderer) Destroy() {
	if r.entry.viewport == r.viewport {
		r.entry.viewport = nil
	}
	r.WidgetRenderer.Destroy()
}

func (a *App) linkPasswordScroll() {
	left, right := a.passwordEntry, a.cPasswordEntry
	if left == nil || right == nil {
		return
	}
	var queued, mirroring bool
	var pending *PasswordEntry
	var pendingViewport *container.Scroll
	schedule := func(source *PasswordEntry, fromScroll bool) {
		if mirroring || a.Window == nil || a.State == nil || a.workers == nil || a.workers.isStopping() ||
			(!fromScroll && a.Window.Canvas().Focused() != source) {
			return
		}
		pending, pendingViewport = source, source.viewport
		if queued {
			return
		}
		queued = true
		// Defer changes until native cursor auto-scroll or scrollbar handling
		// has finished. OnScrolled must not mutate its own Scroll.Offset.
		fyne.Do(func() {
			queued = false
			source, viewport := pending, pendingViewport
			pending, pendingViewport = nil, nil
			if a.workers == nil || a.workers.isStopping() || a.State == nil || a.passwordEntry != left || a.cPasswordEntry != right ||
				source == nil || viewport == nil || source.viewport != viewport ||
				left.Password || right.Password || left.Disabled() || right.Disabled() ||
				!left.Visible() || !right.Visible() || a.confirmRow == nil || !a.confirmRow.Visible() {
				return
			}
			snap := a.State.UISnapshot()
			if snap.Mode != "encrypt" || snap.Working || snap.Scanning || snap.PCVUnavailable ||
				(a.configurationForm != nil && !a.configurationForm.Visible()) {
				return
			}
			peer := left
			if source == left {
				peer = right
			}
			if peer.viewport == nil || peer.viewport.Content == nil || viewport.Content == nil {
				return
			}
			mirroring = true
			// ScrollToOffset clamps to the peer's own extent without changing
			// its caret/selection or refreshing Entry back to its old caret.
			peer.viewport.ScrollToOffset(fyne.NewPos(viewport.Offset.X, peer.viewport.Offset.Y))
			mirroring = false
		})
	}
	for _, entry := range []*PasswordEntry{left, right} {
		entry.onViewportChanged = func(fromScroll bool) { schedule(entry, fromScroll) }
		previous := entry.OnCursorChanged
		entry.OnCursorChanged = func() {
			if previous != nil {
				previous()
			}
			// Fyne invokes this after native ensureCursorVisible. Unlike a
			// scrollbar drag, in-range ScrollToOffset does not emit OnScrolled.
			schedule(entry, false)
		}
	}
}
