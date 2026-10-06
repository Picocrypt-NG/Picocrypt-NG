// Package ui provides the Picocrypt NG graphical user interface using Fyne.
package ui

import (
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/util"
	"image/color"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

type pcv3ArtifactView interface {
	Metadata() pcv3operation.ArtifactInspectionMetadata
	Page(offset, limit uint64) ([]pcv3operation.ArtifactRange, bool)
}

type pcv3ArtifactSurfaceState uint8

const (
	pcv3ArtifactLoading pcv3ArtifactSurfaceState = iota + 1
	pcv3ArtifactFailed
	pcv3ArtifactReady
)

type pcv3ArtifactRangeModel struct {
	view       pcv3ArtifactView
	rangeCount uint64
	pageOffset uint64
	page       []pcv3operation.ArtifactRange
}

func (model *pcv3ArtifactRangeModel) length() int {
	maxInt := uint64(^uint(0) >> 1)
	if model == nil || model.rangeCount == 0 {
		return 0
	}
	if model.rangeCount > maxInt {
		return int(maxInt)
	}
	return int(model.rangeCount)
}

func (model *pcv3ArtifactRangeModel) at(index int) (pcv3operation.ArtifactRange, bool) {
	if model == nil || model.view == nil || index < 0 || uint64(index) >= model.rangeCount {
		return pcv3operation.ArtifactRange{}, false
	}
	offset := (uint64(index) / 128) * 128
	if model.page == nil || model.pageOffset != offset {
		page, ok := model.view.Page(offset, 128)
		if !ok || len(page) == 0 {
			return pcv3operation.ArtifactRange{}, false
		}
		model.pageOffset = offset
		model.page = page
	}
	position := uint64(index) - model.pageOffset
	if position >= uint64(len(model.page)) {
		return pcv3operation.ArtifactRange{}, false
	}
	return model.page[position], true
}

func wrappedPCV3Label(text string) *widget.Label {
	label := widget.NewLabel(text)
	label.Wrapping = fyne.TextWrapWord
	return label
}

func wrappedPCV3Title(text string) *widget.Label {
	label := wrappedPCV3Label(text)
	label.TextStyle = fyne.TextStyle{Bold: true}
	return label
}

func buildPCV3ArtifactSurface(state pcv3ArtifactSurfaceState, view pcv3ArtifactView) fyne.CanvasObject {
	switch state {
	case pcv3ArtifactLoading:
		return wrappedPCV3Label(tr("pcv3.recovery.loading", "Loading recovery details…"))
	case pcv3ArtifactFailed:
		return wrappedPCV3Label(tr("pcv3.recovery.failed", "Recovery details could not be loaded"))
	}
	if view == nil {
		return wrappedPCV3Label(tr("pcv3.recovery.failed", "Recovery details could not be loaded"))
	}
	metadata := view.Metadata()
	summary := container.NewVBox(
		wrappedPCV3Label(tr("pcv3.recovery.summary.kind", "Artifact kind")+": "+pcv3ArtifactKindText(metadata.Kind)),
		wrappedPCV3Label(tr("pcv3.recovery.summary.length", "Plaintext length")+": "+strconv.FormatUint(metadata.PlaintextLength, 10)),
		wrappedPCV3Label(tr("pcv3.recovery.summary.final", "Final record")+": "+pcv3ArtifactFinalText(metadata.Final)),
		wrappedPCV3Label(tr("pcv3.recovery.summary.counts", "Recovery ranges")+": "+pcv3RecoveryRangeCount(metadata.RangeCount)),
	)
	if role := pcv3ArtifactRoleText(metadata.Role); role != "" {
		summary.Add(wrappedPCV3Label(tr("pcv3.recovery.summary.role", "Physical role") + ": " + role))
	}
	counts := strconv.FormatUint(metadata.VerifiedRangeCount, 10) + " / " +
		strconv.FormatUint(metadata.UnverifiedRangeCount, 10) + " / " +
		strconv.FormatUint(metadata.MissingRangeCount, 10)
	summary.Add(wrappedPCV3Label(counts))
	if metadata.RangeCount == 0 {
		summary.Add(wrappedPCV3Label(pcv3RecoveryRangeCount(0)))
		return summary
	}
	model := &pcv3ArtifactRangeModel{view: view, rangeCount: metadata.RangeCount}
	list := widget.NewList(
		model.length,
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.ListItemID, object fyne.CanvasObject) {
			label, ok := object.(*widget.Label)
			if !ok {
				return
			}
			rangeValue, ok := model.at(id)
			if !ok {
				label.SetText("")
				return
			}
			label.SetText(pcv3RecoveryRangeRow(
				rangeValue.RecordIndex, rangeValue.Start, rangeValue.End, rangeValue.Status,
			))
		},
	)
	list.SetItemHeight(0, theme.TextSize()+theme.Padding()*2)
	list.Resize(fyne.NewSize(desktopContentWidth(), 180))
	return container.NewBorder(summary, nil, nil, nil, list)
}

type pcv3ConsentView struct {
	content *fyne.Container
	roles   *widget.RadioGroup
	ack     *widget.Check
	confirm *widget.Button
	cancel  *widget.Button
}

func validPCV3ConsentRoles(mode pcv3operation.Mode, roles []pcv3operation.PhysicalRole) bool {
	if len(roles) != 2 || roles[0] == roles[1] {
		return false
	}
	switch mode {
	case pcv3operation.ModeForceUnverifiedNormal:
		return roles[0] == pcv3operation.RolePrimary && roles[1] == pcv3operation.RoleBackup
	case pcv3operation.ModeForceUnverifiedD1:
		return roles[0] == pcv3operation.RoleD1Front && roles[1] == pcv3operation.RoleD1Tail
	default:
		return false
	}
}

func newPCV3ConsentView(
	mode pcv3operation.Mode,
	roles []pcv3operation.PhysicalRole,
	choose func(pcv3operation.PhysicalRole),
	cancel func(),
) (*pcv3ConsentView, bool) {
	if !validPCV3ConsentRoles(mode, roles) || choose == nil || cancel == nil {
		return nil, false
	}
	labels := make([]string, len(roles))
	roleByLabel := make(map[string]pcv3operation.PhysicalRole, len(roles))
	for index, role := range roles {
		label := pcv3PhysicalRoleText(role)
		if label == "" {
			return nil, false
		}
		labels[index] = label
		roleByLabel[label] = role
	}
	view := &pcv3ConsentView{}
	view.confirm = widget.NewButton(tr("pcv3.consent.confirm", "Recover unverified"), func() {
		role, ok := roleByLabel[view.roles.Selected]
		if ok && view.ack.Checked {
			choose(role)
		}
	})
	view.confirm.Importance = widget.DangerImportance
	view.confirm.Disable()
	view.cancel = widget.NewButton(tr("pcv3.consent.cancel", "Cancel recovery"), cancel)
	view.cancel.Importance = widget.HighImportance
	update := func() {
		_, selected := roleByLabel[view.roles.Selected]
		if selected && view.ack.Checked {
			view.confirm.Enable()
		} else {
			view.confirm.Disable()
		}
	}
	view.roles = widget.NewRadioGroup(labels, func(string) { update() })
	view.ack = widget.NewCheck(
		tr("pcv3.consent.acknowledgement", "I understand that this output is unverified."),
		func(bool) { update() },
	)
	body := widget.NewLabel(tr("pcv3.consent.body", "This operation can save bytes that are not authenticated. They may be incomplete, corrupted, or unsafe to open. Choose the exact physical source to use."))
	body.Wrapping = fyne.TextWrapWord
	view.content = container.NewVBox(body, view.roles, view.ack, container.NewGridWithColumns(2, view.cancel, view.confirm))
	return view, true
}

// PasswordStrengthIndicator is a custom widget that displays password strength
// as a circular arc, colored from red (weak) to green (strong).
// Uses canvas.Arc for efficient GPU-accelerated rendering.
// Matches original Picocrypt behavior: arc from top going clockwise.
type PasswordStrengthIndicator struct {
	widget.BaseWidget
	strength  int  // 0-4 (zxcvbn score)
	visible   bool // whether to show the indicator
	decryMode bool // hide in decrypt mode
}

// NewPasswordStrengthIndicator creates a new password strength indicator.
func NewPasswordStrengthIndicator() *PasswordStrengthIndicator {
	p := &PasswordStrengthIndicator{}
	p.ExtendBaseWidget(p)
	return p
}

// SetStrength updates the strength value (0-4).
func (p *PasswordStrengthIndicator) SetStrength(strength int) {
	p.strength = strength
	p.Refresh()
}

// SetVisible sets whether the indicator should be visible.
func (p *PasswordStrengthIndicator) SetVisible(visible bool) {
	p.visible = visible
	p.Refresh()
}

// SetDecryptMode sets whether in decrypt mode (hides the indicator).
func (p *PasswordStrengthIndicator) SetDecryptMode(decrypt bool) {
	p.decryMode = decrypt
	p.Refresh()
}

// MinSize returns the minimum size of the indicator.
func (p *PasswordStrengthIndicator) MinSize() fyne.Size {
	return fyne.NewSize(24, 24)
}

// CreateRenderer creates the renderer for the widget.
func (p *PasswordStrengthIndicator) CreateRenderer() fyne.WidgetRenderer {
	// Use canvas.Arc for efficient single-object rendering
	// CutoutRatio 0.6 creates a ring appearance similar to the original
	// StartAngle 0 = top (12 o'clock) in Fyne's coordinate system
	arc := newPasswordIndicatorArc(0)

	r := &passwordStrengthRenderer{
		indicator: p,
		arc:       arc,
	}
	r.updateArc()
	return r
}

type passwordStrengthRenderer struct {
	indicator *PasswordStrengthIndicator
	arc       *canvas.Arc
}

func newPasswordIndicatorArc(endAngle float32) *canvas.Arc {
	return canvas.NewArc(0, endAngle, 0.6, color.Transparent)
}

func layoutPasswordIndicator(arc *canvas.Arc, size fyne.Size) {
	arcSize := fyne.NewSize(18, 18)
	arc.Move(fyne.NewPos((size.Width-arcSize.Width)/2, (size.Height-arcSize.Height)/2))
	arc.Resize(arcSize)
}

func (r *passwordStrengthRenderer) Layout(size fyne.Size) {
	layoutPasswordIndicator(r.arc, size)
}

func (r *passwordStrengthRenderer) MinSize() fyne.Size {
	return r.indicator.MinSize()
}

func (r *passwordStrengthRenderer) updateArc() {
	// Hide when not visible or in decrypt mode (matches original behavior)
	if !r.indicator.visible || r.indicator.decryMode {
		r.arc.FillColor = color.Transparent
		return
	}

	// Calculate color based on strength (0-4)
	// Red (weak) to Green (strong): matches original formula exactly
	// strength=0: R=200(0xc8), G=76(0x4c) - red
	// strength=4: R=76, G=200 - green
	// Clamp strength to valid range to prevent overflow
	s := r.indicator.strength
	if s < 0 {
		s = 0
	} else if s > 4 {
		s = 4
	}
	// #nosec G115 -- s is clamped to [0,4], so 31*s is [0,124], result always fits uint8
	col := color.RGBA{
		R: uint8(0xc8 - 31*s),
		G: uint8(0x4c + 31*s),
		B: 0x4b,
		A: 0xff,
	}

	// Arc angle calculation matching original Picocrypt:
	// Original used radians: start=-π/2, end=π*(0.4*strength-0.1)
	// Arc length = π*(0.4*strength-0.1) - (-π/2) = π*(0.4*strength+0.4) = 0.4π*(strength+1)
	// In degrees: 72*(strength+1)
	//
	// Fyne Arc: 0° is top, positive is clockwise
	// strength=0: 72° arc, strength=4: 360° (full circle)
	endAngle := float32(72 * (s + 1))

	r.arc.StartAngle = 0
	r.arc.EndAngle = endAngle
	r.arc.FillColor = col
}

func (r *passwordStrengthRenderer) Refresh() {
	r.updateArc()
	canvas.Refresh(r.arc)
}

func (r *passwordStrengthRenderer) Destroy() {}

func (r *passwordStrengthRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.arc}
}

// ValidationIndicator is a custom widget that displays a circular validation indicator.
// Shows green circle when valid, red circle when invalid, or invisible when not applicable.
// Uses the same ring geometry as the password strength indicator.
type ValidationIndicator struct {
	widget.BaseWidget
	valid   bool // true = green, false = red
	visible bool // whether to show the indicator
}

// NewValidationIndicator creates a new validation indicator.
func NewValidationIndicator() *ValidationIndicator {
	v := &ValidationIndicator{}
	v.ExtendBaseWidget(v)
	return v
}

// SetValid sets whether the validation passed.
func (v *ValidationIndicator) SetValid(valid bool) {
	v.valid = valid
	v.Refresh()
}

// SetVisible sets whether the indicator should be visible.
func (v *ValidationIndicator) SetVisible(visible bool) {
	v.visible = visible
	v.Refresh()
}

// MinSize returns the minimum size of the indicator.
func (v *ValidationIndicator) MinSize() fyne.Size {
	return fyne.NewSize(24, 24)
}

// CreateRenderer creates the renderer for the widget.
func (v *ValidationIndicator) CreateRenderer() fyne.WidgetRenderer {
	r := &validationRenderer{indicator: v, arc: newPasswordIndicatorArc(360)}
	r.updateColor()
	return r
}

type validationRenderer struct {
	indicator *ValidationIndicator
	arc       *canvas.Arc
}

func (r *validationRenderer) Layout(size fyne.Size) {
	layoutPasswordIndicator(r.arc, size)
}

func (r *validationRenderer) MinSize() fyne.Size {
	return r.indicator.MinSize()
}

func (r *validationRenderer) updateColor() {
	if !r.indicator.visible {
		r.arc.FillColor = color.Transparent
	} else if r.indicator.valid {
		r.arc.FillColor = color.RGBA{0x4c, 0xc8, 0x4b, 0xff} // Green
	} else {
		r.arc.FillColor = color.RGBA{0xc8, 0x4c, 0x4b, 0xff} // Red
	}
}

func (r *validationRenderer) Refresh() {
	r.updateColor()
	canvas.Refresh(r.arc)
}

func (r *validationRenderer) Destroy() {}

func (r *validationRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.arc}
}

// OutputDisplay is a read-only single-line text field used for generated output
// names. Unlike Entry, it never shows an editing scrollbar for long filenames.
type OutputDisplay struct {
	widget.BaseWidget
	Text string
}

// NewOutputDisplay creates a read-only output text display.
func NewOutputDisplay() *OutputDisplay {
	o := &OutputDisplay{}
	o.ExtendBaseWidget(o)
	return o
}

// SetText updates the displayed text.
func (o *OutputDisplay) SetText(text string) {
	o.Text = text
	o.Refresh()
}

func (o *OutputDisplay) MinSize() fyne.Size {
	height := fyne.MeasureText("M", theme.TextSize(), fyne.TextStyle{}).Height +
		theme.Padding()*2 + theme.InputBorderSize()*2
	return fyne.NewSize(80, height)
}

func (o *OutputDisplay) CreateRenderer() fyne.WidgetRenderer {
	background := canvas.NewRectangle(theme.Color(theme.ColorNameInputBackground))
	background.StrokeColor = theme.Color(theme.ColorNameInputBorder)
	background.StrokeWidth = theme.InputBorderSize()
	text := canvas.NewText(o.Text, theme.Color(theme.ColorNameForeground))
	text.TextSize = theme.TextSize()

	r := &outputDisplayRenderer{
		display:    o,
		background: background,
		text:       text,
	}
	r.update()
	return r
}

type outputDisplayRenderer struct {
	display    *OutputDisplay
	background *canvas.Rectangle
	text       *canvas.Text
	size       fyne.Size
}

func (r *outputDisplayRenderer) Layout(size fyne.Size) {
	r.size = size
	r.background.Move(fyne.NewPos(0, 0))
	r.background.Resize(size)

	pad := theme.Padding()
	textSize := fyne.MeasureText("M", theme.TextSize(), fyne.TextStyle{})
	y := (size.Height - textSize.Height) / 2
	if y < 0 {
		y = 0
	}
	r.text.Move(fyne.NewPos(pad, y))
	r.text.Resize(fyne.NewSize(size.Width-pad*2, textSize.Height))
	r.update()
}

func (r *outputDisplayRenderer) MinSize() fyne.Size {
	return r.display.MinSize()
}

func (r *outputDisplayRenderer) Refresh() {
	r.update()
}

func (r *outputDisplayRenderer) Destroy() {}

func (r *outputDisplayRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.background, r.text}
}

func (r *outputDisplayRenderer) update() {
	r.background.FillColor = theme.Color(theme.ColorNameInputBackground)
	r.background.StrokeColor = theme.Color(theme.ColorNameInputBorder)
	r.background.StrokeWidth = theme.InputBorderSize()
	r.text.Color = theme.Color(theme.ColorNameForeground)
	r.text.TextSize = theme.TextSize()

	availableWidth := r.size.Width - theme.Padding()*2
	if availableWidth > 0 {
		r.text.Text = truncateTextToWidth(r.display.Text, availableWidth, theme.TextSize())
	} else {
		r.text.Text = r.display.Text
	}
	canvas.Refresh(r.background)
	canvas.Refresh(r.text)
}

// PasswordEntry is an Entry widget that can toggle between password and text mode.
type PasswordEntry struct {
	widget.Entry
	hidden            bool
	viewport          *container.Scroll
	onViewportChanged func(fromScroll bool)
}

// formWheelArea forwards vertical wheel input without replacing Entry's native
// horizontal viewport, caret, selection, or focus handling. It deliberately
// has no tap, drag, or keyboard handlers.
type formWheelArea struct {
	widget.BaseWidget
	onScrolled func(*fyne.ScrollEvent)
}

func (w *formWheelArea) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(canvas.NewRectangle(color.Transparent))
}

func (w *formWheelArea) Scrolled(event *fyne.ScrollEvent) {
	if event.Scrolled.DY != 0 {
		w.onScrolled(event)
	}
}

func (a *App) scrollFormOver(entry fyne.CanvasObject) fyne.CanvasObject {
	if isMobile() {
		return entry
	}
	wheel := &formWheelArea{onScrolled: func(event *fyne.ScrollEvent) {
		if a.mainScroll != nil {
			a.mainScroll.Scrolled(event)
		}
	}}
	wheel.ExtendBaseWidget(wheel)
	return container.NewStack(entry, wheel)
}

// NewPasswordEntry creates a new password entry.
func NewPasswordEntry() *PasswordEntry {
	e := &PasswordEntry{hidden: true}
	e.ExtendBaseWidget(e)
	e.Password = true
	return e
}

// SetHidden sets whether the password is hidden.
func (e *PasswordEntry) SetHidden(hidden bool) {
	e.hidden = hidden
	e.Password = hidden
	e.Refresh()
}

// IsHidden returns whether the password is currently hidden.
func (e *PasswordEntry) IsHidden() bool {
	return e.hidden
}

// ColoredLabel is a compact status link using the current theme's status colors.
type ColoredLabel struct {
	view  *container.ThemeOverride
	link  *widget.Hyperlink
	text  string
	color color.Color
}

// NewColoredLabel creates a status link with native text truncation.
func NewColoredLabel(text string, col color.Color) *ColoredLabel {
	link := widget.NewHyperlink("", nil)
	link.Truncation = fyne.TextTruncateEllipsis
	l := &ColoredLabel{link: link, text: text, color: col}
	l.view = container.NewThemeOverride(link, statusLinkTheme{label: l})
	l.SetText(text)
	return l
}

func (l *ColoredLabel) object() fyne.CanvasObject {
	return l.view
}

// SetText updates the label text.
func (l *ColoredLabel) SetText(text string) {
	l.text = text
	preview := strings.Join(strings.Fields(text), " ")
	l.link.SetText(preview)
}

// SetColor updates the label color.
func (l *ColoredLabel) SetColor(col color.Color) {
	l.color = col
	l.view.Refresh()
}

// SetTruncation updates the label truncation mode.
func (l *ColoredLabel) SetTruncation(truncation fyne.TextTruncation) {
	l.link.Truncation = truncation
	l.link.Refresh()
}

// SetOnTapped sets the details action for mouse and keyboard activation.
func (l *ColoredLabel) SetOnTapped(action func()) {
	l.link.OnTapped = action
}

type statusLinkTheme struct {
	label *ColoredLabel
}

func (statusLinkTheme) base() fyne.Theme {
	if current := fyne.CurrentApp(); current != nil && current.Settings().Theme() != nil {
		return current.Settings().Theme()
	}
	return theme.DefaultTheme()
}

func (t statusLinkTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	if name == theme.ColorNameHyperlink {
		switch t.label.color {
		case util.RED:
			name = theme.ColorNameError
		case util.YELLOW:
			name = theme.ColorNameWarning
		case util.GREEN:
			name = theme.ColorNameSuccess
		default:
			name = theme.ColorNameForeground
		}
	}
	return t.base().Color(name, variant)
}

func (t statusLinkTheme) Font(style fyne.TextStyle) fyne.Resource {
	return t.base().Font(style)
}

func (t statusLinkTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return t.base().Icon(name)
}

func (t statusLinkTheme) Size(name fyne.ThemeSizeName) float32 {
	return t.base().Size(name)
}

// truncateTextToWidth truncates text with ellipsis if it exceeds maxWidth.
func truncateTextToWidth(text string, maxWidth float32, textSize float32) string {
	if maxWidth <= 0 {
		return text
	}

	measured := fyne.MeasureText(text, textSize, fyne.TextStyle{})
	if measured.Width <= maxWidth {
		return text
	}

	ellipsis := "..."
	ellipsisWidth := fyne.MeasureText(ellipsis, textSize, fyne.TextStyle{}).Width
	availableWidth := maxWidth - ellipsisWidth

	if availableWidth <= 0 {
		return ellipsis
	}

	runes := []rune(text)

	// Binary search for the longest substring that fits with ellipsis
	low, high := 0, len(runes)
	for low < high {
		mid := (low + high + 1) / 2
		candidate := string(runes[:mid]) + ellipsis
		candidateWidth := fyne.MeasureText(candidate, textSize, fyne.TextStyle{}).Width

		if candidateWidth <= maxWidth {
			low = mid // This length fits, try longer
		} else {
			high = mid - 1 // This length is too long, try shorter
		}
	}

	if low == 0 {
		return ellipsis
	}
	return string(runes[:low]) + ellipsis
}
