// Package ui provides the Picocrypt NG graphical user interface using Fyne.
package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/pcv3artifact"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3recovery"
	"image/color"
	"strconv"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

type pcv3ArtifactView interface {
	Metadata() pcv3recovery.ArtifactInspectionMetadata
	Page(offset, limit uint64) ([]pcv3artifact.Range, bool)
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
	page       []pcv3artifact.Range
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

func (model *pcv3ArtifactRangeModel) at(index int) (pcv3artifact.Range, bool) {
	if model == nil || model.view == nil || index < 0 || uint64(index) >= model.rangeCount {
		return pcv3artifact.Range{}, false
	}
	offset := (uint64(index) / 128) * 128
	if model.page == nil || model.pageOffset != offset {
		page, ok := model.view.Page(offset, 128)
		if !ok || len(page) == 0 {
			return pcv3artifact.Range{}, false
		}
		model.pageOffset = offset
		model.page = page
	}
	position := uint64(index) - model.pageOffset
	if position >= uint64(len(model.page)) {
		return pcv3artifact.Range{}, false
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

func pcv3FactorPolicyText(policy app.PCV3FactorPolicy) string {
	switch policy {
	case app.PCV3FactorPolicyPassword:
		return tr("pcv3.factor.password", "Password only")
	case app.PCV3FactorPolicyKeyfiles:
		return tr("pcv3.factor.keyfiles", "Keyfiles only")
	case app.PCV3FactorPolicyCombined:
		return tr("pcv3.factor.combined", "Password + keyfiles")
	default:
		return tr("pcv3.factor.unset", "Not selected")
	}
}

func pcv3KeyfileOrderText(order app.PCV3KeyfileOrder) string {
	switch order {
	case app.PCV3KeyfileOrderSelected:
		return tr("pcv3.order.ordered", "Use selected order")
	case app.PCV3KeyfileOrderAny:
		return tr("pcv3.order.unordered", "Any order")
	default:
		return ""
	}
}

func buildPCV3IntentSummary(snap app.UISnapshot) fyne.CanvasObject {
	format := tr("pcv3.format.normal", "Normal PCV3")
	if snap.PCV3Format == app.PCV3FormatD1 {
		format = tr("pcv3.format.d1", "PCV3 D1")
	}
	action := ""
	switch snap.PCV3Action {
	case app.PCV3ActionDecrypt:
		action = tr("pcv3.action.decrypt", "Decrypt")
	case app.PCV3ActionRecovery:
		action = tr("pcv3.action.recovery", "Recovery")
	case app.PCV3ActionForce:
		action = tr("pcv3.action.force", "Force recovery")
	}
	lines := []fyne.CanvasObject{
		wrappedPCV3Label(tr("pcv3.format.label", "Format:") + " " + format),
		wrappedPCV3Label(tr("pcv3.action.label", "PCV3 operation") + ": " + action),
		wrappedPCV3Label(tr("pcv3.factor.label", "Credential policy") + ": " + pcv3FactorPolicyText(snap.PCV3Factor)),
		wrappedPCV3Label(tr("pcv3.intent.keyfiles", "Keyfiles") + ": " + keyfileDisplayLabel(false, snap.KeyfileCount, true)),
		wrappedPCV3Label(tr("pcv3.intent.destination", "Destination") + ": " + func() string {
			if snap.OutputFile == "" {
				return tr("pcv3.factor.unset", "Not selected")
			}
			return tr("pcv3.intent.destination", "Destination")
		}()),
	}
	if order := pcv3KeyfileOrderText(snap.PCV3Order); order != "" {
		lines = append(lines, wrappedPCV3Label(tr("pcv3.order.label", "Keyfile order")+": "+order))
	}
	if len(snap.PCV3KeyfileNames) != 0 {
		items := container.NewVBox()
		for index, name := range snap.PCV3KeyfileNames {
			itemText := strconv.Itoa(index+1) + ". " + name
			label := widget.NewLabel(itemText)
			label.Truncation = fyne.TextTruncateEllipsis
			items.Add(label)
		}
		list := container.NewVScroll(items)
		list.SetMinSize(fyne.NewSize(0, 96))
		lines = append(lines, list)
	}
	return container.NewVBox(lines...)
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
	arc := canvas.NewArc(0, 0, 0.6, color.Transparent)
	arc.SetMinSize(fyne.NewSize(20, 20))

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

func (r *passwordStrengthRenderer) Layout(size fyne.Size) {
	// Center the arc in the widget area
	arcSize := fyne.NewSize(18, 18)
	offset := fyne.NewPos(
		(size.Width-arcSize.Width)/2,
		(size.Height-arcSize.Height)/2,
	)
	r.arc.Move(offset)
	r.arc.Resize(arcSize)
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
// Uses canvas.Circle for efficient GPU-accelerated rendering.
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
	// Use canvas.Circle for efficient single-object rendering
	circle := canvas.NewCircle(color.Transparent)
	circle.StrokeWidth = 2

	r := &validationRenderer{indicator: v, circle: circle}
	r.updateColor()
	return r
}

type validationRenderer struct {
	indicator *ValidationIndicator
	circle    *canvas.Circle
}

func (r *validationRenderer) Layout(size fyne.Size) {
	// Center the circle in the widget area - same optical size as password strength arc.
	circleSize := fyne.NewSize(18, 18)
	offset := fyne.NewPos(
		(size.Width-circleSize.Width)/2,
		(size.Height-circleSize.Height)/2,
	)
	r.circle.Move(offset)
	r.circle.Resize(circleSize)
}

func (r *validationRenderer) MinSize() fyne.Size {
	return r.indicator.MinSize()
}

func (r *validationRenderer) updateColor() {
	if !r.indicator.visible {
		r.circle.StrokeColor = color.Transparent
		r.circle.FillColor = color.Transparent
	} else if r.indicator.valid {
		r.circle.StrokeColor = color.RGBA{0x4c, 0xc8, 0x4b, 0xff} // Green
		r.circle.FillColor = color.Transparent
	} else {
		r.circle.StrokeColor = color.RGBA{0xc8, 0x4c, 0x4b, 0xff} // Red
		r.circle.FillColor = color.Transparent
	}
}

func (r *validationRenderer) Refresh() {
	r.updateColor()
	canvas.Refresh(r.circle)
}

func (r *validationRenderer) Destroy() {}

func (r *validationRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.circle}
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
	hidden bool
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

// ColoredLabel is a label with custom text color.
type ColoredLabel struct {
	widget.BaseWidget
	text       string
	color      color.Color
	truncation fyne.TextTruncation
}

// NewColoredLabel creates a new label with custom color.
func NewColoredLabel(text string, col color.Color) *ColoredLabel {
	l := &ColoredLabel{
		text:       text,
		color:      col,
		truncation: fyne.TextTruncateEllipsis, // Default to ellipsis truncation
	}
	l.ExtendBaseWidget(l)
	return l
}

// SetText updates the label text.
func (l *ColoredLabel) SetText(text string) {
	l.text = text
	l.Refresh()
}

// SetColor updates the label color.
func (l *ColoredLabel) SetColor(col color.Color) {
	l.color = col
	l.Refresh()
}

// SetTruncation updates the label truncation mode.
func (l *ColoredLabel) SetTruncation(truncation fyne.TextTruncation) {
	l.truncation = truncation
	l.Refresh()
}

// MinSize returns the minimum size needed to display the label.
// When truncation is enabled, limits width to prevent window resizing.
func (l *ColoredLabel) MinSize() fyne.Size {
	textSize := fyne.MeasureText(l.text, theme.TextSize(), fyne.TextStyle{})

	// If truncation is enabled, don't let the label force window resizing
	// Use a reasonable maximum width (e.g., 600 pixels)
	if l.truncation != fyne.TextTruncateOff && textSize.Width > 600 {
		textSize.Width = 600
	}

	return textSize
}

// CreateRenderer creates the renderer for the colored label.
func (l *ColoredLabel) CreateRenderer() fyne.WidgetRenderer {
	text := canvas.NewText(l.text, l.color)
	text.TextSize = theme.TextSize()
	return &coloredLabelRenderer{label: l, text: text}
}

type coloredLabelRenderer struct {
	label         *ColoredLabel
	text          *canvas.Text
	availableSize fyne.Size
}

func (r *coloredLabelRenderer) Layout(size fyne.Size) {
	r.availableSize = size
	r.text.Move(fyne.NewPos(0, 0))
	r.text.Resize(size)
	r.updateText()
}

func (r *coloredLabelRenderer) MinSize() fyne.Size {
	return r.label.MinSize()
}

func (r *coloredLabelRenderer) Refresh() {
	r.updateText()
}

// updateText updates the displayed text with truncation if needed
func (r *coloredLabelRenderer) updateText() {
	displayText := r.label.text

	// Apply truncation if needed and we have available size
	if r.label.truncation != fyne.TextTruncateOff && r.availableSize.Width > 0 {
		displayText = truncateTextToWidth(displayText, r.availableSize.Width, theme.TextSize())
	}

	r.text.Text = displayText
	r.text.Color = r.label.color
	canvas.Refresh(r.text)
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

func (r *coloredLabelRenderer) Destroy() {}

func (r *coloredLabelRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.text}
}
