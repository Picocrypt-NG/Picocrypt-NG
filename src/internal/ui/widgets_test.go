// Package ui provides tests for custom Fyne widgets.
package ui

import (
	"Picocrypt-NG/internal/util"
	"image/color"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/test"
	fynetheme "fyne.io/fyne/v2/theme"
)

// strengthColor mirrors passwordStrengthRenderer.updateArc's color formula with
// the same [0,4] clamp the production code applies before computing the RGBA. The
// test recreates the formula (not the value) so a regression in updateArc's
// arithmetic — wrong coefficient, missing clamp, swapped channels — is caught at
// the rendered FillColor rather than silently passing.
func strengthColor(t *testing.T, strength int) color.RGBA {
	t.Helper()
	s := strength
	if s < 0 {
		s = 0
	} else if s > 4 {
		s = 4
	}
	return color.RGBA{
		R: uint8(0xc8 - 31*s),
		G: uint8(0x4c + 31*s),
		B: 0x4b,
		A: 0xff,
	}
}

// TestPasswordStrengthIndicator tests the password strength indicator widget.
func TestPasswordStrengthIndicator(t *testing.T) {
	// Create test app
	newTestFyneApp(t)

	// SetStrength asserts on the rendered arc, not the backing field. For each
	// score the visible arc's FillColor must equal the red→green formula and its
	// EndAngle must equal 72*(clamped strength+1) degrees (the original Picocrypt
	// arc length). Clamp rows (-1, 5) pin both color and angle to [0,4]. This fails if
	// updateArc's color math or angle math regresses, where a field-echo would not.
	t.Run("SetStrength", func(t *testing.T) {
		indicator := NewPasswordStrengthIndicator()
		renderer := indicator.CreateRenderer().(*passwordStrengthRenderer)
		indicator.SetVisible(true)

		for _, tc := range []struct {
			strength int
		}{
			{-1}, {0}, {1}, {2}, {3}, {4}, {5},
		} {
			indicator.SetStrength(tc.strength)
			renderer.updateArc()

			wantColor := strengthColor(t, tc.strength)
			if got := renderer.arc.FillColor; got != wantColor {
				t.Errorf("strength %d: arc.FillColor = %v, want %v", tc.strength, got, wantColor)
			}
			s := tc.strength
			if s < 0 {
				s = 0
			} else if s > 4 {
				s = 4
			}
			wantAngle := float32(72 * (s + 1))
			if got := renderer.arc.EndAngle; got != wantAngle {
				t.Errorf("strength %d: arc.EndAngle = %v, want %v", tc.strength, got, wantAngle)
			}
		}
	})

	// SetVisible+SetDecryptMode are merged into one renderer check covering the
	// three-way visibility gate in updateArc: the arc fill is transparent when
	// hidden, opaque when visible and not decrypting, and transparent again in
	// decrypt mode even while visible. This fails if updateArc drops either guard.
	t.Run("VisibilityGate", func(t *testing.T) {
		indicator := NewPasswordStrengthIndicator()
		renderer := indicator.CreateRenderer().(*passwordStrengthRenderer)
		indicator.SetStrength(2) // a strength with an opaque color

		indicator.SetVisible(false)
		indicator.SetDecryptMode(false)
		renderer.updateArc()
		if got := renderer.arc.FillColor; got != color.Transparent {
			t.Errorf("hidden: arc.FillColor = %v, want transparent", got)
		}

		indicator.SetVisible(true)
		indicator.SetDecryptMode(false)
		renderer.updateArc()
		if got := renderer.arc.FillColor; got == color.Transparent {
			t.Error("visible && !decrypt: arc.FillColor should be opaque, got transparent")
		}

		indicator.SetVisible(true)
		indicator.SetDecryptMode(true)
		renderer.updateArc()
		if got := renderer.arc.FillColor; got != color.Transparent {
			t.Errorf("visible && decrypt: arc.FillColor = %v, want transparent", got)
		}
	})

	t.Run("MinSize", func(t *testing.T) {
		indicator := NewPasswordStrengthIndicator()
		minSize := indicator.MinSize()

		if minSize.Width != 24 {
			t.Errorf("Expected width 24, got %f", minSize.Width)
		}
		if minSize.Height != 24 {
			t.Errorf("Expected height 24, got %f", minSize.Height)
		}
	})

	t.Run("CreateRenderer", func(t *testing.T) {
		indicator := NewPasswordStrengthIndicator()
		renderer := indicator.CreateRenderer()

		if renderer == nil {
			t.Fatal("Expected non-nil renderer")
		}

		objects := renderer.Objects()
		// Uses single canvas.Arc instead of 36 line segments for efficient rendering
		if len(objects) != 1 {
			t.Errorf("Expected 1 canvas object (Arc), got %d", len(objects))
		}
	})
}

// TestValidationIndicator tests the validation indicator widget.
func TestValidationIndicator(t *testing.T) {
	newTestFyneApp(t)

	// SetValid+SetVisible are merged into one renderer check on the ring's
	// FillColor: green
	// when valid, red when invalid, fully transparent when hidden. This asserts the
	// rendered output of updateColor, so it fails if any branch's color regresses
	// or the visibility guard is dropped — a field-echo could not catch that.
	t.Run("ColorState", func(t *testing.T) {
		green := color.RGBA{0x4c, 0xc8, 0x4b, 0xff}
		red := color.RGBA{0xc8, 0x4c, 0x4b, 0xff}

		for _, tc := range []struct {
			name    string
			valid   bool
			visible bool
			want    color.Color
		}{
			{"ValidVisibleGreen", true, true, green},
			{"InvalidVisibleRed", false, true, red},
			{"HiddenTransparent", true, false, color.Transparent},
			{"HiddenInvalidTransparent", false, false, color.Transparent},
		} {
			t.Run(tc.name, func(t *testing.T) {
				indicator := NewValidationIndicator()
				renderer := indicator.CreateRenderer().(*validationRenderer)
				indicator.SetValid(tc.valid)
				indicator.SetVisible(tc.visible)
				renderer.updateColor()

				if got := renderer.arc.FillColor; got != tc.want {
					t.Errorf("arc.FillColor = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("MinSize", func(t *testing.T) {
		indicator := NewValidationIndicator()
		minSize := indicator.MinSize()

		if minSize.Width != 24 {
			t.Errorf("Expected width 24, got %f", minSize.Width)
		}
		if minSize.Height != 24 {
			t.Errorf("Expected height 24, got %f", minSize.Height)
		}
	})

	t.Run("CreateRenderer", func(t *testing.T) {
		indicator := NewValidationIndicator()
		renderer := indicator.CreateRenderer()

		if renderer == nil {
			t.Fatal("Expected non-nil renderer")
		}

		objects := renderer.Objects()
		// Uses the same Arc primitive as the strength indicator.
		if len(objects) != 1 {
			t.Errorf("Expected 1 canvas object (Arc), got %d", len(objects))
		}
	})
}

// TestPasswordEntry asserts the load-bearing coupling between the embedded
// widget.Entry.Password field (which actually masks the text) and the widget's
// own hidden flag (which IsHidden reports). The two must stay in lockstep:
// masking the entry while reporting "shown" — or vice versa — leaks or
// mis-labels the password, so this guards that SetHidden drives BOTH, not just
// the bookkeeping flag.
func TestPasswordEntry(t *testing.T) {
	newTestFyneApp(t)

	entry := NewPasswordEntry()

	// Fresh: masked and reported as hidden.
	if !entry.Password || !entry.IsHidden() {
		t.Fatalf("fresh entry: Password=%v IsHidden=%v; want both true", entry.Password, entry.IsHidden())
	}

	// Reveal: masking off AND reported as shown.
	entry.SetHidden(false)
	if entry.Password {
		t.Error("SetHidden(false): Password (masking) must be off, else text stays masked while labeled shown")
	}
	if entry.IsHidden() {
		t.Error("SetHidden(false): IsHidden must report false")
	}

	// Re-hide: both back on.
	entry.SetHidden(true)
	if !entry.Password || !entry.IsHidden() {
		t.Fatalf("SetHidden(true): Password=%v IsHidden=%v; want both true", entry.Password, entry.IsHidden())
	}
}

func TestColoredLabel(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	fyne.DoAndWait(func() {
		label := NewColoredLabel("Initial", util.WHITE)
		label.object().Resize(fyne.NewSize(300, 30))
		label.SetText("Updated")
		for _, variant := range []fyne.ThemeVariant{fynetheme.VariantLight, fynetheme.VariantDark} {
			current := fixedVariantTheme{Theme: NewCompactTheme(), variant: variant}
			fyneApp.Settings().SetTheme(current)
			for _, status := range []struct {
				color color.Color
				name  fyne.ThemeColorName
			}{
				{util.RED, fynetheme.ColorNameError},
				{util.YELLOW, fynetheme.ColorNameWarning},
				{util.GREEN, fynetheme.ColorNameSuccess},
				{util.WHITE, fynetheme.ColorNameForeground},
			} {
				label.SetColor(status.color)
				found := false
				for _, object := range test.LaidOutObjects(label.object()) {
					text, ok := object.(*canvas.Text)
					if !ok || text.Text != "Updated" {
						continue
					}
					found = true
					want := current.Color(status.name, variant)
					if !sameColor(text.Color, want) {
						t.Errorf("status %s rendered %v, want theme color %v", status.name, text.Color, want)
					}
				}
				if !found {
					t.Error("status did not render updated text")
				}
			}
		}
		message := "stat /" + strings.Repeat("directory/", 80) + "file: not found"
		label.SetText(message)
		found := false
		for _, object := range test.LaidOutObjects(label.object()) {
			text, ok := object.(*canvas.Text)
			if !ok || text.Text == "" {
				continue
			}
			found = true
			if text.Text == message || !strings.HasSuffix(text.Text, "…") {
				t.Error("long status did not render an ellipsized preview")
			}
			if text.MinSize().Width > label.object().Size().Width {
				t.Error("status preview overflows available width")
			}
		}
		if !found {
			t.Error("long status preview was not rendered")
		}
	})
}

// TestOutputDisplay tests the passive output filename display.
func TestOutputDisplay(t *testing.T) {
	newTestFyneApp(t)

	t.Run("NewOutputDisplay", func(t *testing.T) {
		output := NewOutputDisplay()
		if output.MinSize().Width <= 0 || output.MinSize().Height <= 0 {
			t.Fatalf("MinSize = %v; want positive dimensions", output.MinSize())
		}
	})

	t.Run("SetText", func(t *testing.T) {
		output := NewOutputDisplay()
		output.SetText("Test content")

		if output.Text != "Test content" {
			t.Errorf("Expected text 'Test content', got '%s'", output.Text)
		}
	})
}

// TestCompactTheme tests the compact theme.
func TestCompactTheme(t *testing.T) {
	t.Run("Size", func(t *testing.T) {
		theme := NewCompactTheme().(*CompactTheme)

		// Test custom sizes for improved readability
		textSize := theme.Size("text")
		if textSize != 14 {
			t.Errorf("Expected text size 14, got %f", textSize)
		}

		paddingSize := theme.Size("padding")
		if paddingSize != 6 {
			t.Errorf("Expected padding 6, got %f", paddingSize)
		}
	})

	t.Run("Color", func(t *testing.T) {
		theme := NewCompactTheme().(*CompactTheme)

		// Enhanced-contrast foreground: near-white in dark mode, near-black in light mode.
		dark := theme.Color(fynetheme.ColorNameForeground, fynetheme.VariantDark)
		wantDark := color.RGBA{R: 0xF5, G: 0xF5, B: 0xF5, A: 0xFF}
		if dark != wantDark {
			t.Errorf("dark foreground: expected %v, got %v", wantDark, dark)
		}

		light := theme.Color(fynetheme.ColorNameForeground, fynetheme.VariantLight)
		wantLight := color.RGBA{R: 0x10, G: 0x10, B: 0x10, A: 0xFF}
		if light != wantLight {
			t.Errorf("light foreground: expected %v, got %v", wantLight, light)
		}
	})
}
