// Package ui provides tests for custom Fyne widgets.
package ui

import (
	"image/color"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
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

	// SetValid+SetVisible are merged into one renderer check on the drawn circle's
	// StrokeColor (the only visible channel; FillColor stays transparent): green
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

				if got := renderer.circle.StrokeColor; got != tc.want {
					t.Errorf("circle.StrokeColor = %v, want %v", got, tc.want)
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
		// Uses single canvas.Circle instead of 24 line segments for efficient rendering
		if len(objects) != 1 {
			t.Errorf("Expected 1 canvas object (Circle), got %d", len(objects))
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

// TestColoredLabel tests the colored label widget.
func TestColoredLabel(t *testing.T) {
	newTestFyneApp(t)

	// SetText asserts the rendered canvas.Text reflects the new value. Layout is
	// called with a width wide enough that updateText's truncation leaves the text
	// intact, so the drawn Text must equal what was set. This fails if SetText
	// stops propagating into updateText (the renderer would keep the old string).
	t.Run("SetText", func(t *testing.T) {
		label := NewColoredLabel("Initial", color.White)
		renderer := label.CreateRenderer().(*coloredLabelRenderer)
		renderer.Layout(fyne.NewSize(1000, 50)) // wide: no truncation

		label.SetText("Updated")
		renderer.Refresh()

		if got := renderer.text.Text; got != "Updated" {
			t.Errorf("rendered text = %q, want %q", got, "Updated")
		}
	})

	// SetColor asserts the rendered canvas.Text carries the new color. updateText
	// copies label.color onto the drawn text, so a regression that drops the color
	// assignment is caught here where a field-echo on label.color would not.
	t.Run("SetColor", func(t *testing.T) {
		label := NewColoredLabel("Test", color.White)
		renderer := label.CreateRenderer().(*coloredLabelRenderer)
		renderer.Layout(fyne.NewSize(1000, 50))

		newColor := color.RGBA{R: 0, G: 255, B: 0, A: 255}
		label.SetColor(newColor)
		renderer.Refresh()

		if got := renderer.text.Color; got != color.Color(newColor) {
			t.Errorf("rendered text color = %v, want %v", got, newColor)
		}
	})

	t.Run("MinSize", func(t *testing.T) {
		label := NewColoredLabel("Test", color.White)
		minSize := label.MinSize()

		// Width/height must equal the measured text size at the theme text size.
		want := fyne.MeasureText("Test", fynetheme.TextSize(), fyne.TextStyle{})
		if minSize.Width != want.Width {
			t.Errorf("Expected width %f, got %f", want.Width, minSize.Width)
		}
		if minSize.Height != want.Height {
			t.Errorf("Expected height %f, got %f", want.Height, minSize.Height)
		}
	})

	t.Run("MinSize_TruncationCap", func(t *testing.T) {
		// Default truncation is ellipsis (see NewColoredLabel), so a long string
		// must be capped at 600px to avoid forcing window resizing.
		long := strings.Repeat("A", 500)
		raw := fyne.MeasureText(long, fynetheme.TextSize(), fyne.TextStyle{})
		if raw.Width <= 600 {
			t.Fatalf("precondition: long string must exceed 600px, got %f", raw.Width)
		}
		label := NewColoredLabel(long, color.White)
		if got := label.MinSize().Width; got != 600 {
			t.Errorf("Expected capped width 600, got %f", got)
		}
	})

	t.Run("CreateRenderer", func(t *testing.T) {
		label := NewColoredLabel("Test", color.White)
		renderer := label.CreateRenderer()

		if renderer == nil {
			t.Fatal("Expected non-nil renderer")
		}

		objects := renderer.Objects()
		if len(objects) != 1 {
			t.Errorf("Expected 1 object, got %d", len(objects))
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

// TestFixedWidthLayout tests the fixed width layout.
func TestFixedWidthLayout(t *testing.T) {
	newTestFyneApp(t)

	t.Run("MinSize_Empty", func(t *testing.T) {
		layout := &fixedWidthLayout{width: 100}
		minSize := layout.MinSize(nil)

		if minSize.Width != 100 {
			t.Errorf("Expected width 100, got %f", minSize.Width)
		}
		if minSize.Height != 0 {
			t.Errorf("Expected height 0, got %f", minSize.Height)
		}
	})

	t.Run("MinSize_WithObject", func(t *testing.T) {
		layout := &fixedWidthLayout{width: 100}

		// Create a simple label widget
		label := NewColoredLabel("Test", color.White)
		objects := []fyne.CanvasObject{label}
		minSize := layout.MinSize(objects)

		if minSize.Width != 100 {
			t.Errorf("Expected width 100, got %f", minSize.Width)
		}
	})

	t.Run("Layout", func(t *testing.T) {
		layout := &fixedWidthLayout{width: 100}

		// Create a simple label widget
		label := NewColoredLabel("Test", color.White)
		objects := []fyne.CanvasObject{label}

		// Apply layout
		layout.Layout(objects, fyne.NewSize(200, 50))

		// Check that object was resized to fixed width
		if label.Size().Width != 100 {
			t.Errorf("Expected object width 100, got %f", label.Size().Width)
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
