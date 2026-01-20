// Package ui provides the Picocrypt NG graphical user interface using Fyne.
package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// CompactTheme is a custom theme that matches the original Picocrypt (giu) look.
// It uses smaller fonts and reduced padding for a more compact UI.
type CompactTheme struct{}

var _ fyne.Theme = (*CompactTheme)(nil)

// NewCompactTheme creates a new compact theme matching original Picocrypt styling.
func NewCompactTheme() fyne.Theme {
	return &CompactTheme{}
}

// Color returns the color for the specified name and variant.
// Enhanced contrast for better readability.
func (c *CompactTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameForeground:
		// Darker text in light mode, brighter text in dark mode for better contrast
		if variant == theme.VariantLight {
			return color.RGBA{R: 0x10, G: 0x10, B: 0x10, A: 0xFF} // Near-black (#101010)
		}
		return color.RGBA{R: 0xF5, G: 0xF5, B: 0xF5, A: 0xFF} // Near-white (#F5F5F5)

	case theme.ColorNamePlaceHolder:
		// Higher contrast placeholder text
		if variant == theme.VariantLight {
			return color.RGBA{R: 0x60, G: 0x60, B: 0x60, A: 0xFF} // Darker gray
		}
		return color.RGBA{R: 0xA0, G: 0xA0, B: 0xA0, A: 0xFF} // Lighter gray

	case theme.ColorNameDisabled:
		// More visible disabled text
		if variant == theme.VariantLight {
			return color.RGBA{R: 0x70, G: 0x70, B: 0x70, A: 0xFF}
		}
		return color.RGBA{R: 0x90, G: 0x90, B: 0x90, A: 0xFF}

	case theme.ColorNameInputBackground:
		// Slightly differentiated input background for better visibility
		if variant == theme.VariantLight {
			return color.RGBA{R: 0xF8, G: 0xF8, B: 0xF8, A: 0xFF} // Very light gray
		}
		return color.RGBA{R: 0x28, G: 0x28, B: 0x28, A: 0xFF} // Slightly lighter than default

	case theme.ColorNameInputBorder:
		// More visible input borders
		if variant == theme.VariantLight {
			return color.RGBA{R: 0xB0, G: 0xB0, B: 0xB0, A: 0xFF} // Medium gray border
		}
		return color.RGBA{R: 0x60, G: 0x60, B: 0x60, A: 0xFF} // Visible gray in dark mode

	default:
		return theme.DefaultTheme().Color(name, variant)
	}
}

// Font returns the font resource for the specified text style.
func (c *CompactTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

// Icon returns the icon resource for the specified name.
func (c *CompactTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

// Size returns the size for the specified name.
// Increased font sizes for better readability while maintaining compact layout.
func (c *CompactTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNameText:
		return 14 // Increased from 12 for better readability (default is 14)
	case theme.SizeNameCaptionText:
		return 11 // Increased from 10 (default is 11)
	case theme.SizeNameSubHeadingText:
		return 12 // Increased from 11 (default is 13)
	case theme.SizeNameHeadingText:
		return 20 // Increased from 18 (default is 24)
	case theme.SizeNamePadding:
		return 6 // Increased from 4 for better breathing room (default is 6)
	case theme.SizeNameInnerPadding:
		return 6 // Increased from 4 for better spacing (default is 8)
	case theme.SizeNameInlineIcon:
		return 20 // Increased from 18 (default is 20)
	case theme.SizeNameScrollBar:
		return 12 // Default is 16
	case theme.SizeNameScrollBarSmall:
		return 3 // Default is 3
	case theme.SizeNameSeparatorThickness:
		return 1 // Default is 1
	case theme.SizeNameInputBorder:
		return 2 // Increased from 1 for more visible borders (default is 1)
	case theme.SizeNameInputRadius:
		return 4 // Default is 5
	case theme.SizeNameSelectionRadius:
		return 3 // Default is 3
	default:
		return theme.DefaultTheme().Size(name)
	}
}
