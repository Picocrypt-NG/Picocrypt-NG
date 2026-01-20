// Package util provides common utilities and constants for Picocrypt-NG.
//
// This package contains:
//   - Size constants (KiB, MiB, GiB, TiB) for byte calculations
//   - Color constants for UI status messages
//   - Progress/speed/time formatting functions (Statify, Timeify, Sizeify)
//   - Cryptographically secure password generation
//   - Helper functions for file size and time display
//
// All utilities are stateless and thread-safe.
package util

import "image/color"

// Size constants for byte calculations
const (
	KiB = 1 << 10 // 1024
	MiB = 1 << 20 // 1,048,576
	GiB = 1 << 30 // 1,073,741,824
	TiB = 1 << 40 // 1,099,511,627,776
)

// Color constants for UI status messages
var (
	WHITE       = color.RGBA{0xff, 0xff, 0xff, 0xff}
	RED         = color.RGBA{0xff, 0x00, 0x00, 0xff}
	GREEN       = color.RGBA{0x00, 0xff, 0x00, 0xff}
	YELLOW      = color.RGBA{0xcc, 0x70, 0x00, 0xff} // Dark amber for better readability
	TRANSPARENT = color.RGBA{0x00, 0x00, 0x00, 0x00}
)
