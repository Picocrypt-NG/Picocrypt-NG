package util

import (
	"fmt"
	"math"
	"time"
)

// Statify converts done bytes, total bytes, and starting time to progress, speed (MiB/s), and ETA string.
// Returns: progress (0.0-1.0), speed in MiB/s, ETA as "HH:MM:SS"
func Statify(done int64, total int64, start time.Time) (float32, float64, string) {
	// Guard against division by zero
	if total <= 0 {
		return 0, 0, "00:00:00"
	}

	progress := float32(done) / float32(total)

	// Calculate elapsed time in seconds (correct unit conversion)
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		// Just started, no meaningful speed/ETA yet
		return float32(math.Min(float64(progress), 1)), 0, "00:00:00"
	}

	// Speed in MiB/s: bytes / seconds / bytes_per_MiB
	speed := float64(done) / elapsed / float64(MiB)

	// ETA in seconds: remaining_bytes / (speed * bytes_per_MiB)
	var eta int
	if speed > 0 {
		eta = int(math.Floor(float64(total-done) / (speed * float64(MiB))))
	}

	return float32(math.Min(float64(progress), 1)), speed, Timeify(eta)
}

// Timeify converts seconds to "HH:MM:SS" format.
func Timeify(seconds int) string {
	hours := int(math.Floor(float64(seconds) / 3600))
	seconds %= 3600
	minutes := int(math.Floor(float64(seconds) / 60))
	seconds %= 60
	hours = int(math.Max(float64(hours), 0))
	minutes = int(math.Max(float64(minutes), 0))
	seconds = int(math.Max(float64(seconds), 0))
	return fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds)
}

// Sizeify converts bytes to a human-readable string (KiB, MiB, GiB, TiB).
func Sizeify(size int64) string {
	if size >= int64(TiB) {
		return fmt.Sprintf("%.2f TiB", float64(size)/float64(TiB))
	} else if size >= int64(GiB) {
		return fmt.Sprintf("%.2f GiB", float64(size)/float64(GiB))
	} else if size >= int64(MiB) {
		return fmt.Sprintf("%.2f MiB", float64(size)/float64(MiB))
	} else {
		return fmt.Sprintf("%.2f KiB", float64(size)/float64(KiB))
	}
}
