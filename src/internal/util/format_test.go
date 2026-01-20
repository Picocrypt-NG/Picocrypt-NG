package util

import (
	"testing"
	"time"
)

func TestTimeify(t *testing.T) {
	tests := []struct {
		seconds  int
		expected string
	}{
		{0, "00:00:00"},
		{59, "00:00:59"},
		{60, "00:01:00"},
		{3599, "00:59:59"},
		{3600, "01:00:00"},
		{3661, "01:01:01"},
		{86399, "23:59:59"},
		{-10, "00:00:00"}, // negative values should clamp to 0
	}

	for _, tt := range tests {
		result := Timeify(tt.seconds)
		if result != tt.expected {
			t.Errorf("Timeify(%d) = %s; want %s", tt.seconds, result, tt.expected)
		}
	}
}

func TestSizeify(t *testing.T) {
	tests := []struct {
		size     int64
		expected string
	}{
		{0, "0.00 KiB"},
		{1024, "1.00 KiB"},
		{1536, "1.50 KiB"},
		{MiB, "1.00 MiB"},
		{MiB + MiB/2, "1.50 MiB"},
		{GiB, "1.00 GiB"},
		{TiB, "1.00 TiB"},
		{2 * TiB, "2.00 TiB"},
	}

	for _, tt := range tests {
		result := Sizeify(tt.size)
		if result != tt.expected {
			t.Errorf("Sizeify(%d) = %s; want %s", tt.size, result, tt.expected)
		}
	}
}

func TestStatify(t *testing.T) {
	// Test basic progress calculation
	start := time.Now().Add(-time.Second) // 1 second ago
	done := int64(MiB)
	total := int64(2 * MiB)

	progress, speed, eta := Statify(done, total, start)

	// Progress should be 0.5 (50%)
	if progress < 0.49 || progress > 0.51 {
		t.Errorf("Statify progress = %f; want ~0.5", progress)
	}

	// Speed should be positive
	if speed <= 0 {
		t.Errorf("Statify speed = %f; want > 0", speed)
	}

	// ETA should be a valid time string
	if len(eta) != 8 || eta[2] != ':' || eta[5] != ':' {
		t.Errorf("Statify eta = %s; want HH:MM:SS format", eta)
	}
}
