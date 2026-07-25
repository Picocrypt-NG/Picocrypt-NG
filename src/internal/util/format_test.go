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
		{363599, "100:59:59"},
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

// TestStatify pins Statify's two boundary guards plus the happy path. Each guard row
// catches removal of a real defense:
//   - total==0: the divide-by-zero guard. Without it progress = done/0 = +Inf and the
//     ETA math divides by zero; the guard must return exactly (0, 0, "00:00:00").
//   - start in the future (elapsed<=0): the just-started guard. Without it elapsed is
//     negative, making speed negative and ETA = remaining/negative -> garbage/NaN time
//     string; the guard must return speed==0, eta=="00:00:00", with progress still the
//     real fraction (~0.5 here). time.Now().Add(time.Second) keeps elapsed<=0
//     deterministically without sleeping.
//
// The happy-path row keeps the original positive-progress / positive-speed / valid-ETA
// assertions so a regression that breaks the normal case still trips.
func TestStatify(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		start := time.Now().Add(-time.Second) // 1 second ago
		progress, speed, eta := Statify(int64(MiB), int64(2*MiB), start)

		if progress < 0.49 || progress > 0.51 {
			t.Errorf("progress = %f; want ~0.5", progress)
		}
		if speed <= 0 {
			t.Errorf("speed = %f; want > 0", speed)
		}
		if len(eta) != 8 || eta[2] != ':' || eta[5] != ':' {
			t.Errorf("eta = %s; want HH:MM:SS format", eta)
		}
	})

	t.Run("total zero divide-by-zero guard", func(t *testing.T) {
		progress, speed, eta := Statify(int64(MiB), 0, time.Now().Add(-time.Second))

		if progress != 0 {
			t.Errorf("progress = %f; want 0 (total==0 guard)", progress)
		}
		if speed != 0 {
			t.Errorf("speed = %f; want 0 (total==0 guard)", speed)
		}
		if eta != "00:00:00" {
			t.Errorf("eta = %q; want %q (total==0 guard)", eta, "00:00:00")
		}
	})

	t.Run("just started guard (start in future)", func(t *testing.T) {
		start := time.Now().Add(time.Second) // future => elapsed <= 0
		progress, speed, eta := Statify(int64(MiB), int64(2*MiB), start)

		if progress < 0.49 || progress > 0.51 {
			t.Errorf("progress = %f; want ~0.5 (progress still computed when just started)", progress)
		}
		if speed != 0 {
			t.Errorf("speed = %f; want 0 (elapsed<=0 guard)", speed)
		}
		if eta != "00:00:00" {
			t.Errorf("eta = %q; want %q (elapsed<=0 guard)", eta, "00:00:00")
		}
	})
}
