package ui

import (
	"image"
	"testing"
)

type positionRequestWindow struct {
	positions []image.Point
}

func (w *positionRequestWindow) RequestPosition(x, y int) {
	w.positions = append(w.positions, image.Pt(x, y))
}

func (*positionRequestWindow) RequestAlwaysOnTop()         {}
func (*positionRequestWindow) RequestFullScreenSecondary() {}

func TestDesktopWindowPositionRestoresOnlyInAvailableWorkArea(t *testing.T) {
	tests := []struct {
		name     string
		position image.Point
		workArea image.Rectangle
		frame    image.Rectangle
		want     bool
		request  image.Point
	}{
		{
			name:     "disconnected right monitor leaves placement to window manager",
			position: image.Pt(2200, 120), workArea: image.Rect(0, 0, 1920, 1040),
		},
		{
			name:     "connected right monitor keeps saved position",
			position: image.Pt(2200, 120), workArea: image.Rect(1920, 0, 3840, 1040),
			want: true, request: image.Pt(2200, 120),
		},
		{
			name:     "connected left monitor preserves negative coordinates",
			position: image.Pt(-1500, 120), workArea: image.Rect(-1920, 0, 0, 1040),
			want: true, request: image.Pt(-1500, 120),
		},
		{
			name:     "connected upper monitor preserves negative coordinates",
			position: image.Pt(120, -900), workArea: image.Rect(0, -1080, 1920, 0),
			want: true, request: image.Pt(120, -900),
		},
		{
			name:     "taskbar covered position leaves placement to window manager",
			position: image.Pt(120, 1070), workArea: image.Rect(0, 0, 1920, 1040),
		},
		{
			name:     "monitor lookup failure leaves placement to window manager",
			position: image.Pt(120, 120),
		},
		{
			name:     "right edge sliver leaves placement to window manager",
			position: image.Pt(1919, 120), workArea: image.Rect(0, 0, 1920, 1040),
		},
		{
			name:     "caption above top edge leaves placement to window manager",
			position: image.Pt(120, 1), workArea: image.Rect(0, 0, 1920, 1040),
		},
		{
			name:     "origin with clipped caption leaves placement to window manager",
			workArea: image.Rect(0, 0, 1920, 1040),
		},
		{
			name:     "full caption at top boundary remains reachable",
			position: image.Pt(8, 31), workArea: image.Rect(0, 0, 1920, 1040),
			want: true, request: image.Pt(8, 31),
		},
		{
			name:     "scaled caption above top edge leaves placement to window manager",
			position: image.Pt(120, 40), workArea: image.Rect(0, 0, 1920, 1040),
			frame: image.Rect(-16, -62, 304, 178),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			window := &positionRequestWindow{}
			frame := test.frame
			if frame.Empty() {
				frame = image.Rect(-8, -31, 152, 89)
			}
			if got := requestDesktopWindowPosition(window, test.position.X, test.position.Y, test.workArea, frame); got != test.want {
				t.Errorf("restored = %t; want %t", got, test.want)
			}
			if !test.want {
				if len(window.positions) != 0 {
					t.Fatalf("overrode ordinary window placement with unavailable position %v", window.positions)
				}
				return
			}
			if len(window.positions) != 1 || window.positions[0] != test.request {
				t.Fatalf("requested positions %v; want only %v", window.positions, test.request)
			}
		})
	}
}
