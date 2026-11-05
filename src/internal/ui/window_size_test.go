package ui

import (
	"math"
	"testing"
)

func TestValidDesktopWindowDimension(t *testing.T) {
	tests := []struct {
		name  string
		value float64
		valid bool
	}{
		{name: "positive", value: 640, valid: true},
		{name: "zero", value: 0, valid: false},
		{name: "negative", value: -1, valid: false},
		{name: "NaN", value: math.NaN(), valid: false},
		{name: "positive infinity", value: math.MaxFloat64, valid: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validDesktopWindowDimension(test.value); got != test.valid {
				t.Fatalf("validDesktopWindowDimension(%v) = %t; want %t", test.value, got, test.valid)
			}
		})
	}
}
