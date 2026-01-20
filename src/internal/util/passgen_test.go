package util

import (
	"bytes"
	"strings"
	"testing"
)

func TestGenPassword(t *testing.T) {
	// Test with all character sets
	opts := PassgenOptions{
		Length:  32,
		Upper:   true,
		Lower:   true,
		Numbers: true,
		Symbols: true,
	}

	password, err := GenPassword(opts)
	if err != nil {
		t.Fatalf("GenPassword failed: %v", err)
	}

	if len(password) != 32 {
		t.Errorf("GenPassword length = %d; want 32", len(password))
	}

	// Generate multiple passwords and ensure they're different (randomness check)
	password2, err := GenPassword(opts)
	if err != nil {
		t.Fatalf("GenPassword failed: %v", err)
	}
	if password == password2 {
		t.Error("GenPassword generated identical passwords (unlikely if random)")
	}
}

func TestGenPasswordCharacterSets(t *testing.T) {
	// Test uppercase only
	opts := PassgenOptions{Length: 100, Upper: true}
	password, err := GenPassword(opts)
	if err != nil {
		t.Fatalf("GenPassword failed: %v", err)
	}
	for _, c := range password {
		if c < 'A' || c > 'Z' {
			t.Errorf("Uppercase-only password contains invalid char: %c", c)
		}
	}

	// Test lowercase only
	opts = PassgenOptions{Length: 100, Lower: true}
	password, err = GenPassword(opts)
	if err != nil {
		t.Fatalf("GenPassword failed: %v", err)
	}
	for _, c := range password {
		if c < 'a' || c > 'z' {
			t.Errorf("Lowercase-only password contains invalid char: %c", c)
		}
	}

	// Test numbers only
	opts = PassgenOptions{Length: 100, Numbers: true}
	password, err = GenPassword(opts)
	if err != nil {
		t.Fatalf("GenPassword failed: %v", err)
	}
	for _, c := range password {
		if c < '0' || c > '9' {
			t.Errorf("Numbers-only password contains invalid char: %c", c)
		}
	}

	// Test symbols only
	opts = PassgenOptions{Length: 100, Symbols: true}
	password, err = GenPassword(opts)
	if err != nil {
		t.Fatalf("GenPassword failed: %v", err)
	}
	validSymbols := "-=_+!@#$^&()?<>"
	for _, c := range password {
		if !strings.ContainsRune(validSymbols, c) {
			t.Errorf("Symbols-only password contains invalid char: %c", c)
		}
	}
}

func TestGenPasswordEmpty(t *testing.T) {
	// No character sets enabled should return empty
	opts := PassgenOptions{Length: 32}
	password, err := GenPassword(opts)
	if err != nil {
		t.Fatalf("GenPassword failed: %v", err)
	}
	if password != "" {
		t.Errorf("GenPassword with no charset should return empty, got %s", password)
	}

	// Zero length should return empty
	opts = PassgenOptions{Length: 0, Upper: true}
	password, err = GenPassword(opts)
	if err != nil {
		t.Fatalf("GenPassword failed: %v", err)
	}
	if password != "" {
		t.Errorf("GenPassword with zero length should return empty, got %s", password)
	}
}

func TestRandomBytes(t *testing.T) {
	// Test various lengths
	lengths := []int{1, 16, 32, 64, 128, 1024}

	for _, length := range lengths {
		data, err := RandomBytes(length)
		if err != nil {
			t.Fatalf("RandomBytes(%d) failed: %v", length, err)
		}

		if len(data) != length {
			t.Errorf("RandomBytes(%d) returned %d bytes", length, len(data))
		}

		// Check that it's not all zeros (statistically almost impossible for large lengths)
		// Skip this check for small lengths where all zeros is plausible (e.g., 1 byte = 1/256 chance)
		if length >= 8 {
			allZero := true
			for _, b := range data {
				if b != 0 {
					allZero = false
					break
				}
			}
			if allZero {
				t.Errorf("RandomBytes(%d) returned all zeros (extremely unlikely)", length)
			}
		}
	}
}

func TestRandomBytesUniqueness(t *testing.T) {
	// Two calls should produce different results
	data1, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes(32) failed: %v", err)
	}

	data2, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes(32) failed: %v", err)
	}

	if bytes.Equal(data1, data2) {
		t.Error("Two RandomBytes calls should produce different results")
	}
}

func TestRandomBytesInvalidLength(t *testing.T) {
	// Zero length should return error
	_, err := RandomBytes(0)
	if err == nil {
		t.Error("RandomBytes(0) should return error")
	}

	// Negative length should return error
	_, err = RandomBytes(-1)
	if err == nil {
		t.Error("RandomBytes(-1) should return error")
	}
}
