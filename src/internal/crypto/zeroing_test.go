package crypto

import (
	"bytes"
	"testing"
)

func TestSecureZero(t *testing.T) {
	// Test that SecureZero actually zeros the buffer
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	SecureZero(data)

	for i, b := range data {
		if b != 0 {
			t.Errorf("SecureZero: byte %d = %d; want 0", i, b)
		}
	}
}

func TestSecureZeroEmpty(t *testing.T) {
	// Should not panic on empty slice
	SecureZero(nil)
	SecureZero([]byte{})
}

func TestSecureZeroLarge(t *testing.T) {
	// Test with a larger buffer
	data := make([]byte, 1024*1024) // 1 MiB
	for i := range data {
		data[i] = byte(i % 256)
	}

	SecureZero(data)

	// Verify all zeros
	zeros := make([]byte, len(data))
	if !bytes.Equal(data, zeros) {
		t.Error("SecureZero did not zero all bytes in large buffer")
	}
}

func TestSecureZeroMultiple(t *testing.T) {
	slice1 := []byte{1, 2, 3}
	slice2 := []byte{4, 5, 6, 7}
	slice3 := []byte{8, 9}

	SecureZeroMultiple(slice1, slice2, slice3)

	for i, b := range slice1 {
		if b != 0 {
			t.Errorf("slice1[%d] = %d; want 0", i, b)
		}
	}
	for i, b := range slice2 {
		if b != 0 {
			t.Errorf("slice2[%d] = %d; want 0", i, b)
		}
	}
	for i, b := range slice3 {
		if b != 0 {
			t.Errorf("slice3[%d] = %d; want 0", i, b)
		}
	}
}

func TestSecureZeroMultipleEmpty(t *testing.T) {
	// Should not panic on empty or nil slices
	SecureZeroMultiple()
	SecureZeroMultiple(nil)
	SecureZeroMultiple(nil, []byte{}, nil)
}

// TestSecureZeroConcurrent tests that SecureZero works correctly under concurrent access.
// This is security-critical: ensures memory zeroing doesn't race or corrupt data.
func TestSecureZeroConcurrent(t *testing.T) {
	const numGoroutines = 100
	const bufferSize = 1024

	// Create shared buffers
	buffers := make([][]byte, numGoroutines)
	for i := range buffers {
		buffers[i] = make([]byte, bufferSize)
		for j := range buffers[i] {
			buffers[i][j] = byte((i + j) % 256)
		}
	}

	// Zero all buffers concurrently
	done := make(chan bool, numGoroutines)
	for i := range numGoroutines {
		go func(idx int) {
			SecureZero(buffers[idx])
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for range numGoroutines {
		<-done
	}

	// Verify all buffers are zeroed
	zeros := make([]byte, bufferSize)
	for i, buf := range buffers {
		if !bytes.Equal(buf, zeros) {
			t.Errorf("Buffer %d not properly zeroed after concurrent SecureZero", i)
		}
	}
}

// TestSecureZeroMultipleConcurrent tests SecureZeroMultiple under concurrent access.
func TestSecureZeroMultipleConcurrent(t *testing.T) {
	const numGoroutines = 50

	type keySet struct {
		key1 []byte
		key2 []byte
		key3 []byte
	}

	sets := make([]keySet, numGoroutines)
	for i := range sets {
		sets[i] = keySet{
			key1: make([]byte, 32),
			key2: make([]byte, 64),
			key3: make([]byte, 16),
		}
		for j := range sets[i].key1 {
			sets[i].key1[j] = byte(i + j)
		}
		for j := range sets[i].key2 {
			sets[i].key2[j] = byte(i + j + 1)
		}
		for j := range sets[i].key3 {
			sets[i].key3[j] = byte(i + j + 2)
		}
	}

	done := make(chan bool, numGoroutines)
	for i := range numGoroutines {
		go func(idx int) {
			SecureZeroMultiple(sets[idx].key1, sets[idx].key2, sets[idx].key3)
			done <- true
		}(i)
	}

	for range numGoroutines {
		<-done
	}

	// Verify all key sets are zeroed
	for i, set := range sets {
		for j, b := range set.key1 {
			if b != 0 {
				t.Errorf("set[%d].key1[%d] = %d; want 0", i, j, b)
			}
		}
		for j, b := range set.key2 {
			if b != 0 {
				t.Errorf("set[%d].key2[%d] = %d; want 0", i, j, b)
			}
		}
		for j, b := range set.key3 {
			if b != 0 {
				t.Errorf("set[%d].key3[%d] = %d; want 0", i, j, b)
			}
		}
	}
}
