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

func TestSecureZeroHash(t *testing.T) {
	// SecureZeroHash should not panic on nil
	SecureZeroHash(nil)

	// Test with actual hash (just check it doesn't panic)
	mac, _ := NewMAC(make([]byte, 32), false)
	mac.Write([]byte("test data"))
	SecureZeroHash(mac)
}

func TestKeyMaterial(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	km := NewKeyMaterial(data)

	// Bytes should return the data
	if !bytes.Equal(km.Bytes(), data) {
		t.Error("Bytes() should return equivalent data")
	}

	// Data should be a copy, not the same slice
	if &km.Bytes()[0] == &data[0] {
		t.Error("KeyMaterial should make a copy of data")
	}

	// Len should match
	if km.Len() != len(data) {
		t.Errorf("Len() = %d; want %d", km.Len(), len(data))
	}

	// IsClosed should be false
	if km.IsClosed() {
		t.Error("IsClosed() should be false before Close()")
	}
}

func TestKeyMaterialClose(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	km := NewKeyMaterial(data)
	internalData := km.Bytes()

	km.Close()

	// After close:
	// - IsClosed should be true
	if !km.IsClosed() {
		t.Error("IsClosed() should be true after Close()")
	}

	// - Bytes should return nil
	if km.Bytes() != nil {
		t.Error("Bytes() should return nil after Close()")
	}

	// - Len should be 0
	if km.Len() != 0 {
		t.Errorf("Len() = %d; want 0 after Close()", km.Len())
	}

	// - Original data slice should be zeroed
	zeros := make([]byte, len(internalData))
	if !bytes.Equal(internalData, zeros) {
		t.Error("Internal data should be zeroed after Close()")
	}
}

func TestKeyMaterialCloseIdempotent(t *testing.T) {
	km := NewKeyMaterial([]byte{1, 2, 3, 4})

	// Multiple Close() calls should be safe
	km.Close()
	km.Close()
	km.Close()

	if !km.IsClosed() {
		t.Error("Should remain closed after multiple Close() calls")
	}
}

func TestKeyMaterialNil(t *testing.T) {
	km := NewKeyMaterial(nil)

	if km.Bytes() != nil {
		t.Error("Bytes() should return nil for nil input")
	}

	if km.Len() != 0 {
		t.Error("Len() should be 0 for nil input")
	}

	// Close should not panic
	km.Close()
}

func TestCryptoContext(t *testing.T) {
	cc := &CryptoContext{
		Key:          []byte{1, 2, 3, 4},
		KeyfileKey:   []byte{5, 6, 7, 8},
		MacSubkey:    []byte{9, 10, 11, 12},
		SerpentKey:   []byte{13, 14, 15, 16},
		HeaderSubkey: []byte{17, 18, 19, 20},
	}

	// Save references to check zeroing
	keyRef := cc.Key
	keyfileRef := cc.KeyfileKey
	macRef := cc.MacSubkey
	serpentRef := cc.SerpentKey
	headerRef := cc.HeaderSubkey

	cc.Close()

	// All fields should be nil
	if cc.Key != nil {
		t.Error("Key should be nil after Close()")
	}
	if cc.KeyfileKey != nil {
		t.Error("KeyfileKey should be nil after Close()")
	}
	if cc.MacSubkey != nil {
		t.Error("MacSubkey should be nil after Close()")
	}
	if cc.SerpentKey != nil {
		t.Error("SerpentKey should be nil after Close()")
	}
	if cc.HeaderSubkey != nil {
		t.Error("HeaderSubkey should be nil after Close()")
	}

	// Original slices should be zeroed
	zeros4 := make([]byte, 4)
	if !bytes.Equal(keyRef, zeros4) {
		t.Error("Key data should be zeroed")
	}
	if !bytes.Equal(keyfileRef, zeros4) {
		t.Error("KeyfileKey data should be zeroed")
	}
	if !bytes.Equal(macRef, zeros4) {
		t.Error("MacSubkey data should be zeroed")
	}
	if !bytes.Equal(serpentRef, zeros4) {
		t.Error("SerpentKey data should be zeroed")
	}
	if !bytes.Equal(headerRef, zeros4) {
		t.Error("HeaderSubkey data should be zeroed")
	}
}

func TestCryptoContextCloseIdempotent(t *testing.T) {
	cc := &CryptoContext{
		Key: []byte{1, 2, 3, 4},
	}

	// Multiple Close() calls should be safe
	cc.Close()
	cc.Close()
	cc.Close()
}

func TestCryptoContextNilFields(t *testing.T) {
	// Close should handle nil fields gracefully
	cc := &CryptoContext{}
	cc.Close() // Should not panic
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
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			SecureZero(buffers[idx])
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
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
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			SecureZeroMultiple(sets[idx].key1, sets[idx].key2, sets[idx].key3)
			done <- true
		}(i)
	}

	for i := 0; i < numGoroutines; i++ {
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

// TestKeyMaterialConcurrentClose tests KeyMaterial.Close under concurrent access.
func TestKeyMaterialConcurrentClose(t *testing.T) {
	const numGoroutines = 100

	km := NewKeyMaterial([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	internalData := km.Bytes()

	done := make(chan bool, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			km.Close() // Multiple concurrent Close calls should be safe
			done <- true
		}()
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify closed state
	if !km.IsClosed() {
		t.Error("KeyMaterial should be closed after concurrent Close()")
	}

	// Verify data was zeroed
	zeros := make([]byte, len(internalData))
	if !bytes.Equal(internalData, zeros) {
		t.Error("KeyMaterial data should be zeroed after concurrent Close()")
	}
}

// TestCryptoContextConcurrentClose tests CryptoContext.Close under concurrent access.
func TestCryptoContextConcurrentClose(t *testing.T) {
	const numGoroutines = 100

	cc := &CryptoContext{
		Key:          []byte{1, 2, 3, 4, 5, 6, 7, 8},
		KeyfileKey:   []byte{9, 10, 11, 12, 13, 14, 15, 16},
		MacSubkey:    []byte{17, 18, 19, 20, 21, 22, 23, 24},
		SerpentKey:   []byte{25, 26, 27, 28, 29, 30, 31, 32},
		HeaderSubkey: []byte{33, 34, 35, 36, 37, 38, 39, 40},
	}

	// Save references
	keyRef := cc.Key
	keyfileRef := cc.KeyfileKey
	macRef := cc.MacSubkey
	serpentRef := cc.SerpentKey
	headerRef := cc.HeaderSubkey

	done := make(chan bool, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			cc.Close()
			done <- true
		}()
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify all slices zeroed
	zeros8 := make([]byte, 8)
	if !bytes.Equal(keyRef, zeros8) {
		t.Error("Key should be zeroed after concurrent Close()")
	}
	if !bytes.Equal(keyfileRef, zeros8) {
		t.Error("KeyfileKey should be zeroed after concurrent Close()")
	}
	if !bytes.Equal(macRef, zeros8) {
		t.Error("MacSubkey should be zeroed after concurrent Close()")
	}
	if !bytes.Equal(serpentRef, zeros8) {
		t.Error("SerpentKey should be zeroed after concurrent Close()")
	}
	if !bytes.Equal(headerRef, zeros8) {
		t.Error("HeaderSubkey should be zeroed after concurrent Close()")
	}
}
