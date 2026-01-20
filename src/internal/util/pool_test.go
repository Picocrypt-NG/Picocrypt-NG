package util

import (
	"testing"
)

func TestBufferPool(t *testing.T) {
	pool := NewBufferPool(1024)

	// Get a buffer
	buf := pool.Get()
	if len(buf) != 1024 {
		t.Errorf("Expected buffer length 1024, got %d", len(buf))
	}

	// Write some data
	for i := range buf {
		buf[i] = byte(i % 256)
	}

	// Put buffer back
	pool.Put(buf)

	// Get buffer again - should be zeroed
	buf2 := pool.Get()
	for i, v := range buf2 {
		if v != 0 {
			t.Errorf("Buffer should be zeroed at index %d, got %d", i, v)
			break
		}
	}
}

func TestBufferPoolMismatchedSize(t *testing.T) {
	pool := NewBufferPool(1024)

	// Put a mismatched buffer - should be ignored
	wrongSize := make([]byte, 512)
	pool.Put(wrongSize) // Should not panic or cause issues

	// Getting should still return correct size
	buf := pool.Get()
	if len(buf) != 1024 {
		t.Errorf("Expected buffer length 1024, got %d", len(buf))
	}
}

func TestMiBPool(t *testing.T) {
	buf := GetMiBBuffer()
	if len(buf) != MiB {
		t.Errorf("Expected MiB buffer length %d, got %d", MiB, len(buf))
	}
	PutMiBBuffer(buf)
}

func TestSmallPool(t *testing.T) {
	buf := GetSmallBuffer()
	if len(buf) != 4*1024 {
		t.Errorf("Expected small buffer length %d, got %d", 4*1024, len(buf))
	}
	PutSmallBuffer(buf)
}

func BenchmarkBufferPoolGetPut(b *testing.B) {
	pool := NewBufferPool(MiB)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := pool.Get()
		pool.Put(buf)
	}
}

func BenchmarkBufferPoolNoPool(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := make([]byte, MiB)
		_ = buf
	}
}
