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
	for i, v := range buf[:cap(buf)] {
		if v != 0 {
			t.Fatalf("returned plaintext backing array was not zeroed at index %d: %d", i, v)
		}
	}

	// Get buffer again - should be zeroed (buffers may hold plaintext)
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

func TestBufferPoolPutZerosMismatchedBuffer(t *testing.T) {
	p := NewBufferPool(MiB)
	b := p.Get()
	for i := range b {
		b[i] = 0xAA
	}
	p.Put(b[:10]) // wrong length on purpose
	for i := range cap(b) {
		if b[:cap(b)][i] != 0 {
			t.Fatalf("byte %d not zeroed after Put of mismatched slice", i)
		}
	}
}

func BenchmarkBufferPoolGetPut(b *testing.B) {
	pool := NewBufferPool(MiB)

	b.ResetTimer()
	for b.Loop() {
		buf := pool.Get()
		pool.Put(buf)
	}
}

func BenchmarkBufferPoolNoPool(b *testing.B) {
	b.ResetTimer()
	for b.Loop() {
		buf := make([]byte, MiB)
		_ = buf
	}
}
