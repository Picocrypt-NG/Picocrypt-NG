package util

import (
	"sync"
)

// BufferPool provides reusable byte buffers to reduce GC pressure
// during large file operations. Buffers are securely zeroed before
// being returned to the pool.
type BufferPool struct {
	pool sync.Pool
	size int
}

// NewBufferPool creates a new buffer pool with the specified buffer size.
func NewBufferPool(size int) *BufferPool {
	return &BufferPool{
		size: size,
		pool: sync.Pool{
			New: func() any {
				b := make([]byte, size)
				return &b
			},
		},
	}
}

// Get retrieves a buffer from the pool.
// The buffer contents are undefined and should be overwritten.
func (p *BufferPool) Get() []byte {
	return *p.pool.Get().(*[]byte)
}

// Put returns a buffer to the pool after securely zeroing it.
// The buffer should not be used after calling Put.
func (p *BufferPool) Put(b []byte) {
	if len(b) != p.size {
		// Don't return mismatched buffers to avoid corruption
		return
	}
	// Secure zero before returning to pool
	secureZeroBytes(b)
	p.pool.Put(&b)
}

// secureZeroBytes zeros a byte slice in a way that won't be optimized away.
// This is a simplified version - the full SecureZero is in crypto package.
func secureZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Default buffer pools for common sizes
var (
	// MiBPool provides 1 MiB buffers for encryption/decryption
	MiBPool = NewBufferPool(MiB)

	// SmallPool provides 4 KiB buffers for smaller operations
	SmallPool = NewBufferPool(4 * 1024)
)

// GetMiBBuffer gets a 1 MiB buffer from the default pool.
func GetMiBBuffer() []byte {
	return MiBPool.Get()
}

// PutMiBBuffer returns a 1 MiB buffer to the default pool.
func PutMiBBuffer(b []byte) {
	MiBPool.Put(b)
}

// GetSmallBuffer gets a 4 KiB buffer from the default pool.
func GetSmallBuffer() []byte {
	return SmallPool.Get()
}

// PutSmallBuffer returns a 4 KiB buffer to the default pool.
func PutSmallBuffer(b []byte) {
	SmallPool.Put(b)
}
