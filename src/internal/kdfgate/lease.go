// Package kdfgate serializes the memory-intensive Argon2id work in a process.
package kdfgate

import "context"

// Lease guards one admission and derivation at a time.
type Lease struct {
	active chan struct{}
}

func NewLease() Lease {
	return Lease{active: make(chan struct{}, 1)}
}

var processLease = NewLease()

// Acquire waits for the process-wide lease. Call the returned function once,
// normally with defer, after releasing all derivation workspace.
func Acquire(ctx context.Context) (release func(), err error) {
	return processLease.Acquire(ctx)
}

func (lease Lease) Acquire(ctx context.Context) (release func(), err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case lease.active <- struct{}{}:
	}
	if err := ctx.Err(); err != nil {
		lease.release()
		return nil, err
	}
	return lease.release, nil
}

func (lease Lease) release() {
	<-lease.active
}
