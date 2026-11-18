package kdfgate

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
)

func TestAcquireRespectsCancellationWithoutBlockingLaterWork(t *testing.T) {
	release, err := Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if undo, err := Acquire(cancelled); !errors.Is(err, context.Canceled) || undo != nil {
		t.Fatalf("cancelled request returned a lease or the wrong error: %v", err)
	}
	release()

	release, err = Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func TestAcquireSerializesConcurrentDerivations(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease := NewLease()
		release, err := lease.Acquire(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		acquired := make(chan error, 1)
		go func() {
			next, err := lease.Acquire(t.Context())
			if err == nil {
				defer next()
			}
			acquired <- err
		}()
		synctest.Wait()
		select {
		case err := <-acquired:
			release()
			t.Fatalf("overlapping derivation obtained a lease: %v", err)
		default:
		}
		release()
		if err := <-acquired; err != nil {
			t.Fatal(err)
		}
	})
}
