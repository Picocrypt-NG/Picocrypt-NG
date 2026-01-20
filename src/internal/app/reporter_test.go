package app

import (
	"sync"
	"testing"
)

func TestNewUIReporter(t *testing.T) {
	var statusCalled bool
	var progressCalled bool
	var canCancelCalled bool
	var updateCalled bool
	var checkCancelCalled bool

	reporter := NewUIReporter(
		func(text string) { statusCalled = true },
		func(fraction float32, info string) { progressCalled = true },
		func(can bool) { canCancelCalled = true },
		func() { updateCalled = true },
		func() bool { checkCancelCalled = true; return false },
	)

	if reporter == nil {
		t.Fatal("NewUIReporter returned nil")
	}

	// Test all callbacks are called
	reporter.SetStatus("test")
	reporter.SetProgress(0.5, "50%")
	reporter.SetCanCancel(true)
	reporter.Update()
	_ = reporter.IsCancelled()

	if !statusCalled {
		t.Error("OnStatus was not called")
	}
	if !progressCalled {
		t.Error("OnProgress was not called")
	}
	if !canCancelCalled {
		t.Error("OnCanCancel was not called")
	}
	if !updateCalled {
		t.Error("OnUpdate was not called")
	}
	if !checkCancelCalled {
		t.Error("CheckCancel was not called")
	}
}

func TestUIReporterNilCallbacks(t *testing.T) {
	// All callbacks are nil - should not panic
	reporter := NewUIReporter(nil, nil, nil, nil, nil)

	// These should not panic
	reporter.SetStatus("test")
	reporter.SetProgress(0.5, "info")
	reporter.SetCanCancel(true)
	reporter.Update()

	// IsCancelled with nil CheckCancel
	if reporter.IsCancelled() {
		t.Error("IsCancelled should return false when CheckCancel is nil and not cancelled")
	}
}

func TestUIReporterCancel(t *testing.T) {
	reporter := NewUIReporter(nil, nil, nil, nil, nil)

	// Initially not cancelled
	if reporter.IsCancelled() {
		t.Error("Should not be cancelled initially")
	}

	// Cancel
	reporter.Cancel()
	if !reporter.IsCancelled() {
		t.Error("Should be cancelled after Cancel()")
	}

	// Reset
	reporter.Reset()
	if reporter.IsCancelled() {
		t.Error("Should not be cancelled after Reset()")
	}
}

func TestUIReporterCheckCancelOverride(t *testing.T) {
	checkCancelResult := false
	reporter := NewUIReporter(nil, nil, nil, nil, func() bool { return checkCancelResult })

	// CheckCancel returns false
	if reporter.IsCancelled() {
		t.Error("Should not be cancelled when CheckCancel returns false")
	}

	// CheckCancel returns true
	checkCancelResult = true
	if !reporter.IsCancelled() {
		t.Error("Should be cancelled when CheckCancel returns true")
	}

	// Cancel() takes precedence
	reporter.Cancel()
	checkCancelResult = false // CheckCancel would return false
	if !reporter.IsCancelled() {
		t.Error("Cancel() should take precedence over CheckCancel")
	}
}

func TestUIReporterConcurrency(t *testing.T) {
	reporter := NewUIReporter(nil, nil, nil, nil, nil)

	var wg sync.WaitGroup
	iterations := 100

	// Concurrent Cancel/Reset/IsCancelled
	wg.Add(iterations * 3)
	for i := 0; i < iterations; i++ {
		go func() {
			defer wg.Done()
			reporter.Cancel()
		}()
		go func() {
			defer wg.Done()
			reporter.Reset()
		}()
		go func() {
			defer wg.Done()
			_ = reporter.IsCancelled()
		}()
	}

	wg.Wait()
	t.Log("Concurrent access completed without deadlock or race")
}

func TestUIReporterSetStatusText(t *testing.T) {
	var lastStatus string
	reporter := NewUIReporter(
		func(text string) { lastStatus = text },
		nil, nil, nil, nil,
	)

	reporter.SetStatus("Starting...")
	if lastStatus != "Starting..." {
		t.Errorf("lastStatus = %q; want 'Starting...'", lastStatus)
	}

	reporter.SetStatus("Encrypting at 50 MiB/s")
	if lastStatus != "Encrypting at 50 MiB/s" {
		t.Errorf("lastStatus = %q; want 'Encrypting at 50 MiB/s'", lastStatus)
	}
}

func TestUIReporterSetProgressValues(t *testing.T) {
	var lastFraction float32
	var lastInfo string
	reporter := NewUIReporter(
		nil,
		func(fraction float32, info string) {
			lastFraction = fraction
			lastInfo = info
		},
		nil, nil, nil,
	)

	reporter.SetProgress(0.0, "0%")
	if lastFraction != 0.0 || lastInfo != "0%" {
		t.Errorf("Progress = (%f, %q); want (0.0, '0%%')", lastFraction, lastInfo)
	}

	reporter.SetProgress(0.5, "50% (128 MiB/s)")
	if lastFraction != 0.5 {
		t.Errorf("lastFraction = %f; want 0.5", lastFraction)
	}
	if lastInfo != "50% (128 MiB/s)" {
		t.Errorf("lastInfo = %q; want '50%% (128 MiB/s)'", lastInfo)
	}

	reporter.SetProgress(1.0, "Done")
	if lastFraction != 1.0 {
		t.Errorf("lastFraction = %f; want 1.0", lastFraction)
	}
}

func TestUIReporterSetCanCancelValue(t *testing.T) {
	var lastCanCancel bool
	reporter := NewUIReporter(
		nil, nil,
		func(can bool) { lastCanCancel = can },
		nil, nil,
	)

	reporter.SetCanCancel(true)
	if !lastCanCancel {
		t.Error("lastCanCancel should be true")
	}

	reporter.SetCanCancel(false)
	if lastCanCancel {
		t.Error("lastCanCancel should be false")
	}
}
