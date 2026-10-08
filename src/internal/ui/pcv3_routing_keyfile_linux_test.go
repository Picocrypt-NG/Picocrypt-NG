//go:build linux

package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/pcv3operation"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"golang.org/x/sys/unix"
)

func TestRegressionUnsplitNormalPrefixStillAllowsExplicitD1(t *testing.T) {
	resetLocalizationForTest(t)
	path := filepath.Join(t.TempDir(), "collision.pcv")
	data := make([]byte, 128)
	copy(data, []byte{'P', 'C', 'V', 0, 1, 2, 3, 4})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	a := createUIReadyDropTestApp(t, newTestFyneApp(t))
	t.Cleanup(func() { a.workers.wait(); fyne.DoAndWait(func() { a.State.Reset() }) })
	fyne.DoAndWait(func() { a.onDrop([]string{path}) })
	waitForDropProcessing(t, a)
	fyne.DoAndWait(func() {
		before := a.State.UISnapshot()
		if !a.State.SelectPCV3D1() {
			t.Errorf("explicit D1 is unavailable for a regular unsplit file with a normal-prefix collision; route=%v format=%v", before.PCV3Route, before.PCV3Format)
		}
	})
}

func TestRegressionUnsplitDamagedPreambleKeepsRecoverySelectable(t *testing.T) {
	resetLocalizationForTest(t)
	path := filepath.Join(t.TempDir(), "damaged-preamble.pcv")
	data := loadPCV3DropFixture(t)
	// Keep the PCV family discriminator and authenticated capsule bytes intact.
	// Recovery admission tolerates invalid raw front-header geometry.
	data[12], data[13], data[14], data[15] = 0, 0, 0, 0
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	a := createUIReadyDropTestApp(t, newTestFyneApp(t))
	t.Cleanup(func() { a.workers.wait(); fyne.DoAndWait(func() { a.State.Reset() }) })
	fyne.DoAndWait(func() { a.onDrop([]string{path}) })
	waitForDropProcessing(t, a)
	fyne.DoAndWait(func() {
		snap := a.State.UISnapshot()
		if snap.PCV3Route != app.PCV3RouteReady || snap.PCV3Format != app.PCV3FormatNormal {
			t.Fatalf("damaged preamble discarded normal-PCV ownership before user could choose recovery; route=%v format=%v", snap.PCV3Route, snap.PCV3Format)
		}
	})
}

func TestRegressionPCV3KeyfileFIFORejectedWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "factor.pipe")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		intent := app.PCV3OperationIntent{FactorPolicy: app.PCV3FactorPolicyKeyfiles, KeyfileOrder: app.PCV3KeyfileOrderAny, Keyfiles: []string{path}}
		factors, err := pcv3FactorsForIntent(&intent)
		if factors != nil {
			err = errors.Join(err, factors.Close())
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted as a regular keyfile")
		}
	case <-time.After(250 * time.Millisecond):
		// Release the blocked reader so this bounded reproduction leaves no
		// goroutine or FIFO peer behind; no product code is changed.
		fd, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := unix.Close(fd); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("FIFO accepted after peer opened")
			}
			t.Fatalf("keyfile preparation blocked until an external FIFO writer connected; late rejection: %v", err)
		case <-time.After(2 * time.Second):
			t.Fatal("keyfile preparation remained blocked after FIFO peer opened")
		}
	}
}

func TestPCV3KeyfilePreparationLeavesUIResponsiveAndCancelsBeforeExecution(t *testing.T) {
	a := newPCV3ReadUI(t, app.PCV3FormatNormal)
	path := filepath.Join(t.TempDir(), "factor.key")
	if err := os.WriteFile(path, []byte("factor"), 0o600); err != nil {
		t.Fatal(err)
	}
	entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	previous := openPCV3Keyfile
	openPCV3Keyfile = func(path string) (*os.File, error) {
		close(entered)
		<-release
		return previous(path)
	}
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }); a.workers.wait(); openPCV3Keyfile = previous })
	var executions atomic.Int32
	a.pcv3OperationExecutor = func(_ context.Context, request *pcv3operation.Request) *pcv3operation.Result {
		executions.Add(1)
		_ = request.Source.Close()
		_ = request.Factors.Close()
		return nil
	}
	go func() {
		fyne.DoAndWait(func() {
			a.State.Keyfiles = []string{path}
			a.startPCV3Work()
		})
		close(returned)
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("keyfile preparation never started")
	}
	select {
	case <-returned:
	case <-time.After(250 * time.Millisecond):
		once.Do(func() { close(release) })
		<-returned
		t.Fatal("keyfile preparation blocked the GUI thread")
	}
	fyne.DoAndWait(func() { a.cancelOperation(a.operationSession) })
	once.Do(func() { close(release) })
	a.workers.wait()
	fyne.DoAndWait(func() {})
	if executions.Load() != 0 {
		t.Fatal("cancelled keyfile preparation reached the executor")
	}
}
