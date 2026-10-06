package mobile

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

// Cancellation must settle consent whether it wins or loses registration,
// including the owned credentials and real descriptors acquired by StartPCV3.
func TestPCV3MobileCancellationSettlesConsentRegistration(t *testing.T) {
	for _, ordering := range []struct {
		name           string
		cancelBefore   bool
		cancelInFlight bool
	}{
		{name: "registered-before-cancel"},
		{name: "cancel-before-registration", cancelBefore: true},
		{name: "cancel-published-before-context-cancel", cancelInFlight: true},
	} {
		t.Run(ordering.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				directory := t.TempDir()
				source := writePCV3MobileFile(t, directory, "source.pcv", "claimed-pcv3")
				key := writePCV3MobileFile(t, directory, "factor.key", "keyfile")
				target := filepath.Join(directory, "plain")
				var opened []*os.File
				oldOpen := openPCV3Existing
				openPCV3Existing = func(path string, flag int) (*os.File, error) {
					file, err := fileops.OpenExistingNoSymlink(path, flag)
					if file != nil {
						opened = append(opened, file)
					}
					return file, err
				}
				defer func() { openPCV3Existing = oldOpen }()
				reached := make(chan struct{})
				resume := make(chan struct{})
				var workerPassword []byte
				invoked := false
				oldRun := runPCV3Operation
				runPCV3Operation = func(ctx context.Context, request *pcv3operation.Request) *pcv3operation.Result {
					workerPassword = request.Factors.Password
					consent := request.Consent
					request.Consent = func(input pcv3operation.ConsentRequest, action pcv3operation.ConsentAction) error {
						close(reached)
						<-resume
						return consent(input, func(role pcv3operation.PhysicalRole) error { invoked = true; return action(role) })
					}
					return oldRun(ctx, request)
				}
				defer func() { runPCV3Operation = oldRun }()
				password := []byte("password")
				start := StartPCV3(pcv3TestEnvelope("force-unverified-normal", "password-and-keyfiles", "unordered", source, target, []string{key}), password)
				if start == nil || start.Code() != "" || start.Operation() == nil {
					t.Fatalf("start = %#v", start)
				}
				operation := start.Operation()
				var releaseCancellation func()
				var cancellationDone chan struct{}
				// RED must also settle a late waiter, so a failed assertion cannot strand
				// the production worker in the synctest bubble.
				defer func() {
					if releaseCancellation != nil {
						releaseCancellation()
						<-cancellationDone
					}
					operation.Cancel()
					if consent := operation.Consent(); consent != nil {
						_ = consent.Refuse()
					}
					synctest.Wait()
					_ = operation.Release()
				}()
				<-reached
				if ordering.cancelInFlight {
					cancelEntered := make(chan struct{})
					cancelRelease := make(chan struct{})
					cancellationDone = make(chan struct{})
					var firstCall atomic.Bool
					var releaseOnce sync.Once
					releaseCancellation = func() { releaseOnce.Do(func() { close(cancelRelease) }) }
					globalProgressMap.mu.Lock()
					originalCancel := globalProgressMap.cancels[operation.ID()]
					// Pause only the first caller, preserving CancelFunc's idempotence
					// for the consent callback to finish this published cancellation.
					globalProgressMap.cancels[operation.ID()] = func() {
						if firstCall.CompareAndSwap(false, true) {
							close(cancelEntered)
							<-cancelRelease
						}
						originalCancel()
					}
					globalProgressMap.mu.Unlock()
					go func() {
						operation.Cancel()
						close(cancellationDone)
					}()
					<-cancelEntered
				} else if ordering.cancelBefore {
					operation.Cancel()
				}
				close(resume)
				synctest.Wait()
				if !ordering.cancelBefore && !ordering.cancelInFlight {
					if operation.Consent() == nil {
						t.Fatal("consent was not registered")
					}
					operation.Cancel()
					synctest.Wait()
				}
				if snapshot := operation.Snapshot(); snapshot.Stage() != "cancellation" || snapshot.Diagnostic() != "cancellation" {
					t.Errorf("cancelled terminal snapshot = %s/%s", snapshot.Stage(), snapshot.Diagnostic())
				}
				if operation.Consent() != nil || invoked {
					t.Error("cancellation left consent authority or invoked its action")
				}
				if !allZero(password) || !allZero(workerPassword) {
					t.Error("cancellation retained caller or owned password")
				}
				if len(opened) != 2 {
					t.Fatalf("opened descriptors = %d", len(opened))
				}
				for _, file := range opened {
					if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
						t.Errorf("owned descriptor remains open: %v", err)
					}
				}
				if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("unexpected output: %v", err)
				}
				if releaseCancellation != nil {
					// Join the original Cancel caller before releasing the operation.
					releaseCancellation()
					<-cancellationDone
				}
				if code := operation.Release(); code != "" {
					t.Errorf("terminal release = %q", code)
				}
			})
		})
	}
}
