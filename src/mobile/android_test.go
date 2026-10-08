package mobile

import (
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/volume"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	perrors "Picocrypt-NG/internal/errors"
)

// TestErrorCodeFor pins the pipeline-error -> stable-code mapping the Android
// layer relies on to gate force-decrypt (corruption-only) and password-retry
// (auth-only). The mapping is security-relevant: misclassifying a wrong-password
// (*header.AuthError) as corruption would wrongly offer force-decrypt, which
// BYPASSES integrity/RS checks. Each case wraps the real error value with %w to
// prove errors.Is/As classification survives wrapping (as it does through the
// pipeline's fmt.Errorf("...: %w", err) chains).
func TestErrorCodeFor(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "nil is no error", err: nil, want: ""},
		// Normal decrypt path: wrong password/keyfile surfaces as *header.AuthError
		// (decrypt.go:273,283,335,345). It does NOT wrap perrors.ErrAuthFailed, so
		// errors.Is(ErrAuthFailed) alone would miss it; errorCode uses errors.As.
		{name: "v2 password-or-tamper AuthError", err: header.NewV2PasswordOrTamperError(), want: "AUTH_FAILED"},
		{name: "v1 password AuthError", err: header.NewPasswordError(), want: "AUTH_FAILED"},
		{name: "keyfile AuthError", err: header.NewKeyfileError(true), want: "AUTH_FAILED"},
		{name: "wrapped AuthError", err: fmt.Errorf("decrypt: %w", header.NewPasswordError()), want: "AUTH_FAILED"},
		// Verify-first path returns the bare sentinel (decrypt.go:572).
		{name: "ErrAuthFailed sentinel", err: perrors.ErrAuthFailed, want: "AUTH_FAILED"},
		{name: "wrapped ErrAuthFailed", err: fmt.Errorf("verify: %w", perrors.ErrAuthFailed), want: "AUTH_FAILED"},
		// Payload corruption RS cannot recover (decrypt.go:796 and decodeWithRSFast).
		{name: "ErrCorruptData sentinel", err: perrors.ErrCorruptData, want: "DATA_CORRUPTED"},
		{name: "wrapped ErrCorruptData", err: fmt.Errorf("finalize: %w", perrors.ErrCorruptData), want: "DATA_CORRUPTED"},
		// Header damage: decrypt.go:204 wraps header.ErrCorruptedHeader. Must NOT
		// be DATA_CORRUPTED (old logic excluded header) -> CORRUPT_HEADER (not
		// force-decryptable on the Kotlin side).
		{name: "header damaged wraps ErrCorruptedHeader", err: fmt.Errorf("header damaged: %w", header.ErrCorruptedHeader), want: "CORRUPT_HEADER"},
		{name: "ErrCorruptHeader sentinel", err: perrors.ErrCorruptHeader, want: "CORRUPT_HEADER"},
		{name: "ErrFileNotFound sentinel", err: perrors.ErrFileNotFound, want: "FILE_NOT_FOUND"},
		{name: "wrapped ErrFileNotFound", err: fmt.Errorf("open: %w", perrors.ErrFileNotFound), want: "FILE_NOT_FOUND"},
		{name: "ErrCancelled sentinel", err: perrors.ErrCancelled, want: "CANCELLED"},
		// Auth must win over corruption when both are in the chain, mirroring the
		// old substring logic (auth checked before/over corruption).
		{name: "auth wins over corruption", err: fmt.Errorf("%w: %w", perrors.ErrAuthFailed, perrors.ErrCorruptData), want: "AUTH_FAILED"},
		{name: "unknown error is generic", err: errors.New("something unexpected"), want: "GENERIC"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := errorCode(tc.err); got != tc.want {
				t.Errorf("errorCode(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

func resetProgressMap() {
	globalProgressMap.mu.Lock()
	defer globalProgressMap.mu.Unlock()

	globalProgressMap.ops = make(map[string]*ProgressState)
	globalProgressMap.ctxs = make(map[string]context.Context)
	globalProgressMap.cancels = make(map[string]context.CancelFunc)
}

func TestDetectOperation(t *testing.T) {
	t.Cleanup(resetProgressMap)

	tests := []struct {
		name     string
		filename string
		want     bool
	}{
		{name: "pcv file decrypts", filename: "sample.txt.pcv", want: false},
		{name: "split volume decrypts", filename: "archive.zip.pcv.0", want: false},
		{name: "false positive backup stays encrypt", filename: "backup.pcv.tmp1", want: true},
		{name: "false positive version stays encrypt", filename: "notes.pcv.v2", want: true},
		{name: "plain file encrypts", filename: "plain.txt", want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tc.filename)
			if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}

			got, err := DetectOperation(path)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("DetectOperation(%q) = %v, want %v", path, got, tc.want)
			}
		})
	}
}

func TestCompleteOperationDoesNotOverwriteCancelledState(t *testing.T) {
	resetProgressMap()

	id := startOperation()
	if _, err := CancelOperation(id); err != nil {
		t.Fatal(err)
	}

	completeOperation(id, nil)

	state, err := getProgress(id)
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "Cancelled" {
		t.Fatalf("state.Status = %q, want %q", state.Status, "Cancelled")
	}
	if state.StatusCode != "CANCELLED" {
		t.Fatalf("state.StatusCode = %q, want %q", state.StatusCode, "CANCELLED")
	}
	if !state.Done {
		t.Fatalf("cancelled operation should remain done")
	}
}

func TestCancelledOperationIgnoresLateReporterCallbacksAndCompletion(t *testing.T) {
	resetProgressMap()

	id := startOperation()
	reporter := &androidProgressReporter{opID: id}
	reporter.SetStatus("Deriving key...")
	reporter.SetProgress(0.25, "1/10")
	if _, err := CancelOperation(id); err != nil {
		t.Fatal(err)
	}

	reporter.SetStatus("Encrypting at 12.34 MiB/s (ETA: 01:02:03)")
	reporter.SetProgress(0.75, "3/10")
	completeOperation(id, context.Canceled)

	state, err := getProgress(id)
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "Cancelled" || state.StatusCode != "CANCELLED" || !state.Done {
		t.Fatalf("terminal cancellation was overwritten: %#v", state)
	}
	if state.Progress != 0.25 || state.Info != "1/10" || state.InfoCode != "ITEM_COUNT" ||
		state.InfoCurrent != 1 || state.InfoTotal != 10 {
		t.Fatalf("late progress callback changed cancelled state: %#v", state)
	}
	if state.Error != "" || state.Code != "" {
		t.Fatalf("late completion added cancellation diagnostics: Error=%q Code=%q", state.Error, state.Code)
	}
}

func TestCancelOperationPreservesSuccessfulTerminalSnapshot(t *testing.T) {
	resetProgressMap()

	id := startOperation()
	reporter := &androidProgressReporter{opID: id}
	reporter.SetStatus("Deriving key...")
	reporter.SetProgress(0.25, "1/10")
	completeOperation(id, nil)

	firstTerminal, err := getProgress(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CancelOperation(id); err != nil {
		t.Fatal(err)
	}
	afterCancel, err := getProgress(id)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(afterCancel, firstTerminal) {
		t.Fatalf("cancel changed successful terminal snapshot\n got: %#v\nwant: %#v", afterCancel, firstTerminal)
	}
}

func TestCancelOperationPreservesFailedTerminalSnapshot(t *testing.T) {
	resetProgressMap()

	id := startOperation()
	reporter := &androidProgressReporter{opID: id}
	reporter.SetStatus("Decrypting at 12.34 MiB/s (ETA: 01:02:03)")
	reporter.SetProgress(0.25, "1/10")
	completeOperation(id, errors.New("diagnostic failure"))

	firstTerminal, err := getProgress(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CancelOperation(id); err != nil {
		t.Fatal(err)
	}
	afterCancel, err := getProgress(id)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(afterCancel, firstTerminal) {
		t.Fatalf("cancel changed failed terminal snapshot\n got: %#v\nwant: %#v", afterCancel, firstTerminal)
	}
}

func TestCancelOperationReturnsCanonicalTerminalSnapshot(t *testing.T) {
	tests := []struct {
		name         string
		finish       func(id string)
		wantStatus   string
		wantProgress float32
		wantError    string
		wantCode     string
	}{
		{
			name:         "running operation becomes cancelled",
			finish:       func(string) {},
			wantStatus:   "CANCELLED",
			wantProgress: 0.25,
		},
		{
			name:         "completed operation stays completed",
			finish:       func(id string) { completeOperation(id, nil) },
			wantStatus:   "COMPLETED",
			wantProgress: 1,
		},
		{
			name:         "failed operation stays failed",
			finish:       func(id string) { completeOperation(id, errors.New("diagnostic failure")) },
			wantStatus:   "ERROR",
			wantProgress: 0.25,
			wantError:    "diagnostic failure",
			wantCode:     "GENERIC",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetProgressMap()
			id := startOperation()
			reporter := &androidProgressReporter{opID: id}
			reporter.SetProgress(0.25, "1/10")
			tc.finish(id)

			state, err := CancelOperation(id)
			if err != nil {
				t.Fatal(err)
			}
			if state.StatusCode != tc.wantStatus || !state.Done {
				t.Fatalf("CancelOperation returned %#v, want terminal status %q", state, tc.wantStatus)
			}
			if state.Progress != tc.wantProgress || state.InfoCode != "ITEM_COUNT" ||
				state.InfoCurrent != 1 || state.InfoTotal != 10 {
				t.Fatalf("CancelOperation lost progress detail: %#v", state)
			}
			if state.Error != tc.wantError || state.Code != tc.wantCode {
				t.Fatalf(
					"CancelOperation error = (%q, %q), want (%q, %q)",
					state.Error,
					state.Code,
					tc.wantError,
					tc.wantCode,
				)
			}
		})
	}
}

func TestProgressTerminalStatusCodes(t *testing.T) {
	tests := []struct {
		name       string
		finish     func(t *testing.T, id string)
		status     string
		statusCode string
		errorText  string
		errorCode  string
		done       bool
	}{
		{
			name:       "starting",
			finish:     func(*testing.T, string) {},
			status:     "Starting...",
			statusCode: "STARTING",
			done:       false,
		},
		{
			name:       "success",
			finish:     func(_ *testing.T, id string) { completeOperation(id, nil) },
			status:     "Completed",
			statusCode: "COMPLETED",
			done:       true,
		},
		{
			name: "cancellation",
			finish: func(t *testing.T, id string) {
				if _, err := CancelOperation(id); err != nil {
					t.Fatal(err)
				}
			},
			status:     "Cancelled",
			statusCode: "CANCELLED",
			done:       true,
		},
		{
			name:       "failure",
			finish:     func(_ *testing.T, id string) { completeOperation(id, errors.New("diagnostic failure")) },
			status:     "Error",
			statusCode: "ERROR",
			errorText:  "diagnostic failure",
			errorCode:  "GENERIC",
			done:       true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetProgressMap()
			id := startOperation()
			tc.finish(t, id)

			state, err := getProgress(id)
			if err != nil {
				t.Fatal(err)
			}
			if state.Status != tc.status || state.StatusCode != tc.statusCode {
				t.Fatalf("terminal status = (%q, %q), want (%q, %q)", state.Status, state.StatusCode, tc.status, tc.statusCode)
			}
			if state.Error != tc.errorText || state.Code != tc.errorCode {
				t.Fatalf("diagnostic fields = (%q, %q), want (%q, %q)", state.Error, state.Code, tc.errorText, tc.errorCode)
			}
			if state.Done != tc.done {
				t.Fatalf("state.Done = %v, want %v", state.Done, tc.done)
			}
			if state.Info != "" || state.InfoCode != "NONE" {
				t.Fatalf("initial info fields = (%q, %q), want (%q, %q)", state.Info, state.InfoCode, "", "NONE")
			}
		})
	}
}

func TestAndroidProgressReporterUpdatesFieldFamiliesAtomically(t *testing.T) {
	resetProgressMap()

	id := startOperation()
	reporter := &androidProgressReporter{opID: id}

	// Hold the write lock until both reporter calls have arrived at their first
	// progress-map lock acquisition. A stale read-copy-write implementation then
	// releases both readers together, forcing both to snapshot the old state
	// before either full-state write can proceed.
	globalProgressMap.mu.Lock()
	op := globalProgressMap.ops[id]
	op.Status = "Deriving key..."
	op.StatusCode = "DERIVING_KEY"
	op.StatusSpeedMiBPerSecond = 0
	op.StatusETA = ""
	op.Progress = 0.25
	op.Info = "1/10"
	op.InfoCode = "ITEM_COUNT"
	op.InfoCurrent = 1
	op.InfoTotal = 10

	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(2)
	var calls sync.WaitGroup
	calls.Add(2)
	go func() {
		defer calls.Done()
		ready.Done()
		<-start
		reporter.SetStatus("Encrypting at 12.34 MiB/s (ETA: 01:02:03)")
	}()
	go func() {
		defer calls.Done()
		ready.Done()
		<-start
		reporter.SetProgress(0.75, "3/10")
	}()
	ready.Wait()
	close(start)
	if !reporterCallsBlockedOnProgressMapLock(2 * time.Second) {
		globalProgressMap.mu.Unlock()
		calls.Wait()
		t.Fatal("reporter calls did not reach the progress-map lock")
	}
	globalProgressMap.mu.Unlock()
	calls.Wait()

	state, err := getProgress(id)
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "Encrypting at 12.34 MiB/s (ETA: 01:02:03)" ||
		state.StatusCode != "ENCRYPTING_RATE" ||
		state.StatusSpeedMiBPerSecond != 12.34 || state.StatusETA != "01:02:03" {
		t.Fatalf("concurrent update reverted status family: %#v", state)
	}
	if state.Progress != 0.75 || state.Info != "3/10" || state.InfoCode != "ITEM_COUNT" ||
		state.InfoCurrent != 3 || state.InfoTotal != 10 {
		t.Fatalf("concurrent update reverted progress family: %#v", state)
	}
}

func reporterCallsBlockedOnProgressMapLock(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	stack := make([]byte, 1<<20)
	for time.Now().Before(deadline) {
		n := runtime.Stack(stack, true)
		statusBlocked := false
		progressBlocked := false
		for _, goroutine := range strings.Split(string(stack[:n]), "\n\n") {
			blockedOnRWMutex := strings.Contains(goroutine, "sync.(*RWMutex).Lock") ||
				strings.Contains(goroutine, "sync.(*RWMutex).RLock")
			if !blockedOnRWMutex {
				continue
			}
			statusBlocked = statusBlocked || strings.Contains(goroutine, "(*androidProgressReporter).SetStatus")
			progressBlocked = progressBlocked || strings.Contains(goroutine, "(*androidProgressReporter).SetProgress")
		}
		if statusBlocked && progressBlocked {
			return true
		}
		runtime.Gosched()
	}
	return false
}

func TestGetProgressCopiesStructuredFields(t *testing.T) {
	resetProgressMap()

	id := startOperation()
	globalProgressMap.mu.Lock()
	globalProgressMap.ops[id] = &ProgressState{
		ID:                      id,
		Status:                  "Encrypting at 12.34 MiB/s (ETA: 01:02:03)",
		StatusCode:              "ENCRYPTING_RATE",
		StatusSpeedMiBPerSecond: 12.34,
		StatusETA:               "01:02:03",
		Progress:                0.3,
		Info:                    "3/10",
		InfoCode:                "ITEM_COUNT",
		InfoCurrent:             3,
		InfoTotal:               10,
		Error:                   "diagnostic",
		Code:                    "GENERIC",
	}
	globalProgressMap.mu.Unlock()

	state, err := getProgress(id)
	if err != nil {
		t.Fatal(err)
	}
	result, err := GetProgress(id)
	if err != nil {
		t.Fatal(err)
	}

	if result.StatusCode != state.StatusCode ||
		result.StatusSpeedMiBPerSecond != state.StatusSpeedMiBPerSecond ||
		result.StatusETA != state.StatusETA || result.InfoCode != state.InfoCode ||
		result.InfoCurrent != state.InfoCurrent || result.InfoTotal != state.InfoTotal {
		t.Fatalf("GetProgress() dropped structured fields: result=%#v state=%#v", result, state)
	}

	state.StatusCode = "MUTATED_COPY"
	fresh, err := getProgress(id)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.StatusCode != "ENCRYPTING_RATE" {
		t.Fatalf("getProgress returned shared state: StatusCode = %q", fresh.StatusCode)
	}
}

func TestStartDecryptValidationFailureCleansUpOperation(t *testing.T) {
	resetProgressMap()

	id := StartOperation()
	reqJSON, err := json.Marshal(DecryptRequestJSON{
		OperationID: id,
		InputFile:   "",
		OutputFile:  "out",
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := StartDecrypt(string(reqJSON), []byte("password")); !strings.Contains(got, "input file is required") {
		t.Fatalf("StartDecrypt(...) = %q", got)
	}

	globalProgressMap.mu.RLock()
	_, opExists := globalProgressMap.ops[id]
	_, ctxExists := globalProgressMap.ctxs[id]
	_, cancelExists := globalProgressMap.cancels[id]
	globalProgressMap.mu.RUnlock()

	if opExists || ctxExists || cancelExists {
		t.Fatalf("validation failure leaked operation state: op=%v ctx=%v cancel=%v", opExists, ctxExists, cancelExists)
	}
}

func TestStartDecryptFailsWhenOperationContextIsMissing(t *testing.T) {
	resetProgressMap()

	inputPath := filepath.Join(t.TempDir(), "sample.txt.pcv")
	if err := os.WriteFile(inputPath, []byte("not-a-real-volume"), 0o600); err != nil {
		t.Fatal(err)
	}

	outputPath := filepath.Join(t.TempDir(), "sample.txt")
	id := StartOperation()

	globalProgressMap.mu.Lock()
	delete(globalProgressMap.ctxs, id)
	globalProgressMap.mu.Unlock()

	reqJSON, err := json.Marshal(DecryptRequestJSON{
		OperationID: id,
		InputFile:   inputPath,
		OutputFile:  outputPath,
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := StartDecrypt(string(reqJSON), []byte("password")); got != "" {
		t.Fatalf("StartDecrypt(...) returned %q, want empty string", got)
	}

	state := waitForDone(t, id)
	if state.Status != "Error" {
		t.Fatalf("state.Status = %q, want %q", state.Status, "Error")
	}
	if !strings.Contains(state.Error, "context") {
		t.Fatalf("state.Error = %q, want context-related error", state.Error)
	}
}

func TestStartDecryptRecoversPanic(t *testing.T) {
	resetProgressMap()

	inputPath := filepath.Join(t.TempDir(), "sample.txt.pcv")
	if err := os.WriteFile(inputPath, []byte("not-a-real-volume"), 0o600); err != nil {
		t.Fatal(err)
	}

	outputPath := filepath.Join(t.TempDir(), "sample.txt")
	id := StartOperation()

	orig := runDecrypt
	runDecrypt = func(context.Context, *volume.DecryptRequest) error {
		panic("boom")
	}
	defer func() { runDecrypt = orig }()

	reqJSON, err := json.Marshal(DecryptRequestJSON{
		OperationID: id,
		InputFile:   inputPath,
		OutputFile:  outputPath,
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := StartDecrypt(string(reqJSON), []byte("password")); got != "" {
		t.Fatalf("StartDecrypt(...) returned %q, want empty string", got)
	}

	state := waitForDone(t, id)
	if state.Status != "Error" {
		t.Fatalf("state.Status = %q, want %q", state.Status, "Error")
	}
	if !strings.Contains(state.Error, "panic: boom") {
		t.Fatalf("state.Error = %q, want panic error", state.Error)
	}
}

func waitForDone(t *testing.T, id string) *ProgressState {
	t.Helper()
	return waitForDoneTimeout(t, id, 2*time.Second)
}

func waitForDoneTimeout(t *testing.T, id string, timeout time.Duration) *ProgressState {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		state, err := getProgress(id)
		if err != nil {
			t.Fatal(err)
		}
		if state.Done {
			return state
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("operation %s did not complete before timeout", id)
	return nil
}

func TestRetiredStartEncryptRefusesEveryCreationShapeAndClearsPassword(t *testing.T) {
	resetProgressMap()
	dir := t.TempDir()
	input := filepath.Join(dir, "plain")
	original := []byte("unchanged original")
	if err := os.WriteFile(input, original, 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "output")
	for _, request := range []EncryptRequestJSON{
		{InputFile: input, OutputFile: output},
		{InputFiles: []string{input}, OnlyFolders: []string{dir}, OutputFile: output},
		{InputFile: input, OutputFile: output, Keyfiles: []string{input}, Deniability: true},
	} {
		request.OperationID = StartOperation()
		encoded, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		password := []byte("owned credential")
		if code := StartEncrypt(string(encoded), password); code != "PCV3_UNSUPPORTED" {
			t.Fatalf("retired writer returned %q", code)
		}
		if !allZero(password) {
			t.Fatal("retired endpoint retained credential")
		}
		cleanupOperation(request.OperationID)
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatalf("retired writer created output: %v", err)
		}
		actual, err := os.ReadFile(input)
		if err != nil || !bytes.Equal(actual, original) {
			t.Fatalf("retired writer changed source: %v", err)
		}
	}
}
