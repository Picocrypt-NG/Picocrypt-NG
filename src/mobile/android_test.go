package mobile

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/volume"
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	if err := cancelOperation(id); err != nil {
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
	if err := cancelOperation(id); err != nil {
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
				if err := cancelOperation(id); err != nil {
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

func TestStartEncryptFailsWhenOperationContextIsMissing(t *testing.T) {
	resetProgressMap()

	inputPath := filepath.Join(t.TempDir(), "plain.txt")
	if err := os.WriteFile(inputPath, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	outputPath := filepath.Join(t.TempDir(), "plain.txt.pcv")
	id := StartOperation()

	globalProgressMap.mu.Lock()
	delete(globalProgressMap.ctxs, id)
	globalProgressMap.mu.Unlock()

	reqJSON, err := json.Marshal(EncryptRequestJSON{
		OperationID: id,
		InputFile:   inputPath,
		OutputFile:  outputPath,
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := StartEncrypt(string(reqJSON), []byte("password")); got != "" {
		t.Fatalf("StartEncrypt(...) returned %q, want empty string", got)
	}

	state := waitForDone(t, id)
	if state.Status != "Error" {
		t.Fatalf("state.Status = %q, want %q", state.Status, "Error")
	}
	if !strings.Contains(state.Error, "context") {
		t.Fatalf("state.Error = %q, want context-related error", state.Error)
	}
}

func TestStartEncryptValidationFailureCleansUpOperation(t *testing.T) {
	resetProgressMap()

	id := StartOperation()
	reqJSON, err := json.Marshal(EncryptRequestJSON{
		OperationID: id,
		InputFile:   "",
		OutputFile:  "out.pcv",
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := StartEncrypt(string(reqJSON), []byte("password")); !strings.Contains(got, "input file is required") {
		t.Fatalf("StartEncrypt(...) = %q", got)
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

func TestStartEncryptZeroesPasswordBytes(t *testing.T) {
	resetProgressMap()
	inputPath := filepath.Join(t.TempDir(), "plain.txt")
	if err := os.WriteFile(inputPath, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(t.TempDir(), "plain.txt.pcv")
	id := StartOperation()

	orig := runEncrypt
	runEncrypt = func(context.Context, *volume.EncryptRequest) error { return nil }
	defer func() { runEncrypt = orig }()

	reqJSON, err := json.Marshal(EncryptRequestJSON{OperationID: id, InputFile: inputPath, OutputFile: outputPath})
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("hunter2")
	if got := StartEncrypt(string(reqJSON), password); got != "" {
		t.Fatalf("StartEncrypt(...) = %q, want empty", got)
	}
	for i, b := range password {
		if b != 0 {
			t.Fatalf("password[%d] = %d, want 0", i, b)
		}
	}
	_ = waitForDone(t, id)
}

func TestStartEncryptPassesMultiFileSelection(t *testing.T) {
	resetProgressMap()

	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	b := filepath.Join(dir, "b.txt")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	outputPath := filepath.Join(dir, "out.pcv")

	var captured *volume.EncryptRequest
	orig := runEncrypt
	runEncrypt = func(_ context.Context, req *volume.EncryptRequest) error {
		captured = req
		return nil
	}
	defer func() { runEncrypt = orig }()

	id := StartOperation()
	reqJSON, err := json.Marshal(EncryptRequestJSON{
		OperationID: id,
		InputFiles:  []string{a, b},
		OnlyFiles:   []string{a, b},
		OnlyFolders: []string{dir},
		OutputFile:  outputPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := StartEncrypt(string(reqJSON), []byte("pw")); got != "" {
		t.Fatalf("StartEncrypt(...) = %q, want empty", got)
	}
	_ = waitForDone(t, id)

	if captured == nil {
		t.Fatal("runEncrypt was not called")
	}
	if len(captured.InputFiles) != 2 || captured.InputFiles[0] != a || captured.InputFiles[1] != b {
		t.Fatalf("InputFiles = %#v, want [%q %q]", captured.InputFiles, a, b)
	}
	if len(captured.OnlyFiles) != 2 {
		t.Fatalf("OnlyFiles = %#v, want 2 entries", captured.OnlyFiles)
	}
	if len(captured.OnlyFolders) != 1 || captured.OnlyFolders[0] != dir {
		t.Fatalf("OnlyFolders = %#v, want [%q]", captured.OnlyFolders, dir)
	}
	if captured.InputFile != "" {
		t.Fatalf("InputFile = %q, want empty for multi-file selection", captured.InputFile)
	}
}

func TestStartEncryptFolderRoundTripsToZip(t *testing.T) {
	if raceEnabled {
		// This drives the real, memory-hard (~1 GiB) Argon2id KDF. Under -race's shadow
		// memory times `go test ./...` package parallelism it OOM-kills the hosted amd64
		// runner (SIGTERM / exit 143). It tests crypto, not concurrency, so -race adds no
		// coverage; it still runs on the no-race matrix (arm64) and locally.
		t.Skip("skipping real memory-hard Argon2id KDF round-trip under -race (OOMs CI runners)")
	}
	resetProgressMap()

	root := t.TempDir()
	folder := filepath.Join(root, "MyDocs")
	if err := os.MkdirAll(filepath.Join(folder, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	a := filepath.Join(folder, "a.txt")
	b := filepath.Join(folder, "sub", "b.txt")
	if err := os.WriteFile(a, []byte("aaa"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("bbb"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "MyDocs.zip.pcv")

	id := StartOperation()
	reqJSON, err := json.Marshal(EncryptRequestJSON{
		OperationID: id,
		InputFiles:  []string{a, b},
		OnlyFolders: []string{folder},
		OutputFile:  out,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := StartEncrypt(string(reqJSON), []byte("pw")); got != "" {
		t.Fatalf("StartEncrypt = %q, want empty", got)
	}
	// Real Argon2id KDF takes ~3-4 s locally, but it is memory-hard: a contended or
	// low-memory CI runner can run it many times slower (a hosted amd64 runner has timed
	// out at 30 s while arm64 passed). Use a generous deadline that absorbs CI variance
	// without masking a genuine hang -- still well under Go's 10 min per-package timeout.
	if state := waitForDoneTimeout(t, id, 120*time.Second); state.Status == "Error" {
		t.Fatalf("encrypt failed: %s", state.Error)
	}

	// Decrypt to a .zip and inspect entries.
	zipOut := filepath.Join(root, "decrypted.zip")
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatal(err)
	}
	if err := volume.Decrypt(context.Background(), &volume.DecryptRequest{
		InputFile:  out,
		OutputFile: zipOut,
		Password:   []byte("pw"),
		RSCodecs:   rsCodecs,
	}); err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	zr, err := zip.OpenReader(zipOut)
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	defer func() { _ = zr.Close() }()
	got := map[string]bool{}
	for _, f := range zr.File {
		got[f.Name] = true
	}
	for _, want := range []string{"MyDocs/a.txt", "MyDocs/sub/b.txt"} {
		if !got[want] {
			t.Fatalf("zip missing %q; entries=%v", want, got)
		}
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
