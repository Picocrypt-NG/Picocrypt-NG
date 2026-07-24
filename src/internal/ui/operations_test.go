// Package ui provides tests for UI operations and validation logic.
package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/volume"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
)

type controlledOperationCall struct {
	ctx      context.Context
	input    operationInput
	reporter volume.ProgressReporter
}

type controlledOperationExecutor struct {
	calls   chan controlledOperationCall
	results chan operationResult
}

func newControlledOperationExecutor() *controlledOperationExecutor {
	return &controlledOperationExecutor{
		calls:   make(chan controlledOperationCall, 4),
		results: make(chan operationResult, 4),
	}
}

func (e *controlledOperationExecutor) execute(ctx context.Context, input operationInput, reporter volume.ProgressReporter) operationResult {
	e.calls <- controlledOperationCall{ctx: ctx, input: input, reporter: reporter}
	return <-e.results
}

func waitForControlledOperation(t *testing.T, calls <-chan controlledOperationCall) controlledOperationCall {
	t.Helper()
	select {
	case call := <-calls:
		return call
	case <-time.After(2 * time.Second):
		t.Fatal("operation executor was not called")
		return controlledOperationCall{}
	}
}

func drainOperationFinalizer(t *testing.T, a *App) {
	t.Helper()
	a.workers.wait()
	fyne.DoAndWait(func() {})
}

func requireZeroedPassword(t *testing.T, password []byte) {
	t.Helper()
	for i, value := range password {
		if value != 0 {
			t.Fatalf("owned operation password byte %d was not zeroed after executor return", i)
		}
	}
}

func TestCancelOperationRejectsLateProgressUntilWorkerFinalizes(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	executor := newControlledOperationExecutor()
	a.operationExecutor = executor.execute

	inputPath := filepath.Join(t.TempDir(), "input.txt")
	if err := os.WriteFile(inputPath, []byte("payload"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	fyne.DoAndWait(func() {
		a.onDrop([]string{inputPath})
		a.State.Password = "secret"
		a.State.CPassword = "secret"
		a.startWork()
	})
	call := waitForControlledOperation(t, executor.calls)

	call.reporter.SetStatus("before cancellation")
	call.reporter.SetProgress(0.25, "25%")
	call.reporter.SetCanCancel(true)
	fyne.DoAndWait(func() {
		a.cancelButton.OnTapped()
	})

	select {
	case <-call.ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("cancel button did not cancel the operation context")
	}

	cancelledState := a.State.UISnapshot()
	cancelledProgress := a.State.Progress
	cancelledProgressInfo := a.State.ProgressInfo
	cancelledCanCancel := a.State.CanCancel
	cancelledBoundStatus, err := a.boundStatus.Get()
	if err != nil {
		t.Fatalf("read status binding after cancel: %v", err)
	}
	cancelledBoundProgress, err := a.boundProgress.Get()
	if err != nil {
		t.Fatalf("read progress binding after cancel: %v", err)
	}

	call.reporter.SetStatus("late update")
	call.reporter.SetProgress(0.9, "90%")
	call.reporter.SetCanCancel(true)
	fyne.DoAndWait(func() {})

	got := a.State.UISnapshot()
	if got.Status.Kind != app.StatusCancelledByUser || !got.Working {
		t.Fatalf("state after cancel = status %v, working %v; want semantic cancellation while worker remains active", got.Status.Kind, got.Working)
	}
	if got.Status != cancelledState.Status || got.PopupStatus != cancelledState.PopupStatus {
		t.Fatalf("late reporter status changed cancelled state: before=%+v/%+v after=%+v/%+v", cancelledState.Status, cancelledState.PopupStatus, got.Status, got.PopupStatus)
	}
	if a.State.Progress != cancelledProgress || a.State.ProgressInfo != cancelledProgressInfo {
		t.Fatalf("late reporter progress changed state: before=%v/%q after=%v/%q", cancelledProgress, cancelledProgressInfo, a.State.Progress, a.State.ProgressInfo)
	}
	if cancelledCanCancel || a.State.CanCancel {
		t.Fatalf("CanCancel after cancel/late callback = %v/%v; want false throughout", cancelledCanCancel, a.State.CanCancel)
	}
	if !a.cancelButton.Disabled() {
		t.Fatal("cancel button remained enabled after cancellation")
	}
	boundStatus, err := a.boundStatus.Get()
	if err != nil {
		t.Fatalf("read status binding: %v", err)
	}
	if boundStatus != cancelledBoundStatus {
		t.Fatalf("late reporter status replaced cancellation binding: before=%q after=%q", cancelledBoundStatus, boundStatus)
	}
	boundProgress, err := a.boundProgress.Get()
	if err != nil {
		t.Fatalf("read progress binding: %v", err)
	}
	if boundProgress != cancelledBoundProgress {
		t.Fatalf("late reporter progress replaced cancellation binding: before=%v after=%v", cancelledBoundProgress, boundProgress)
	}

	executor.results <- operationResult{completed: true}
	drainOperationFinalizer(t, a)
	finalState := a.State.UISnapshot()
	if finalState.Status.Kind != app.StatusCancelledByUser {
		t.Fatalf("final status after cancelled executor returned success = %v; want semantic cancellation", finalState.Status.Kind)
	}
	finalBoundStatus, err := a.boundStatus.Get()
	if err != nil {
		t.Fatalf("read final status binding: %v", err)
	}
	if finalBoundStatus != cancelledBoundStatus {
		t.Fatalf("finalizer replaced cancellation binding: before=%q after=%q", cancelledBoundStatus, finalBoundStatus)
	}
	if finalState.Working {
		t.Fatal("Working remained true after the controlled executor finalized")
	}
	if finalState.ShowProgress {
		t.Fatal("progress modal state remained visible after finalization")
	}
	if overlays := a.Window.Canvas().Overlays().List(); len(overlays) != 0 {
		t.Fatalf("progress modal overlay count = %d; want hidden", len(overlays))
	}
}

func TestOperationInputPreservesSelectedVolumeOptions(t *testing.T) {
	t.Run("encrypt", func(t *testing.T) {
		fyneApp := newTestFyneApp(t)
		a := createUIReadyDropTestApp(t, fyneApp)
		executor := newControlledOperationExecutor()
		a.operationExecutor = executor.execute

		dir := t.TempDir()
		files := []string{filepath.Join(dir, "first.txt"), filepath.Join(dir, "second.txt")}
		for _, path := range files {
			if err := os.WriteFile(path, []byte(filepath.Base(path)), 0o600); err != nil {
				t.Fatalf("write source %q: %v", path, err)
			}
		}
		onlyFiles := []string{files[0]}
		folders := []string{filepath.Join(dir, "folder")}
		if err := os.Mkdir(folders[0], 0o700); err != nil {
			t.Fatalf("create source folder: %v", err)
		}
		keyfiles := []string{filepath.Join(dir, "key-b"), filepath.Join(dir, "key-a")}
		for _, path := range keyfiles {
			if err := os.WriteFile(path, []byte(filepath.Base(path)), 0o600); err != nil {
				t.Fatalf("write keyfile %q: %v", path, err)
			}
		}
		inputFile := filepath.Join(dir, "input.zip")
		outputFile := filepath.Join(dir, "output.pcv")
		fyne.DoAndWait(func() {
			a.State.Mode = "encrypt"
			a.State.InputFile = inputFile
			a.State.OutputFile = outputFile
			a.State.AllFiles = append([]string(nil), files...)
			a.State.OnlyFiles = append([]string(nil), onlyFiles...)
			a.State.OnlyFolders = append([]string(nil), folders...)
			a.State.Password = "owned password"
			a.State.CPassword = "owned password"
			a.State.Keyfiles = append([]string(nil), keyfiles...)
			a.State.KeyfileOrdered = true
			a.State.Comments = "public comment"
			a.State.Paranoid = true
			a.State.ReedSolomon = true
			a.State.Deniability = true
			a.State.Compress = true
			a.State.Split = true
			a.State.SplitSize = "7"
			a.State.SplitSelected = 3
			a.State.Delete = true
			a.startWork()
		})

		call := waitForControlledOperation(t, executor.calls)
		released := false
		t.Cleanup(func() {
			if !released {
				select {
				case executor.results <- operationResult{err: errors.New("test cleanup release")}:
				default:
				}
			}
		})
		fyne.DoAndWait(func() {
			a.State.Password = "changed"
			a.State.AllFiles[0] = "changed-file"
			a.State.OnlyFiles[0] = "changed-direct-file"
			a.State.OnlyFolders[0] = "changed-folder"
			a.State.Keyfiles[0] = "changed-key"
		})

		got := call.input
		if got.mode != "encrypt" || got.inputFile != inputFile || got.outputFile != outputFile {
			t.Fatalf("encrypt paths/mode = (%q, %q, %q)", got.mode, got.inputFile, got.outputFile)
		}
		if !reflect.DeepEqual(got.inputFiles, files) ||
			!reflect.DeepEqual(got.onlyFiles, onlyFiles) ||
			!reflect.DeepEqual(got.onlyFolders, folders) {
			t.Fatalf("owned selections changed: all=%v files=%v folders=%v", got.inputFiles, got.onlyFiles, got.onlyFolders)
		}
		if string(got.password) != "owned password" || !reflect.DeepEqual(got.keyfiles, keyfiles) || !got.keyfileOrdered {
			t.Fatalf("owned credentials changed: password=%q keyfiles=%v ordered=%v", got.password, got.keyfiles, got.keyfileOrdered)
		}
		if got.comments != "public comment" || !got.paranoid || !got.reedSolomon || !got.deniability || !got.compress {
			t.Fatalf("encrypt options were not preserved: %+v", got)
		}
		if !got.split || got.chunkSize != 7 || got.chunkUnit != fileops.SplitUnitTiB || !got.delete {
			t.Fatalf("split/delete options were not preserved: split=%v size=%d unit=%v delete=%v", got.split, got.chunkSize, got.chunkUnit, got.delete)
		}
		if got.rsCodecs != a.rsCodecs {
			t.Fatal("operation input did not preserve the initialized Reed-Solomon codecs")
		}

		executor.results <- operationResult{err: errors.New("controlled stop")}
		released = true
		drainOperationFinalizer(t, a)
		requireZeroedPassword(t, got.password)
	})

	t.Run("decrypt", func(t *testing.T) {
		fyneApp := newTestFyneApp(t)
		a := createUIReadyDropTestApp(t, fyneApp)
		executor := newControlledOperationExecutor()
		a.operationExecutor = executor.execute

		dir := t.TempDir()
		inputBase := filepath.Join(dir, "volume.pcv")
		inputFile := inputBase + ".0"
		for i := range 2 {
			if err := os.WriteFile(inputBase+"."+strconv.Itoa(i), []byte{byte(i + 1)}, 0o600); err != nil {
				t.Fatalf("write split source %d: %v", i, err)
			}
		}
		outputFile := filepath.Join(dir, "plain.txt")
		keyfiles := []string{filepath.Join(dir, "key-2"), filepath.Join(dir, "key-1")}
		for _, path := range keyfiles {
			if err := os.WriteFile(path, []byte(filepath.Base(path)), 0o600); err != nil {
				t.Fatalf("write keyfile %q: %v", path, err)
			}
		}
		fyne.DoAndWait(func() {
			a.State.Mode = "decrypt"
			a.State.InputFile = inputFile
			a.State.OutputFile = outputFile
			a.State.OnlyFiles = []string{inputFile}
			a.State.AllFiles = []string{inputFile}
			a.State.Password = "decrypt password"
			a.State.Keyfiles = append([]string(nil), keyfiles...)
			a.State.Keep = true
			a.State.VerifyFirst = true
			a.State.AutoUnzip = true
			a.State.SameLevel = true
			a.State.Recombine = true
			a.State.Deniability = true
			a.State.Delete = true
			// Split is an encrypt-only option. A stale recursive split value must
			// never reject or alter a decrypt request.
			a.State.Split = true
			a.State.SplitSize = "irrelevant to decrypt"
			a.startWork()
		})

		call := waitForControlledOperation(t, executor.calls)
		released := false
		t.Cleanup(func() {
			if !released {
				select {
				case executor.results <- operationResult{err: errors.New("test cleanup release")}:
				default:
				}
			}
		})
		fyne.DoAndWait(func() {
			a.State.Password = "changed"
			a.State.Keyfiles[0] = "changed-key"
			a.State.AllFiles[0] = "changed-volume"
		})

		got := call.input
		if got.mode != "decrypt" || got.inputFile != inputFile || got.outputFile != outputFile {
			t.Fatalf("decrypt paths/mode = (%q, %q, %q)", got.mode, got.inputFile, got.outputFile)
		}
		if string(got.password) != "decrypt password" || !reflect.DeepEqual(got.keyfiles, keyfiles) {
			t.Fatalf("decrypt credentials changed: password=%q keyfiles=%v", got.password, got.keyfiles)
		}
		if !got.forceDecrypt || !got.verifyFirst || !got.autoUnzip || !got.sameLevel || !got.recombine || !got.deniability || !got.delete {
			t.Fatalf("decrypt options were not preserved: %+v", got)
		}
		if got.rsCodecs != a.rsCodecs {
			t.Fatal("decrypt input did not preserve the initialized Reed-Solomon codecs")
		}

		executor.results <- operationResult{err: errors.New("controlled stop")}
		released = true
		drainOperationFinalizer(t, a)
		requireZeroedPassword(t, got.password)
	})
}

func TestCancelAfterSuccessfulOperationPreservesSource(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)

	source := filepath.Join(t.TempDir(), "source.txt")
	if err := os.WriteFile(source, []byte("keep me"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	a.operationExecutor = func(context.Context, operationInput, volume.ProgressReporter) operationResult {
		return operationResult{completed: true}
	}
	type cleanupObservation struct {
		ctx       context.Context
		inputFile string
	}
	cleanupEntered := make(chan cleanupObservation, 1)
	releaseCleanup := make(chan struct{})
	a.operationSourceRemover = func(ctx context.Context, path string) error {
		cleanupEntered <- cleanupObservation{ctx: ctx, inputFile: path}
		<-releaseCleanup
		return removeOperationSource(ctx, path)
	}

	fyne.DoAndWait(func() {
		a.State.Mode = "encrypt"
		a.State.InputFile = source
		a.State.OutputFile = source + ".pcv"
		a.State.OnlyFiles = []string{source}
		a.State.AllFiles = []string{source}
		a.State.Password = "secret"
		a.State.CPassword = "secret"
		a.State.Delete = true
		a.startWork()
	})

	var observed cleanupObservation
	select {
	case observed = <-cleanupEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("successful executor did not reach the production cleanup boundary")
	}
	if observed.inputFile != source {
		t.Fatalf("cleanup boundary path = %q, want single-file removal for %q", observed.inputFile, source)
	}
	if observed.ctx.Err() != nil {
		t.Fatalf("operation was already cancelled on entry to cleanup boundary: %v", observed.ctx.Err())
	}

	fyne.DoAndWait(func() {
		a.cancelButton.OnTapped()
	})
	close(releaseCleanup)
	drainOperationFinalizer(t, a)

	if _, err := os.Stat(source); err != nil {
		t.Fatalf("source was removed after cancellation reached the cleanup boundary: %v", err)
	}
}

func TestRecursiveOperationKeepsWorkingAndProcessesEveryFile(t *testing.T) {
	t.Run("complete batch", func(t *testing.T) {
		fyneApp := newTestFyneApp(t)
		a := createUIReadyDropTestApp(t, fyneApp)
		dir := t.TempDir()
		files := []string{filepath.Join(dir, "first.txt"), filepath.Join(dir, "second.txt")}
		for _, path := range files {
			if err := os.WriteFile(path, []byte(filepath.Base(path)), 0o600); err != nil {
				t.Fatalf("write %s: %v", path, err)
			}
		}

		type observation struct {
			path           string
			working        bool
			password       string
			keyfiles       []string
			keyfileOrdered bool
			comments       string
			paranoid       bool
			reedSolomon    bool
			deniability    bool
			split          bool
			chunkSize      int
			chunkUnit      fileops.SplitUnit
			delete         bool
		}
		observed := make(chan observation, len(files))
		a.operationExecutor = func(_ context.Context, input operationInput, _ volume.ProgressReporter) operationResult {
			observed <- observation{
				path:           input.inputFile,
				working:        a.State.IsWorking(),
				password:       string(input.password),
				keyfiles:       append([]string(nil), input.keyfiles...),
				keyfileOrdered: input.keyfileOrdered,
				comments:       input.comments,
				paranoid:       input.paranoid,
				reedSolomon:    input.reedSolomon,
				deniability:    input.deniability,
				split:          input.split,
				chunkSize:      input.chunkSize,
				chunkUnit:      input.chunkUnit,
				delete:         input.delete,
			}
			return operationResult{completed: true}
		}

		fyne.DoAndWait(func() {
			a.State.Mode = "encrypt"
			a.State.InputFile = files[0]
			a.State.OutputFile = files[0] + ".pcv"
			a.State.OnlyFiles = append([]string(nil), files...)
			a.State.AllFiles = append([]string(nil), files...)
			a.State.Password = "secret"
			a.State.CPassword = "secret"
			a.State.Keyfile = true
			a.State.Keyfiles = []string{"key-b", "key-a"}
			a.State.KeyfileOrdered = true
			a.State.Comments = "recursive comment"
			a.State.Paranoid = true
			a.State.ReedSolomon = true
			a.State.Deniability = true
			a.State.Split = true
			a.State.SplitSize = "64"
			a.State.SplitSelected = 2
			a.State.Delete = true
			a.State.Recursively = true
			a.startWork()
		})

		for i, want := range files {
			select {
			case got := <-observed:
				if got.path != want {
					t.Fatalf("executor input %d = %q; want %q", i, got.path, want)
				}
				if !got.working {
					t.Fatalf("Working was false when executor entered for item %d", i)
				}
				if got.password != "secret" || !reflect.DeepEqual(got.keyfiles, []string{"key-b", "key-a"}) || !got.keyfileOrdered {
					t.Fatalf("recursive credentials for item %d = password %q keyfiles %v ordered %v", i, got.password, got.keyfiles, got.keyfileOrdered)
				}
				if got.comments != "recursive comment" || !got.paranoid || !got.reedSolomon || !got.deniability || !got.delete {
					t.Fatalf("recursive options were not restored for item %d: %+v", i, got)
				}
				if !got.split || got.chunkSize != 64 || got.chunkUnit != fileops.SplitUnitGiB {
					t.Fatalf("recursive split options for item %d = split %v size %d unit %v", i, got.split, got.chunkSize, got.chunkUnit)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("executor did not receive recursive item %d", i)
			}
		}
		drainOperationFinalizer(t, a)
		if a.State.IsWorking() {
			t.Fatal("recursive finalizer did not perform the single final Working clear")
		}
		status := a.State.UISnapshot().Status
		if status.Kind != app.StatusRecursiveCompleted || status.Args.Count != len(files) {
			t.Fatalf("recursive status = %+v; want completed count %d", status, len(files))
		}
	})

	t.Run("shutdown before recursive selection commits", func(t *testing.T) {
		fyneApp := newTestFyneApp(t)
		a := createUIReadyDropTestApp(t, fyneApp)
		file := filepath.Join(t.TempDir(), "pending.txt")
		if err := os.WriteFile(file, []byte("payload"), 0o600); err != nil {
			t.Fatalf("write input: %v", err)
		}
		var calls atomic.Int32
		a.operationExecutor = func(context.Context, operationInput, volume.ProgressReporter) operationResult {
			calls.Add(1)
			return operationResult{completed: true}
		}

		fyne.DoAndWait(func() {
			a.State.Mode = "encrypt"
			a.State.InputFile = file
			a.State.OutputFile = file + ".pcv"
			a.State.OnlyFiles = []string{file}
			a.State.AllFiles = []string{file}
			a.State.Password = "secret"
			a.State.CPassword = "secret"
			a.State.Recursively = true
			a.startWork()
			a.workers.beginStop()
		})
		a.workers.wait()
		if got := calls.Load(); got != 0 {
			t.Fatalf("stale/unapplied recursive selection reached executor %d time(s); want zero", got)
		}
	})

	t.Run("selection failure is counted", func(t *testing.T) {
		fyneApp := newTestFyneApp(t)
		a := createUIReadyDropTestApp(t, fyneApp)
		file := filepath.Join(t.TempDir(), "disappears.txt")
		if err := os.WriteFile(file, []byte("payload"), 0o600); err != nil {
			t.Fatalf("write input: %v", err)
		}
		var calls atomic.Int32
		a.operationExecutor = func(context.Context, operationInput, volume.ProgressReporter) operationResult {
			calls.Add(1)
			return operationResult{completed: true}
		}

		fyne.DoAndWait(func() {
			a.State.Mode = "encrypt"
			a.State.InputFile = file
			a.State.OutputFile = file + ".pcv"
			a.State.OnlyFiles = []string{file}
			a.State.AllFiles = []string{file}
			a.State.Password = "secret"
			a.State.CPassword = "secret"
			a.State.Recursively = true
			a.startWork()
			if err := os.Remove(file); err != nil {
				t.Fatalf("remove captured input: %v", err)
			}
		})
		drainOperationFinalizer(t, a)
		if got := calls.Load(); got != 0 {
			t.Fatalf("failed recursive selection reached executor %d time(s); want zero", got)
		}
		status := a.State.UISnapshot().Status
		if status.Kind != app.StatusRecursiveFailedAll || status.Args.Count != 1 {
			t.Fatalf("selection failure status = %+v; want failed-all count 1", status)
		}
	})
}

// TestOnClickStartValidation tests the validation logic in onClickStart.
func TestOnClickStartValidation(t *testing.T) {
	newTestFyneApp(t)
	selected := filepath.Join(t.TempDir(), "selected.txt")
	if err := os.WriteFile(selected, []byte("payload"), 0o600); err != nil {
		t.Fatalf("write selected input: %v", err)
	}

	assertRejected := func(t *testing.T, a *App) {
		t.Helper()
		var calls atomic.Int32
		a.operationExecutor = func(context.Context, operationInput, volume.ProgressReporter) operationResult {
			calls.Add(1)
			return operationResult{completed: true}
		}
		a.State.InputFile = selected
		a.State.OutputFile = selected + ".pcv"
		a.State.OnlyFiles = []string{selected}
		a.State.AllFiles = []string{selected}

		a.onClickStart()
		a.workers.wait()
		fyne.DoAndWait(func() {})
		if got := calls.Load(); got != 0 {
			t.Fatalf("invalid start reached operation executor %d time(s); want zero", got)
		}
		if a.State.IsWorking() {
			t.Fatal("invalid start entered working state")
		}
	}

	t.Run("NoMode", func(t *testing.T) {
		a := createTestApp(t)
		a.State.Mode = ""
		a.State.Password = "secret"
		assertRejected(t, a)
	})

	t.Run("NoCredentials", func(t *testing.T) {
		a := createTestApp(t)
		a.State.Mode = "encrypt"
		a.State.Password = ""
		a.State.Keyfiles = nil
		assertRejected(t, a)
	})

	t.Run("EncryptPasswordMismatch", func(t *testing.T) {
		a := createTestApp(t)
		a.State.Mode = "encrypt"
		a.State.Password = "secret"
		a.State.CPassword = "different"
		assertRejected(t, a)
	})
}

func TestDeleteSafetyRejectsPathsInsideSourceFolderBeforeExecution(t *testing.T) {
	tests := []struct {
		name            string
		outputInFolder  bool
		keyfileInFolder bool
		wantStatus      string
	}{
		{
			name:           "output inside deleted folder",
			outputInFolder: true,
			wantStatus:     "output",
		},
		{
			name:            "keyfile inside deleted folder",
			keyfileInFolder: true,
			wantStatus:      "keyfile",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fyneApp := newTestFyneApp(t)
			a := createUIReadyDropTestApp(t, fyneApp)
			dir := t.TempDir()
			sourceFolder := filepath.Join(dir, "source")
			if err := os.Mkdir(sourceFolder, 0o700); err != nil {
				t.Fatalf("create source folder: %v", err)
			}
			source := filepath.Join(sourceFolder, "payload.txt")
			sourceBytes := []byte("source must survive rejected delete plan")
			if err := os.WriteFile(source, sourceBytes, 0o600); err != nil {
				t.Fatalf("write source: %v", err)
			}

			output := filepath.Join(dir, "outside.pcv")
			if tc.outputInFolder {
				output = filepath.Join(sourceFolder, "unsafe-output.pcv")
			}
			keyfile := filepath.Join(dir, "outside.key")
			if tc.keyfileInFolder {
				keyfile = filepath.Join(sourceFolder, "unsafe.key")
			}
			keyfileBytes := []byte("keyfile must survive rejected delete plan")
			if err := os.WriteFile(keyfile, keyfileBytes, 0o600); err != nil {
				t.Fatalf("write keyfile: %v", err)
			}

			var executorCalls atomic.Int32
			var removerCalls atomic.Int32
			a.operationExecutor = func(context.Context, operationInput, volume.ProgressReporter) operationResult {
				executorCalls.Add(1)
				return operationResult{completed: true}
			}
			a.operationSourceRemover = func(context.Context, string) error {
				removerCalls.Add(1)
				return nil
			}

			fyne.DoAndWait(func() {
				a.State.Mode = "encrypt"
				a.State.InputFile = source
				a.State.AllFiles = []string{source}
				a.State.OnlyFolders = []string{sourceFolder}
				a.State.OutputFile = output
				a.State.Password = "delete-safety-password"
				a.State.CPassword = "delete-safety-password"
				a.State.Keyfiles = []string{keyfile}
				a.State.Delete = true
				a.onClickStart()
			})
			a.workers.wait()
			fyne.DoAndWait(func() {})

			if got := executorCalls.Load(); got != 0 {
				t.Fatalf("unsafe delete plan reached executor %d time(s); want zero", got)
			}
			if got := removerCalls.Load(); got != 0 {
				t.Fatalf("unsafe delete plan reached source remover %d time(s); want zero", got)
			}
			if a.State.IsWorking() {
				t.Fatal("unsafe delete plan entered working state")
			}
			if status := a.State.UISnapshot().Status.Text; !strings.Contains(status, tc.wantStatus) ||
				!strings.Contains(status, "scheduled for deletion") {
				t.Fatalf("rejection status = %q, want explicit %s deletion conflict", status, tc.wantStatus)
			}

			gotSource, err := os.ReadFile(source)
			if err != nil {
				t.Fatalf("read preserved source: %v", err)
			}
			if !reflect.DeepEqual(gotSource, sourceBytes) {
				t.Fatalf("source changed: got %q, want %q", gotSource, sourceBytes)
			}
			gotKeyfile, err := os.ReadFile(keyfile)
			if err != nil {
				t.Fatalf("read preserved keyfile: %v", err)
			}
			if !reflect.DeepEqual(gotKeyfile, keyfileBytes) {
				t.Fatalf("keyfile changed: got %q, want %q", gotKeyfile, keyfileBytes)
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unsafe output was created: %v", err)
			}
			if overlays := a.Window.Canvas().Overlays().List(); len(overlays) != 0 {
				t.Fatalf("unsafe delete plan opened %d modal overlay(s); want none", len(overlays))
			}
		})
	}
}

// When the selected split input is "volume.pcv.0", delete-after-success must
// derive "volume.pcv" before counting chunks. Counting from the selected chunk
// would leave every encrypted source behind while reporting a delete failure.
func TestSuccessfulRecombineDeletesActualChunkSet(t *testing.T) {
	a := createTestApp(t)
	dir := t.TempDir()
	inputBase := filepath.Join(dir, "volume.pcv")
	chunks := []string{inputBase + ".0", inputBase + ".1"}
	for i, chunk := range chunks {
		if err := os.WriteFile(chunk, []byte{byte(i + 1)}, 0o600); err != nil {
			t.Fatalf("write chunk %q: %v", chunk, err)
		}
	}
	unrelated := inputBase + ".notes"
	if err := os.WriteFile(unrelated, []byte("keep"), 0o600); err != nil {
		t.Fatalf("write unrelated file: %v", err)
	}

	input := operationInput{
		mode:      "decrypt",
		inputFile: chunks[0],
		recombine: true,
		delete:    true,
	}
	manifest, err := captureOperationDeletionManifest(input)
	if err != nil {
		t.Fatalf("capture deletion manifest: %v", err)
	}
	result := a.cleanupOperationSources(context.Background(), input, manifest, operationResult{completed: true})
	if result.err != nil || result.cancelled || result.deleteFailed {
		t.Fatalf("cleanup result = %+v, want successful source deletion", result)
	}
	for _, chunk := range chunks {
		if _, err := os.Lstat(chunk); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("encrypted chunk %q remains after successful delete: %v", chunk, err)
		}
	}
	if got, err := os.ReadFile(unrelated); err != nil || string(got) != "keep" {
		t.Fatalf("unrelated file changed: data=%q err=%v", got, err)
	}
}

func TestDeleteAfterSuccessPreservesReplacedSource(t *testing.T) {
	a := createTestApp(t)
	dir := t.TempDir()
	source := filepath.Join(dir, "source.txt")
	original := []byte("original source used by the operation")
	if err := os.WriteFile(source, original, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	originalInfo, err := os.Stat(source)
	if err != nil {
		t.Fatalf("inspect source: %v", err)
	}
	backup := filepath.Join(dir, "source-used-by-operation.txt")
	foreign := []byte(strings.Repeat("x", len(original)))
	input := operationInput{
		mode:       "encrypt",
		inputFile:  source,
		outputFile: filepath.Join(dir, "output.pcv"),
		delete:     true,
	}
	result := a.runCapturedOperation(
		context.Background(),
		func(context.Context, operationInput, volume.ProgressReporter) operationResult {
			if err := os.Rename(source, backup); err != nil {
				t.Fatalf("move captured source during executor: %v", err)
			}
			if err := os.WriteFile(source, foreign, 0o600); err != nil {
				t.Fatalf("write replacement source during executor: %v", err)
			}
			if err := os.Chtimes(source, originalInfo.ModTime(), originalInfo.ModTime()); err != nil {
				t.Fatalf("match replacement source timestamp: %v", err)
			}
			return operationResult{completed: true}
		},
		nil,
		input,
	)
	if !result.completed || result.err != nil || result.cancelled || !result.deleteFailed {
		t.Fatalf("operation result = %+v, want completed with explicit delete failure", result)
	}
	if got, err := os.ReadFile(source); err != nil || !reflect.DeepEqual(got, foreign) {
		t.Fatalf("replacement source changed: data=%q err=%v", got, err)
	}
	if got, err := os.ReadFile(backup); err != nil || !reflect.DeepEqual(got, original) {
		t.Fatalf("captured source backup changed: data=%q err=%v", got, err)
	}
}

func TestDeleteAfterFolderEncryptionPreservesReplacedEmptyRoot(t *testing.T) {
	a := createTestApp(t)
	dir := t.TempDir()
	sourceFolder := filepath.Join(dir, "source")
	if err := os.Mkdir(sourceFolder, 0o700); err != nil {
		t.Fatalf("create source folder: %v", err)
	}
	source := filepath.Join(sourceFolder, "captured.txt")
	sourceBytes := []byte("captured source")
	if err := os.WriteFile(source, sourceBytes, 0o600); err != nil {
		t.Fatalf("write captured source: %v", err)
	}
	backup := filepath.Join(dir, "source-used-by-operation")
	input := operationInput{
		mode:        "encrypt",
		inputFile:   source,
		inputFiles:  []string{source},
		onlyFolders: []string{sourceFolder},
		outputFile:  filepath.Join(dir, "output.pcv"),
		delete:      true,
	}
	result := a.runCapturedOperation(
		context.Background(),
		func(context.Context, operationInput, volume.ProgressReporter) operationResult {
			if err := os.Rename(sourceFolder, backup); err != nil {
				t.Fatalf("move captured source folder during executor: %v", err)
			}
			if err := os.Mkdir(sourceFolder, 0o700); err != nil {
				t.Fatalf("create replacement source folder: %v", err)
			}
			return operationResult{completed: true}
		},
		nil,
		input,
	)
	if !result.completed || result.err != nil || result.cancelled || !result.deleteFailed {
		t.Fatalf("operation result = %+v, want completed with explicit delete failure", result)
	}
	entries, err := os.ReadDir(sourceFolder)
	if err != nil {
		t.Fatalf("read replacement source folder: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("replacement source folder contains unexpected entries: %v", entries)
	}
	if got, err := os.ReadFile(filepath.Join(backup, "captured.txt")); err != nil ||
		!reflect.DeepEqual(got, sourceBytes) {
		t.Fatalf("captured source changed: data=%q err=%v", got, err)
	}
}

func TestDeleteAfterFolderEncryptionPreservesNewEntries(t *testing.T) {
	a := createTestApp(t)
	dir := t.TempDir()
	sourceFolder := filepath.Join(dir, "source")
	if err := os.Mkdir(sourceFolder, 0o700); err != nil {
		t.Fatalf("create source folder: %v", err)
	}
	source := filepath.Join(sourceFolder, "captured.txt")
	if err := os.WriteFile(source, []byte("captured source"), 0o600); err != nil {
		t.Fatalf("write captured source: %v", err)
	}
	latePath := filepath.Join(sourceFolder, "created-during-encryption.txt")
	lateBytes := []byte("this file was never part of the encrypted input")
	input := operationInput{
		mode:        "encrypt",
		inputFile:   source,
		inputFiles:  []string{source},
		onlyFolders: []string{sourceFolder},
		outputFile:  filepath.Join(dir, "output.pcv"),
		delete:      true,
	}
	result := a.runCapturedOperation(
		context.Background(),
		func(context.Context, operationInput, volume.ProgressReporter) operationResult {
			if err := os.WriteFile(latePath, lateBytes, 0o600); err != nil {
				t.Fatalf("write late folder entry: %v", err)
			}
			return operationResult{completed: true}
		},
		nil,
		input,
	)
	if !result.completed || result.err != nil || result.cancelled || !result.deleteFailed {
		t.Fatalf("operation result = %+v, want completed with explicit delete failure", result)
	}
	if _, err := os.Lstat(source); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unchanged captured source remains: %v", err)
	}
	if got, err := os.ReadFile(latePath); err != nil || !reflect.DeepEqual(got, lateBytes) {
		t.Fatalf("late folder entry changed: data=%q err=%v", got, err)
	}
	if info, err := os.Stat(sourceFolder); err != nil || !info.IsDir() {
		t.Fatalf("source folder containing a new entry was removed: info=%v err=%v", info, err)
	}
}

func TestDeleteAfterRecombineNeverDeletesLateChunk(t *testing.T) {
	a := createTestApp(t)
	dir := t.TempDir()
	inputBase := filepath.Join(dir, "volume.pcv")
	for i := range 2 {
		if err := os.WriteFile(inputBase+"."+strconv.Itoa(i), []byte{byte(i + 1)}, 0o600); err != nil {
			t.Fatalf("write initial chunk %d: %v", i, err)
		}
	}
	lateChunk := inputBase + ".2"
	lateBytes := []byte("chunk created after the exact input manifest")
	input := operationInput{
		mode:       "decrypt",
		inputFile:  inputBase + ".0",
		outputFile: filepath.Join(dir, "plaintext.bin"),
		recombine:  true,
		delete:     true,
	}
	result := a.runCapturedOperation(
		context.Background(),
		func(context.Context, operationInput, volume.ProgressReporter) operationResult {
			if err := os.WriteFile(lateChunk, lateBytes, 0o600); err != nil {
				t.Fatalf("write late split chunk: %v", err)
			}
			return operationResult{completed: true}
		},
		nil,
		input,
	)
	if !result.completed || result.err != nil || result.cancelled || result.deleteFailed {
		t.Fatalf("operation result = %+v, want successful deletion of only the captured chunk set", result)
	}
	for i := range 2 {
		if _, err := os.Lstat(inputBase + "." + strconv.Itoa(i)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("captured chunk %d remains: %v", i, err)
		}
	}
	if got, err := os.ReadFile(lateChunk); err != nil || !reflect.DeepEqual(got, lateBytes) {
		t.Fatalf("late chunk changed: data=%q err=%v", got, err)
	}
}

func TestRecursiveDeleteFailureIsNotOverwrittenByLaterSuccess(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	dir := t.TempDir()
	files := []string{filepath.Join(dir, "first.txt"), filepath.Join(dir, "second.txt")}
	for _, path := range files {
		if err := os.WriteFile(path, []byte(filepath.Base(path)), 0o600); err != nil {
			t.Fatalf("write recursive source %q: %v", path, err)
		}
	}
	firstBackup := files[0] + ".used"
	firstReplacement := []byte("replacement created during first operation")
	var call atomic.Int32
	a.operationExecutor = func(context.Context, operationInput, volume.ProgressReporter) operationResult {
		if call.Add(1) == 1 {
			if err := os.Rename(files[0], firstBackup); err != nil {
				t.Fatalf("move first recursive source: %v", err)
			}
			if err := os.WriteFile(files[0], firstReplacement, 0o600); err != nil {
				t.Fatalf("replace first recursive source: %v", err)
			}
		}
		return operationResult{completed: true}
	}

	fyne.DoAndWait(func() {
		a.State.Mode = "encrypt"
		a.State.InputFile = files[0]
		a.State.OutputFile = files[0] + ".pcv"
		a.State.OnlyFiles = append([]string(nil), files...)
		a.State.AllFiles = append([]string(nil), files...)
		a.State.Password = "recursive-delete-password"
		a.State.CPassword = "recursive-delete-password"
		a.State.Delete = true
		a.State.Recursively = true
		a.startWork()
	})
	drainOperationFinalizer(t, a)

	if got := call.Load(); got != 2 {
		t.Fatalf("recursive executor calls = %d, want 2", got)
	}
	if got, err := os.ReadFile(files[0]); err != nil || !reflect.DeepEqual(got, firstReplacement) {
		t.Fatalf("first replacement changed: data=%q err=%v", got, err)
	}
	if _, err := os.Lstat(files[1]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unchanged second source remains: %v", err)
	}
	if status := a.State.UISnapshot().Status.Kind; status != app.StatusCompletedSomeDeleteFailed {
		t.Fatalf("recursive final status = %v, want delete-failure warning", status)
	}
}

func TestUpdateOutputFileForCompressClearsDialogConfirmation(t *testing.T) {
	newTestFyneApp(t)

	a := createTestApp(t)
	a.State.Mode = "encrypt"
	a.State.InputFile = filepath.Join(t.TempDir(), "report.txt")
	a.State.OutputFile = filepath.Join(t.TempDir(), "report.txt.pcv")
	a.State.OutputChosenViaSaveDialog = true

	a.updateOutputFileForCompress(true)

	if a.State.OutputChosenViaSaveDialog {
		t.Fatal("programmatic output path changes should clear dialog confirmation state")
	}
	if got := a.State.OutputFile; got != filepath.Join(filepath.Dir(a.State.OutputFile), "report.txt.zip.pcv") {
		t.Fatalf("OutputFile = %q", got)
	}
}

func TestCreateReporterCallbacksUpdateStateAndCancelButton(t *testing.T) {
	fyneApp := test.NewApp()
	t.Cleanup(fyneApp.Quit)

	a := createUIReadyDropTestApp(t, fyneApp)
	session := a.newOperationSession()
	a.setOperationSession(session)
	defer func() {
		session.cancel()
		a.clearOperationSession(session)
	}()
	fyne.DoAndWait(func() {
		a.showProgressModal(session)
	})

	reporter := a.CreateReporter(session)

	done := make(chan struct{})
	go func() {
		reporter.SetStatus("Encrypting...")
		reporter.SetProgress(0.5, "50%")
		reporter.SetCanCancel(false)
		reporter.SetCanCancel(true)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reporter callbacks did not complete")
	}

	fyne.DoAndWait(func() {})

	if a.State.PopupStatus != "Encrypting..." {
		t.Fatalf("PopupStatus = %q; want %q", a.State.PopupStatus, "Encrypting...")
	}
	if a.State.Progress != 0.5 {
		t.Fatalf("Progress = %v; want 0.5", a.State.Progress)
	}
	if a.State.ProgressInfo != "50%" {
		t.Fatalf("ProgressInfo = %q; want %q", a.State.ProgressInfo, "50%")
	}
	boundStatus, err := a.boundStatus.Get()
	if err != nil {
		t.Fatalf("read reporter status binding: %v", err)
	}
	if boundStatus != "Encrypting..." {
		t.Fatalf("status binding = %q; want %q", boundStatus, "Encrypting...")
	}
	boundProgress, err := a.boundProgress.Get()
	if err != nil {
		t.Fatalf("read reporter progress binding: %v", err)
	}
	if boundProgress != 0.5 {
		t.Fatalf("progress binding = %v; want 0.5", boundProgress)
	}
	if !a.State.CanCancel {
		t.Fatal("CanCancel should be true after final callback")
	}
	if a.cancelButton == nil {
		t.Fatal("cancelButton should exist after showProgressModal")
	}
	if a.cancelButton.Disabled() {
		t.Fatal("cancelButton should be enabled")
	}
}

// TestSplitUnitConversion verifies that splitUnitFromIndex turns each
// State.SplitSelected value into the fileops.SplitUnit the request adapter
// carries to the encryption operation.
func TestSplitUnitConversion(t *testing.T) {
	testCases := []struct {
		name  string
		index int32
		want  fileops.SplitUnit
	}{
		{"KiB", 0, fileops.SplitUnitKiB},
		{"MiB", 1, fileops.SplitUnitMiB},
		{"GiB", 2, fileops.SplitUnitGiB},
		{"TiB", 3, fileops.SplitUnitTiB},
		{"Total", 4, fileops.SplitUnitTotal},
		{"OutOfRangeFallsBackToKiB", 99, fileops.SplitUnitKiB},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := splitUnitFromIndex(tc.index); got != tc.want {
				t.Errorf("splitUnitFromIndex(%d) = %d; want %d", tc.index, got, tc.want)
			}
		})
	}
}

// TestSplitUnitsLabelsAlignWithIndices keeps the GUI dropdown labels aligned
// with the index meanings splitUnitFromIndex encodes: SplitUnits[i] must name
// the unit splitUnitFromIndex(i) returns.
func TestSplitUnitsLabelsAlignWithIndices(t *testing.T) {
	state := mustNewState(t)
	want := []string{"KiB", "MiB", "GiB", "TiB", "Total"}
	if len(state.SplitUnits) != len(want) {
		t.Fatalf("len(SplitUnits) = %d; want %d", len(state.SplitUnits), len(want))
	}
	for i, w := range want {
		if state.SplitUnits[i] != w {
			t.Errorf("SplitUnits[%d] = %q; want %q", i, state.SplitUnits[i], w)
		}
	}
}

// createTestApp creates a minimal App instance for testing.
func createTestApp(t *testing.T) *App {
	t.Helper()

	a, err := NewApp("v2.02")
	if err != nil {
		t.Fatalf("Failed to create test app: %v", err)
	}
	return a
}
