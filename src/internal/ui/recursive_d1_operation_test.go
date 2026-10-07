package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/volume"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"fyne.io/fyne/v2"
)

func TestRecursiveExplicitD1ReadsNestedFilesAndWrongPasswordLeavesNoOutput(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	plain := []byte("explicit D1 batch plaintext")
	input := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(input, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	encodedPath := filepath.Join(t.TempDir(), "D1.pcv")
	if err := volume.Encrypt(context.Background(), &volume.EncryptRequest{InputFile: input, OutputFile: encodedPath, Password: []byte("D1 batch password"), PCV3: true, Paranoid: true, Deniability: true, RSCodecs: a.rsCodecs}); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(encodedPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []bool{false, true} {
		name := "matching factors"
		if wrong {
			name = "wrong password"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "nested"), 0o700); err != nil {
				t.Fatal(err)
			}
			files := []string{filepath.Join(dir, "first.pcv"), filepath.Join(dir, "nested", "opaque-name")}
			for _, path := range files {
				if err := os.WriteFile(path, encoded, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			var sources []*os.File
			a.pcv3OperationExecutor = func(ctx context.Context, request *pcv3operation.Request) *pcv3operation.Result {
				calls++
				if request.Mode != pcv3operation.ModeReadD1 || request.Consent != nil || request.SplitBase != "" {
					t.Error("explicit D1 batch chose another format/action")
				}
				sources = append(sources, request.Source)
				return pcv3operation.RunWithOptions(ctx, request, pcv3operation.ExecutionOptions{ArchiveAction: pcv3operation.ArchiveSave})
			}
			a.operationExecutor = func(context.Context, operationInput, volume.ProgressReporter) operationResult {
				t.Error("explicit D1 batch reached legacy or creation")
				return operationResult{err: errors.New("wrong format")}
			}
			fyne.DoAndWait(func() { a.onDrop([]string{dir}) })
			waitForDropProcessing(t, a)
			fyne.DoAndWait(func() {
				a.State.Recursively = true
				if !a.State.SetRecursiveD1(true) {
					t.Fatal("explicit D1 selection refused")
				}
				a.State.Password = "D1 batch password"
				if wrong {
					a.State.Password = "wrong D1 batch password"
				}
				a.State.CPassword = "" // decryption must not ask for encryption confirmation.
				a.State.Split = true
				a.State.SplitSize = "not a split size" // stale encrypt settings confer no authority.
				if !a.State.CanStart() {
					t.Fatal("explicit batch decryption cannot start without password confirmation")
				}
				a.startWork()
			})
			drainOperationFinalizer(t, a)
			if calls != 2 {
				t.Fatalf("explicit D1 facade calls=%d want2", calls)
			}
			for _, path := range files {
				got, err := os.ReadFile(defaultPCV3Output(path))
				if wrong {
					if !errors.Is(err, os.ErrNotExist) {
						t.Errorf("wrong factors produced output %s: %v", path, err)
					}
				} else if err != nil || !bytes.Equal(got, plain) {
					t.Errorf("D1 plaintext mismatch %s: %q %v", path, got, err)
				}
				original, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(original, encoded) {
					t.Errorf("D1 original changed: %v", err)
				}
			}
			for _, source := range sources {
				if _, err := source.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Error("D1 batch retained consumed source")
				}
			}
			snap := a.State.UISnapshot()
			want := app.StatusRecursiveCompleted
			if wrong {
				want = app.StatusRecursiveFailedAll
			}
			if snap.Working || snap.Status.Kind != want || snap.Status.Args.Count != 2 {
				t.Fatalf("D1 batch terminal=%+v", snap.Status)
			}
		})
	}
}

func TestRecursiveExplicitD1DoesNotProbePCVPrefixAndCancellationStopsNextFile(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	dir := t.TempDir()
	first, second := filepath.Join(dir, "collision.pcv"), filepath.Join(dir, "second.pcv")
	body := append([]byte("PCV\x00"), bytes.Repeat([]byte{0xa5}, 2048)...)
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	oldProbe := probeDroppedPCVInput
	defer func() { probeDroppedPCVInput = oldProbe }()
	probeDroppedPCVInput = func(io.ReaderAt, int64) (pcv3operation.Route, error) {
		t.Error("explicit D1 was sent to Normal probe")
		return pcv3operation.RouteNormalPCV, errors.New("do not infer the explicitly selected format")
	}
	calls := 0
	var source *os.File
	a.pcv3OperationExecutor = func(ctx context.Context, request *pcv3operation.Request) *pcv3operation.Result {
		calls++
		source = request.Source
		if request.Mode != pcv3operation.ModeReadD1 || source.Name() != first {
			t.Error("PCV prefix overrode explicit D1 intent")
		}
		a.stopCurrentOperation()
		return pcv3operation.Run(ctx, request)
	}
	fyne.DoAndWait(func() {
		a.State.Mode = "encrypt"
		a.State.AllFiles = []string{first, second}
		a.State.Recursively = true
		a.State.SetRecursiveD1(true)
		a.State.Password = "explicit D1"
		a.startWork()
	})
	drainOperationFinalizer(t, a)
	if calls != 1 || source == nil {
		t.Fatalf("explicit D1 collision/cancellation calls=%d", calls)
	}
	if _, err := source.ReadAt(make([]byte, 1), 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("cancelled D1 source stayed open: %v", err)
	}
	for _, path := range []string{first, second} {
		if _, err := os.Stat(defaultPCV3Output(path)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("cancelled D1 created output: %v", err)
		}
	}
	if snap := a.State.UISnapshot(); snap.Working || snap.Status.Kind != app.StatusCancelledByUser {
		t.Fatalf("D1 cancellation state=%+v", snap.Status)
	}
}
