package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/volume"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"fyne.io/fyne/v2"
)

func TestRecursivePCV3DecryptsNestedMixedFolderAndRetainsDamagedInput(t *testing.T) {
	resetLocalizationForTest(t)
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(dir, "a-first.pcv")
	second := filepath.Join(dir, "nested", "z-second.pcv")
	damaged := filepath.Join(dir, "b-damaged.pcv")
	plain := []byte("exact Normal PCV3 recursive plaintext")
	plainPath := filepath.Join(t.TempDir(), "normal.txt")
	if err := os.WriteFile(plainPath, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	requireNativePCV3EncryptionError(t, volume.Encrypt(context.Background(), &volume.EncryptRequest{InputFile: plainPath, OutputFile: first, Password: []byte("mix"), PCV3: true}))
	encoded, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	broken := bytes.Clone(encoded)
	broken[4] = 0xff // unknown claimed major is terminal, never a legacy input.
	for path, body := range map[string][]byte{first: encoded, second: encoded, damaged: broken} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	legacyPlain := filepath.Join(t.TempDir(), "legacy.txt")
	legacy := filepath.Join(dir, "c-legacy.pcv")
	legacyBody := []byte("legacy member of the same recursive folder")
	if err := os.WriteFile(legacyPlain, legacyBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := volume.Encrypt(context.Background(), &volume.EncryptRequest{InputFile: legacyPlain, OutputFile: legacy, Password: []byte("mix"), RSCodecs: a.rsCodecs}); err != nil {
		t.Fatal(err)
	}

	fyne.DoAndWait(func() { a.onDrop([]string{dir}) })
	waitForDropProcessing(t, a)
	fyne.DoAndWait(func() {
		a.State.Password = "mix"
		a.State.CPassword = "mix"
		a.State.Recursively = true
		a.State.Delete = true
		a.startWork()
	})
	drainOperationFinalizer(t, a)
	for path, want := range map[string][]byte{first[:len(first)-4]: plain, second[:len(second)-4]: plain, legacy[:len(legacy)-4]: legacyBody} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("recursive plaintext %s = %q err=%v", path, got, err)
		}
	}
	for path, want := range map[string][]byte{first: encoded, second: encoded, damaged: broken} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("PCV3 read without source-deletion authority changed original %s: %v", path, err)
		}
	}
	if _, err := os.Stat(damaged[:len(damaged)-4]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("damaged input produced output: %v", err)
	}
	snap := a.State.UISnapshot()
	if runtime.GOOS == "windows" {
		requireNativePCV3Publication(t, a.pcv3Result)
		if snap.Working || snap.Status.Kind != app.StatusCustom || snap.Status.Text != "Output durability not confirmed\nCompleted (1 ok, 3 failed)" {
			t.Fatalf("uncertain native batch summary = %+v working=%v", snap.Status, snap.Working)
		}
	} else if snap.Working || snap.Status.Kind != app.StatusRecursiveCompletedFailed || snap.Status.Args.OK != 3 || snap.Status.Args.Failed != 1 {
		t.Fatalf("batch terminal summary = %+v working=%v", snap.Status, snap.Working)
	}
}

func TestRecursivePCV3CancellationConsumesCurrentSourceAndDoesNotOpenNext(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	fixture := filepath.Join("..", "pcv3operation", "internal", "pcv3", "testdata", "schema1-minimal.pcv")
	body, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	first, second := filepath.Join(dir, "first.pcv"), filepath.Join(dir, "second.pcv")
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	oldOpen := openDroppedPCVInput
	defer func() { openDroppedPCVInput = oldOpen }()
	var opened []*os.File
	openDroppedPCVInput = func(path string, split bool) (*os.File, error) {
		source, err := oldOpen(path, split)
		if source != nil {
			opened = append(opened, source)
		}
		return source, err
	}
	calls := 0
	var password []byte
	a.pcv3OperationExecutor = func(ctx context.Context, request *pcv3operation.Request) *pcv3operation.Result {
		calls++
		if request.Mode != pcv3operation.ModeReadNormal || request.Consent != nil {
			t.Error("recursive route inferred recovery authority")
		}
		password = request.Factors.Password
		a.stopCurrentOperation()
		return pcv3operation.Run(ctx, request)
	}
	a.operationExecutor = func(context.Context, operationInput, volume.ProgressReporter) operationResult {
		t.Error("Normal batch fell through to legacy")
		return operationResult{}
	}
	fyne.DoAndWait(func() {
		a.State.Mode = "encrypt"
		a.State.AllFiles = []string{first, second}
		a.State.Password = "cancelled batch secret"
		a.State.CPassword = a.State.Password
		a.State.Recursively = true
		a.startWork()
	})
	drainOperationFinalizer(t, a)
	if calls != 1 || len(opened) != 1 {
		t.Fatalf("cancelled batch facade calls=%d opened=%d", calls, len(opened))
	}
	if _, err := opened[0].ReadAt(make([]byte, 1), 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("cancelled batch retained source: %v", err)
	}
	requireZeroedPassword(t, password)
	for _, path := range []string{first, second} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("cancelled original changed: %v", err)
		}
		if _, err := os.Stat(defaultPCV3Output(path)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("cancelled batch produced output: %v", err)
		}
	}
	if snap := a.State.UISnapshot(); snap.Working || snap.Status.Kind != app.StatusCancelledByUser {
		t.Fatalf("cancelled batch terminal=%+v", snap.Status)
	}
}

func TestRecursivePCV3EarlyRefusalCannotHideLaterPublishedCleanupWarning(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	fixtureRoot := filepath.Join("..", "pcv3operation", "internal", "pcv3", "testdata", "normal")
	body, err := os.ReadFile(filepath.Join(fixtureRoot, "volumes", "normal-standard-combined-ordered-one.pcv"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := os.ReadFile(filepath.Join(fixtureRoot, "plaintext", "normal-standard-combined-ordered-one.bin"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	first, second := filepath.Join(dir, "refused.pcv"), filepath.Join(dir, "published.pcv")
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	keyDir := t.TempDir()
	keys := []string{filepath.Join(keyDir, "red.key"), filepath.Join(keyDir, "blue.key")}
	for index, value := range []string{"red", "blue"} {
		if err := os.WriteFile(keys[index], []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	calls := 0
	var published *pcv3operation.Result
	a.pcv3OperationExecutor = func(ctx context.Context, request *pcv3operation.Request) *pcv3operation.Result {
		calls++
		if calls == 1 {
			request.Factors.ExpectedPolicy = pcv3operation.FactorPolicyPasswordOnly
			refused := pcv3operation.Run(ctx, request)
			refused.WithCleanupWarning()
			return refused
		}
		published = pcv3operation.Run(ctx, request)
		requireNativePCV3Publication(t, published)
		// Model a caller-owned cleanup failure after a real publication.
		// This public operation can only revoke success/deletion authority.
		published.WithCleanupWarning()
		return published
	}
	fyne.DoAndWait(func() {
		a.State.Mode = "encrypt"
		a.State.AllFiles = []string{first, second}
		a.State.Password = "mix"
		a.State.CPassword = "mix"
		a.State.Keyfiles = keys
		a.State.KeyfileOrdered = true
		a.State.Recursively = true
		a.State.Delete = true
		a.startWork()
	})
	drainOperationFinalizer(t, a)
	wantClass := pcv3operation.CompletionWarning
	if runtime.GOOS == "windows" {
		wantClass = pcv3operation.CompletionDurabilityUncertain
	}
	if calls != 2 || published == nil || a.pcv3Result != published || !published.PublicationAttempted() || published.CompletionClass() != wantClass {
		t.Fatalf("published warning lost to earlier refusal: calls=%d retained=%v published=%v", calls, a.pcv3Result, published)
	}
	if !a.State.UISnapshot().PCV3CleanupIncomplete {
		t.Fatal("batch lost cleanup uncertainty")
	}
	got, err := os.ReadFile(defaultPCV3Output(second))
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("published exact plaintext missing: %x %v", got, err)
	}
	if _, err := os.Stat(defaultPCV3Output(first)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refused item produced output: %v", err)
	}
	for _, path := range []string{first, second} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("batch removed original without authority: %v", err)
		}
	}
}
