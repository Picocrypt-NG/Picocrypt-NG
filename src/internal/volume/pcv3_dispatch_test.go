package volume

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/pcv3"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

type pcv3DispatchReporter struct {
	statusCalls    int
	progressCalls  int
	canCancelCalls int
	updateCalls    int
	cancelCalls    int
}

func (reporter *pcv3DispatchReporter) SetStatus(string) {
	reporter.statusCalls++
}

func (reporter *pcv3DispatchReporter) SetProgress(float32, string) {
	reporter.progressCalls++
}

func (reporter *pcv3DispatchReporter) SetCanCancel(bool) {
	reporter.canCancelCalls++
}

func (reporter *pcv3DispatchReporter) Update() {
	reporter.updateCalls++
}

func (reporter *pcv3DispatchReporter) IsCancelled() bool {
	reporter.cancelCalls++
	return false
}

func (reporter *pcv3DispatchReporter) calls() int {
	return reporter.statusCalls + reporter.progressCalls + reporter.canCancelCalls + reporter.updateCalls + reporter.cancelCalls
}

func loadPCV3DispatchFixture(t *testing.T) []byte {
	t.Helper()
	fixture, err := os.ReadFile(filepath.Join("..", "pcv3", "testdata", "schema1-minimal.pcv"))
	if err != nil {
		t.Fatalf("read literal PCV3 fixture: %v", err)
	}
	return fixture
}

func writePCV3DispatchInput(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
}

func TestPreflightPCV3(t *testing.T) {
	fixture := loadPCV3DispatchFixture(t)
	dir := t.TempDir()

	legacy := filepath.Join(dir, "legacy.pcv")
	writePCV3DispatchInput(t, legacy, []byte("not-pcv3"))
	if err := PreflightPCV3(legacy, false); err != nil {
		t.Fatalf("PreflightPCV3(legacy) = %v; want nil legacy eligibility", err)
	}

	claimed := filepath.Join(dir, "claimed.pcv")
	writePCV3DispatchInput(t, claimed, fixture)
	if err := PreflightPCV3(claimed, false); !errors.Is(err, pcv3.ErrReaderUnavailable) {
		t.Fatalf("PreflightPCV3(admitted PCV3) = %v; want ErrReaderUnavailable", err)
	}

	unsupported := append([]byte(nil), fixture...)
	unsupported[5] = 4
	unsupportedPath := filepath.Join(dir, "unsupported.pcv")
	writePCV3DispatchInput(t, unsupportedPath, unsupported)
	var failure pcv3.Failure
	if err := PreflightPCV3(unsupportedPath, false); !errors.As(err, &failure) || failure.Outcome() != pcv3.OutcomeUnsupportedRoutingPreKDF {
		t.Fatalf("PreflightPCV3(unsupported PCV3) = %v; want typed unsupported route", err)
	}

	base := filepath.Join(dir, "split.pcv")
	writePCV3DispatchInput(t, base+".0", fixture)
	writePCV3DispatchInput(t, base+".1", []byte("uninspected tail"))
	if err := PreflightPCV3(base+".1", true); !errors.Is(err, pcv3.ErrReaderUnavailable) {
		t.Fatalf("PreflightPCV3(split chunk 1) = %v; want chunk-zero ErrReaderUnavailable", err)
	}
	if _, err := os.Stat(base); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preflight created recombined input %q: %v", base, err)
	}
}

func TestEncryptTreatsPCV3BytesAsPlaintext(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "pcv3-as-plaintext.bin")
	volumePath := filepath.Join(dir, "encrypted.pcv")
	output := filepath.Join(dir, "decrypted.bin")
	plaintext := loadPCV3DispatchFixture(t)
	writePCV3DispatchInput(t, input, plaintext)
	password := []byte("nested-volume-password")
	codecs := newRSCodecsT(t)

	if err := Encrypt(t.Context(), &EncryptRequest{
		InputFile:  input,
		OutputFile: volumePath,
		Password:   password,
		RSCodecs:   codecs,
	}); err != nil {
		t.Fatalf("Encrypt(PCV3 plaintext) = %v; want arbitrary input bytes accepted", err)
	}
	if err := Decrypt(t.Context(), &DecryptRequest{
		InputFile:  volumePath,
		OutputFile: output,
		Password:   password,
		RSCodecs:   codecs,
	}); err != nil {
		t.Fatalf("Decrypt(nested PCV3 plaintext) = %v", err)
	}
	decrypted, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read decrypted plaintext: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("nested PCV3 plaintext changed during encryption round trip")
	}
}

func TestDecryptPCV3RoutesBeforeLegacy(t *testing.T) {
	fixture := loadPCV3DispatchFixture(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "claimed.pcv")
	output := filepath.Join(dir, "plaintext")
	writePCV3DispatchInput(t, input, fixture)
	before := append([]byte(nil), fixture...)

	previousVolumeKey := deriveVolumeKey
	previousDeniabilityKey := deriveDeniabilityKey
	volumeKDFCalls := 0
	deniabilityKDFCalls := 0
	deriveVolumeKey = func(password, salt []byte, paranoid bool) ([]byte, error) {
		volumeKDFCalls++
		return previousVolumeKey(password, salt, paranoid)
	}
	deriveDeniabilityKey = func(password, salt []byte) []byte {
		deniabilityKDFCalls++
		return previousDeniabilityKey(password, salt)
	}
	t.Cleanup(func() {
		deriveVolumeKey = previousVolumeKey
		deriveDeniabilityKey = previousDeniabilityKey
	})

	codecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}
	reporter := &pcv3DispatchReporter{}
	err = Decrypt(t.Context(), &DecryptRequest{
		InputFile:    input,
		OutputFile:   output,
		Password:     []byte("must-not-be-used"),
		ForceDecrypt: true,
		Deniability:  true,
		Reporter:     reporter,
		RSCodecs:     codecs,
	})
	if !errors.Is(err, pcv3.ErrReaderUnavailable) {
		t.Fatalf("Decrypt(claimed PCV3) = %v; want ErrReaderUnavailable", err)
	}
	if volumeKDFCalls != 0 || deniabilityKDFCalls != 0 {
		t.Fatalf("KDF calls = volume %d, deniability %d; want both zero", volumeKDFCalls, deniabilityKDFCalls)
	}
	if reporter.calls() != 0 {
		t.Fatalf("reporter calls = %d; claimed PCV3 must stop before operation/progress", reporter.calls())
	}
	after, err := os.ReadFile(input)
	if err != nil {
		t.Fatalf("read input after rejection: %v", err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("claimed PCV3 input changed during rejection")
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("claimed PCV3 created output %q: %v", output, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read temp directory: %v", err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	if len(names) != 1 || names[0] != filepath.Base(input) {
		t.Fatalf("filesystem artifacts after rejection = %v; want only original input", names)
	}
}

func TestDecryptRejectsPCV3PathSwapBeforeLegacyOpen(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.pcv")
	backup := filepath.Join(dir, "original-input.pcv")
	replacement := filepath.Join(dir, "replacement.pcv")
	output := filepath.Join(dir, "plaintext")
	writePCV3DispatchInput(t, input, []byte("legacy input"))
	writePCV3DispatchInput(t, replacement, loadPCV3DispatchFixture(t))

	previousVolumeKey := deriveVolumeKey
	volumeKDFCalls := 0
	deriveVolumeKey = func([]byte, []byte, bool) ([]byte, error) {
		volumeKDFCalls++
		return nil, errors.New("unexpected volume KDF call")
	}
	t.Cleanup(func() {
		deriveVolumeKey = previousVolumeKey
	})

	reporter := &pathMoveReporter{
		trigger:     "Reading values...",
		path:        input,
		backup:      backup,
		replacement: replacement,
	}
	err := Decrypt(t.Context(), &DecryptRequest{
		InputFile:  input,
		OutputFile: output,
		Password:   []byte("must-not-be-used"),
		Reporter:   reporter,
		RSCodecs:   newRSCodecsT(t),
	})
	if reporter.err != nil {
		t.Fatalf("replace input before legacy open: %v", reporter.err)
	}
	if !errors.Is(err, pcv3.ErrReaderUnavailable) {
		t.Fatalf("Decrypt(input swapped to PCV3) = %v; want ErrReaderUnavailable", err)
	}
	if volumeKDFCalls != 0 {
		t.Fatalf("volume KDF calls = %d; swapped PCV3 must stop before credential work", volumeKDFCalls)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("swapped PCV3 created output %q: %v", output, err)
	}
}

func TestDecryptPreprocessRejectsPCV3SwapBeforeDeniabilityEffects(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.pcv")
	backup := filepath.Join(dir, "legacy-input.pcv")
	replacement := filepath.Join(dir, "replacement.pcv")
	writePCV3DispatchInput(t, input, []byte("legacy-eligible input"))
	writePCV3DispatchInput(t, replacement, loadPCV3DispatchFixture(t))
	if err := PreflightPCV3(input, false); err != nil {
		t.Fatalf("initial legacy preflight: %v", err)
	}
	if err := os.Rename(input, backup); err != nil {
		t.Fatalf("retain initial input: %v", err)
	}
	if err := os.Rename(replacement, input); err != nil {
		t.Fatalf("replace input with PCV3: %v", err)
	}

	previousDeniabilityKey := deriveDeniabilityKey
	deniabilityKDFCalls := 0
	deriveDeniabilityKey = func([]byte, []byte) []byte {
		deniabilityKDFCalls++
		return make([]byte, 32)
	}
	t.Cleanup(func() { deriveDeniabilityKey = previousDeniabilityKey })

	reporter := &pcv3DispatchReporter{}
	req := &DecryptRequest{
		InputFile:   input,
		Password:    []byte("must-not-be-used"),
		Deniability: true,
		Reporter:    reporter,
		RSCodecs:    newRSCodecsT(t),
	}
	ctx := NewDecryptContext(t.Context(), req)
	t.Cleanup(func() { _ = ctx.Close() })

	err := decryptPreprocess(ctx, req)
	if !errors.Is(err, pcv3.ErrReaderUnavailable) {
		t.Fatalf("decryptPreprocess(input swapped to PCV3) = %v; want ErrReaderUnavailable", err)
	}
	if deniabilityKDFCalls != 0 {
		t.Fatalf("deniability KDF calls = %d; swapped PCV3 must stop before credential work", deniabilityKDFCalls)
	}
	if reporter.calls() != 0 {
		t.Fatalf("reporter calls = %d; swapped PCV3 must stop before deniability progress", reporter.calls())
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatalf("read input directory: %v", readErr)
	}
	if len(entries) != 2 {
		t.Fatalf("filesystem entries after rejection = %d; want only current and retained input", len(entries))
	}
}

func TestDecryptPreprocessRejectsPCV3SwapBeforeRecombineOutput(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "split.pcv")
	firstChunk := base + ".0"
	backup := filepath.Join(dir, "legacy-chunk-zero")
	replacement := filepath.Join(dir, "replacement.pcv")
	writePCV3DispatchInput(t, firstChunk, []byte("legacy-eligible chunk zero"))
	writePCV3DispatchInput(t, base+".1", []byte("legacy tail"))
	writePCV3DispatchInput(t, replacement, loadPCV3DispatchFixture(t))
	if err := PreflightPCV3(firstChunk, true); err != nil {
		t.Fatalf("initial split legacy preflight: %v", err)
	}
	if err := os.Rename(firstChunk, backup); err != nil {
		t.Fatalf("retain initial chunk zero: %v", err)
	}
	if err := os.Rename(replacement, firstChunk); err != nil {
		t.Fatalf("replace chunk zero with PCV3: %v", err)
	}

	reporter := &pcv3DispatchReporter{}
	req := &DecryptRequest{
		InputFile: firstChunk,
		Recombine: true,
		Reporter:  reporter,
	}
	ctx := NewDecryptContext(t.Context(), req)
	t.Cleanup(func() {
		_ = ctx.cleanupRecombinedFile()
		_ = ctx.Close()
	})

	err := decryptPreprocess(ctx, req)
	if !errors.Is(err, pcv3.ErrReaderUnavailable) {
		t.Fatalf("decryptPreprocess(chunk zero swapped to PCV3) = %v; want ErrReaderUnavailable", err)
	}
	if reporter.calls() != 0 {
		t.Fatalf("reporter calls = %d; swapped PCV3 must stop before recombine progress", reporter.calls())
	}
	if _, statErr := os.Stat(base); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("swapped PCV3 created recombined output %q: %v", base, statErr)
	}
}

func TestPCV3TerminalNoFallback(t *testing.T) {
	fixture := loadPCV3DispatchFixture(t)
	unsupported := append([]byte(nil), fixture...)
	unsupported[5] = 4
	codecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}

	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "admitted", data: fixture},
		{name: "unsupported", data: unsupported},
		{name: "truncated", data: []byte{'P', 'C', 'V', 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "claimed.pcv")
			output := filepath.Join(dir, "plaintext")
			writePCV3DispatchInput(t, input, test.data)
			reporter := &pcv3DispatchReporter{}

			err := Decrypt(t.Context(), &DecryptRequest{
				InputFile:    input,
				OutputFile:   output,
				Password:     []byte("must-not-be-used"),
				ForceDecrypt: true,
				Deniability:  true,
				Reporter:     reporter,
				RSCodecs:     codecs,
			})
			var failure pcv3.Failure
			if !errors.Is(err, pcv3.ErrReaderUnavailable) && !errors.As(err, &failure) {
				t.Fatalf("Decrypt(claimed PCV3) = %v; want terminal typed PCV3 result", err)
			}
			if reporter.calls() != 0 {
				t.Fatalf("reporter calls = %d; claimed PCV3 reached legacy operation", reporter.calls())
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("claimed PCV3 created output %q: %v", output, err)
			}
		})
	}

	t.Run("legacy eligible reaches existing reader", func(t *testing.T) {
		dir := t.TempDir()
		input := filepath.Join(dir, "legacy.pcv")
		output := filepath.Join(dir, "plaintext")
		writePCV3DispatchInput(t, input, []byte("legacy input"))
		reporter := &pcv3DispatchReporter{}
		err := Decrypt(t.Context(), &DecryptRequest{
			InputFile:  input,
			OutputFile: output,
			Password:   []byte("legacy"),
			Reporter:   reporter,
		})
		var failure pcv3.Failure
		if errors.Is(err, pcv3.ErrReaderUnavailable) || errors.As(err, &failure) {
			t.Fatalf("legacy input was claimed as PCV3: %v", err)
		}
		if reporter.statusCalls == 0 {
			t.Fatal("legacy-eligible input did not reach the existing header reader")
		}
	})

	t.Run("missing split chunk zero keeps legacy validation error", func(t *testing.T) {
		dir := t.TempDir()
		input := filepath.Join(dir, "split.pcv.1")
		output := filepath.Join(dir, "plaintext")
		writePCV3DispatchInput(t, input, fixture)
		err := Decrypt(t.Context(), &DecryptRequest{
			InputFile:  input,
			OutputFile: output,
			Recombine:  true,
		})
		var failure pcv3.Failure
		if errors.Is(err, pcv3.ErrReaderUnavailable) || errors.As(err, &failure) {
			t.Fatalf("missing chunk zero was classified as PCV3: %v", err)
		}
		if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("missing chunk zero created output %q: %v", output, err)
		}
	})
}
