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

func TestPCV3TerminalNoFallback(t *testing.T) {
	fixture := loadPCV3DispatchFixture(t)
	unsupported := append([]byte(nil), fixture...)
	unsupported[5] = 4

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
