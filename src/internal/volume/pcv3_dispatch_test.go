package volume

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/pcv3"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

type pcv3DispatchReporter struct {
	statusCalls    int
	progressCalls  int
	canCancelCalls int
	updateCalls    int
	cancelCalls    int
	onStatus       func(string)
}

func (reporter *pcv3DispatchReporter) SetStatus(status string) {
	reporter.statusCalls++
	if reporter.onStatus != nil {
		reporter.onStatus(status)
	}
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

func TestOpenLegacyPCVInputPinsClassifiedDescriptor(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.pcv")
	backup := filepath.Join(dir, "legacy-input.pcv")
	replacement := filepath.Join(dir, "replacement.pcv")
	legacy := []byte("legacy bytes read from the routed descriptor")
	writePCV3DispatchInput(t, input, legacy)
	writePCV3DispatchInput(t, replacement, loadPCV3DispatchFixture(t))

	fin, err := OpenLegacyPCVInput(input, false)
	if err != nil {
		t.Fatalf("OpenLegacyPCVInput(legacy) = %v", err)
	}
	t.Cleanup(func() { _ = fin.Close() })
	if err := os.Rename(input, backup); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("Windows denied atomic replacement of an open descriptor: %v", err)
		}
		t.Fatalf("preserve routed input: %v", err)
	}
	if err := os.Rename(replacement, input); err != nil {
		t.Fatalf("replace pathname with claimed PCV3: %v", err)
	}

	got, err := io.ReadAll(fin)
	if err != nil {
		t.Fatalf("read routed descriptor: %v", err)
	}
	if !bytes.Equal(got, legacy) {
		t.Fatalf("routed descriptor followed pathname replacement: got %q, want original legacy bytes", got)
	}
	if err := PreflightPCV3(input, false); !errors.Is(err, pcv3.ErrReaderUnavailable) {
		t.Fatalf("replacement pathname route = %v; want ErrReaderUnavailable", err)
	}
}

func TestDecryptPinsClassifiedInputAcrossHeaderAndPayload(t *testing.T) {
	dir := t.TempDir()
	plaintextPath := filepath.Join(dir, "plaintext.bin")
	input := filepath.Join(dir, "legacy.pcv")
	retainedInput := filepath.Join(dir, "legacy-open-descriptor.pcv")
	replacement := filepath.Join(dir, "replacement.pcv")
	output := filepath.Join(dir, "decrypted.bin")
	plaintext := []byte("the payload must come from the descriptor whose header was classified")
	password := []byte("pin-one-input-through-the-operation")
	writePCV3DispatchInput(t, plaintextPath, plaintext)
	writePCV3DispatchInput(t, replacement, loadPCV3DispatchFixture(t))
	codecs := newRSCodecsT(t)

	if err := Encrypt(t.Context(), &EncryptRequest{
		InputFile:  plaintextPath,
		OutputFile: input,
		Password:   password,
		RSCodecs:   codecs,
	}); err != nil {
		t.Fatalf("Encrypt() = %v", err)
	}

	var swapErr error
	swapped := false
	reporter := &pcv3DispatchReporter{
		onStatus: func(status string) {
			if swapped || swapErr != nil || status != "Deriving key..." {
				return
			}
			if err := os.Rename(input, retainedInput); err != nil {
				swapErr = fmt.Errorf("retain classified input: %w", err)
				return
			}
			if err := os.Rename(replacement, input); err != nil {
				_ = os.Rename(retainedInput, input)
				swapErr = fmt.Errorf("replace input pathname: %w", err)
				return
			}
			swapped = true
		},
	}

	preparedInput, err := PrepareDecryptInput(input, false)
	if err != nil {
		t.Fatalf("PrepareDecryptInput() = %v", err)
	}
	t.Cleanup(func() { _ = preparedInput.Close() })
	err = DecryptPrepared(t.Context(), &DecryptRequest{
		InputFile:  input,
		OutputFile: output,
		Password:   password,
		Reporter:   reporter,
		RSCodecs:   codecs,
	}, preparedInput)
	if swapErr != nil {
		if windowsPreventedOpenHandleRename(swapErr) {
			if err != nil {
				t.Fatalf("DecryptPrepared() after Windows protected the open input = %v", err)
			}
			got, readErr := os.ReadFile(output)
			if readErr != nil || !bytes.Equal(got, plaintext) {
				t.Fatalf("Windows-protected decrypt output = %q err=%v; want %q", got, readErr, plaintext)
			}
			if routeErr := PreflightPCV3(input, false); routeErr != nil {
				t.Fatalf("Windows-protected legacy input route = %v", routeErr)
			}
			if routeErr := PreflightPCV3(replacement, false); !errors.Is(routeErr, pcv3.ErrReaderUnavailable) {
				t.Fatalf("untouched replacement route = %v; want ErrReaderUnavailable", routeErr)
			}
			if _, headerErr := preparedInput.ReadLegacyHeader(codecs); headerErr != nil {
				t.Fatalf("DecryptPrepared closed its borrowed input: %v", headerErr)
			}
			return
		}
		t.Fatal(swapErr)
	}
	if !swapped {
		t.Fatal("test did not replace the pathname after the classified header read")
	}
	if err != nil {
		t.Fatalf("DecryptPrepared() after pathname replacement = %v; want the classified descriptor to remain authoritative", err)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read decrypted output: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypted output = %q; want original descriptor payload %q", got, plaintext)
	}
	if err := PreflightPCV3(input, false); !errors.Is(err, pcv3.ErrReaderUnavailable) {
		t.Fatalf("replacement pathname route = %v; want the PCV3 replacement to remain untouched", err)
	}
	if _, err := preparedInput.ReadLegacyHeader(codecs); err != nil {
		t.Fatalf("DecryptPrepared closed its borrowed input: %v", err)
	}
}

func TestDecryptDoesNotPublishOverMovedPreparedInput(t *testing.T) {
	dir := t.TempDir()
	plaintextPath := filepath.Join(dir, "plaintext.bin")
	input := filepath.Join(dir, "legacy.pcv")
	replacement := filepath.Join(dir, "replacement.pcv")
	output := filepath.Join(dir, "decrypted.bin")
	plaintext := []byte("plaintext must never replace the encrypted descriptor it came from")
	password := []byte("protect-the-prepared-input-identity")
	replacementBytes := []byte("a different legacy-eligible pathname occupant")
	writePCV3DispatchInput(t, plaintextPath, plaintext)
	writePCV3DispatchInput(t, replacement, replacementBytes)
	codecs := newRSCodecsT(t)

	if err := Encrypt(t.Context(), &EncryptRequest{
		InputFile:  plaintextPath,
		OutputFile: input,
		Password:   password,
		RSCodecs:   codecs,
	}); err != nil {
		t.Fatalf("Encrypt() = %v", err)
	}
	originalVolume, err := os.ReadFile(input)
	if err != nil {
		t.Fatalf("read encrypted input: %v", err)
	}

	var swapErr error
	swapped := false
	reporter := &pcv3DispatchReporter{
		onStatus: func(status string) {
			if swapped || swapErr != nil || status != "Deriving key..." {
				return
			}
			if err := os.Rename(input, output); err != nil {
				swapErr = fmt.Errorf("move prepared input onto output path: %w", err)
				return
			}
			if err := os.Rename(replacement, input); err != nil {
				_ = os.Rename(output, input)
				swapErr = fmt.Errorf("replace input pathname: %w", err)
				return
			}
			swapped = true
		},
	}

	err = Decrypt(t.Context(), &DecryptRequest{
		InputFile:  input,
		OutputFile: output,
		Password:   password,
		Reporter:   reporter,
		RSCodecs:   codecs,
	})
	if swapErr != nil {
		if windowsPreventedOpenHandleRename(swapErr) {
			if err != nil {
				t.Fatalf("Decrypt() after Windows protected the open input = %v", err)
			}
			gotOutput, readErr := os.ReadFile(output)
			if readErr != nil || !bytes.Equal(gotOutput, plaintext) {
				t.Fatalf("Windows-protected decrypt output = %q err=%v; want %q", gotOutput, readErr, plaintext)
			}
			gotInput, readErr := os.ReadFile(input)
			if readErr != nil || !bytes.Equal(gotInput, originalVolume) {
				t.Fatalf("Windows-protected encrypted input changed: len=%d err=%v", len(gotInput), readErr)
			}
			gotReplacement, readErr := os.ReadFile(replacement)
			if readErr != nil || !bytes.Equal(gotReplacement, replacementBytes) {
				t.Fatalf("unused replacement changed: got %q err=%v", gotReplacement, readErr)
			}
			assertNoPicocryptStages(t, dir)
			return
		}
		t.Fatal(swapErr)
	}
	if !swapped {
		t.Fatal("test did not move the prepared input onto the output path")
	}
	if err == nil || !strings.Contains(err.Error(), "routed encrypted input") {
		t.Fatalf("Decrypt() = %v; want prepared-input output-alias refusal", err)
	}
	gotOutput, readErr := os.ReadFile(output)
	if readErr != nil {
		t.Fatalf("read preserved encrypted input: %v", readErr)
	}
	if !bytes.Equal(gotOutput, originalVolume) {
		t.Fatal("failed decrypt replaced or changed the moved encrypted input")
	}
	gotInput, readErr := os.ReadFile(input)
	if readErr != nil || !bytes.Equal(gotInput, replacementBytes) {
		t.Fatalf("replacement input changed: got %q err=%v", gotInput, readErr)
	}
	assertNoPicocryptStages(t, dir)
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

func TestRemoveDeniabilityRejectsBorrowedPCV3BeforeEffects(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "claimed.pcv")
	fixture := loadPCV3DispatchFixture(t)
	writePCV3DispatchInput(t, input, fixture)
	fin, err := os.Open(input)
	if err != nil {
		t.Fatalf("open borrowed PCV3 input: %v", err)
	}
	t.Cleanup(func() { _ = fin.Close() })

	previousDeniabilityKey := deriveDeniabilityKey
	deniabilityKDFCalls := 0
	deriveDeniabilityKey = func([]byte, []byte) []byte {
		deniabilityKDFCalls++
		return make([]byte, 32)
	}
	t.Cleanup(func() { deriveDeniabilityKey = previousDeniabilityKey })

	reporter := &pcv3DispatchReporter{}
	stage, err := removeDeniability(
		input,
		[]byte("must-not-be-used"),
		reporter,
		newRSCodecsT(t),
		nil,
		fin,
	)
	if stage != nil {
		_ = stage.Cleanup()
		t.Fatal("borrowed PCV3 input created a deniability output stage")
	}
	if !errors.Is(err, pcv3.ErrReaderUnavailable) {
		t.Fatalf("removeDeniability(borrowed PCV3) = %v; want ErrReaderUnavailable", err)
	}
	if deniabilityKDFCalls != 0 {
		t.Fatalf("deniability KDF calls = %d; want zero before terminal PCV3 routing", deniabilityKDFCalls)
	}
	if reporter.calls() != 0 {
		t.Fatalf("reporter calls = %d; want zero before terminal PCV3 routing", reporter.calls())
	}
	if _, err := fin.Stat(); err != nil {
		t.Fatalf("removeDeniability closed the borrowed input: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read input directory: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(input) {
		t.Fatalf("filesystem artifacts after rejection = %v; want only original input", entries)
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
	previousVolumeKey := deriveVolumeKey
	previousDeniabilityKey := deriveDeniabilityKey
	volumeKDFCalls := 0
	deniabilityKDFCalls := 0
	deriveVolumeKey = func([]byte, []byte, bool) ([]byte, error) {
		volumeKDFCalls++
		return make([]byte, 32), nil
	}
	deriveDeniabilityKey = func([]byte, []byte) []byte {
		deniabilityKDFCalls++
		return make([]byte, 32)
	}
	t.Cleanup(func() {
		deriveVolumeKey = previousVolumeKey
		deriveDeniabilityKey = previousDeniabilityKey
	})

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
			if volumeKDFCalls != 0 || deniabilityKDFCalls != 0 {
				t.Fatalf("KDF calls = volume %d, deniability %d; claimed PCV3 reached legacy credentials", volumeKDFCalls, deniabilityKDFCalls)
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
