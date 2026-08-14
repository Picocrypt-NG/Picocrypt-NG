package volume

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/util"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	perrors "Picocrypt-NG/internal/errors"
)

const verifiedLegacyPlaintextSHA256 = "f13a40d162f6002d178bc052d93a177a2a261260f1fe03e359755901b039ad95"
const verifiedLegacyRSPlaintextSHA256 = "479ad71598de182171230acbe3322cdac3b9bb9f70894a7cc3e7b526be46693b"

func verifiedLegacyRequest(t *testing.T, fixture string) (*DecryptRequest, *PreparedDecryptInput) {
	t.Helper()
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}

	source := filepath.Join(findTestdata(t), fixture)
	volumeBytes, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read frozen fixture %s: %v", fixture, err)
	}

	path := filepath.Join(t.TempDir(), fixture)
	if err := os.WriteFile(path, volumeBytes, 0o600); err != nil {
		t.Fatalf("copy frozen fixture %s: %v", fixture, err)
	}
	prepared, err := PrepareDecryptInput(path, false)
	if err != nil {
		t.Fatalf("PrepareDecryptInput(%s): %v", fixture, err)
	}
	return &DecryptRequest{
		InputFile: path,
		Password:  []byte(goldenPassword),
		RSCodecs:  rsCodecs,
	}, prepared
}

func verifiedLegacyRSRequest(t *testing.T, correctableDamage bool) (*DecryptRequest, *PreparedDecryptInput) {
	t.Helper()
	path := materializeGoldenBase64Fixture(t, goldenLegacyKeyfileRSFixture, goldenLegacyKeyfileRSSHA256)
	if correctableDamage {
		corruptOneRSBlock(t, path, 0, 4)
	}
	prepared, err := PrepareDecryptInput(path, false)
	if err != nil {
		t.Fatalf("PrepareDecryptInput: %v", err)
	}
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}
	return &DecryptRequest{
		InputFile: path,
		Password:  []byte(goldenPassword),
		Keyfiles:  []string{filepath.Join(findTestdata(t), "keyfile_alpha.bin")},
		RSCodecs:  rsCodecs,
	}, prepared
}

func TestVerifiedLegacyPayloadFrozenInputs(t *testing.T) {
	restore := useProductionTestKDF()
	defer restore()

	for _, tc := range []struct {
		name    string
		fixture string
	}{
		{name: "v1", fixture: "pico_test_v1.txt.pcv"},
		{name: "v2", fixture: "pico_test_v2.txt.pcv"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, prepared := verifiedLegacyRequest(t, tc.fixture)
			payload, err := PrepareVerifiedLegacyPayload(context.Background(), req, prepared)
			if err != nil {
				t.Fatalf("prepareVerifiedLegacyPayload: %v", err)
			}
			defer func() {
				if err := payload.Close(); err != nil {
					t.Fatalf("Close: %v", err)
				}
			}()

			if got := payload.Len(); got != int64(len(expectedContent)) {
				t.Fatalf("Len = %d; want %d", got, len(expectedContent))
			}
			if got := payload.DecodeMode(); got != LegacyDecodePlain {
				t.Fatalf("DecodeMode = %v; want plain", got)
			}

			var out bytes.Buffer
			if err := payload.StreamTo(&out); err != nil {
				t.Fatalf("StreamTo: %v", err)
			}
			if !bytes.Equal(out.Bytes(), []byte(expectedContent)) {
				t.Fatalf("plaintext = %q; want frozen %q", out.Bytes(), expectedContent)
			}
			sum := sha256.Sum256(out.Bytes())
			if got := hex.EncodeToString(sum[:]); got != verifiedLegacyPlaintextSHA256 {
				t.Fatalf("plaintext SHA-256 = %s; want %s", got, verifiedLegacyPlaintextSHA256)
			}
		})
	}

	t.Run("beyond-budget RS damage mints no owner", func(t *testing.T) {
		req, prepared := verifiedLegacyRSRequest(t, false)
		defer func() { _ = prepared.Close() }()
		mutator, err := os.OpenFile(req.InputFile, os.O_RDWR, 0) // #nosec G304 -- test-owned path
		if err != nil {
			t.Fatalf("open corruption handle: %v", err)
		}
		for _, offset := range []int64{0, 31, 62, 93, 124} {
			position := int64(header.HeaderSize(0)) + offset
			one := []byte{0}
			if _, err := mutator.ReadAt(one, position); err != nil {
				t.Fatalf("read corruption byte: %v", err)
			}
			one[0] ^= 0xff
			if _, err := mutator.WriteAt(one, position); err != nil {
				t.Fatalf("write corruption byte: %v", err)
			}
		}
		if err := mutator.Sync(); err != nil {
			t.Fatalf("sync corruption: %v", err)
		}
		if err := mutator.Close(); err != nil {
			t.Fatalf("close corruption handle: %v", err)
		}
		payload, err := PrepareVerifiedLegacyPayload(context.Background(), req, prepared)
		if err == nil || payload != nil {
			t.Fatalf("beyond-budget prepare = (%v, %v); want nil owner and error", payload, err)
		}
	})

	for _, tc := range []struct {
		name              string
		correctableDamage bool
		wantMode          LegacyDecodeMode
	}{
		{name: "clean v2 RS pins fast decode", wantMode: LegacyDecodeRSFast},
		{name: "correctable v2 RS pins full decode", correctableDamage: true, wantMode: LegacyDecodeRSFull},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, prepared := verifiedLegacyRSRequest(t, tc.correctableDamage)
			payload, err := PrepareVerifiedLegacyPayload(context.Background(), req, prepared)
			if err != nil {
				t.Fatalf("PrepareVerifiedLegacyPayload: %v", err)
			}
			defer func() { _ = payload.Close() }()
			if got := payload.DecodeMode(); got != tc.wantMode {
				t.Fatalf("DecodeMode = %v; want %v", got, tc.wantMode)
			}
			var out bytes.Buffer
			if err := payload.StreamTo(&out); err != nil {
				t.Fatalf("StreamTo: %v", err)
			}
			if out.Len() != 512 {
				t.Fatalf("plaintext length = %d; want 512", out.Len())
			}
			sum := sha256.Sum256(out.Bytes())
			if got := hex.EncodeToString(sum[:]); got != verifiedLegacyRSPlaintextSHA256 {
				t.Fatalf("plaintext SHA-256 = %s; want %s", got, verifiedLegacyRSPlaintextSHA256)
			}
		})
	}

	t.Run("wrong password mints no owner and emits nothing", func(t *testing.T) {
		req, prepared := verifiedLegacyRequest(t, "pico_test_v2.txt.pcv")
		defer func() { _ = prepared.Close() }()
		req.Password = []byte("not-the-password")
		payload, err := PrepareVerifiedLegacyPayload(context.Background(), req, prepared)
		if err == nil || payload != nil {
			t.Fatalf("prepare wrong password = (%v, %v); want nil owner and error", payload, err)
		}
	})

	t.Run("Force is categorically ineligible", func(t *testing.T) {
		req, prepared := verifiedLegacyRequest(t, "pico_test_v2.txt.pcv")
		req.ForceDecrypt = true
		payload, err := PrepareVerifiedLegacyPayload(context.Background(), req, prepared)
		if err == nil || payload != nil {
			t.Fatalf("prepare Force input = (%v, %v); want nil owner and error", payload, err)
		}
		_ = prepared.Close()
	})
}

func TestVerifiedLegacyPayloadPinsDecodeModeAndFinalMAC(t *testing.T) {
	restore := useProductionTestKDF()
	defer restore()

	req, prepared := verifiedLegacyRequest(t, "pico_test_v2.txt.pcv")
	payload, err := PrepareVerifiedLegacyPayload(context.Background(), req, prepared)
	if err != nil {
		t.Fatalf("prepareVerifiedLegacyPayload: %v", err)
	}
	defer func() { _ = payload.Close() }()

	// Same descriptor, same inode, same size: an identity-only guard would miss
	// this. The stream pass must recompute and reject the final legacy MAC.
	info, err := os.Stat(req.InputFile)
	if err != nil {
		t.Fatalf("stat payload descriptor: %v", err)
	}
	last := info.Size() - 1
	one := []byte{0}
	mutator, err := os.OpenFile(req.InputFile, os.O_RDWR, 0) // #nosec G304 -- test-owned path
	if err != nil {
		t.Fatalf("open mutation handle: %v", err)
	}
	if _, err := mutator.ReadAt(one, last); err != nil {
		t.Fatalf("read mutation byte: %v", err)
	}
	one[0] ^= 0x80
	if _, err := mutator.WriteAt(one, last); err != nil {
		t.Fatalf("mutate same descriptor: %v", err)
	}
	if err := mutator.Sync(); err != nil {
		t.Fatalf("sync mutation: %v", err)
	}
	if err := mutator.Close(); err != nil {
		t.Fatalf("close mutation handle: %v", err)
	}

	var out bytes.Buffer
	err = payload.StreamTo(&out)
	if !errors.Is(err, perrors.ErrAuthFailed) && !errors.Is(err, perrors.ErrCorruptData) {
		t.Fatalf("StreamTo after same-inode mutation = %v; want authentication failure", err)
	}
}

func TestVerifiedLegacyPayloadPinsNormalizationAndRekey(t *testing.T) {
	t.Run("winning legacy NFD form survives the stream pass", func(t *testing.T) {
		temp := t.TempDir()
		plaintext := []byte("legacy normalization owner payload")
		input := filepath.Join(temp, "plain.txt")
		volumePath := filepath.Join(temp, "legacy-nfd.pcv")
		if err := os.WriteFile(input, plaintext, 0o600); err != nil {
			t.Fatal(err)
		}
		rsCodecs, err := encoding.NewRSCodecs()
		if err != nil {
			t.Fatal(err)
		}

		restoreLegacy := legacyKDF([]byte(decomposedPassword))
		err = Encrypt(context.Background(), &EncryptRequest{
			InputFile: input, OutputFile: volumePath,
			Password: []byte(composedPassword), RSCodecs: rsCodecs,
		})
		restoreLegacy()
		if err != nil {
			t.Fatalf("create legacy NFD volume: %v", err)
		}

		prepared, err := PrepareDecryptInput(volumePath, false)
		if err != nil {
			t.Fatal(err)
		}
		request := &DecryptRequest{
			InputFile: volumePath, Password: []byte(composedPassword), RSCodecs: rsCodecs,
		}
		payload, err := PrepareVerifiedLegacyPayload(context.Background(), request, prepared)
		if err != nil {
			t.Fatalf("select legacy NFD credential form: %v", err)
		}
		defer func() { _ = payload.Close() }()
		for pass := 1; pass <= 2; pass++ {
			var output bytes.Buffer
			if err := payload.StreamTo(&output); err != nil {
				t.Fatalf("stream pass %d with retained NFD form: %v", pass, err)
			}
			if !bytes.Equal(output.Bytes(), plaintext) {
				t.Fatalf("NFD stream pass %d plaintext = %q; want %q", pass, output.Bytes(), plaintext)
			}
		}
	})

	t.Run("stream pass recreates cipher state across rekey", func(t *testing.T) {
		previousThreshold := crypto.RekeyThreshold
		crypto.RekeyThreshold = util.MiB
		defer func() { crypto.RekeyThreshold = previousThreshold }()

		plaintext := make([]byte, 2*util.MiB+173)
		for index := range plaintext {
			plaintext[index] = byte(index*29 + 11)
		}
		if int64(len(plaintext)) <= crypto.RekeyThreshold {
			t.Fatal("rekey test payload does not cross the configured threshold")
		}
		temp := t.TempDir()
		input := filepath.Join(temp, "plain.bin")
		volumePath := filepath.Join(temp, "rekey.pcv")
		if err := os.WriteFile(input, plaintext, 0o600); err != nil {
			t.Fatal(err)
		}
		rsCodecs, err := encoding.NewRSCodecs()
		if err != nil {
			t.Fatal(err)
		}
		password := []byte("verified-owner-rekey")
		if err := Encrypt(context.Background(), &EncryptRequest{
			InputFile: input, OutputFile: volumePath,
			Password: password, RSCodecs: rsCodecs,
		}); err != nil {
			t.Fatalf("create rekey volume: %v", err)
		}

		prepared, err := PrepareDecryptInput(volumePath, false)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := PrepareVerifiedLegacyPayload(context.Background(), &DecryptRequest{
			InputFile: volumePath, Password: password, RSCodecs: rsCodecs,
		}, prepared)
		if err != nil {
			t.Fatalf("prepare rekey owner: %v", err)
		}
		defer func() { _ = payload.Close() }()
		var output bytes.Buffer
		if err := payload.StreamTo(&output); err != nil {
			t.Fatalf("stream across rekey boundary: %v", err)
		}
		if !bytes.Equal(output.Bytes(), plaintext) {
			t.Fatal("rekey stream plaintext mismatch")
		}
	})
}

func TestVerifiedLegacyPayloadClosesEveryExit(t *testing.T) {
	restore := useProductionTestKDF()
	defer restore()

	t.Run("size drift is rejected before bytes", func(t *testing.T) {
		req, prepared := verifiedLegacyRequest(t, "pico_test_v2.txt.pcv")
		payload, err := PrepareVerifiedLegacyPayload(context.Background(), req, prepared)
		if err != nil {
			t.Fatalf("prepareVerifiedLegacyPayload: %v", err)
		}
		info, err := os.Stat(req.InputFile)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		mutator, err := os.OpenFile(req.InputFile, os.O_RDWR, 0) // #nosec G304 -- test-owned path
		if err != nil {
			t.Fatalf("open truncate handle: %v", err)
		}
		if err := mutator.Truncate(info.Size() - 1); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		if err := mutator.Sync(); err != nil {
			t.Fatalf("sync truncate: %v", err)
		}
		if err := mutator.Close(); err != nil {
			t.Fatalf("close truncate handle: %v", err)
		}
		var out bytes.Buffer
		if err := payload.StreamTo(&out); err == nil {
			t.Fatal("StreamTo after size drift succeeded")
		}
		if out.Len() != 0 {
			t.Fatalf("size-drift output = %d bytes; want 0", out.Len())
		}
		if err := payload.Close(); err != nil {
			t.Fatalf("first Close: %v", err)
		}
		if err := payload.Close(); err != nil {
			t.Fatalf("second Close: %v", err)
		}
	})

	t.Run("cancelled preparation emits no owner", func(t *testing.T) {
		req, prepared := verifiedLegacyRequest(t, "pico_test_v1.txt.pcv")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		payload, err := PrepareVerifiedLegacyPayload(ctx, req, prepared)
		if err == nil || payload != nil {
			t.Fatalf("cancelled prepare = (%v, %v); want nil owner and error", payload, err)
		}
		_ = prepared.Close()
	})

	t.Run("writer failure is returned and Close remains idempotent", func(t *testing.T) {
		req, prepared := verifiedLegacyRequest(t, "pico_test_v1.txt.pcv")
		payload, err := PrepareVerifiedLegacyPayload(context.Background(), req, prepared)
		if err != nil {
			t.Fatalf("prepareVerifiedLegacyPayload: %v", err)
		}
		if err := payload.StreamTo(panickingLegacyWriter{}); err == nil {
			t.Fatal("StreamTo writer panic = nil")
		}
		if err := payload.StreamTo(failingLegacyWriter{}); err == nil {
			t.Fatal("StreamTo writer failure = nil")
		}
		if err := payload.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if err := payload.Close(); err != nil {
			t.Fatalf("second Close: %v", err)
		}
	})
}

type failingLegacyWriter struct{}

func (failingLegacyWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

type panickingLegacyWriter struct{}

func (panickingLegacyWriter) Write([]byte) (int, error) { panic("test writer panic") }
