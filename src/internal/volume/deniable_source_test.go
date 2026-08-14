package volume

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/util"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	perrors "Picocrypt-NG/internal/errors"
)

const deniableSourcePlaintextSHA256 = "f13a40d162f6002d178bc052d93a177a2a261260f1fe03e359755901b039ad95"

type frozenDeniableSourceFixture struct {
	dir      string
	path     string
	wrapper  []byte
	request  *DecryptRequest
	prepared *PreparedDecryptInput
}

func prepareFrozenDeniableSourceFixture(t *testing.T) frozenDeniableSourceFixture {
	t.Helper()
	testdata := findTestdata(t)
	wrapper, err := os.ReadFile(filepath.Join(testdata, goldenLegacyKeyfileOnlyDeniableFixture))
	if err != nil {
		t.Fatalf("read frozen deniable fixture: %v", err)
	}
	sum := sha256.Sum256(wrapper)
	if got := hex.EncodeToString(sum[:]); got != goldenLegacyKeyfileOnlyDeniableSHA256 {
		t.Fatalf("frozen deniable fixture SHA-256 = %s; want %s", got, goldenLegacyKeyfileOnlyDeniableSHA256)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, goldenLegacyKeyfileOnlyDeniableFixture)
	if err := os.WriteFile(path, wrapper, 0o600); err != nil {
		t.Fatalf("copy frozen deniable fixture: %v", err)
	}
	prepared, err := PrepareDecryptInput(path, false)
	if err != nil {
		t.Fatalf("PrepareDecryptInput: %v", err)
	}
	t.Cleanup(func() { _ = prepared.Close() })
	codecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}
	return frozenDeniableSourceFixture{
		dir:      dir,
		path:     path,
		wrapper:  wrapper,
		prepared: prepared,
		request: &DecryptRequest{
			InputFile:   path,
			Password:    nil,
			Keyfiles:    []string{filepath.Join(testdata, "keyfile_alpha.bin")},
			Deniability: true,
			RSCodecs:    codecs,
		},
	}
}

func TestDeniableSourceFrozenInputs(t *testing.T) {
	restoreKDF := useProductionTestKDF()
	defer restoreKDF()

	t.Run("frozen wrapper stays on its routed descriptor", func(t *testing.T) {
		fixture := prepareFrozenDeniableSourceFixture(t)
		originalInfo, err := fixture.prepared.file.Stat()
		if err != nil {
			t.Fatalf("stat prepared descriptor: %v", err)
		}

		retainedPath := filepath.Join(fixture.dir, "retained-wrapper.pcv")
		replacement := []byte("a replacement pathname occupant must never be opened")
		swapped := false
		if err := os.Rename(fixture.path, retainedPath); err != nil {
			if runtime.GOOS != "windows" {
				t.Fatalf("retain routed wrapper: %v", err)
			}
		} else {
			swapped = true
			if err := os.WriteFile(fixture.path, replacement, 0o600); err != nil {
				t.Fatalf("install pathname replacement: %v", err)
			}
		}

		productionOuterKDF := deriveDeniabilityKey
		outerKDFCalls := 0
		deriveDeniabilityKey = func(password, salt []byte) []byte {
			outerKDFCalls++
			return productionOuterKDF(password, salt)
		}
		defer func() { deriveDeniabilityKey = productionOuterKDF }()

		source, err := PrepareDeniableSource(t.Context(), fixture.request, fixture.prepared)
		if err != nil {
			t.Fatalf("PrepareDeniableSource: %v", err)
		}
		if outerKDFCalls != 1 {
			t.Fatalf("outer key derivations = %d; want one frozen selection", outerKDFCalls)
		}
		if source.Len() != int64(len(expectedContent)) {
			t.Fatalf("Len = %d; want %d", source.Len(), len(expectedContent))
		}
		if source.DecodeMode() != LegacyDecodePlain {
			t.Fatalf("DecodeMode = %v; want plain", source.DecodeMode())
		}

		var plaintext bytes.Buffer
		if err := source.StreamTo(&plaintext); err != nil {
			t.Fatalf("StreamTo: %v", err)
		}
		if !bytes.Equal(plaintext.Bytes(), []byte(expectedContent)) {
			t.Fatalf("plaintext = %q; want frozen %q", plaintext.Bytes(), expectedContent)
		}
		plainSum := sha256.Sum256(plaintext.Bytes())
		if got := hex.EncodeToString(plainSum[:]); got != deniableSourcePlaintextSHA256 {
			t.Fatalf("plaintext SHA-256 = %s; want %s", got, deniableSourcePlaintextSHA256)
		}
		currentInfo, err := fixture.prepared.file.Stat()
		if err != nil {
			t.Fatalf("stat retained descriptor after stream: %v", err)
		}
		if !os.SameFile(originalInfo, currentInfo) {
			t.Fatal("DeniableSource changed the routed descriptor identity")
		}

		if err := source.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if err := source.Close(); err != nil {
			t.Fatalf("second Close: %v", err)
		}
		if fixture.prepared.file != nil {
			t.Fatal("Close did not release the transferred prepared descriptor")
		}
		if swapped {
			assertExactDeniableSourceTree(t, fixture.dir, map[string][]byte{
				filepath.Base(retainedPath): fixture.wrapper,
				filepath.Base(fixture.path): replacement,
			})
		} else {
			assertExactDeniableSourceTree(t, fixture.dir, map[string][]byte{
				filepath.Base(fixture.path): fixture.wrapper,
			})
		}
	})

	t.Run("wrong outer password mints no source", func(t *testing.T) {
		fixture := prepareFrozenDeniableSourceFixture(t)
		fixture.request.Password = []byte("wrong outer password")
		source, err := PrepareDeniableSource(t.Context(), fixture.request, fixture.prepared)
		if err == nil || source != nil {
			t.Fatalf("wrong-password prepare = (%v, %v); want nil source and error", source, err)
		}
		assertExactDeniableSourceTree(t, fixture.dir, map[string][]byte{
			filepath.Base(fixture.path): fixture.wrapper,
		})
	})
}

func TestDeniableSourceRecreatesOuterRekeyState(t *testing.T) {
	previousThreshold := crypto.RekeyThreshold
	crypto.RekeyThreshold = util.MiB
	defer func() { crypto.RekeyThreshold = previousThreshold }()

	plaintext := make([]byte, 2*util.MiB+173)
	for index := range plaintext {
		plaintext[index] = byte(index*31 + 7)
	}
	if int64(len(plaintext)) <= crypto.RekeyThreshold {
		t.Fatal("rekey test payload does not cross the configured threshold")
	}

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "plaintext.bin")
	volumePath := filepath.Join(dir, "rekey.pcv")
	if err := os.WriteFile(inputPath, plaintext, 0o600); err != nil {
		t.Fatalf("write rekey plaintext: %v", err)
	}
	codecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}
	password := []byte("deniable-source-rekey")
	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: volumePath,
		Password:   password,
		RSCodecs:   codecs,
	}); err != nil {
		t.Fatalf("create inner volume: %v", err)
	}
	if err := AddDeniability(volumePath, password, nil); err != nil {
		t.Fatalf("create deniability wrapper: %v", err)
	}

	prepared, err := PrepareDecryptInput(volumePath, false)
	if err != nil {
		t.Fatalf("PrepareDecryptInput: %v", err)
	}
	source, err := PrepareDeniableSource(context.Background(), &DecryptRequest{
		InputFile:   volumePath,
		Password:    password,
		Deniability: true,
		RSCodecs:    codecs,
	}, prepared)
	if err != nil {
		_ = prepared.Close()
		t.Fatalf("PrepareDeniableSource: %v", err)
	}
	defer func() { _ = source.Close() }()

	for pass := 1; pass <= 2; pass++ {
		var output bytes.Buffer
		if err := source.StreamTo(&output); err != nil {
			t.Fatalf("StreamTo pass %d across outer rekey: %v", pass, err)
		}
		if !bytes.Equal(output.Bytes(), plaintext) {
			t.Fatalf("outer-rekey pass %d plaintext mismatch", pass)
		}
	}
}

func TestDeniableSourceRejectsBetweenPassMutation(t *testing.T) {
	restoreKDF := useProductionTestKDF()
	defer restoreKDF()

	fixture := prepareFrozenDeniableSourceFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	source, err := PrepareDeniableSource(ctx, fixture.request, fixture.prepared)
	if err != nil {
		t.Fatalf("PrepareDeniableSource: %v", err)
	}
	defer func() { _ = source.Close() }()
	originalInfo, err := os.Stat(fixture.path)
	if err != nil {
		t.Fatalf("stat frozen wrapper: %v", err)
	}

	mutated := append([]byte(nil), fixture.wrapper...)
	mutated[len(mutated)-1] ^= 0x80
	rewriteDeniableSourceFixture(t, fixture.path, mutated)
	var payloadMutation bytes.Buffer
	err = source.StreamTo(&payloadMutation)
	if !errors.Is(err, perrors.ErrAuthFailed) && !errors.Is(err, perrors.ErrCorruptData) {
		t.Fatalf("StreamTo after same-inode payload mutation = %v; want final legacy MAC failure", err)
	}
	if payloadMutation.Len() != len(expectedContent) {
		t.Fatalf("payload-mutation stream wrote %d bytes; want the %d-byte active pass before its final MAC refusal", payloadMutation.Len(), len(expectedContent))
	}
	assertDeniableSourceIdentity(t, fixture.path, originalInfo)

	rewriteDeniableSourceFixture(t, fixture.path, fixture.wrapper)
	mutated = append([]byte(nil), fixture.wrapper...)
	mutated[0] ^= 0x01
	rewriteDeniableSourceFixture(t, fixture.path, mutated)
	var saltMutation bytes.Buffer
	if err := source.StreamTo(&saltMutation); err == nil {
		t.Fatal("StreamTo after outer salt mutation succeeded")
	}
	if saltMutation.Len() != 0 {
		t.Fatalf("salt-mutation output = %d bytes; want zero before the inner pass", saltMutation.Len())
	}

	rewriteDeniableSourceFixture(t, fixture.path, fixture.wrapper)
	mutated = append([]byte(nil), fixture.wrapper...)
	mutated[16] ^= 0x01
	rewriteDeniableSourceFixture(t, fixture.path, mutated)
	var nonceMutation bytes.Buffer
	if err := source.StreamTo(&nonceMutation); err == nil {
		t.Fatal("StreamTo after outer nonce mutation succeeded")
	}
	if nonceMutation.Len() != 0 {
		t.Fatalf("nonce-mutation output = %d bytes; want zero before the inner pass", nonceMutation.Len())
	}

	rewriteDeniableSourceFixture(t, fixture.path, fixture.wrapper)
	if err := os.Truncate(fixture.path, int64(len(fixture.wrapper)-1)); err != nil {
		t.Fatalf("truncate routed wrapper: %v", err)
	}
	var truncated bytes.Buffer
	if err := source.StreamTo(&truncated); err == nil {
		t.Fatal("StreamTo after wrapper truncation succeeded")
	}
	if truncated.Len() != 0 {
		t.Fatalf("truncated-wrapper output = %d bytes; want zero", truncated.Len())
	}

	rewriteDeniableSourceFixture(t, fixture.path, fixture.wrapper)
	cancel()
	var cancelled bytes.Buffer
	if err := source.StreamTo(&cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("StreamTo after cancellation = %v; want context.Canceled", err)
	}
	if cancelled.Len() != 0 {
		t.Fatalf("cancelled output = %d bytes; want zero", cancelled.Len())
	}
	assertDeniableSourceIdentity(t, fixture.path, originalInfo)
	assertExactDeniableSourceTree(t, fixture.dir, map[string][]byte{
		filepath.Base(fixture.path): fixture.wrapper,
	})
}

func TestDeniableSourceLeavesNoRecognizableStage(t *testing.T) {
	restoreKDF := useProductionTestKDF()
	defer restoreKDF()

	fixture := prepareFrozenDeniableSourceFixture(t)
	wantTree := map[string][]byte{filepath.Base(fixture.path): fixture.wrapper}
	productionOuterKDF := deriveDeniabilityKey
	productionVolumeKDF := deriveVolumeKey
	deriveDeniabilityKey = func(password, salt []byte) []byte {
		assertExactDeniableSourceTree(t, fixture.dir, wantTree)
		return productionOuterKDF(password, salt)
	}
	deriveVolumeKey = func(password, salt []byte, paranoid bool) ([]byte, error) {
		assertExactDeniableSourceTree(t, fixture.dir, wantTree)
		return productionVolumeKDF(password, salt, paranoid)
	}
	defer func() {
		deriveDeniabilityKey = productionOuterKDF
		deriveVolumeKey = productionVolumeKDF
	}()

	source, err := PrepareDeniableSource(t.Context(), fixture.request, fixture.prepared)
	if err != nil {
		t.Fatalf("PrepareDeniableSource: %v", err)
	}
	assertExactDeniableSourceTree(t, fixture.dir, wantTree)
	if err := source.StreamTo(io.Discard); err != nil {
		_ = source.Close()
		t.Fatalf("StreamTo: %v", err)
	}
	assertExactDeniableSourceTree(t, fixture.dir, wantTree)
	if err := source.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	assertExactDeniableSourceTree(t, fixture.dir, wantTree)
}

func rewriteDeniableSourceFixture(t *testing.T, path string, contents []byte) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0) // #nosec G304 -- test-owned path
	if err != nil {
		t.Fatalf("open wrapper for same-inode rewrite: %v", err)
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		t.Fatalf("rewrite wrapper: %v", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatalf("sync wrapper rewrite: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close wrapper rewrite: %v", err)
	}
}

func assertDeniableSourceIdentity(t *testing.T, path string, want os.FileInfo) {
	t.Helper()
	got, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat routed wrapper after mutation: %v", err)
	}
	if !os.SameFile(want, got) {
		t.Fatal("test mutation replaced the routed wrapper instead of changing the same inode")
	}
}

func assertExactDeniableSourceTree(t *testing.T, dir string, want map[string][]byte) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read deniable source directory: %v", err)
	}
	if len(entries) != len(want) {
		t.Fatalf("deniable source directory entries = %v; want exactly %v", entryNames(entries), sortedStringKeys(want))
	}
	for _, entry := range entries {
		expected, ok := want[entry.Name()]
		if !ok {
			t.Fatalf("unexpected deniable source artifact %q (mode %s)", entry.Name(), entry.Type())
		}
		info, err := entry.Info()
		if err != nil {
			t.Fatalf("inspect deniable source artifact %q: %v", entry.Name(), err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("artifact %q mode = %s; want one original private regular file", entry.Name(), info.Mode())
		}
		got, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("read deniable source artifact %q: %v", entry.Name(), err)
		}
		if !bytes.Equal(got, expected) {
			t.Fatalf("artifact %q bytes changed", entry.Name())
		}
	}
}

func entryNames(entries []os.DirEntry) []string {
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	return names
}

func sortedStringKeys(values map[string][]byte) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
