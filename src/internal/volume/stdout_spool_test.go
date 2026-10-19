package volume

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	perrors "Picocrypt-NG/internal/errors"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/header"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The fixture bypasses only the expensive password KDF. Payload processing,
// MAC policy, retained descriptors and encrypted temporary storage are real.
func legacyStdoutFixture(t *testing.T, plaintext []byte) (*OperationContext, *DecryptRequest, **fileops.EncryptedSpool) {
	t.Helper()
	dir := t.TempDir()
	var output *fileops.EncryptedSpool
	req := &DecryptRequest{
		InputFile: filepath.Join(dir, "input.pcv"), OutputFile: filepath.Join(dir, "stdout"),
		EncryptedOutput: &output,
	}
	ctx := NewDecryptContext(t.Context(), req)
	ctx.Header = header.NewVolumeHeader(bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 16), bytes.Repeat([]byte{4}, 24))
	legacyStdoutResetKeys(t, ctx)
	macKey, err := ctx.SubkeyReader.MACSubkey()
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.SecureZero(macKey)
	serpentKey, err := ctx.SubkeyReader.SerpentKey()
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.SecureZero(serpentKey)
	mac, err := crypto.NewMAC(macKey, false)
	if err != nil {
		t.Fatal(err)
	}
	suite, err := crypto.NewCipherSuite(append([]byte(nil), ctx.Key.Bytes()...), ctx.Header.Nonce, serpentKey, ctx.Header.SerpentIV, mac, ctx.SubkeyReader.Reader(), false)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, len(plaintext))
	suite.Encrypt(ciphertext, plaintext)
	ctx.Header.AuthTag = suite.Sum()
	suite.Close()
	if err := os.WriteFile(req.InputFile, append(make([]byte, header.HeaderSize(0)), ciphertext...), 0o600); err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(req.InputFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := ctx.pinLegacyDecryptInput(input, true); err != nil {
		_ = input.Close()
		t.Fatal(err)
	}
	info, err := input.Stat()
	if err != nil {
		t.Fatal(err)
	}
	ctx.protectedInputInfos = []os.FileInfo{info}
	ctx.Total = int64(len(ciphertext))
	legacyStdoutResetKeys(t, ctx)
	t.Cleanup(func() {
		if err := ctx.Close(); err != nil {
			t.Error(err)
		}
		if err := output.Close(); err != nil {
			t.Error(err)
		}
	})
	return ctx, req, &output
}

func legacyStdoutResetKeys(t *testing.T, ctx *OperationContext) {
	t.Helper()
	ctx.setKey(bytes.Repeat([]byte{5}, 32))
	ctx.SubkeyReader = crypto.NewSubkeyReader(crypto.NewHKDFStream(ctx.Key.Bytes(), ctx.Header.HKDFSalt))
	headerKey, err := ctx.SubkeyReader.HeaderSubkey()
	if err != nil {
		t.Fatal(err)
	}
	crypto.SecureZero(headerKey)
}

func TestLegacyStdoutEncryptsFirstPlaintextAndTransfersOnlyAfterCleanup(t *testing.T) {
	for _, size := range []int{0, 180000} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			marker := []byte("stdout plaintext must never reach a temporary file\n")
			plaintext := bytes.Repeat(marker, (size+len(marker)-1)/len(marker))[:size]
			ctx, req, output := legacyStdoutFixture(t, plaintext)
			if err := decryptPayload(ctx, req); err != nil {
				t.Fatal(err)
			}
			if *output != nil || ctx.stagedOutput != nil {
				t.Fatal("payload processing published output or created a plaintext stage")
			}
			if _, err := os.Stat(req.OutputFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("stdout target was written: %v", err)
			}
			spool := ctx.encryptedOutput
			if spool == nil {
				t.Fatal("plaintext was not sent directly to an encrypted owner")
			}
			if _, err := spool.OpenReader(); err == nil {
				t.Fatal("unfinished output became readable before MAC acceptance")
			}
			if err := decryptFinalize(ctx, req); err != nil {
				t.Fatal(err)
			}
			if *output != nil {
				t.Fatal("finalize transferred output before final operation cleanup")
			}
			path := spool.Path()
			disk, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(plaintext) > 0 && bytes.Contains(disk, plaintext[:min(64, len(plaintext))]) {
				t.Fatal("plaintext reached disk")
			}
			if err := finishLegacyDecrypt(ctx, req, nil); err != nil {
				t.Fatal(err)
			}
			if *output != spool {
				t.Fatal("successful cleanup did not transfer the sealed owner")
			}
			reader, err := spool.OpenReader()
			if err != nil {
				t.Fatal(err)
			}
			got, readErr := io.ReadAll(reader)
			if err := errors.Join(readErr, reader.Close()); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatal("authenticated output differs from original payload")
			}
			if err := spool.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("caller close left encrypted staging: %v", err)
			}
		})
	}
}

func TestLegacyStdoutMACPolicyWithholdsRejectedOutputAndPreservesForceKept(t *testing.T) {
	for _, force := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary", true: "force"}[force], func(t *testing.T) {
			ctx, req, output := legacyStdoutFixture(t, []byte("MAC policy protects stdout"))
			req.ForceDecrypt = force
			var kept bool
			req.Kept = &kept
			ctx.Header.AuthTag[0] ^= 0xff
			if err := decryptPayload(ctx, req); err != nil {
				t.Fatal(err)
			}
			path := ctx.encryptedOutput.Path()
			err := decryptFinalize(ctx, req)
			if !force && !errors.Is(err, perrors.ErrCorruptData) {
				t.Fatalf("ordinary MAC rejection = %v", err)
			}
			if force && (err != nil || !kept) {
				t.Fatalf("Force MAC bypass lost kept status: kept=%v, err=%v", kept, err)
			}
			err = finishLegacyDecrypt(ctx, req, err)
			if force {
				if err != nil || *output == nil {
					t.Fatalf("Force output unavailable after cleanup: %v", err)
				}
			} else {
				if *output != nil {
					t.Fatal("failed MAC transferred stdout authority")
				}
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("failed MAC left encrypted output: %v", err)
				}
			}
		})
	}
}

func TestLegacyStdoutNewAttemptRevokesOldOwnerAndUsesFreshEncryption(t *testing.T) {
	ctx, req, output := legacyStdoutFixture(t, bytes.Repeat([]byte{0x7b}, 140000))
	if err := decryptPayload(ctx, req); err != nil {
		t.Fatal(err)
	}
	old := ctx.encryptedOutput
	oldPath := old.Path()
	oldFile := old.File()
	before := make([]byte, 65536+16)
	if _, err := oldFile.ReadAt(before, 0); err != nil {
		t.Fatal(err)
	}
	legacyStdoutResetKeys(t, ctx)
	if err := decryptPayloadWithFastDecode(ctx, req, false); err != nil {
		t.Fatal(err)
	}
	if *output != nil || old == ctx.encryptedOutput || oldPath == ctx.encryptedOutput.Path() {
		t.Fatal("new attempt reused the old output authority")
	}
	if _, err := old.Write([]byte("must be revoked")); err == nil {
		t.Fatal("new attempt retained a writable old key/nonce session")
	}
	if _, err := oldFile.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("old attempt descriptor is live: %v", err)
	}
	if _, err := os.Stat(oldPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old attempt stage survived: %v", err)
	}
	after := make([]byte, len(before))
	if _, err := ctx.encryptedOutput.File().ReadAt(after, 0); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("identical payload re-encrypted under the previous key/nonce session")
	}
}

func TestLegacyStdoutRejectsArchiveExtractionWithoutCreatingOutput(t *testing.T) {
	volumePath, codecs := legacyStdoutWrittenVolume(t, nil, false)
	var output *fileops.EncryptedSpool
	req := &DecryptRequest{
		InputFile: volumePath, OutputFile: filepath.Join(filepath.Dir(volumePath), "stdout"),
		Password: []byte("stdout-test"), RSCodecs: codecs, AutoUnzip: true, EncryptedOutput: &output,
	}
	if err := Decrypt(t.Context(), req); err == nil {
		t.Fatal("stdout archive extraction was accepted")
	}
	if output != nil {
		_ = output.Close()
		t.Fatal("invalid stdout/archive combination created output")
	}
}

type legacyStdoutReporter struct {
	GoldenTestReporter
	afterWrite func()
}

func (reporter *legacyStdoutReporter) SetStatus(status string) {
	reporter.GoldenTestReporter.SetStatus(status)
	if strings.HasPrefix(status, "Decrypting at ") && reporter.afterWrite != nil {
		reporter.afterWrite()
	}
}

func legacyStdoutWrittenVolume(t *testing.T, plaintext []byte, rs bool) (string, *encoding.RSCodecs) {
	t.Helper()
	codecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	input, volumePath := filepath.Join(dir, "plaintext"), filepath.Join(dir, "input.pcv")
	if err := os.WriteFile(input, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Encrypt(t.Context(), &EncryptRequest{
		InputFile: input, OutputFile: volumePath, Password: []byte("stdout-test"), RSCodecs: codecs, ReedSolomon: rs,
	}); err != nil {
		t.Fatal(err)
	}
	return volumePath, codecs
}

func TestLegacyStdoutPanicRevokesPrivateOutput(t *testing.T) {
	volumePath, codecs := legacyStdoutWrittenVolume(t, bytes.Repeat([]byte{0x6d}, 140000), false)
	var output *fileops.EncryptedSpool
	defer func() { _ = output.Close() }()
	var paths []string
	reporter := &legacyStdoutReporter{afterWrite: func() {
		var err error
		paths, err = filepath.Glob(filepath.Join(filepath.Dir(volumePath), ".picocrypt-*"))
		if err != nil {
			t.Fatal(err)
		}
		panic("reporter interruption")
	}}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("reporter panic did not propagate")
			}
		}()
		_ = Decrypt(t.Context(), &DecryptRequest{
			InputFile: volumePath, OutputFile: filepath.Join(filepath.Dir(volumePath), "stdout"),
			Password: []byte("stdout-test"), RSCodecs: codecs, Reporter: reporter, EncryptedOutput: &output,
		})
	}()
	if len(paths) != 1 {
		t.Fatalf("panic did not interrupt an active output: %v", paths)
	}
	if output != nil {
		t.Fatal("panicking operation transferred its unfinished stdout owner")
	}
	if _, err := os.Stat(paths[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("panic left output staging: %v", err)
	}
}

type legacyStdoutDeniabilityPanicReporter struct {
	GoldenTestReporter
	panicValue any
}

func (reporter *legacyStdoutDeniabilityPanicReporter) SetStatus(status string) {
	if strings.HasPrefix(status, "Removing deniability at ") {
		panic(reporter.panicValue)
	}
	reporter.GoldenTestReporter.SetStatus(status)
}

func TestLegacyStdoutPreprocessPanicClosesUnpinnedRecombinedDeniabilityInput(t *testing.T) {
	volumePath, codecs := legacyStdoutWrittenVolume(t, []byte("recombined deniable input must keep descriptor custody before pinning"), false)
	if err := AddDeniability(volumePath, []byte("stdout-test"), nil); err != nil {
		t.Fatal(err)
	}
	chunks, err := fileops.Split(fileops.SplitOptions{InputPath: volumePath, ChunkSize: 2, Unit: fileops.SplitUnitTotal})
	if err != nil {
		t.Fatal(err)
	}
	chunkBytes := make([][]byte, len(chunks))
	for i, chunk := range chunks {
		chunkBytes[i], err = os.ReadFile(chunk)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(volumePath); err != nil {
		t.Fatal(err)
	}
	var localInput *os.File
	originalReader := newDeniabilityReader
	newDeniabilityReader = func(reader io.Reader) io.Reader {
		var ok bool
		localInput, ok = reader.(*os.File)
		if !ok {
			t.Fatal("deniability did not receive the retained filesystem descriptor")
		}
		return reader
	}
	defer func() {
		newDeniabilityReader = originalReader
		if localInput != nil {
			_ = localInput.Close()
		}
	}()
	var output *fileops.EncryptedSpool
	defer func() { _ = output.Close() }()
	wantPanic := &struct{ message string }{message: "pre-pin reporter interruption"}
	var gotPanic any
	func() {
		defer func() { gotPanic = recover() }()
		_ = Decrypt(t.Context(), &DecryptRequest{
			InputFile: chunks[0], OutputFile: filepath.Join(filepath.Dir(volumePath), "stdout"),
			Password: []byte("stdout-test"), Recombine: true, Deniability: true,
			RSCodecs: codecs, EncryptedOutput: &output,
			Reporter: &legacyStdoutDeniabilityPanicReporter{panicValue: wantPanic},
		})
	}()
	if gotPanic != wantPanic {
		t.Fatalf("preprocess panic identity changed despite successful cleanup: %v", gotPanic)
	}
	if localInput == nil {
		t.Fatal("panic did not interrupt the real deniability input before pinning")
	}
	if _, err := localInput.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("pre-pin recombined descriptor leaked after panic: %v", err)
	}
	if output != nil {
		t.Fatal("preprocess panic transferred stdout output")
	}
	if _, err := os.Stat(volumePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preprocess panic left recombined temporary input: %v", err)
	}
	for i, chunk := range chunks {
		got, err := os.ReadFile(chunk)
		if err != nil || !bytes.Equal(got, chunkBytes[i]) {
			t.Fatalf("preprocess panic changed source chunk %d: %v", i, err)
		}
	}
	assertNoPicocryptStages(t, filepath.Dir(volumePath))
}

func TestLegacyStdoutCompleteDecryptAndCorrectableRSRetry(t *testing.T) {
	plaintext := bytes.Repeat([]byte("legacy payload survived authenticated stdout staging\n"), 4000)
	for _, tc := range []struct {
		name        string
		reedSolomon bool
		verifyFirst bool
	}{
		{name: "ordinary"},
		{name: "verify-first", verifyFirst: true},
		{name: "full-RS-retry", reedSolomon: true},
		{name: "verify-first-RS-repair", reedSolomon: true, verifyFirst: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			volumePath, codecs := legacyStdoutWrittenVolume(t, plaintext, tc.reedSolomon)
			if tc.reedSolomon {
				corruptOneRSBlock(t, volumePath, 0, 4)
			}
			var output *fileops.EncryptedSpool
			defer func() { _ = output.Close() }()
			reporter := &repairingReporter{}
			req := &DecryptRequest{
				InputFile: volumePath, OutputFile: filepath.Join(filepath.Dir(volumePath), "stdout"),
				Password: []byte("stdout-test"), RSCodecs: codecs, Reporter: reporter,
				VerifyFirst: tc.verifyFirst, EncryptedOutput: &output,
			}
			if err := Decrypt(t.Context(), req); err != nil {
				t.Fatal(err)
			}
			if tc.reedSolomon && !reporter.sawRepairing {
				t.Fatal("correctable corruption did not enter the RS repair path")
			}
			if output == nil {
				t.Fatal("successful decrypt did not transfer output")
			}
			reader, err := output.OpenReader()
			if err != nil {
				t.Fatal(err)
			}
			got, readErr := io.ReadAll(reader)
			if err := errors.Join(readErr, reader.Close()); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatal("complete decrypt or retry changed the recovered payload")
			}
			if _, err := os.Stat(req.OutputFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("stdout decrypt published a plaintext file: %v", err)
			}
		})
	}
}

func TestLegacyStdoutCancellationRevokesOutput(t *testing.T) {
	volumePath, codecs := legacyStdoutWrittenVolume(t, bytes.Repeat([]byte{0x6d}, 140000), false)
	operationCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var output *fileops.EncryptedSpool
	defer func() { _ = output.Close() }()
	var paths []string
	reporter := &legacyStdoutReporter{afterWrite: func() {
		var err error
		paths, err = filepath.Glob(filepath.Join(filepath.Dir(volumePath), ".picocrypt-*"))
		if err != nil {
			t.Fatal(err)
		}
		cancel()
	}}
	err := Decrypt(operationCtx, &DecryptRequest{
		InputFile: volumePath, OutputFile: filepath.Join(filepath.Dir(volumePath), "stdout"),
		Password: []byte("stdout-test"), RSCodecs: codecs, Reporter: reporter, EncryptedOutput: &output,
	})
	if !errors.Is(err, context.Canceled) || len(paths) != 1 {
		t.Fatalf("cancellation did not interrupt a live output: paths=%v, err=%v", paths, err)
	}
	if output != nil {
		t.Fatal("cancelled operation transferred output authority")
	}
	if _, err := os.Stat(paths[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancellation left output staging: %v", err)
	}
}

func TestLegacyStdoutCleanupUncertaintyWithholdsSealedOwnerAndPreservesReplacement(t *testing.T) {
	ctx, req, output := legacyStdoutFixture(t, []byte("private output"))
	if err := decryptPayload(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := decryptFinalize(ctx, req); err != nil {
		t.Fatal(err)
	}
	spoolPath := ctx.encryptedOutput.Path()
	stage, err := fileops.CreateSiblingTemp(filepath.Join(filepath.Dir(req.OutputFile), "other-temp"))
	if err != nil {
		t.Fatal(err)
	}
	ctx.ownedTemps = append(ctx.ownedTemps, stage)
	foreignPath := stage.Path()
	if err := os.Rename(foreignPath, foreignPath+".moved"); err != nil {
		t.Fatal(err)
	}
	foreign := []byte("foreign replacement must survive")
	if err := os.WriteFile(foreignPath, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := finishLegacyDecrypt(ctx, req, nil); err == nil {
		t.Fatal("uncertain input cleanup reported successful output")
	}
	if *output != nil {
		t.Fatal("cleanup uncertainty transferred stdout authority")
	}
	if _, err := os.Stat(spoolPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("withheld output was not closed: %v", err)
	}
	got, err := os.ReadFile(foreignPath)
	if err != nil || !bytes.Equal(got, foreign) {
		t.Fatalf("cleanup damaged foreign replacement: %q %v", got, err)
	}
}

type legacyStdoutReadFunc func([]byte) (int, error)

func (read legacyStdoutReadFunc) Read(p []byte) (int, error) { return read(p) }

func TestLegacyStdoutWriteAndSealFailuresNeverTransferOrFallback(t *testing.T) {
	for _, fault := range []string{"write", "seal"} {
		t.Run(fault, func(t *testing.T) {
			ctx, req, output := legacyStdoutFixture(t, bytes.Repeat([]byte{0x71}, 140000))
			if fault == "write" {
				original := newPayloadReader
				defer func() { newPayloadReader = original }()
				closed := false
				newPayloadReader = func(reader io.Reader) io.Reader {
					return legacyStdoutReadFunc(func(p []byte) (int, error) {
						if !closed {
							closed = true
							if err := ctx.encryptedOutput.File().Close(); err != nil {
								t.Fatal(err)
							}
						}
						return reader.Read(p)
					})
				}
			}
			err := decryptPayload(ctx, req)
			if fault == "seal" {
				if err != nil {
					t.Fatal(err)
				}
				if err := ctx.encryptedOutput.File().Close(); err != nil {
					t.Fatal(err)
				}
				err = decryptFinalize(ctx, req)
			}
			if !errors.Is(err, os.ErrClosed) {
				t.Fatalf("%s did not surface the real descriptor failure: %v", fault, err)
			}
			path := ctx.encryptedOutput.Path()
			_ = finishLegacyDecrypt(ctx, req, err)
			if *output != nil || ctx.stagedOutput != nil {
				t.Fatal("failed encrypted backend transferred output or created a plaintext fallback")
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed encrypted stage survived: %v", err)
			}
		})
	}
}

func TestLegacyStdoutAdmissionKeepsPhysicalTagsInsideExistingReservePolicy(t *testing.T) {
	for _, tc := range []struct {
		available int64
		want      uint64
		wantErr   bool
	}{
		{available: 10 << 20, wantErr: true},
		{available: (10 << 20) + 24, want: 16},
		{available: (10 << 20) + 150, want: 100},
	} {
		budget, err := encryptedDecryptOutputBudget(tc.available)
		if (err != nil) != tc.wantErr || budget != tc.want {
			t.Fatalf("available=%d: budget=%d, err=%v", tc.available, budget, err)
		}
	}
	budget, err := encryptedDecryptOutputBudget((10 << 20) + 150)
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{84, 85} {
		owner, err := fileops.CreateEncryptedSpool(t.Context(), fileops.EncryptedSpoolOptions{
			NearPath: filepath.Join(t.TempDir(), "stdout"), MaxPhysicalBytes: budget,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := owner.Write(make([]byte, size))
		err = errors.Join(writeErr, owner.Seal())
		if (err != nil) != (size == 85) {
			t.Fatalf("payload %d plus one 16-byte tag: %v", size, err)
		}
		if err := owner.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
