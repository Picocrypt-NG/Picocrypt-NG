package volume

import (
	"Picocrypt-NG/internal/encoding"
	perrors "Picocrypt-NG/internal/errors"
	"Picocrypt-NG/internal/fileops"
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestPreparedEncryptInputDecryptsTemporaryArchiveAndClosesOwnedStage(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "plain.txt")
	payload := []byte("original payload before temporary archive encryption")
	if err := os.WriteFile(source, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	input, err := PrepareEncryptInput(context.Background(), EncryptInputRequest{InputFile: source, OutputFile: filepath.Join(dir, "output.pcv"), Compress: true})
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	stagePath := input.Path()
	diskBytes, err := os.ReadFile(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	logical, err := io.ReadAll(input.Reader())
	if err != nil {
		t.Fatal(err)
	}
	if input.Length() != uint64(len(logical)) || len(diskBytes) <= len(logical) {
		t.Fatal("physical tags entered logical payload length")
	}
	if bytes.Equal(diskBytes, logical) {
		t.Fatal("temporary archive was not encrypted")
	}
	archive, err := zip.NewReader(bytes.NewReader(logical), int64(len(logical)))
	if err != nil {
		t.Fatalf("prepared reader exposed encrypted temp bytes: %v", err)
	}
	if len(archive.File) != 1 || archive.File[0].Name != "plain.txt" {
		t.Fatalf("unexpected archive: %v", archive.File)
	}
	entry, err := archive.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(entry)
	_ = entry.Close()
	if err != nil || !bytes.Equal(content, payload) {
		t.Fatalf("archive plaintext changed: %v", err)
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stagePath); !os.IsNotExist(err) {
		t.Fatalf("temporary archive retained: %v", err)
	}
	if got, err := os.ReadFile(source); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("source changed: %v", err)
	}
}

type cancelPreparedInputReporter struct {
	cancel     context.CancelFunc
	progressed bool
}

func (*cancelPreparedInputReporter) SetStatus(string) {}
func (r *cancelPreparedInputReporter) SetProgress(fraction float32, _ string) {
	if fraction > 0 {
		r.progressed = true
		r.cancel()
	}
}
func (*cancelPreparedInputReporter) SetCanCancel(bool) {}
func (*cancelPreparedInputReporter) Update()           {}
func (*cancelPreparedInputReporter) IsCancelled() bool { return false }

func TestPreparedEncryptInputCancellationRemovesOnlyOwnedTemporaryArchive(t *testing.T) {
	dir := t.TempDir()
	files := []string{filepath.Join(dir, "a"), filepath.Join(dir, "b")}
	payload := bytes.Repeat([]byte("plaintext"), 1<<17)
	for _, file := range files {
		if err := os.WriteFile(file, payload, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reporter := &cancelPreparedInputReporter{cancel: cancel}
	prepared, err := PrepareEncryptInput(ctx, EncryptInputRequest{InputFiles: files, OnlyFiles: files, OutputFile: filepath.Join(dir, "output.pcv"), Reporter: reporter})
	if prepared != nil {
		defer prepared.Close()
	}
	if !reporter.progressed || err == nil || prepared != nil {
		t.Fatalf("cancel during actual ZIP copy = progressed:%v input:%v err:%v", reporter.progressed, prepared, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(files) {
		t.Fatalf("cancel left preparation artifacts: %v", entries)
	}
	for _, file := range files {
		got, err := os.ReadFile(file)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("cancel altered source: %v", err)
		}
	}
}

// Private record tags must not change legacy's logical length or its RS padded
// flag at the last 128-byte window of a MiB. This hits the real preparation and
// header-value generation path without substituting a size-only source.
func TestAuthenticatedTempZIPTagsDoNotChangeLegacyRSPadding(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "input")
	empty := filepath.Join(dir, "empty")
	for _, p := range []string{source, empty} {
		if e := os.WriteFile(p, nil, 0o600); e != nil {
			t.Fatal(e)
		}
	}
	req := &EncryptRequest{InputFiles: []string{source, empty}, OnlyFiles: []string{source, empty}, OutputFile: filepath.Join(dir, "out.pcv"), ReedSolomon: true}
	// Measure the fixture archive overhead only to arrange the independent
	// literal length boundary; the production padding expectation is fixed.
	initial, e := PrepareEncryptInput(context.Background(), EncryptInputRequest{InputFiles: req.InputFiles, OnlyFiles: req.OnlyFiles, OutputFile: req.OutputFile})
	if e != nil {
		t.Fatal(e)
	}
	overhead := initial.Length()
	initial.Close()
	const want = (1 << 20) - 64
	if overhead >= want {
		t.Fatal("unexpected fixture overhead")
	}
	payload := bytes.Repeat([]byte{0x5a}, want-int(overhead))
	if e = os.WriteFile(source, payload, 0o600); e != nil {
		t.Fatal(e)
	}
	ctx := NewEncryptContext(context.Background(), req)
	defer ctx.Close()
	if e = encryptPreprocess(ctx, req); e != nil {
		t.Fatal(e)
	}
	if ctx.tempZip.Length() != want {
		t.Fatalf("ZIP fixture length=%d", ctx.tempZip.Length())
	}
	if e = encryptGenerateValues(ctx, req); e != nil {
		t.Fatal(e)
	}
	if ctx.Total != want || !ctx.Padded || !ctx.Header.Flags.Padded {
		t.Fatalf("private tags changed public RS geometry: total=%d padded=%v", ctx.Total, ctx.Padded)
	}
}

// Ciphertext identity and logical plaintext are different inputs to the public
// serializer. Compressing the physical descriptor would encrypt ciphertext twice.
func TestPreparedEncryptedStdinUsesLogicalPlaintext(t *testing.T) {
	for _, compress := range []bool{false, true} {
		t.Run(strconv.FormatBool(compress), func(t *testing.T) {
			dir := t.TempDir()
			spool, err := fileops.CreateEncryptedSpool(context.Background(), fileops.EncryptedSpoolOptions{NearPath: filepath.Join(dir, "stdin"), MaxPhysicalBytes: 1 << 20})
			if err != nil {
				t.Fatal(err)
			}
			defer spool.Close()
			plain := bytes.Repeat([]byte("secret original stdin"), 4000)
			if _, err := spool.Write(plain); err != nil {
				t.Fatal(err)
			}
			if err := spool.Seal(); err != nil {
				t.Fatal(err)
			}
			sourcePath, sourceFile := spool.Path(), spool.File()
			sourceInfo, err := sourceFile.Stat()
			if err != nil {
				t.Fatal(err)
			}
			input, err := PrepareEncryptInput(context.Background(), EncryptInputRequest{InputFile: spool.Path(), OnlyFiles: []string{spool.Path()}, OutputFile: filepath.Join(dir, "out.pcv"), BorrowedSpool: spool, PCV3: true, Compress: compress})
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			preparedPath := input.Path()
			got, err := io.ReadAll(input.Reader())
			if err != nil {
				t.Fatal(err)
			}
			if compress {
				archive, err := zip.NewReader(bytes.NewReader(got), int64(len(got)))
				if err != nil {
					t.Fatal(err)
				}
				if len(archive.File) != 1 || archive.File[0].UncompressedSize64 != uint64(len(plain)) {
					t.Fatalf("wrong logical metadata: %v", archive.File)
				}
				if archive.File[0].Name != "stdin" {
					t.Errorf("stdin archive member = %q; want visible logical name stdin", archive.File[0].Name)
				}
				entry, err := archive.File[0].Open()
				if err != nil {
					t.Fatal(err)
				}
				got, err = io.ReadAll(entry)
				_ = entry.Close()
				if err != nil {
					t.Fatal(err)
				}
			} else if input.File() != spool.File() || input.Length() != uint64(len(plain)) {
				t.Fatal("physical identity lost or physical tags used as logical length")
			}
			if !bytes.Equal(got, plain) {
				t.Fatalf("physical ciphertext used as plaintext: got %d want %d", len(got), len(plain))
			}
			if err := input.Close(); err != nil {
				t.Fatal(err)
			}
			if spool.Path() != sourcePath || spool.File() != sourceFile {
				t.Fatal("preparation changed or closed the borrowed ciphertext owner")
			}
			selectedInfo, err := os.Stat(sourcePath)
			if err != nil || !os.SameFile(sourceInfo, selectedInfo) {
				t.Fatalf("preparation changed the borrowed ciphertext identity: %v", err)
			}
			if compress {
				if _, err := os.Stat(preparedPath); !os.IsNotExist(err) {
					t.Fatalf("prepared archive stage was retained: %v", err)
				}
			}
			reader, err := spool.OpenReader()
			if err != nil {
				t.Fatalf("borrowed spool session not released: %v", err)
			}
			got, err = io.ReadAll(reader)
			closeErr := reader.Close()
			if err != nil || closeErr != nil || !bytes.Equal(got, plain) {
				t.Fatalf("preparation altered borrowed stdin: read=%v close=%v", err, closeErr)
			}
			if err := spool.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(sourcePath); !os.IsNotExist(err) {
				t.Fatalf("borrowed source owner cleanup retained its stage: %v", err)
			}
		})
	}
}

func TestPreparedEncryptedStdinRejectsReplacedPhysicalIdentityBeforeZIP(t *testing.T) {
	dir := t.TempDir()
	spool, err := fileops.CreateEncryptedSpool(context.Background(), fileops.EncryptedSpoolOptions{NearPath: filepath.Join(dir, "stdin"), MaxPhysicalBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	if _, err := spool.Write([]byte("original pipe payload")); err != nil {
		t.Fatal(err)
	}
	if err := spool.Seal(); err != nil {
		t.Fatal(err)
	}
	path := spool.Path()
	if err := os.Rename(path, path+".moved"); err != nil {
		t.Fatal(err)
	}
	foreign := []byte("unrelated replacement must survive")
	if err := os.WriteFile(path, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareEncryptInput(context.Background(), EncryptInputRequest{InputFile: path, OutputFile: filepath.Join(dir, "out.pcv"), BorrowedSpool: spool, PCV3: true, Compress: true})
	if prepared != nil {
		_ = prepared.Close()
	}
	if err == nil {
		t.Fatal("compressed stdin accepted a replacement ciphertext pathname")
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, foreign) {
		t.Fatalf("foreign path changed: %v", err)
	}
}

func TestPublicEncryptRejectsLegacyBorrowedSpoolBeforeKDFAndPreservesCaller(t *testing.T) {
	for _, entrypoint := range []string{"Encrypt", "PrepareEncryptInput"} {
		t.Run(entrypoint, func(t *testing.T) {
			dir := t.TempDir()
			spool, err := fileops.CreateEncryptedSpool(context.Background(), fileops.EncryptedSpoolOptions{NearPath: filepath.Join(dir, "stdin"), MaxPhysicalBytes: 1 << 20})
			if err != nil {
				t.Fatal(err)
			}
			defer spool.Close()
			plain := []byte("borrowed logical plaintext must never enter the legacy descriptor path")
			if _, err := spool.Write(plain); err != nil {
				t.Fatal(err)
			}
			if err := spool.Seal(); err != nil {
				t.Fatal(err)
			}
			path := spool.Path()
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(dir, "legacy.pcv")
			kdfCalls := 0
			previous := deriveVolumeKey
			deriveVolumeKey = func([]byte, []byte, bool) ([]byte, error) {
				kdfCalls++
				return nil, errors.New("legacy borrowed spool must be refused before KDF")
			}
			defer func() { deriveVolumeKey = previous }()
			if entrypoint == "Encrypt" {
				codecs, codecErr := encoding.NewRSCodecs()
				if codecErr != nil {
					t.Fatal(codecErr)
				}
				err = Encrypt(context.Background(), &EncryptRequest{InputFile: path, OutputFile: output, Password: []byte("test-only-password"), BorrowedSpool: spool, RSCodecs: codecs})
			} else {
				var prepared *PreparedEncryptInput
				prepared, err = PrepareEncryptInput(context.Background(), EncryptInputRequest{InputFile: path, OutputFile: output, BorrowedSpool: spool})
				if prepared != nil {
					_ = prepared.Close()
					t.Error("legacy preparation transferred a plaintext reader")
				}
			}
			var validation *perrors.ValidationError
			if !errors.As(err, &validation) || validation.Field != "BorrowedSpool" || kdfCalls != 0 {
				t.Errorf("legacy spool was not refused before KDF: err=%v calls=%d", err, kdfCalls)
			}
			entries, listErr := os.ReadDir(dir)
			if listErr != nil || len(entries) != 1 || filepath.Join(dir, entries[0].Name()) != path {
				t.Errorf("legacy refusal created output or staging: %v %v", entries, listErr)
			}
			after, readErr := os.ReadFile(path)
			if readErr != nil || !bytes.Equal(before, after) {
				t.Errorf("caller ciphertext changed: %v", readErr)
			}
			reader, openErr := spool.OpenReader()
			if openErr != nil {
				t.Fatalf("caller spool was closed or its session retained: %v", openErr)
			}
			got, readErr := io.ReadAll(reader)
			_ = reader.Close()
			if readErr != nil || !bytes.Equal(got, plain) {
				t.Fatalf("caller logical plaintext changed: %v", readErr)
			}
		})
	}
}
