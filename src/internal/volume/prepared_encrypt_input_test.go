package volume

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
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
