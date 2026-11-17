package volume

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type closeLegacyMetadataReporter struct {
	GoldenTestReporter
	closeSource func()
}

func (r *closeLegacyMetadataReporter) SetStatus(status string) {
	r.GoldenTestReporter.SetStatus(status)
	if status == "Comparing values..." {
		r.closeSource()
	}
}

func TestOwningDecryptWithholdsMetadataUntilPreparedInputCloseSucceeds(t *testing.T) {
	dir := t.TempDir()
	source, encrypted := filepath.Join(dir, "source"), filepath.Join(dir, "source.pcv")
	if err := os.WriteFile(source, []byte("owned close boundary"), 0o600); err != nil {
		t.Fatal(err)
	}
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatal(err)
	}
	if err := Encrypt(context.Background(), &EncryptRequest{InputFile: source, OutputFile: encrypted, Password: []byte("test"), Comments: "authenticated comment", RSCodecs: rs}); err != nil {
		t.Fatal(err)
	}
	var retained *os.File
	previous := newPayloadReader
	newPayloadReader = func(reader io.Reader) io.Reader { retained, _ = reader.(*os.File); return reader }
	t.Cleanup(func() { newPayloadReader = previous })
	closed := false
	reporter := &closeLegacyMetadataReporter{closeSource: func() {
		if retained == nil {
			t.Fatal("production reader did not expose the prepared descriptor")
		}
		if !closed {
			if err := retained.Close(); err != nil {
				t.Fatal(err)
			}
			closed = true
		}
	}}
	metadata := header.LegacyMetadata{Version: "stale", CommentAuthenticity: header.CommentAuthenticated}
	err = Decrypt(context.Background(), &DecryptRequest{InputFile: encrypted, OutputFile: filepath.Join(dir, "output"), Password: []byte("test"), RSCodecs: rs, Reporter: reporter, LegacyMetadata: &metadata})
	if !closed || !errors.Is(err, os.ErrClosed) {
		t.Fatalf("late owned-source failure not exercised: closed=%v err=%v", closed, err)
	}
	if metadata != (header.LegacyMetadata{}) {
		t.Fatalf("failed owning operation released authentication metadata: %+v", metadata)
	}
}
