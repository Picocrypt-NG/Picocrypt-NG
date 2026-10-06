package fileops

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

type tempEOFReaderAt struct {
	data []byte
	err  error
}

func (r tempEOFReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	return copy(p, r.data[off:]), r.err
}

// EOF with a complete final record is legal; all other errors remain terminal
// even when they accompany a full count, so source probes cannot swallow faults.
func TestEncryptedReaderDecryptsDataDeliveredWithEOF(t *testing.T) {
	fixture, e := os.ReadFile("testdata/temp_zip_stream/1.bin")
	if e != nil {
		t.Fatal(e)
	}
	a, _ := chacha20poly1305.New(tempStreamKey())
	r := newTempStreamReader(tempEOFReaderAt{fixture, io.EOF}, a, 1, nil)
	got, e := io.ReadAll(r)
	if e != nil || !bytes.Equal(got, []byte{0}) {
		t.Fatalf("complete data with EOF: %x %v", got, e)
	}
}

func TestTempStreamFullReadWithErrorRemainsSticky(t *testing.T) {
	fixture, e := os.ReadFile("testdata/temp_zip_stream/1.bin")
	if e != nil {
		t.Fatal(e)
	}
	a, _ := chacha20poly1305.New(tempStreamKey())
	fault := errors.New("source fault")
	r := newTempStreamReader(tempEOFReaderAt{fixture, fault}, a, 1, nil)
	got, e := io.ReadAll(r)
	if len(got) != 0 || e != fault { //nolint:errorlint // Exact error identity proves the original storage fault survives.
		t.Fatalf("released faulted plaintext: %x %v", got, e)
	}
	if _, e = r.Read(make([]byte, 1)); e != fault { //nolint:errorlint // The original error must remain sticky, not merely wrapped.
		t.Fatal("fault lost")
	}
}
