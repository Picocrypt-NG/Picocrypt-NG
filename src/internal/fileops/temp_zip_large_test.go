package fileops

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// sequentialTempReaderAt adapts the bounded pipe used only in this actual-byte
// lane. Production uses the retained regular-file descriptor's ReadAt.
type sequentialTempReaderAt struct {
	r      io.Reader
	offset int64
}

func (r *sequentialTempReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off != r.offset {
		return 0, errTempStream
	}
	n, e := io.ReadFull(r.r, p)
	r.offset += int64(n)
	return n, e
}

// This processes real bytes through every record and digest, without storing a
// 257 GiB file. It proves stream correctness, not physical filesystem throughput.
func TestTempStreamActualBytesBeyond256GiB(t *testing.T) {
	if os.Getenv("PICOCRYPT_RUN_TEMP_STREAM_LARGE") != "1" {
		t.Skip("opt-in actual-byte 257 GiB stream lane")
	}
	const total = uint64(257)<<30 | 37
	start := time.Now()
	pr, pw := io.Pipe()
	defer pr.Close()
	a, e := chacha20poly1305.New(tempStreamKey())
	if e != nil {
		t.Fatal(e)
	}
	type result struct {
		digest []byte
		err    error
	}
	done := make(chan result, 1)
	go func() {
		w := newTempStreamWriter(pw, a, math.MaxInt64, nil)
		defer w.close()
		buf := tempStreamPlain(tempStreamBlock)
		h := sha256.New()
		remaining := total
		var e error
		for remaining > 0 {
			// Give every record a distinct public offset so repeated payloads
			// cannot hide lost or reordered records in the digest comparison.
			binary.BigEndian.PutUint64(buf[:8], total-remaining)
			n := int(min(remaining, uint64(len(buf))))
			if _, e = w.Write(buf[:n]); e != nil {
				break
			}
			h.Write(buf[:n])
			remaining -= uint64(n)
		}
		if e == nil {
			e = w.finish()
		}
		pw.CloseWithError(e)
		done <- result{h.Sum(nil), e}
	}()
	r := newTempStreamReader(&sequentialTempReaderAt{r: pr}, a, total, nil)
	defer r.close()
	h := sha256.New()
	n, e := io.CopyBuffer(h, r, make([]byte, 1<<20))
	if e != nil {
		pr.CloseWithError(e)
	}
	want := <-done
	if e != nil || want.err != nil || uint64(n) != total || !bytes.Equal(h.Sum(nil), want.digest) {
		t.Fatalf("actual-byte roundtrip: bytes=%d read=%v write=%v", n, e, want.err)
	}
	extent, _ := tempStreamExtent(total)
	t.Logf("actual plaintext bytes=%d encrypted bytes=%d sha256=%s duration=%s MiB/s=%.2f", total, extent, hex.EncodeToString(h.Sum(nil)), time.Since(start), float64(total)/(1<<20)/time.Since(start).Seconds())
}
