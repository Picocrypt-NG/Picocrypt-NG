package fileops

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func tempStreamKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func tempStreamPlain(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i % 251)
	}
	return p
}

func TestTempStreamIndependentAgeFixtures(t *testing.T) {
	for _, n := range []int{0, 1, 65535, 65536, 65537, 196608} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			fixture, e := os.ReadFile(fmt.Sprintf("testdata/temp_zip_stream/%d.bin", n))
			if e != nil {
				t.Fatal(e)
			}
			a, _ := chacha20poly1305.New(tempStreamKey())
			var out bytes.Buffer
			w := newTempStreamWriter(&out, a, math.MaxInt64, nil)
			plain := tempStreamPlain(n)
			for off := 0; off < n; {
				end := min(n, off+997)
				if _, e = w.Write(plain[off:end]); e != nil {
					t.Fatal(e)
				}
				off = end
			}
			if e = w.finish(); e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(out.Bytes(), fixture) {
				t.Fatal("ciphertext differs from pinned age fixture")
			}
			r := newTempStreamReader(bytes.NewReader(fixture), a, uint64(n), nil)
			got, e := io.ReadAll(r)
			if e != nil || !bytes.Equal(got, plain) {
				t.Fatalf("decode mismatch: %v", e)
			}
		})
	}
}

func TestTempStreamRejectsCorruptionWithoutFailedRecordPlaintext(t *testing.T) {
	original, e := os.ReadFile("testdata/temp_zip_stream/196608.bin")
	if e != nil {
		t.Fatal(e)
	}
	cases := map[string][]byte{}
	for _, at := range []int{0, 65536, 65552, 131088, len(original) - 1} {
		p := bytes.Clone(original)
		p[at] ^= 1
		cases[fmt.Sprintf("mutation-%d", at)] = p
	}
	for _, n := range []int{0, 16, 65551, 65552, 131104, len(original) - 1} {
		cases[fmt.Sprintf("truncate-%d", n)] = bytes.Clone(original[:n])
	}
	cases["trailing"] = append(bytes.Clone(original), 1)
	swapped := bytes.Clone(original)
	copy(swapped[:65552], original[65552:131104])
	copy(swapped[65552:131104], original[:65552])
	cases["reorder"] = swapped
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			a, _ := chacha20poly1305.New(tempStreamKey())
			r := newTempStreamReader(bytes.NewReader(data), a, 196608, nil)
			got, e := io.ReadAll(r)
			if e == nil || errors.Is(e, io.EOF) || errors.Is(e, io.ErrUnexpectedEOF) {
				t.Fatalf("integrity failure became completion: %v", e)
			}
			if len(got) > 131072 {
				t.Fatalf("released invalid final plaintext: %d", len(got))
			}
			_, again := r.Read(make([]byte, 1))
			if again != e { //nolint:errorlint // Exact identity verifies that the original failure remains latched.
				t.Fatalf("failure not sticky: %v / %v", e, again)
			}
		})
	}
}

type tempStreamFaultWriter struct {
	n     int
	err   error
	calls int
}

func (w *tempStreamFaultWriter) Write(p []byte) (int, error) { w.calls++; return w.n, w.err }
func TestTempStreamWriteFailureIsTerminal(t *testing.T) {
	for _, count := range []int{-1, 0, 10, 65553} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			dst := &tempStreamFaultWriter{n: count}
			a, _ := chacha20poly1305.New(tempStreamKey())
			w := newTempStreamWriter(dst, a, math.MaxInt64, nil)
			_, e := w.Write(make([]byte, 65537))
			if e == nil {
				t.Fatal("invalid/short write accepted")
			}
			calls := dst.calls
			if _, again := w.Write([]byte{1}); again != e { //nolint:errorlint // Exact identity verifies that the original failure remains latched.
				t.Fatal("failure not sticky")
			}
			if again := w.finish(); again != e { //nolint:errorlint // Exact identity verifies that the original failure remains latched.
				t.Fatal("finish lost failure")
			}
			if dst.calls != calls {
				t.Fatal("retried failed nonce")
			}
		})
	}
}

func TestTempStreamExtentAndAdmission(t *testing.T) {
	for _, tc := range []struct{ p, e uint64 }{{0, 16}, {1, 17}, {65535, 65551}, {65536, 65552}, {65537, 65569}, {196608, 196656}} {
		e, err := tempStreamExtent(tc.p)
		if err != nil || e != tc.e {
			t.Fatalf("%d: %d %v", tc.p, e, err)
		}
	}
	if _, e := tempStreamExtent(math.MaxInt64); e == nil {
		t.Fatal("overflow admitted")
	}
	a, _ := chacha20poly1305.New(tempStreamKey())
	var b bytes.Buffer
	w := newTempStreamWriter(&b, a, 16, nil)
	if _, e := w.Write([]byte{1}); e == nil {
		t.Fatal("disk budget bypass")
	}
	if b.Len() != 0 {
		t.Fatal("wrote before admission")
	}
}

func TestTempStreamFinalizationAndCloseWipePendingPlaintext(t *testing.T) {
	a, _ := chacha20poly1305.New(tempStreamKey())
	var out bytes.Buffer
	w := newTempStreamWriter(&out, a, math.MaxInt64, nil)
	if _, e := w.Write([]byte("secret")); e != nil {
		t.Fatal(e)
	}
	alias := w.buf[:]
	w.close()
	if !bytes.Equal(alias, make([]byte, len(alias))) {
		t.Fatal("pending plaintext retained")
	}
	if e := w.finish(); e == nil || out.Len() != 0 {
		t.Fatal("aborted writer finalized")
	}
	a, _ = chacha20poly1305.New(tempStreamKey())
	r := newTempStreamReader(bytes.NewReader(nil), a, 0, nil)
	if _, e := r.Read(make([]byte, 1)); e == nil || errors.Is(e, io.EOF) {
		t.Fatal("missing final record accepted")
	}
}

func TestTempStreamRejectsWrongTrustedLengthAndDuplicatedRecords(t *testing.T) {
	fixture, e := os.ReadFile("testdata/temp_zip_stream/65537.bin")
	if e != nil {
		t.Fatal(e)
	}
	for _, length := range []uint64{0, 1, 65536, 65538} {
		a, _ := chacha20poly1305.New(tempStreamKey())
		r := newTempStreamReader(bytes.NewReader(fixture), a, length, nil)
		_, e := io.ReadAll(r)
		if e == nil || errors.Is(e, io.EOF) {
			t.Fatalf("length %d accepted", length)
		}
	}
	duplicate := append(bytes.Clone(fixture[:65552]), fixture...)
	a, _ := chacha20poly1305.New(tempStreamKey())
	r := newTempStreamReader(bytes.NewReader(duplicate), a, 65537, nil)
	_, e = io.ReadAll(r)
	if e == nil || errors.Is(e, io.EOF) {
		t.Fatal("duplicate record accepted")
	}
}

func TestTempStreamTrailingMutationBeforeEOFRemainsFailure(t *testing.T) {
	a, _ := chacha20poly1305.New(tempStreamKey())
	fixture, e := os.ReadFile("testdata/temp_zip_stream/1.bin")
	if e != nil {
		t.Fatal(e)
	}
	src := bytes.NewReader(fixture)
	r := newTempStreamReader(src, a, 1, nil)
	if n, e := r.Read(make([]byte, 1)); n != 1 || e != nil {
		t.Fatal(n, e)
	}
	src.Reset(append(fixture, 1))
	if _, e = r.Read(make([]byte, 1)); e == nil || errors.Is(e, io.EOF) {
		t.Fatal("trailing data became final EOF")
	}
}

func FuzzTempStreamNeverReleasesUnauthenticatedFixture(f *testing.F) {
	fixture, e := os.ReadFile("testdata/temp_zip_stream/65537.bin")
	if e != nil {
		f.Fatal(e)
	}
	f.Add(fixture)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 200000 {
			return
		}
		a, _ := chacha20poly1305.New(tempStreamKey())
		r := newTempStreamReader(bytes.NewReader(data), a, 65537, nil)
		got, e := io.ReadAll(r)
		if e == nil && !bytes.Equal(data, fixture) {
			t.Fatal("accepted changed fixture")
		}
		if len(got) > 0 && !bytes.Equal(got, tempStreamPlain(65537)[:len(got)]) {
			t.Fatal("released unauthenticated bytes")
		}
	})
}

type tempBadCountReaderAt struct{ n int }

func (r tempBadCountReaderAt) ReadAt(p []byte, _ int64) (int, error) { return r.n, nil }
func TestTempStreamInvalidAndNonprogressReadCountsFailClosed(t *testing.T) {
	for _, count := range []int{-1, 0, 1, 18} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			a, _ := chacha20poly1305.New(tempStreamKey())
			r := newTempStreamReader(tempBadCountReaderAt{count}, a, 1, nil)
			out := []byte{0xa5}
			n, e := r.Read(out)
			if n != 0 || e == nil || out[0] != 0xa5 {
				t.Fatalf("invalid count released plaintext: %d %v", n, e)
			}
			if _, again := r.Read(out); again != e { //nolint:errorlint // Exact identity verifies that the original failure remains latched.
				t.Fatal("read count failure not sticky")
			}
		})
	}
}

func TestTempStreamCancellationDuringReadWipesUnreadPlaintext(t *testing.T) {
	fixture, e := os.ReadFile("testdata/temp_zip_stream/65537.bin")
	if e != nil {
		t.Fatal(e)
	}
	cancelled := false
	a, _ := chacha20poly1305.New(tempStreamKey())
	r := newTempStreamReader(bytes.NewReader(fixture), a, 65537, func() bool { return cancelled })
	if n, e := r.Read(make([]byte, 1)); n != 1 || e != nil {
		t.Fatal(n, e)
	}
	alias := r.buf[:]
	cancelled = true
	if n, e := r.Read(make([]byte, 1)); n != 0 || e == nil || errors.Is(e, io.EOF) {
		t.Fatalf("cancel released unread plaintext: %d %v", n, e)
	}
	if !bytes.Equal(alias, make([]byte, len(alias))) {
		t.Fatal("cancel kept plaintext")
	}
}

func TestTempStreamFullCountWriteWithErrorNeverFinalizes(t *testing.T) {
	fault := errors.New("storage I/O failure after accepting bytes")
	dst := &tempStreamFaultWriter{n: 65552, err: fault}
	a, _ := chacha20poly1305.New(tempStreamKey())
	w := newTempStreamWriter(dst, a, math.MaxInt64, nil)
	if _, e := w.Write(make([]byte, 65537)); e != fault { //nolint:errorlint // Exact identity verifies that the original failure remains latched.
		t.Fatalf("full-count error swallowed: %v", e)
	}
	if e := w.finish(); e != fault || dst.calls != 1 { //nolint:errorlint // Exact identity verifies that the original failure remains latched.
		t.Fatal("failed write retried or finalized")
	}
	if !bytes.Equal(w.buf[:], make([]byte, len(w.buf))) {
		t.Fatal("failed write retained plaintext")
	}
}

// A fixed scratch buffer must not be shadowed by per-record wipe or nonce
// allocations. The oracle is allocation growth with record count, not an exact
// compiler-dependent allocation count.
func TestTempStreamWorkingAllocationsDoNotScaleWithRecordCount(t *testing.T) {
	a, _ := chacha20poly1305.New(tempStreamKey())
	plain := tempStreamPlain(65536)
	measure := func(records int) float64 {
		return testing.AllocsPerRun(3, func() {
			w := newTempStreamWriter(io.Discard, a, math.MaxInt64, nil)
			for range records {
				if _, e := w.Write(plain); e != nil {
					t.Fatal(e)
				}
			}
			if e := w.finish(); e != nil {
				t.Fatal(e)
			}
			w.close()
		})
	}
	small, large := measure(1), measure(64)
	if large > small+1 {
		t.Fatalf("record count grew allocations: one=%.0f sixty-four=%.0f", small, large)
	}
}

// Small fuzz parameters keep execution focused on real multi-record corruption
// instead of spending the lane mutating/minimizing a 64 KiB seed representation.
func FuzzTempStreamCorruptedRecordBoundaries(f *testing.F) {
	fixture, e := os.ReadFile("testdata/temp_zip_stream/65537.bin")
	if e != nil {
		f.Fatal(e)
	}
	for mode := range uint8(4) {
		f.Add(uint64(0), byte(1), mode)
	}
	f.Fuzz(func(t *testing.T, index uint64, mask byte, mode uint8) {
		data := bytes.Clone(fixture)
		switch mode % 4 {
		case 0:
			data[index%uint64(len(data))] ^= mask | 1
		case 1:
			data = data[:index%uint64(len(data))]
		case 2:
			data = append(data, mask)
		case 3:
			data = append(bytes.Clone(fixture[:65552]), data...)
		}
		a, _ := chacha20poly1305.New(tempStreamKey())
		r := newTempStreamReader(bytes.NewReader(data), a, 65537, nil)
		got, e := io.ReadAll(r)
		if e == nil || errors.Is(e, io.EOF) || errors.Is(e, io.ErrUnexpectedEOF) {
			t.Fatal("corruption accepted as completion")
		}
		if len(got) > 65536 || !bytes.Equal(got, tempStreamPlain(len(got))) {
			t.Fatal("released failed-record plaintext")
		}
	})
}
