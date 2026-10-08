package fileops

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"math"
	"runtime"
)

// The private spool uses the age v1.1 STREAM payload framing: 64 KiB records,
// an 88-bit big-endian counter and a final-record flag. A key is used for one
// object and never restarted. This does not change public volume formats.
const (
	tempStreamBlock = 64 << 10
	tempStreamTag   = 16
)

var (
	errTempStream       = errors.New("fileops: invalid authenticated temporary stream")
	errTempStreamClosed = errors.New("fileops: temporary stream closed")
	errTempStreamBudget = errors.New("fileops: temporary stream exceeds admitted disk extent")
)

// Wipe owned scratch without allocating a second same-sized zero slice per
// record. The noinline boundary and KeepAlive support a best-effort overwrite;
// generated code is compiler/platform dependent, and this does not guarantee
// erasure of Go/runtime copies or the AEAD implementation's private state.
//
//go:noinline
func wipeTempStreamBuffer(buf []byte) {
	clear(buf)
	runtime.KeepAlive(buf)
}

func tempStreamExtent(plain uint64) (uint64, error) {
	records := plain / tempStreamBlock
	if plain%tempStreamBlock != 0 || records == 0 {
		records++
	}
	if plain > math.MaxInt64 || records > (math.MaxInt64-plain)/tempStreamTag {
		return 0, errTempStreamBudget
	}
	return plain + records*tempStreamTag, nil
}

// The signed file-extent bound permits fewer than 2^47 records, so the
// upper three bytes of the published 88-bit counter are always zero.
func tempStreamNonce(record uint64, final bool) [12]byte {
	var n [12]byte
	for i := 10; i >= 3; i-- {
		n[i] = byte(record)
		record >>= 8
	}
	if final {
		n[11] = 1
	}
	return n
}

type tempStreamWriter struct {
	dst                         io.Writer
	a                           cipher.AEAD
	buf                         [tempStreamBlock + tempStreamTag]byte
	nonce                       [12]byte
	pending                     int
	length, record, maxPhysical uint64
	err                         error
	finished                    bool
	cancel                      CancelFunc
}

func newTempStreamWriter(dst io.Writer, a cipher.AEAD, maxPhysical uint64, cancel CancelFunc) *tempStreamWriter {
	return &tempStreamWriter{dst: dst, a: a, maxPhysical: maxPhysical, cancel: cancel}
}

func (w *tempStreamWriter) fail(err error) error {
	if w.err == nil {
		w.err = err
	}
	wipeTempStreamBuffer(w.buf[:])
	return w.err
}

func (w *tempStreamWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.finished {
		return 0, errTempStreamClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	if uint64(len(p)) > math.MaxUint64-w.length {
		return 0, w.fail(errTempStreamBudget)
	}
	extent, e := tempStreamExtent(w.length + uint64(len(p)))
	if e != nil || extent > w.maxPhysical {
		return 0, w.fail(errTempStreamBudget)
	}
	consumed := 0
	for len(p) > 0 {
		if w.cancel != nil && w.cancel() {
			return consumed, w.fail(errZIPCancelled)
		}
		if w.pending == tempStreamBlock {
			if e := w.flush(false); e != nil {
				return consumed, e
			}
		}
		n := copy(w.buf[w.pending:tempStreamBlock], p)
		w.pending += n
		w.length += uint64(n)
		consumed += n
		p = p[n:]
	}
	return consumed, nil
}

func (w *tempStreamWriter) flush(final bool) error {
	if w.cancel != nil && w.cancel() {
		return w.fail(errZIPCancelled)
	}
	w.nonce = tempStreamNonce(w.record, final)
	sealed := w.a.Seal(w.buf[:0], w.nonce[:], w.buf[:w.pending], nil)
	n, e := w.dst.Write(sealed)
	if n < 0 || n > len(sealed) {
		return w.fail(fmt.Errorf("%w: invalid write count", errTempStream))
	}
	if e != nil {
		return w.fail(e)
	}
	if n != len(sealed) {
		return w.fail(io.ErrShortWrite)
	}
	w.record++
	w.pending = 0
	wipeTempStreamBuffer(w.buf[:])
	return nil
}

func (w *tempStreamWriter) finish() error {
	if w.err != nil {
		return w.err
	}
	if w.finished {
		return errTempStreamClosed
	}
	extent, e := tempStreamExtent(w.length)
	if e != nil || extent > w.maxPhysical {
		return w.fail(errTempStreamBudget)
	}
	if e = w.flush(true); e != nil {
		return e
	}
	w.finished = true
	return nil
}

func (w *tempStreamWriter) close() {
	_ = w.fail(errTempStreamClosed)
	w.a = nil
	w.dst = nil
	w.cancel = nil
}

type tempStreamReader struct {
	src               io.ReaderAt
	a                 cipher.AEAD
	buf               [tempStreamBlock + tempStreamTag]byte
	nonce             [12]byte
	remaining, record uint64
	offset            int64
	unread            []byte
	err               error
	final             bool
	cancel            CancelFunc
	checkExtent       func() error
}

func newTempStreamReader(src io.ReaderAt, a cipher.AEAD, length uint64, cancel CancelFunc) *tempStreamReader {
	return &tempStreamReader{src: src, a: a, remaining: length, cancel: cancel}
}

func (r *tempStreamReader) fail(e error) error {
	// Never expose EOF-like corruption: legacy payload loops accept partial EOF.
	if errors.Is(e, io.EOF) || errors.Is(e, io.ErrUnexpectedEOF) {
		e = fmt.Errorf("%w: truncated record", errTempStream)
	}
	if r.err == nil {
		r.err = e
	}
	wipeTempStreamBuffer(r.buf[:])
	r.unread = nil
	return r.err
}

func (r *tempStreamReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if r.cancel != nil && r.cancel() {
		return 0, r.fail(errZIPCancelled)
	}
	if len(r.unread) == 0 {
		if r.final {
			if r.checkExtent != nil {
				if e := r.checkExtent(); e != nil {
					return 0, r.fail(e)
				}
			}
			var probe [1]byte
			n, e := r.src.ReadAt(probe[:], r.offset)
			if n != 0 || e != io.EOF { //nolint:errorlint // Only bare EOF is completion; joined/wrapped I/O faults stay terminal.
				if e == nil || e == io.EOF { //nolint:errorlint // Only bare EOF is completion; joined/wrapped I/O faults stay terminal.
					e = errTempStream
				}
				return 0, r.fail(e)
			}
			return 0, io.EOF
		}
		size := int(min(r.remaining, uint64(tempStreamBlock)))
		final := r.remaining <= tempStreamBlock
		in := r.buf[:size+tempStreamTag]
		n, e := r.src.ReadAt(in, r.offset)
		if n < 0 || n > len(in) {
			return 0, r.fail(fmt.Errorf("%w: invalid read count", errTempStream))
		}
		if n != len(in) {
			if e == nil {
				e = errTempStream
			}
			return 0, r.fail(e)
		}
		if e != nil && (!final || e != io.EOF) { //nolint:errorlint // Only bare EOF completes a full final record; joined storage faults stay terminal.
			return 0, r.fail(e)
		}

		if final {
			if r.checkExtent != nil {
				if e := r.checkExtent(); e != nil {
					return 0, r.fail(e)
				}
			}
			var probe [1]byte
			n, e = r.src.ReadAt(probe[:], r.offset+int64(len(in)))
			if n != 0 || e != io.EOF { //nolint:errorlint // Only bare EOF is completion; joined/wrapped I/O faults stay terminal.
				if e == nil || e == io.EOF { //nolint:errorlint // Only bare EOF is completion; joined/wrapped I/O faults stay terminal.
					e = fmt.Errorf("%w: trailing bytes", errTempStream)
				}
				return 0, r.fail(e)
			}
		}
		r.nonce = tempStreamNonce(r.record, final)
		plain, e := r.a.Open(r.buf[:0], r.nonce[:], in, nil)
		if e != nil {
			return 0, r.fail(fmt.Errorf("%w: authentication", errTempStream))
		}
		r.unread = plain
		r.remaining -= uint64(size)
		r.record++
		r.offset += int64(len(in))
		r.final = final
		if len(r.unread) == 0 {
			return 0, io.EOF
		}
	}
	n := copy(p, r.unread)
	wipeTempStreamBuffer(r.unread[:n])
	r.unread = r.unread[n:]
	return n, nil
}

func (r *tempStreamReader) close() {
	_ = r.fail(errTempStreamClosed)
	r.a = nil
	r.src = nil
	r.cancel = nil
	r.checkExtent = nil
}
