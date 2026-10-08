package pcv3

import (
	pcencoding "Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3artifact"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"runtime"
	"testing"
	"time"
)

// This is a codec/stream lane with literal TEST ONLY keys, not a KDF or disk
// throughput test. Each pass runs the production serializer; recovery consumes
// actual ciphertext through a bounded pipe, authenticates it, and reauthenticates
// before streaming plaintext into the production artifact encoder. Losing,
// duplicating or reordering any record changes the independent plaintext hash.
func TestRecoveryActualBytesBeyond64GiB(t *testing.T) {
	if os.Getenv("PICOCRYPT_RUN_RECOVERY_LARGE") != "1" {
		t.Skip("opt-in: processes 65 GiB + 37 bytes through the real recovery codec")
	}
	testRecoveryStreamingArtifact(t, (65<<30)+37)
}

func TestRecoveryStreamingArtifact(t *testing.T) {
	length := uint64((8 << 20) + 37)
	if os.Getenv("PICOCRYPT_RUN_RECOVERY_CALIBRATION") == "1" {
		length = (1 << 30) + 37
	}
	testRecoveryStreamingArtifact(t, length)
}

func testRecoveryStreamingArtifact(t *testing.T, length uint64) {
	t.Helper()
	ctx := context.Background()
	started := time.Now()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fixture := loadNormalFixtureManifest(t).FixturesByID()["normal-standard-combined-ordered-two-mib"]
	request, material, entropy := decodeNormalWriterFixtureInputs(t, fixture, readNormalFixtureArtifact(t, fixture.Volume))
	defer material.keys.close()
	request.plaintextLength, request.comment = length, nil
	codecs, err := pcencoding.NewRSCodecs()
	if err != nil {
		t.Fatal(err)
	}
	// Literal schema-1 dimensions, independent of production geometry helpers:
	// 1112-byte front; 48-byte descriptor and 64-byte tag per data record;
	// truncate immediately before the final record, removing the suffix too.
	count := (length + (1<<20 - 1)) >> 20
	sourceSize := int64(1112 + length + 112*count) //nolint:gosec // Test lengths are at most 65 GiB + 37.
	capture := &recoveryWindowCapture{windows: []recoveryByteWindow{
		{offset: 0, data: make([]byte, 1112)},
		{offset: sourceSize - 1008, data: make([]byte, 1008)},
	}}
	generate := func(destination io.Writer) recoveryStreamResult {
		plain := newRecoveryPattern(length)
		defer clear(plain.block)
		plainHash, ciphertextHash := sha256.New(), sha256.New()
		completion, writeErr := serializeNormalVolume(ctx, request,
			io.TeeReader(plain, plainHash), io.MultiWriter(destination, ciphertextHash), material,
			normalWriteSeams{entropy: bytes.NewReader(entropy), codecs: codecs})
		if writeErr == nil && completion == nil {
			writeErr = errors.New("serializer returned no completion")
		}
		return recoveryStreamResult{plain: plainHash.Sum(nil), cipher: ciphertextHash.Sum(nil), err: writeErr}
	}
	baseline := generate(capture)
	if baseline.err != nil || capture.written != sourceSize+1120 {
		t.Fatalf("source serialization: bytes=%d expected=%d error=%v", capture.written, sourceSize+1120, baseline.err)
	}
	t.Logf("generated plaintext_bytes=%d records=%d elapsed=%s plaintext_sha256=%x ciphertext_sha256=%x", length, count, time.Since(started), baseline.plain, baseline.cipher)
	structure, err := InspectRecovery(capture, sourceSize)
	if err != nil || structure.CandidateCount() != 1 {
		t.Fatalf("real large truncated volume admission: candidates=%d error=%v", structure.CandidateCount(), err)
	}
	candidate, _ := structure.CandidateAt(0)
	geometry, _ := structure.GeometryAt(0)
	if candidate.PlaintextLength() != length || candidate.RecordCount() != count {
		t.Fatal("inspection changed the writer's real plaintext geometry")
	}
	provider := newNormalFixtureCredentialProvider(t, fixture.Keys)
	provider.access.adopted = true
	defer provider.close()
	recoveryRequest, err := newRecoveryRequest(RecoveryModeForce)
	if err != nil {
		t.Fatal(err)
	}
	analysisSource := newRecoveryReplay(t, sourceSize, generate)
	analysis, err := analyzeRecoveryRecords(ctx, analysisSource, sourceSize, candidate, geometry, provider, recoveryRequest, candidate.Role())
	if err != nil {
		t.Fatal(err)
	}
	analysisSource.finish(t, baseline)
	summary := analysis.ranges.Summary()
	if summary.Verified != count || summary.Unverified != 0 || summary.Missing != 0 || summary.RecoveredBytes != length ||
		analysis.final != RecoveryFinalMissing || analysis.damageStage != StageFinalRecord {
		t.Fatalf("lost authenticated evidence: summary=%+v final=%v stage=%v", summary, analysis.final, analysis.damageStage)
	}
	t.Logf("analyzed authenticated_bytes=%d map_bytes=%d elapsed=%s", summary.RecoveredBytes, recoveryRequest.budget.Used(), time.Since(started))
	plan, err := pcv3artifact.Prepare(pcv3artifact.Descriptor{
		State: pcv3artifact.StatePartial, Final: pcv3artifact.FinalMissing,
		PlaintextLength: length, Ranges: analysis.ranges,
	})
	if err != nil {
		t.Fatal(err)
	}
	metadataLength := 80 + 40*count
	artifact := &recoveryArtifactDigest{metadata: make([]byte, int(metadataLength)), payload: sha256.New()}
	emissionSource := newRecoveryReplay(t, sourceSize, generate)
	emitted := uint64(0)
	err = pcv3artifact.Encode(ctx, artifact, plan, func(yield func(uint64, io.Reader) error) error {
		return emitRecoveryRecords(ctx, emissionSource, candidate, geometry, provider, recoveryRequest, candidate.Role(), analysis,
			func(r RecoveryRange, plaintext []byte) error {
				if r.RecordIndex() != emitted || r.Start() != emitted<<20 || r.End() != min((emitted+1)<<20, length) || r.State() != RecoveryRangeVerified {
					return fmt.Errorf("noncanonical authenticated segment at %d", emitted)
				}
				emitted++
				return yield(r.RecordIndex(), bytes.NewReader(plaintext))
			})
	})
	if err != nil {
		t.Fatal(err)
	}
	emissionSource.finish(t, baseline)
	if emitted != count || artifact.written != metadataLength+length || !bytes.Equal(artifact.payload.Sum(nil), baseline.plain) {
		t.Fatalf("artifact lost plaintext: segments=%d bytes=%d payload_sha256=%x want=%x", emitted, artifact.written, artifact.payload.Sum(nil), baseline.plain)
	}
	// The actual emitted header/table are retained; only payload bytes are hashed.
	// Parse validates all emitted offsets, including those beyond 64 GiB. This
	// does not claim a disk readback of the discarded plaintext payload.
	parsed, err := pcv3artifact.Parse(ctx, bytes.NewReader(artifact.metadata), int64(artifact.written)) //nolint:gosec // Bounded test lengths above.
	if err != nil || parsed.Metadata() != plan.Metadata() {
		t.Fatalf("encoded artifact metadata: %v", err)
	}
	runtime.ReadMemStats(&after)
	t.Logf("recovered plaintext_bytes=%d records=%d artifact_bytes=%d metadata_bytes=%d payload_sha256=%x elapsed=%s total_alloc_delta=%d heap_alloc_end=%d gc_delta=%d",
		length, count, artifact.written, metadataLength, artifact.payload.Sum(nil), time.Since(started), after.TotalAlloc-before.TotalAlloc, after.HeapAlloc, after.NumGC-before.NumGC)
	if status, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range bytes.Split(status, []byte{'\n'}) {
			if bytes.HasPrefix(line, []byte("VmHWM:")) || bytes.HasPrefix(line, []byte("VmRSS:")) {
				t.Logf("linux_process %s", line)
			}
		}
	}
}

type recoveryPattern struct {
	block           []byte
	length, emitted uint64
}

func newRecoveryPattern(length uint64) *recoveryPattern {
	block := make([]byte, 1<<20)
	for i := range block {
		block[i] = byte((i*29 + i/257) & 255)
	}
	return &recoveryPattern{block: block, length: length}
}

func (r *recoveryPattern) Read(p []byte) (int, error) {
	if r.emitted == r.length {
		return 0, io.EOF
	}
	n := 0
	for len(p) != 0 && r.emitted < r.length {
		offset := r.emitted % (1 << 20)
		if offset == 0 {
			binary.BigEndian.PutUint64(r.block[:8], r.emitted>>20)
		}
		length := min(uint64(len(p)), 1<<20-offset, r.length-r.emitted)
		copied := copy(p, r.block[offset:offset+length])
		p, n, r.emitted = p[copied:], n+copied, r.emitted+uint64(copied)
	}
	return n, nil
}

type recoveryByteWindow struct {
	offset int64
	data   []byte
}

type recoveryWindowCapture struct {
	windows []recoveryByteWindow
	written int64
}

func (w *recoveryWindowCapture) Write(p []byte) (int, error) {
	for _, window := range w.windows {
		start, end := max(w.written, window.offset), min(w.written+int64(len(p)), window.offset+int64(len(window.data)))
		if start < end {
			copy(window.data[start-window.offset:end-window.offset], p[start-w.written:end-w.written])
		}
	}
	w.written += int64(len(p))
	return len(p), nil
}

func (w *recoveryWindowCapture) ReadAt(p []byte, offset int64) (int, error) {
	for _, window := range w.windows {
		if offset >= window.offset && offset+int64(len(p)) <= window.offset+int64(len(window.data)) {
			return copy(p, window.data[offset-window.offset:]), nil
		}
	}
	return 0, fmt.Errorf("unexpected structural read at %d length %d", offset, len(p))
}

type recoveryStreamResult struct {
	plain, cipher []byte
	err           error
}

type recoveryReplay struct {
	pipe         *io.PipeReader
	done         <-chan recoveryStreamResult
	offset, size int64
	finished     bool
}

func newRecoveryReplay(t *testing.T, size int64, generate func(io.Writer) recoveryStreamResult) *recoveryReplay {
	t.Helper()
	reader, writer := io.Pipe()
	done := make(chan recoveryStreamResult, 1)
	go func() {
		result := generate(writer)
		_ = writer.CloseWithError(result.err)
		done <- result
	}()
	r := &recoveryReplay{pipe: reader, done: done, size: size}
	t.Cleanup(func() {
		if !r.finished {
			_ = reader.Close()
			<-done
		}
	})
	return r
}

func (r *recoveryReplay) ReadAt(p []byte, offset int64) (int, error) {
	if offset < r.offset {
		return 0, fmt.Errorf("nonsequential recovery read at %d after %d", offset, r.offset)
	}
	if offset >= r.size {
		return 0, io.EOF
	}
	if _, err := io.CopyN(io.Discard, r.pipe, offset-r.offset); err != nil {
		return 0, err
	}
	r.offset = offset
	available := min(int64(len(p)), r.size-offset)
	n, err := io.ReadFull(r.pipe, p[:available])
	r.offset += int64(n)
	if n < len(p) && err == nil {
		err = io.EOF
	}
	return n, err
}

func (r *recoveryReplay) finish(t *testing.T, want recoveryStreamResult) {
	t.Helper()
	if r.offset != r.size {
		t.Fatalf("recovery did not consume actual records: offset=%d size=%d", r.offset, r.size)
	}
	_, err := io.Copy(io.Discard, r.pipe)
	_ = r.pipe.Close()
	got := <-r.done
	r.finished = true
	if err != nil || got.err != nil || !bytes.Equal(got.plain, want.plain) || !bytes.Equal(got.cipher, want.cipher) {
		t.Fatalf("serializer replay changed source: read=%v serialize=%v plaintext=%x ciphertext=%x", err, got.err, got.plain, got.cipher)
	}
}

type recoveryArtifactDigest struct {
	metadata []byte
	payload  hash.Hash
	written  uint64
}

func (w *recoveryArtifactDigest) Write(p []byte) (int, error) {
	n := len(p)
	if w.written < uint64(len(w.metadata)) {
		copied := copy(w.metadata[w.written:], p)
		p = p[copied:]
	}
	_, _ = w.payload.Write(p)
	w.written += uint64(n)
	return n, nil
}
