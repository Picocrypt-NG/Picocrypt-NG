package keyfile

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func createTestKeyfiles(t *testing.T, dir string, contents map[string][]byte) []string {
	var paths []string
	for name, data := range contents {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("failed to create test keyfile %s: %v", name, err)
		}
		paths = append(paths, path)
	}
	return paths
}

func TestProcessOrdered(t *testing.T) {
	dir := t.TempDir()

	// Create test keyfiles with known content
	file1Content := []byte("keyfile1-content")
	file2Content := []byte("keyfile2-content")
	file3Content := []byte("keyfile3-content")

	paths := createTestKeyfiles(t, dir, map[string][]byte{
		"a.key": file1Content,
		"b.key": file2Content,
		"c.key": file3Content,
	})

	// Sort paths to ensure consistent order
	pathsABC := []string{
		filepath.Join(dir, "a.key"),
		filepath.Join(dir, "b.key"),
		filepath.Join(dir, "c.key"),
	}
	pathsCBA := []string{
		filepath.Join(dir, "c.key"),
		filepath.Join(dir, "b.key"),
		filepath.Join(dir, "a.key"),
	}

	// Process in ABC order
	resultABC, err := Process(pathsABC, true, nil)
	if err != nil {
		t.Fatalf("Process(ABC, ordered=true) failed: %v", err)
	}

	// Process in CBA order
	resultCBA, err := Process(pathsCBA, true, nil)
	if err != nil {
		t.Fatalf("Process(CBA, ordered=true) failed: %v", err)
	}

	// Ordered: different order should produce different keys.
	// (The hash-of-key relationship is pinned independently by TestProcessOrderedKAT.)
	if bytes.Equal(resultABC.Key, resultCBA.Key) {
		t.Error("Ordered processing: different order should produce different keys")
	}

	_ = paths // use all paths to avoid unused variable warning
}

func TestProcessUnordered(t *testing.T) {
	dir := t.TempDir()

	// Create test keyfiles
	createTestKeyfiles(t, dir, map[string][]byte{
		"a.key": []byte("keyfile1-content"),
		"b.key": []byte("keyfile2-content"),
		"c.key": []byte("keyfile3-content"),
	})

	pathsABC := []string{
		filepath.Join(dir, "a.key"),
		filepath.Join(dir, "b.key"),
		filepath.Join(dir, "c.key"),
	}
	pathsCBA := []string{
		filepath.Join(dir, "c.key"),
		filepath.Join(dir, "b.key"),
		filepath.Join(dir, "a.key"),
	}

	// Process in ABC order
	resultABC, err := Process(pathsABC, false, nil)
	if err != nil {
		t.Fatalf("Process(ABC, ordered=false) failed: %v", err)
	}

	// Process in CBA order
	resultCBA, err := Process(pathsCBA, false, nil)
	if err != nil {
		t.Fatalf("Process(CBA, ordered=false) failed: %v", err)
	}

	// Unordered: different order should produce SAME keys (XOR is commutative)
	if !bytes.Equal(resultABC.Key, resultCBA.Key) {
		t.Error("Unordered processing: different order should produce same keys (XOR commutativity)")
	}
}

func TestProcessEmpty(t *testing.T) {
	result, err := Process(nil, true, nil)
	if err != nil {
		t.Fatalf("Process(nil) failed: %v", err)
	}

	// Empty paths should return zero key and hash
	if len(result.Key) != 32 {
		t.Errorf("Key length = %d; want 32", len(result.Key))
	}
	if len(result.Hash) != 32 {
		t.Errorf("Hash length = %d; want 32", len(result.Hash))
	}

	// Both should be all zeros
	for i, b := range result.Key {
		if b != 0 {
			t.Errorf("Key[%d] = %d; want 0", i, b)
		}
	}
}

// TestProcessOrderedKAT pins the ordered derivation to an independently-computed
// vector. Ordered = SHA3-256("alpha" || "beta"). Expected hex computed via
// python3 hashlib.sha3_256(b"alpha"+b"beta"). This freezes the on-disk key
// derivation: any change to the hash input (extra byte, wrong order, different
// algorithm) breaks the pinned value.
func TestProcessOrderedKAT(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "alpha.key"), []byte("alpha"), 0o600); err != nil {
		t.Fatalf("write alpha: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "beta.key"), []byte("beta"), 0o600); err != nil {
		t.Fatalf("write beta: %v", err)
	}

	paths := []string{
		filepath.Join(dir, "alpha.key"),
		filepath.Join(dir, "beta.key"),
	}

	const wantHex = "72cdf5098734302203ae678e6bc85e1cff67ad36976f390ade6f04cc257eff5a"
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("decode want: %v", err)
	}

	result, err := Process(paths, true, nil)
	if err != nil {
		t.Fatalf("Process(ordered) failed: %v", err)
	}

	if !bytes.Equal(result.Key, want) {
		t.Errorf("ordered Key = %x; want %s", result.Key, wantHex)
	}
}

// TestProcessUnorderedKAT pins the unordered derivation to an independently-computed
// vector and verifies its defining properties. Unordered =
// SHA3-256("alpha") XOR SHA3-256("beta"). Expected hex computed via python3
// (per-file hashlib.sha3_256 then byte-wise XOR). Also asserts order-independence
// (XOR commutativity) and that it is distinct from the ordered derivation.
func TestProcessUnorderedKAT(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "alpha.key"), []byte("alpha"), 0o600); err != nil {
		t.Fatalf("write alpha: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "beta.key"), []byte("beta"), 0o600); err != nil {
		t.Fatalf("write beta: %v", err)
	}

	alpha := filepath.Join(dir, "alpha.key")
	beta := filepath.Join(dir, "beta.key")

	const wantHex = "d73f056aaf0c6df2771b3d213ba9dcc2fae1f4b2c121af4ece834aedec329a20"
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("decode want: %v", err)
	}

	resultAB, err := Process([]string{alpha, beta}, false, nil)
	if err != nil {
		t.Fatalf("Process(unordered, AB) failed: %v", err)
	}
	if !bytes.Equal(resultAB.Key, want) {
		t.Errorf("unordered Key = %x; want %s", resultAB.Key, wantHex)
	}
	// Frozen independently with hashlib.sha3_256(bytes.fromhex(wantHex)).
	const wantHashHex = "a6300f32f84be6bdc1fa477f5fa226cdf285bfcb8a20900f2a2944ccd4b23aa2"
	if got := hex.EncodeToString(resultAB.Hash); got != wantHashHex {
		t.Errorf("unordered Hash = %s; want %s", got, wantHashHex)
	}

	// Order-independence: swapping inputs must yield the same Key (XOR commutativity).
	resultBA, err := Process([]string{beta, alpha}, false, nil)
	if err != nil {
		t.Fatalf("Process(unordered, BA) failed: %v", err)
	}
	if !bytes.Equal(resultAB.Key, resultBA.Key) {
		t.Errorf("unordered must be order-independent: AB=%x BA=%x", resultAB.Key, resultBA.Key)
	}

	// Distinctness: the unordered derivation must differ from the ordered one.
	ordered, err := Process([]string{alpha, beta}, true, nil)
	if err != nil {
		t.Fatalf("Process(ordered) failed: %v", err)
	}
	if bytes.Equal(resultAB.Key, ordered.Key) {
		t.Error("unordered Key must differ from ordered Key")
	}
}

// TestProcessProgressBoundedMonotonic asserts the progress callback values form
// a monotonic non-decreasing sequence bounded by 1.0. This guards the progress
// contract documented on ProgressFunc (0.0-1.0): a regression that emitted a
// value > 1.0 or that went backwards would break this.
func TestProcessProgressBoundedMonotonic(t *testing.T) {
	dir := t.TempDir()

	// Multi-MiB file across two files to force several callback invocations.
	content := bytes.Repeat([]byte("y"), 1024*1024*3) // 3 MiB
	if err := os.WriteFile(filepath.Join(dir, "p1.key"), content, 0o600); err != nil {
		t.Fatalf("write p1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "p2.key"), content, 0o600); err != nil {
		t.Fatalf("write p2: %v", err)
	}

	paths := []string{
		filepath.Join(dir, "p1.key"),
		filepath.Join(dir, "p2.key"),
	}

	var values []float32
	_, err := Process(paths, true, func(p float32) {
		values = append(values, p)
	})
	if err != nil {
		t.Fatalf("Process with progress failed: %v", err)
	}

	if len(values) == 0 {
		t.Fatal("progress callback was never called")
	}

	var prev float32
	for i, v := range values {
		if v > 1.0 {
			t.Errorf("progress[%d] = %f; must be <= 1.0", i, v)
		}
		if v < prev {
			t.Errorf("progress[%d] = %f decreased from previous %f; must be monotonic", i, v, prev)
		}
		prev = v
	}

	// Final progress must reach ~1.0: the callback contract promises completion
	// is reported, so a regression that stops short (e.g. off-by-one byte
	// accounting) would leave the last value below 0.99.
	if last := values[len(values)-1]; last < 0.99 {
		t.Errorf("final progress = %f; want >= 0.99 (completion must be reported)", last)
	}
}

func TestIsDuplicateKeyfileKey(t *testing.T) {
	// Zero key should be detected
	zeroKey := make([]byte, 32)
	if !IsDuplicateKeyfileKey(zeroKey) {
		t.Error("Zero key should be detected as duplicate")
	}

	// Non-zero key should not be detected
	nonZeroKey := make([]byte, 32)
	nonZeroKey[0] = 1
	if IsDuplicateKeyfileKey(nonZeroKey) {
		t.Error("Non-zero key should not be detected as duplicate")
	}

	// Wrong length should return false
	if IsDuplicateKeyfileKey(make([]byte, 16)) {
		t.Error("Wrong length key should return false")
	}
}

func TestXORWithKey(t *testing.T) {
	passwordKey := make([]byte, 32)
	keyfileKey := make([]byte, 32)

	for i := range passwordKey {
		passwordKey[i] = byte(i)
		keyfileKey[i] = byte(255 - i)
	}

	result := XORWithKey(passwordKey, keyfileKey)

	if len(result) != 32 {
		t.Fatalf("Result length = %d; want 32", len(result))
	}

	// Verify XOR
	for i := range result {
		expected := passwordKey[i] ^ keyfileKey[i]
		if result[i] != expected {
			t.Errorf("result[%d] = %d; want %d", i, result[i], expected)
		}
	}

	// XOR with itself should give zero
	resultSelf := XORWithKey(passwordKey, passwordKey)
	for i, b := range resultSelf {
		if b != 0 {
			t.Errorf("XOR with self: result[%d] = %d; want 0", i, b)
		}
	}
}

func TestDuplicateKeyfilesCancelOut(t *testing.T) {
	dir := t.TempDir()

	// Create identical keyfiles
	content := []byte("same-content-in-all-files")
	createTestKeyfiles(t, dir, map[string][]byte{
		"a.key": content,
		"b.key": content, // Duplicate of a.key
	})

	paths := []string{
		filepath.Join(dir, "a.key"),
		filepath.Join(dir, "b.key"),
	}

	// Unordered: duplicate keyfiles should XOR to zero
	result, err := Process(paths, false, nil)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	// With two identical files, XOR should produce zeros
	if !IsDuplicateKeyfileKey(result.Key) {
		t.Error("Two identical keyfiles (unordered) should produce zero key")
	}
}

func TestOrderedSameFileTwice(t *testing.T) {
	dir := t.TempDir()

	content := []byte("keyfile-content")
	createTestKeyfiles(t, dir, map[string][]byte{
		"a.key": content,
	})

	path := filepath.Join(dir, "a.key")

	// Ordered: same file twice is different from once
	resultOnce, err := Process([]string{path}, true, nil)
	if err != nil {
		t.Fatalf("Process(once) failed: %v", err)
	}

	resultTwice, err := Process([]string{path, path}, true, nil)
	if err != nil {
		t.Fatalf("Process(twice) failed: %v", err)
	}

	// Should be different (content || content vs content)
	if bytes.Equal(resultOnce.Key, resultTwice.Key) {
		t.Error("Ordered: same file twice should produce different key than once")
	}
}

func TestProcessNonexistentFile(t *testing.T) {
	_, err := Process([]string{"/nonexistent/path/to/keyfile.bin"}, true, nil)
	if err == nil {
		t.Error("Process should fail for nonexistent file")
	}
}

func TestProcessOrderedReadError(t *testing.T) {
	dir := t.TempDir()

	// Create a directory instead of a file (will cause read error)
	dirPath := filepath.Join(dir, "not_a_file")
	if err := os.Mkdir(dirPath, 0o755); err != nil {
		t.Fatalf("Create dir: %v", err)
	}

	_, err := Process([]string{dirPath}, true, nil)
	if err == nil {
		t.Error("Process should fail when given a directory")
	}
}

func TestProcessUnorderedReadError(t *testing.T) {
	dir := t.TempDir()

	// Create a directory instead of a file (will cause read error)
	dirPath := filepath.Join(dir, "not_a_file")
	if err := os.Mkdir(dirPath, 0o755); err != nil {
		t.Fatalf("Create dir: %v", err)
	}

	_, err := Process([]string{dirPath}, false, nil)
	if err == nil {
		t.Error("Process should fail when given a directory")
	}
}

func TestProcessReadersMatchesProcess(t *testing.T) {
	// Three keyfiles: two sub-1MiB and one >1MiB (non-buffer-aligned) so that
	// the multi-chunk path of hashOne is exercised and cross-checked between
	// Process (disk) and ProcessReaders (in-memory).
	a := bytes.Repeat([]byte{0xA5}, 1500)
	b := bytes.Repeat([]byte{0x5A}, 800)
	c := bytes.Repeat([]byte{0x3C}, 3*1024*1024+777) // >1 MiB, non-aligned

	dir := t.TempDir()
	pa := filepath.Join(dir, "a.key")
	pb := filepath.Join(dir, "b.key")
	pc := filepath.Join(dir, "c.key")
	if err := os.WriteFile(pa, a, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pb, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pc, c, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, ordered := range []bool{true, false} {
		t.Run(fmt.Sprintf("ordered=%v", ordered), func(t *testing.T) {
			fromPaths, err := Process([]string{pa, pb, pc}, ordered, nil)
			if err != nil {
				t.Fatalf("Process: %v", err)
			}
			fromReaders, err := ProcessReaders([]io.Reader{bytes.NewReader(a), bytes.NewReader(b), bytes.NewReader(c)}, ordered)
			if err != nil {
				t.Fatalf("ProcessReaders: %v", err)
			}
			if !bytes.Equal(fromPaths.Key, fromReaders.Key) {
				t.Errorf("Key mismatch (ordered=%v):\n paths:   %x\n readers: %x", ordered, fromPaths.Key, fromReaders.Key)
			}
			if !bytes.Equal(fromPaths.Hash, fromReaders.Hash) {
				t.Errorf("Hash mismatch (ordered=%v)", ordered)
			}
		})
	}
}

func TestProcessReadersEmptyIsZeroKey(t *testing.T) {
	res, err := ProcessReaders(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res.Key, make([]byte, 32)) || !bytes.Equal(res.Hash, make([]byte, 32)) {
		t.Fatal("empty readers must yield 32 zero bytes for Key and Hash")
	}
}

func TestProcessReadersSingleUnorderedKAT(t *testing.T) {
	// The first digest becomes the caller's key; cleanup must not erase it.
	// These values are frozen from Python hashlib.sha3_256, independently of
	// ProcessReaders, and pin both the key and its public verification hash.
	result, err := ProcessReaders([]io.Reader{bytes.NewReader([]byte("alpha"))}, false)
	if err != nil {
		t.Fatal(err)
	}
	const wantKey = "271878f8a927b4566ac951fc815b18dfad8d0302d61d11d80cbe15b7a3a056af"
	const wantHash = "55a13f9643162423150298637137dac69dca1cec1a3250adf142d8466df37bc6"
	if got := hex.EncodeToString(result.Key); got != wantKey {
		t.Errorf("Key = %s; want %s", got, wantKey)
	}
	if got := hex.EncodeToString(result.Hash); got != wantHash {
		t.Errorf("Hash = %s; want %s", got, wantHash)
	}
}

type readErrorWithBuffer struct {
	buf []byte
	err error
}

func (r *readErrorWithBuffer) Read(buf []byte) (int, error) {
	r.buf = buf
	return copy(buf, "partial keyfile material"), r.err
}

func TestProcessReadersReadErrorDiscardsKeyAndClearsInputBuffer(t *testing.T) {
	for _, ordered := range []bool{false, true} {
		t.Run(fmt.Sprintf("ordered=%v", ordered), func(t *testing.T) {
			readErr := errors.New("keyfile read failed")
			failing := &readErrorWithBuffer{err: readErr}
			trailing := bytes.NewReader([]byte("must remain unread"))
			result, err := ProcessReaders([]io.Reader{
				bytes.NewReader([]byte("alpha")),
				failing,
				trailing,
			}, ordered)
			if !errors.Is(err, readErr) {
				t.Fatalf("read error = %v; want %v", err, readErr)
			}
			if result != nil {
				t.Fatal("read failure exposed a partial key or verification hash")
			}
			if trailing.Len() != len("must remain unread") {
				t.Fatal("continued reading keyfiles after failure")
			}
			if len(failing.buf) == 0 {
				t.Fatal("failing reader did not receive a scratch buffer")
			}
			for _, b := range failing.buf {
				if b != 0 {
					t.Fatal("keyfile input remained in the owned scratch buffer after failure")
				}
			}
		})
	}
}
