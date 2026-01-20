package keyfile

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/sha3"
)

func createTestKeyfiles(t *testing.T, dir string, contents map[string][]byte) []string {
	var paths []string
	for name, data := range contents {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
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

	// Ordered: different order should produce different keys
	if bytes.Equal(resultABC.Key, resultCBA.Key) {
		t.Error("Ordered processing: different order should produce different keys")
	}

	// Verify the hash is correct (SHA3-256 of key)
	h := sha3.New256()
	h.Write(resultABC.Key)
	expectedHash := h.Sum(nil)
	if !bytes.Equal(resultABC.Hash, expectedHash) {
		t.Error("Hash should be SHA3-256 of key")
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

func TestProcessProgress(t *testing.T) {
	dir := t.TempDir()

	// Create a larger file to ensure multiple progress updates
	largeContent := bytes.Repeat([]byte("x"), 1024*1024*2) // 2 MiB
	createTestKeyfiles(t, dir, map[string][]byte{
		"large.key": largeContent,
	})

	var progressCalls int
	var lastProgress float32

	result, err := Process([]string{filepath.Join(dir, "large.key")}, true, func(p float32) {
		progressCalls++
		lastProgress = p
	})

	if err != nil {
		t.Fatalf("Process with progress failed: %v", err)
	}

	if progressCalls == 0 {
		t.Error("Progress callback was never called")
	}

	// Last progress should be ~1.0
	if lastProgress < 0.99 {
		t.Errorf("Last progress = %f; want ~1.0", lastProgress)
	}

	if len(result.Key) != 32 {
		t.Errorf("Key length = %d; want 32", len(result.Key))
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

func TestResultClose(t *testing.T) {
	dir := t.TempDir()

	createTestKeyfiles(t, dir, map[string][]byte{
		"test.key": []byte("keyfile-content-for-testing"),
	})

	result, err := Process([]string{filepath.Join(dir, "test.key")}, true, nil)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	// Verify key is non-nil before close
	if result.Key == nil {
		t.Error("Key should not be nil before Close()")
	}
	if len(result.Key) != 32 {
		t.Errorf("Key length = %d; want 32", len(result.Key))
	}

	// Close the result
	result.Close()

	// After close, key should be nil
	if result.Key != nil {
		t.Error("Key should be nil after Close()")
	}

	// Multiple Close() calls should be safe
	result.Close()
	result.Close()
}

func TestResultCloseNil(t *testing.T) {
	// Close on nil should not panic
	var result *Result
	result.Close()
}

func TestResultClosePreservesHash(t *testing.T) {
	dir := t.TempDir()

	createTestKeyfiles(t, dir, map[string][]byte{
		"test.key": []byte("keyfile-content"),
	})

	result, err := Process([]string{filepath.Join(dir, "test.key")}, true, nil)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	// Save hash before close
	hashCopy := make([]byte, len(result.Hash))
	copy(hashCopy, result.Hash)

	// Close
	result.Close()

	// Hash should still be present (needed for header verification)
	if !bytes.Equal(result.Hash, hashCopy) {
		t.Error("Hash should be preserved after Close()")
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
	if err := os.Mkdir(dirPath, 0755); err != nil {
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
	if err := os.Mkdir(dirPath, 0755); err != nil {
		t.Fatalf("Create dir: %v", err)
	}

	_, err := Process([]string{dirPath}, false, nil)
	if err == nil {
		t.Error("Process should fail when given a directory")
	}
}
