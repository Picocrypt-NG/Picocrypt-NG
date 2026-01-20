// Package keyfile handles keyfile processing for Picocrypt volumes.
// This is AUDIT-CRITICAL code - changes here directly affect key derivation.
package keyfile

import (
	"fmt"
	"io"
	"os"

	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/util"

	"golang.org/x/crypto/sha3"
)

// Result contains the computed keyfile key and its hash for verification.
// Call Close() when done to securely zero the key material.
type Result struct {
	Key    []byte // 32 bytes - derived key for XOR with main password key
	Hash   []byte // 32 bytes - SHA3-256(Key) for header storage/verification
	closed bool
}

// Close securely zeros the keyfile key material.
// The hash is retained as it's not sensitive (stored in header).
//
// SECURITY: Always call Close() when done with the keyfile result.
func (r *Result) Close() {
	if r == nil || r.closed {
		return
	}
	crypto.SecureZero(r.Key)
	r.Key = nil
	r.closed = true
}

// ProgressFunc is called during keyfile processing with progress 0.0-1.0
type ProgressFunc func(progress float32)

// Process computes the keyfile key from the given paths.
// If ordered is true, files are hashed sequentially (order matters).
// If ordered is false, files are hashed individually and XORed (order doesn't matter).
//
// CRITICAL: The ordered vs unordered distinction affects key derivation:
//   - Ordered:   SHA3-256(file1 || file2 || file3 || ...)
//   - Unordered: SHA3-256(file1) XOR SHA3-256(file2) XOR SHA3-256(file3) XOR ...
func Process(paths []string, ordered bool, progress ProgressFunc) (*Result, error) {
	if len(paths) == 0 {
		return &Result{
			Key:  make([]byte, 32),
			Hash: make([]byte, 32),
		}, nil
	}

	// Calculate total size for progress reporting
	var totalSize int64
	for _, path := range paths {
		stat, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		totalSize += stat.Size()
	}

	var key []byte
	var err error

	if ordered {
		key, err = processOrdered(paths, totalSize, progress)
	} else {
		key, err = processUnordered(paths, totalSize, progress)
	}

	if err != nil {
		return nil, err
	}

	// Compute hash of keyfile key for verification
	h := sha3.New256()
	h.Write(key)
	hash := h.Sum(nil)

	return &Result{
		Key:  key,
		Hash: hash,
	}, nil
}

// processOrdered hashes all keyfiles sequentially.
// The file order IS IMPORTANT - different order = different key.
// Algorithm: SHA3-256(file1_contents || file2_contents || ...)
func processOrdered(paths []string, totalSize int64, progress ProgressFunc) ([]byte, error) {
	hasher := sha3.New256()
	var done int64

	for _, path := range paths {
		fin, err := os.Open(path)
		if err != nil {
			return nil, err
		}

		buf := make([]byte, util.MiB)
		for {
			n, err := fin.Read(buf)
			if err == io.EOF {
				break
			}
			if err != nil {
				_ = fin.Close()
				return nil, err
			}

			if _, err := hasher.Write(buf[:n]); err != nil {
				_ = fin.Close()
				return nil, err
			}

			done += int64(n)
			if progress != nil {
				progress(float32(done) / float32(totalSize))
			}
		}

		if err := fin.Close(); err != nil {
			return nil, err
		}
	}

	return hasher.Sum(nil), nil
}

// processUnordered hashes each keyfile individually and XORs the results.
// The file order IS NOT important due to XOR commutativity.
// Algorithm: SHA3-256(file1) XOR SHA3-256(file2) XOR ...
func processUnordered(paths []string, totalSize int64, progress ProgressFunc) ([]byte, error) {
	var combinedKey []byte
	var done int64

	for _, path := range paths {
		fin, err := os.Open(path)
		if err != nil {
			return nil, err
		}

		hasher := sha3.New256()
		buf := make([]byte, util.MiB)
		for {
			n, err := fin.Read(buf)
			if err == io.EOF {
				break
			}
			if err != nil {
				_ = fin.Close()
				return nil, err
			}

			if _, err := hasher.Write(buf[:n]); err != nil {
				_ = fin.Close()
				return nil, err
			}

			done += int64(n)
			if progress != nil {
				progress(float32(done) / float32(totalSize))
			}
		}

		if err := fin.Close(); err != nil {
			return nil, err
		}

		fileHash := hasher.Sum(nil)

		// XOR with combined key
		if combinedKey == nil {
			combinedKey = fileHash
		} else {
			for i, b := range fileHash {
				combinedKey[i] ^= b
			}
		}
	}

	return combinedKey, nil
}

// IsDuplicateKeyfileKey checks if the keyfile key is all zeros,
// which would indicate an even number of duplicate keyfiles (XOR cancellation).
func IsDuplicateKeyfileKey(key []byte) bool {
	if len(key) != 32 {
		return false
	}
	for _, b := range key {
		if b != 0 {
			return false
		}
	}
	return true
}

// XORWithKey XORs the keyfile key with the password-derived key.
// This is the final step to produce the encryption key.
//
// INVARIANT: Both keys must be exactly 32 bytes (Argon2KeySize / SHA3-256 output).
// Violation indicates a programming error, not a runtime condition.
func XORWithKey(passwordKey, keyfileKey []byte) []byte {
	if len(passwordKey) != 32 || len(keyfileKey) != 32 {
		panic(fmt.Sprintf("XORWithKey: invariant violation - expected 32-byte keys, got %d and %d bytes",
			len(passwordKey), len(keyfileKey)))
	}

	result := make([]byte, 32)
	for i := range result {
		result[i] = passwordKey[i] ^ keyfileKey[i]
	}
	return result
}
