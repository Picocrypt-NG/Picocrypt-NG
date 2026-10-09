// Package keyfile handles keyfile processing for Picocrypt volumes.
// This is AUDIT-CRITICAL code - changes here directly affect key derivation.
package keyfile

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/util"
	"crypto/sha3"
	"errors"
	"fmt"
	"io"
	"os"
)

// Result contains the computed keyfile key and its hash for verification.
type Result struct {
	Key  []byte // 32 bytes - derived key for XOR with main password key
	Hash []byte // 32 bytes - SHA3-256(Key) for header storage/verification
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

	key := make([]byte, 32)
	transferred := false
	defer func() {
		if !transferred {
			crypto.SecureZero(key)
		}
	}()
	hasher := sha3.New256()
	buf := make([]byte, util.MiB)
	defer crypto.SecureZero(buf)

	var done int64
	for _, path := range paths {
		if !ordered {
			hasher.Reset()
		}
		err := func() (retErr error) {
			// #nosec G304 -- keyfile paths validated by caller
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer func() { retErr = errors.Join(retErr, file.Close()) }()
			return hashOne(hasher, &progressReader{r: file, done: &done, total: totalSize, progress: progress}, buf)
		}()
		if err != nil {
			return nil, err
		}
		if !ordered {
			digest := hasher.Sum(nil)
			for i, b := range digest {
				key[i] ^= b
			}
			crypto.SecureZero(digest)
		}
	}
	if ordered {
		key = hasher.Sum(key[:0])
	}
	sum := sha3.Sum256(key)
	result := &Result{Key: key, Hash: append([]byte(nil), sum[:]...)}
	transferred = true
	return result, nil
}

// progressReader reports cumulative read progress across all keyfiles.
type progressReader struct {
	r        io.Reader
	done     *int64
	total    int64
	progress ProgressFunc
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 && p.progress != nil && p.total > 0 {
		*p.done += int64(n)
		p.progress(float32(*p.done) / float32(p.total))
	}
	return n, err
}

// ProcessReaders computes the keyfile key from in-memory/streamed readers.
// Same algorithm as Process, decoupled from the filesystem so the WASM build
// (no paths) can share this AUDIT-CRITICAL logic:
//   - Ordered:   SHA3-256(r1 || r2 || ...)
//   - Unordered: SHA3-256(r1) XOR SHA3-256(r2) XOR ...
func ProcessReaders(readers []io.Reader, ordered bool) (*Result, error) {
	if len(readers) == 0 {
		return &Result{Key: make([]byte, 32), Hash: make([]byte, 32)}, nil
	}

	var key []byte
	var err error
	if ordered {
		key, err = hashOrdered(readers)
	} else {
		key, err = hashUnordered(readers)
	}
	if err != nil {
		return nil, err
	}

	sum := sha3.Sum256(key)
	hash := append([]byte(nil), sum[:]...)
	return &Result{Key: key, Hash: hash}, nil
}

// hashOrdered: single hash over the concatenation of all readers.
func hashOrdered(readers []io.Reader) ([]byte, error) {
	hasher := sha3.New256()
	buf := make([]byte, util.MiB)
	defer crypto.SecureZero(buf)
	for _, r := range readers {
		if err := hashOne(hasher, r, buf); err != nil {
			return nil, err
		}
	}
	return hasher.Sum(nil), nil
}

// hashUnordered: per-reader SHA3-256, XOR-combined.
func hashUnordered(readers []io.Reader) ([]byte, error) {
	var combined []byte
	buf := make([]byte, util.MiB)
	defer crypto.SecureZero(buf)
	for _, r := range readers {
		hasher := sha3.New256()
		if err := hashOne(hasher, r, buf); err != nil {
			crypto.SecureZero(combined)
			return nil, err
		}
		fileHash := hasher.Sum(nil)
		if combined == nil {
			combined = fileHash
		} else {
			for i, b := range fileHash {
				combined[i] ^= b
			}
			crypto.SecureZero(fileHash)
		}
	}
	return combined, nil
}

// hashOne streams r into hasher using the provided scratch buffer (zeroed by the
// caller). Uses an explicit loop (not io.Copy) to keep the scratch buffer
// secure-zeroable.
//
// NOTE: buf[:n] is written to the hasher BEFORE the error is inspected. This
// is intentional: the io.Reader contract permits a non-nil error (including
// io.EOF) to be returned alongside n > 0 bytes in the same Read call, and
// those bytes must not be silently dropped.
func hashOne(hasher io.Writer, r io.Reader, buf []byte) error {
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, werr := hasher.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
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
