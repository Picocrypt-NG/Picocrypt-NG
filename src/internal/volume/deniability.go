package volume

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/util"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20"
)

// AddDeniability wraps a volume with a deniability layer.
// This encrypts the entire volume with XChaCha20 using a separate key derived from the password.
//
// CRITICAL: Deniability uses its own Argon2 derivation (4 passes, 1 GiB, 4 threads)
// and stores salt(16) + nonce(24) at the beginning of the file.
func AddDeniability(volumePath, password string, reporter ProgressReporter) error {
	if reporter != nil {
		reporter.SetStatus("Adding plausible deniability...")
		reporter.SetCanCancel(false)
		reporter.Update()
	}

	stat, err := os.Stat(volumePath)
	if err != nil {
		return fmt.Errorf("stat volume: %w", err)
	}
	total := stat.Size()

	// Rename original to .tmp
	tmpPath := volumePath + ".tmp"
	incompletePath := volumePath + ".incomplete"

	if err := os.Rename(volumePath, tmpPath); err != nil {
		return fmt.Errorf("rename to tmp: %w", err)
	}

	// Helper to restore original file on error
	restoreOriginal := func() {
		_ = os.Remove(incompletePath)
		_ = os.Rename(tmpPath, volumePath)
	}

	fin, err := os.Open(tmpPath)
	if err != nil {
		restoreOriginal()
		return fmt.Errorf("open tmp: %w", err)
	}
	defer func() { _ = fin.Close() }()

	fout, err := os.Create(incompletePath)
	if err != nil {
		_ = fin.Close()
		restoreOriginal()
		return fmt.Errorf("create output: %w", err)
	}
	defer func() { _ = fout.Close() }()

	// Generate random salt and nonce
	salt, err := crypto.RandomBytes(16)
	if err != nil {
		restoreOriginal()
		return err
	}
	nonce, err := crypto.RandomBytes(24)
	if err != nil {
		restoreOriginal()
		return err
	}

	// Write salt and nonce to output
	if _, err := fout.Write(salt); err != nil {
		restoreOriginal()
		return fmt.Errorf("write salt: %w", err)
	}
	if _, err := fout.Write(nonce); err != nil {
		restoreOriginal()
		return fmt.Errorf("write nonce: %w", err)
	}

	// Derive key using Argon2 (normal mode parameters)
	key := argon2.IDKey([]byte(password), salt,
		crypto.Argon2NormalPasses,
		crypto.Argon2NormalMemory,
		crypto.Argon2NormalThreads,
		crypto.Argon2KeySize,
	)

	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		restoreOriginal()
		return fmt.Errorf("create cipher: %w", err)
	}

	// Encrypt the entire volume
	var done int64
	var counter int64
	buf := util.GetMiBBuffer()
	defer util.PutMiBBuffer(buf)
	dst := util.GetMiBBuffer()
	defer util.PutMiBBuffer(dst)

	for {
		n, readErr := fin.Read(buf)
		if n > 0 {
			cipher.XORKeyStream(dst[:n], buf[:n])

			if _, err := fout.Write(dst[:n]); err != nil {
				restoreOriginal()
				return fmt.Errorf("write encrypted: %w", err)
			}

			done += int64(n)
			counter += int64(n)

			if reporter != nil {
				reporter.SetProgress(float32(done)/float32(total), "")
				reporter.Update()
			}

			// Rekey after 60 GiB (deniability uses SHA3-256(nonce) for rekeying)
			if counter >= crypto.RekeyThreshold {
				cipher, nonce, err = crypto.DeniabilityRekey(key, nonce)
				if err != nil {
					restoreOriginal()
					return fmt.Errorf("rekey: %w", err)
				}
				counter = 0
			}
		}

		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			restoreOriginal()
			return fmt.Errorf("read: %w", readErr)
		}
	}

	_ = fin.Close()

	// Sync to ensure all data is written before renaming
	if err := fout.Sync(); err != nil {
		restoreOriginal()
		return fmt.Errorf("sync output: %w", err)
	}
	_ = fout.Close()

	// Clean up: remove .tmp and rename .incomplete to final name
	if err := os.Remove(tmpPath); err != nil {
		// .tmp removal failed, but we have the complete .incomplete
		// Don't try to rename - leave both files for manual inspection
		// User can manually: verify .incomplete is correct, remove .tmp, rename .incomplete
		return fmt.Errorf("remove tmp failed (data saved in %s): %w", incompletePath, err)
	}

	if err := os.Rename(incompletePath, volumePath); err != nil {
		return fmt.Errorf("rename output: %w", err)
	}

	if reporter != nil {
		reporter.SetCanCancel(true)
		reporter.Update()
	}

	return nil
}

// RemoveDeniability decrypts a deniability-wrapped volume.
// Returns the path to the decrypted volume (a .tmp file).
//
// CRITICAL: Must read salt(16) + nonce(24) from the beginning,
// then decrypt with XChaCha20 using Argon2-derived key.
func RemoveDeniability(volumePath, password string, reporter ProgressReporter, rs *encoding.RSCodecs) (string, error) {
	if reporter != nil {
		reporter.SetStatus("Removing deniability protection...")
		reporter.SetProgress(0, "")
		reporter.SetCanCancel(false)
		reporter.Update()
	}

	stat, err := os.Stat(volumePath)
	if err != nil {
		return "", fmt.Errorf("stat volume: %w", err)
	}
	total := stat.Size()

	fin, err := os.Open(volumePath)
	if err != nil {
		return "", fmt.Errorf("open volume: %w", err)
	}
	defer func() { _ = fin.Close() }()

	// Determine output path (strip .tmp suffixes, add .tmp)
	outputPath := volumePath
	for strings.HasSuffix(outputPath, ".tmp") {
		outputPath = strings.TrimSuffix(outputPath, ".tmp")
	}
	outputPath += ".tmp"

	fout, err := os.Create(outputPath)
	if err != nil {
		return "", fmt.Errorf("create output: %w", err)
	}

	// Helper to cleanup on error
	cleanup := func() {
		_ = fout.Close()
		_ = os.Remove(outputPath)
	}

	// Read salt and nonce
	salt := make([]byte, 16)
	nonce := make([]byte, 24)

	if _, err := io.ReadFull(fin, salt); err != nil {
		cleanup()
		return "", fmt.Errorf("read salt: %w", err)
	}
	if _, err := io.ReadFull(fin, nonce); err != nil {
		cleanup()
		return "", fmt.Errorf("read nonce: %w", err)
	}

	// Derive key using Argon2 (normal mode parameters)
	key := argon2.IDKey([]byte(password), salt,
		crypto.Argon2NormalPasses,
		crypto.Argon2NormalMemory,
		crypto.Argon2NormalThreads,
		crypto.Argon2KeySize,
	)

	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		cleanup()
		return "", fmt.Errorf("create cipher: %w", err)
	}

	// Decrypt the volume
	var done int64
	var counter int64
	buf := util.GetMiBBuffer()
	defer util.PutMiBBuffer(buf)
	dst := util.GetMiBBuffer()
	defer util.PutMiBBuffer(dst)

	for {
		n, readErr := fin.Read(buf)
		if n > 0 {
			cipher.XORKeyStream(dst[:n], buf[:n])

			if _, err := fout.Write(dst[:n]); err != nil {
				cleanup()
				return "", fmt.Errorf("write decrypted: %w", err)
			}

			done += int64(n)
			counter += int64(n)

			if reporter != nil {
				reporter.SetProgress(float32(done)/float32(total), "")
				reporter.Update()
			}

			// Rekey after 60 GiB
			if counter >= crypto.RekeyThreshold {
				cipher, nonce, err = crypto.DeniabilityRekey(key, nonce)
				if err != nil {
					cleanup()
					return "", fmt.Errorf("rekey: %w", err)
				}
				counter = 0
			}
		}

		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			cleanup()
			return "", fmt.Errorf("read: %w", readErr)
		}
	}

	_ = fin.Close()

	// Sync to ensure all data is written before verification
	if err := fout.Sync(); err != nil {
		cleanup()
		return "", fmt.Errorf("sync output: %w", err)
	}
	_ = fout.Close()

	// Verify the decrypted file is a valid volume
	verifyFin, err := os.Open(outputPath)
	if err != nil {
		_ = os.Remove(outputPath)
		return "", fmt.Errorf("open for verification: %w", err)
	}

	versionEnc := make([]byte, 15)
	if _, err := io.ReadFull(verifyFin, versionEnc); err != nil {
		_ = verifyFin.Close()
		_ = os.Remove(outputPath)
		return "", fmt.Errorf("read version: %w", err)
	}
	_ = verifyFin.Close()

	versionDec, err := encoding.Decode(rs.RS5, versionEnc, false)
	if err != nil {
		_ = os.Remove(outputPath)
		return "", errors.New("password is incorrect or the file is not a volume")
	}

	if valid, _ := regexp.Match(`^v\d\.\d{2}$`, versionDec); !valid {
		_ = os.Remove(outputPath)
		return "", errors.New("password is incorrect or the file is not a volume")
	}

	return outputPath, nil
}

// IsDeniable checks if a volume appears to have deniability protection.
// This is done by attempting to read and decode the version - if it fails,
// the volume likely has a deniability wrapper.
func IsDeniable(volumePath string, rs *encoding.RSCodecs) bool {
	fin, err := os.Open(volumePath)
	if err != nil {
		return false
	}
	defer func() { _ = fin.Close() }()

	versionEnc := make([]byte, 15)
	if _, err := io.ReadFull(fin, versionEnc); err != nil {
		return true // Can't read, might be deniable
	}

	versionDec, err := encoding.Decode(rs.RS5, versionEnc, false)
	if err != nil {
		return true // Decode failed, likely deniable
	}

	valid, _ := regexp.Match(`^v\d\.\d{2}$`, versionDec)
	return !valid // Invalid version format means deniable
}
