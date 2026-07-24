package volume

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/util"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	pwnorm "Picocrypt-NG/internal/password"

	"golang.org/x/crypto/chacha20"
)

// newDeniabilityReader is identity in production; tests replace it to inject
// short reads and verify the io.ReadFull loops pin the rekey boundary to a
// fixed block count regardless of read chunking. Mirrors newPayloadReader in
// decrypt.go for the main payload path.
var newDeniabilityReader = func(r io.Reader) io.Reader { return r }

// isDeniableReadVersion reads IsDeniable's encoded version prefix. It is a
// package-level seam (mirroring newDeniabilityReader) so tests can inject an I/O
// failure on a file that already cleared the size guard, exercising the
// read-error branch that is otherwise unreachable on a real filesystem.
var isDeniableReadVersion = io.ReadFull

// AddDeniability wraps a volume with a deniability layer.
// This encrypts the entire volume with XChaCha20 using a separate key derived from the password.
//
// CRITICAL: Deniability uses its own Argon2 derivation (4 passes, 1 GiB, 4 threads)
// and stores salt(16) + nonce(24) at the beginning of the file.
func AddDeniability(volumePath string, password []byte, reporter ProgressReporter) error {
	return addDeniability(volumePath, password, reporter, nil, nil)
}

// addDeniability optionally pins the input identity and returns the exact
// identity of the published wrapper. Encrypt uses both identities so a path
// replacement cannot be mistaken for operation-owned output.
func addDeniability(
	volumePath string,
	password []byte,
	reporter ProgressReporter,
	expectedInput os.FileInfo,
	outputInfo *os.FileInfo,
) (retErr error) {
	if reporter != nil {
		reporter.SetStatus("Adding plausible deniability...")
		reporter.SetCanCancel(false)
		reporter.Update()
	}

	// Read the original in place and build the wrapper beside it. The original
	// path is not touched until the complete wrapper is published.
	fin, err := os.Open(volumePath) // #nosec G304 -- user-selected volume path
	if err != nil {
		return fmt.Errorf("open volume: %w", err)
	}
	defer func() { _ = fin.Close() }()
	originalInfo, err := fin.Stat()
	if err != nil {
		return fmt.Errorf("stat volume: %w", err)
	}
	if expectedInput != nil && !os.SameFile(expectedInput, originalInfo) {
		return errors.New("volume path changed before adding deniability")
	}
	total := originalInfo.Size()

	stage, err := fileops.CreateSiblingTemp(volumePath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer func() {
		retErr = errors.Join(retErr, stage.Cleanup())
	}()
	fout := stage.File()

	// Generate random salt and nonce
	salt, err := crypto.RandomBytes(16)
	if err != nil {
		return err
	}
	nonce, err := crypto.RandomBytes(24)
	if err != nil {
		return err
	}

	// Write salt and nonce to output
	if _, err := fout.Write(salt); err != nil {
		return fmt.Errorf("write salt: %w", err)
	}
	if _, err := fout.Write(nonce); err != nil {
		return fmt.Errorf("write nonce: %w", err)
	}

	// Derive key using Argon2 (normal mode parameters). NFC-normalize the
	// password so a deniable volume — which has no readable header to fall back
	// on — is cross-platform-decryptable (#19).
	kdfInput := pwnorm.EncodeForKDF(password)
	defer crypto.SecureZero(kdfInput)
	key := deriveDeniabilityKey(kdfInput, salt)
	defer crypto.SecureZero(key)

	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}

	// Encrypt the entire volume
	var done int64
	var counter int64
	buf := util.GetMiBBuffer()
	defer util.PutMiBBuffer(buf)
	dst := util.GetMiBBuffer()
	defer util.PutMiBBuffer(dst)

	reader := newDeniabilityReader(io.Reader(fin))
	startTime := time.Now()

	for {
		n, readErr := io.ReadFull(reader, buf)
		if n > 0 {
			cipher.XORKeyStream(dst[:n], buf[:n])

			if _, err := fout.Write(dst[:n]); err != nil {
				return fmt.Errorf("write encrypted: %w", err)
			}

			done += int64(n)
			// Pin the rekey boundary to a fixed block count regardless of read
			// chunking: io.ReadFull delivers full MiB blocks, so the counter
			// advances by util.MiB per block. The threshold is a MiB multiple
			// and only crossable on a full block, so the final partial block's
			// over-count is irrelevant (the loop breaks at EOF).
			counter += int64(util.MiB)

			if reporter != nil {
				progress, speed, eta := util.Statify(done, total, startTime)
				reporter.SetProgress(progress, "")
				reporter.SetStatus(fmt.Sprintf("Adding deniability at %.2f MiB/s (ETA: %s)", speed, eta))
				reporter.Update()
			}

			// Rekey after 60 GiB (deniability uses SHA3-256(nonce) for rekeying)
			if counter >= crypto.RekeyThreshold {
				cipher, nonce, err = crypto.DeniabilityRekey(key, nonce)
				if err != nil {
					return fmt.Errorf("rekey: %w", err)
				}
				counter = 0
			}
		}

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read: %w", readErr)
		}
	}

	if err := fin.Close(); err != nil {
		return fmt.Errorf("close volume: %w", err)
	}
	currentInfo, err := os.Stat(volumePath)
	if err != nil {
		return fmt.Errorf("inspect volume before publish: %w", err)
	}
	if !os.SameFile(originalInfo, currentInfo) {
		return errors.New("volume path changed while adding deniability")
	}
	publishedInfo, err := fout.Stat()
	if err != nil {
		return fmt.Errorf("inspect deniability wrapper before publish: %w", err)
	}
	if err := stage.Commit(); err != nil {
		return fmt.Errorf("publish deniability wrapper: %w", err)
	}
	if outputInfo != nil {
		*outputInfo = publishedInfo
	}

	if reporter != nil {
		reporter.SetCanCancel(true)
		reporter.Update()
	}

	return nil
}

// RemoveDeniability decrypts a deniability-wrapped volume.
// Returns an owned random temporary file containing the decrypted inner volume.
//
// CRITICAL: Must read salt(16) + nonce(24) from the beginning,
// then decrypt with XChaCha20 using Argon2-derived key.
func RemoveDeniability(volumePath string, password []byte, reporter ProgressReporter, rs *encoding.RSCodecs) (*fileops.StagedFile, error) {
	return removeDeniability(volumePath, password, reporter, rs, nil)
}

func removeDeniability(
	volumePath string,
	password []byte,
	reporter ProgressReporter,
	rs *encoding.RSCodecs,
	expectedInput os.FileInfo,
) (retStage *fileops.StagedFile, retErr error) {
	if reporter != nil {
		reporter.SetStatus("Removing deniability protection...")
		reporter.SetProgress(0, "")
		reporter.SetCanCancel(false)
		reporter.Update()
	}

	// #nosec G304 -- volumePath is user-provided .pcv file
	fin, err := os.Open(volumePath)
	if err != nil {
		return nil, fmt.Errorf("open volume: %w", err)
	}
	defer func() { _ = fin.Close() }()
	stat, err := fin.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat volume: %w", err)
	}
	if expectedInput != nil && !os.SameFile(expectedInput, stat) {
		return nil, errors.New("recombined input path changed before removing deniability")
	}
	total := stat.Size()

	stage, err := fileops.CreateSiblingTemp(volumePath)
	if err != nil {
		return nil, fmt.Errorf("create output: %w", err)
	}
	keepStage := false
	defer func() {
		if !keepStage {
			retErr = errors.Join(retErr, stage.Cleanup())
		}
	}()
	fout := stage.File()

	// Read salt and nonce
	salt := make([]byte, 16)
	nonce := make([]byte, 24)

	if _, err := io.ReadFull(fin, salt); err != nil {
		return nil, fmt.Errorf("read salt: %w", err)
	}
	if _, err := io.ReadFull(fin, nonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}

	// The deniable wrapper carries no MAC; the correct key is the one whose
	// keystream decodes a valid inner volume version. Probe the first encoded
	// version field with each password normalization form (NFC/NFD/raw) and keep
	// the first that matches, then decrypt the whole volume with that key (#19).
	probe := make([]byte, header.VersionEncSize)
	if _, err := io.ReadFull(fin, probe); err != nil {
		return nil, fmt.Errorf("read version probe: %w", err)
	}
	if _, err := fin.Seek(int64(len(salt)+len(nonce)), io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek after probe: %w", err)
	}

	key, err := selectDeniabilityKey(password, salt, nonce, probe, rs)
	if err != nil {
		return nil, err
	}
	defer crypto.SecureZero(key)

	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	// Decrypt the volume
	var done int64
	var counter int64
	buf := util.GetMiBBuffer()
	defer util.PutMiBBuffer(buf)
	dst := util.GetMiBBuffer()
	defer util.PutMiBBuffer(dst)

	reader := newDeniabilityReader(io.Reader(fin))
	startTime := time.Now()

	for {
		n, readErr := io.ReadFull(reader, buf)
		if n > 0 {
			cipher.XORKeyStream(dst[:n], buf[:n])

			if _, err := fout.Write(dst[:n]); err != nil {
				return nil, fmt.Errorf("write decrypted: %w", err)
			}

			done += int64(n)
			// Pin the rekey boundary to a fixed block count (see AddDeniability):
			// io.ReadFull delivers full MiB blocks, so the rekey offset is
			// independent of how the underlying reader chunks its reads.
			counter += int64(util.MiB)

			if reporter != nil {
				progress, speed, eta := util.Statify(done, total, startTime)
				reporter.SetProgress(progress, "")
				reporter.SetStatus(fmt.Sprintf("Removing deniability at %.2f MiB/s (ETA: %s)", speed, eta))
				reporter.Update()
			}

			// Rekey after 60 GiB
			if counter >= crypto.RekeyThreshold {
				cipher, nonce, err = crypto.DeniabilityRekey(key, nonce)
				if err != nil {
					return nil, fmt.Errorf("rekey: %w", err)
				}
				counter = 0
			}
		}

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("read: %w", readErr)
		}
	}

	if err := fin.Close(); err != nil {
		return nil, fmt.Errorf("close volume: %w", err)
	}

	// Sync to ensure all data is written before verification
	if err := fout.Sync(); err != nil {
		return nil, fmt.Errorf("sync output: %w", err)
	}
	if _, err := fout.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind output for verification: %w", err)
	}

	versionEnc := make([]byte, header.VersionEncSize)
	if _, err := io.ReadFull(fout, versionEnc); err != nil {
		return nil, fmt.Errorf("read version: %w", err)
	}

	versionDec, err := encoding.Decode(rs.RS5, versionEnc, false)
	if err != nil {
		return nil, errors.New("password is incorrect or the file is not a volume")
	}

	if !header.MatchVersion(versionDec) {
		return nil, errors.New("password is incorrect or the file is not a volume")
	}

	if _, err := fout.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind decrypted volume: %w", err)
	}
	keepStage = true
	return stage, nil
}

// selectDeniabilityKey returns the deniability key for the first password
// normalization form (NFC/NFD/raw) whose keystream decodes a valid inner volume
// version from probe (the RS-encoded version field). It returns an error if no
// form matches. Trying several canonical forms of the same password does not
// weaken the wrapper: each candidate must still yield a recognizable inner
// header. ASCII passwords yield a single candidate, so there is no extra work.
func selectDeniabilityKey(password []byte, salt, nonce, probe []byte, rs *encoding.RSCodecs) ([]byte, error) {
	for _, cand := range pwnorm.Candidates(password) {
		key := deriveDeniabilityKey(cand, salt)
		cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
		if err != nil {
			crypto.SecureZero(key)
			return nil, fmt.Errorf("create cipher: %w", err)
		}
		dec := make([]byte, len(probe))
		cipher.XORKeyStream(dec, probe)
		if versionDec, decodeErr := encoding.Decode(rs.RS5, dec, false); decodeErr == nil && header.MatchVersion(versionDec) {
			return key, nil
		}
		crypto.SecureZero(key)
	}
	return nil, errors.New("password is incorrect or the file is not a volume")
}

// IsDeniable checks if a volume appears to have deniability protection.
//
// The leading bytes of a deniable volume are random salt/nonce bytes, while a
// regular volume starts with an RS5-encoded version. A version decode failure is
// ambiguous: it can be a deniable wrapper or a damaged regular header. Resolve
// that ambiguity by checking whether the following comment-length and flags
// fields still look like a regular Picocrypt header.
func IsDeniable(volumePath string, rs *encoding.RSCodecs) bool {
	// #nosec G304 -- volumePath is user-provided .pcv file
	fin, err := os.Open(volumePath)
	if err != nil {
		return false
	}
	defer func() { _ = fin.Close() }()

	// QUAL-02 negative pre-guard: a deniability-wrapped volume always wraps a COMPLETE
	// inner regular volume, so its on-disk size is at least salt(16) + nonce(24) +
	// header.BaseHeaderSize. A file shorter than that cannot be deniable — it is a
	// truncated/corrupt regular volume (or junk). Classifying such a short file as
	// deniable mis-routes it down the deniability-strip path; reject it here instead.
	// This only ADDS a negative rejection; the positive RS5-magic detection path below
	// is format-frozen and unchanged.
	const minDeniableSize = 16 + 24 + header.BaseHeaderSize
	if fi, err := fin.Stat(); err != nil || fi.Size() < int64(minDeniableSize) {
		return false // too short to be a deniable volume (truncated/corrupt regular)
	}

	versionEnc := make([]byte, 15)
	if _, err := isDeniableReadVersion(fin, versionEnc); err != nil {
		// Size already cleared the minimum above, so a short read here means an I/O
		// error rather than truncation — treat as non-deniable (cannot confirm).
		return false
	}

	versionDec, err := encoding.Decode(rs.RS5, versionEnc, false)
	if err != nil {
		return !looksLikeRegularHeaderAfterDamagedVersion(fin, rs)
	}

	if header.MatchVersion(versionDec) {
		return false
	}

	return !looksLikeRegularHeaderAfterDamagedVersion(fin, rs)
}

func looksLikeRegularHeaderAfterDamagedVersion(fin *os.File, rs *encoding.RSCodecs) bool {
	commentLenEnc := make([]byte, header.CommentLenEncSize)
	if _, err := fin.ReadAt(commentLenEnc, int64(header.VersionEncSize)); err != nil {
		return false
	}
	commentLenDec, err := encoding.Decode(rs.RS5, commentLenEnc, false)
	if err != nil {
		return false
	}
	commentsLen, ok := parseHeaderCommentLen(commentLenDec)
	if !ok {
		return false
	}

	flagsOffset := int64(header.VersionEncSize + header.CommentLenEncSize + commentsLen*3)
	flagsEnc := make([]byte, header.FlagsEncSize)
	if _, err := fin.ReadAt(flagsEnc, flagsOffset); err != nil {
		return false
	}
	flagsDec, err := encoding.Decode(rs.RS5, flagsEnc, false)
	if err != nil {
		return false
	}
	return headerFlagsBytesPlausible(flagsDec)
}

func parseHeaderCommentLen(b []byte) (int, bool) {
	if len(b) != 5 {
		return 0, false
	}
	var n int
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	if n > header.MaxCommentLen {
		return 0, false
	}
	return n, true
}

func headerFlagsBytesPlausible(b []byte) bool {
	if len(b) < 5 {
		return false
	}
	for _, c := range b[:5] {
		if c != 0 && c != 1 {
			return false
		}
	}
	return true
}
