package volume

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/keyfile"
	"Picocrypt-NG/internal/log"
	"Picocrypt-NG/internal/util"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	perrors "Picocrypt-NG/internal/errors"

	pwnorm "Picocrypt-NG/internal/password"
)

// newPayloadReader is identity in production; tests replace it to inject short
// reads and check that the io.ReadFull loops reassemble full blocks.
var newPayloadReader = func(r io.Reader) io.Reader { return r }

// Decrypt performs a complete volume decryption operation.
// This is the main entry point for decryption.
// If ctx is nil, a background context is used.
func Decrypt(ctx context.Context, req *DecryptRequest) (retErr error) {
	if err := req.Validate(); err != nil {
		return err
	}

	opCtx := NewDecryptContext(ctx, req)
	defer func() {
		if err := opCtx.cleanupRecombinedFile(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("cleanup recombined input: %w", err))
		}
		retErr = errors.Join(retErr, opCtx.Close())
	}() // Secure zeroing of key material and fail-loud temporary-file cleanup

	log.Info("starting decryption", log.String("input", req.InputFile))

	// Phase 1: Preprocess (recombine if split, remove deniability)
	if err := decryptPreprocess(opCtx, req); err != nil {
		return err
	}

	// Phase 2: Read header
	if err := decryptReadHeader(opCtx, req); err != nil {
		return err
	}

	// Phases 3-5: derive keys, process keyfiles, and verify authentication,
	// trying each password normalization form (NFC/NFD/raw) until one
	// authenticates (#19). On success the winning form is left on the context so
	// the verify-first and RS-retry re-derivations reuse it.
	if err := decryptDeriveProcessVerify(opCtx, req); err != nil {
		return err
	}

	// Phase 5.5 (optional): Two-pass verification - verify MAC BEFORE decryption
	// This addresses security audit recommendation PCC-004: authenticate ciphertext
	// before decrypting. Slower but ensures we never decrypt attacker-controlled data.
	if req.VerifyFirst {
		if err := decryptVerifyMACFirst(opCtx, req); err != nil {
			return err
		}

		// Re-derive keys to reset HKDF stream for actual decryption
		if err := decryptDeriveKeys(opCtx, req); err != nil {
			return err
		}
		if err := decryptProcessKeyfiles(opCtx, req); err != nil {
			return err
		}
		if err := decryptVerifyAuth(opCtx, req); err != nil {
			return err
		}
	}

	// Phase 6: Decrypt payload
	if err := decryptPayload(opCtx, req); err != nil {
		return err
	}

	// Phase 7: Finalize (verify MAC, cleanup, auto-unzip)
	if err := decryptFinalize(opCtx, req); err != nil {
		return err
	}

	log.Info("decryption completed successfully")
	return nil
}

func decryptPreprocess(ctx *OperationContext, req *DecryptRequest) error {
	inputFile := req.InputFile

	// Recombine split chunks if needed
	if req.Recombine {
		ctx.SetStatus("Recombining chunks...")

		inputBase := inputFile
		if base, ok := fileops.SplitChunkBase(inputFile); ok {
			inputBase = base
		}

		outputPath := inputBase
		var recombinedInfo os.FileInfo
		err := fileops.Recombine(fileops.RecombineOptions{
			InputBase:  inputBase,
			OutputPath: outputPath,
			OutputInfo: &recombinedInfo,
			Progress: func(p float32, info string) {
				ctx.UpdateProgress(p, info)
			},
			Status: func(s string) {
				ctx.SetStatus(s)
			},
			Cancel: func() bool {
				return ctx.IsCancelled()
			},
		})
		if err != nil {
			return err
		}

		// Retain the recombined file identity so cleanup cannot unlink a
		// replacement planted at the same pathname.
		if err := ctx.rememberRecombinedFile(outputPath, recombinedInfo); err != nil {
			return err
		}
		ctx.TempFile = outputPath
		inputFile = outputPath
	}

	// Remove deniability wrapper if present
	if req.Deniability {
		var expectedInput os.FileInfo
		if ctx.RecombinedFile == inputFile {
			expectedInput = ctx.recombinedInfo
		}
		decrypted, err := removeDeniability(
			inputFile,
			req.Password,
			ctx.Reporter,
			req.RSCodecs,
			expectedInput,
		)
		if err != nil {
			return err
		}

		// Note: if we recombined, the recombined file path is stored in ctx.RecombinedFile
		// for cleanup after decryption completes (see decryptFinalize)

		ctx.adoptTempInput(decrypted)
		inputFile = decrypted.Path()
	}

	ctx.InputFile = inputFile

	// Get file size
	stat, err := os.Stat(inputFile)
	if err != nil {
		return fmt.Errorf("stat input: %w", err)
	}
	ctx.Total = stat.Size() - int64(header.BaseHeaderSize)

	return nil
}

func decryptReadHeader(ctx *OperationContext, req *DecryptRequest) error {
	ctx.SetStatus("Reading values...")

	fin, closeInput, err := ctx.openInput()
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	if closeInput {
		defer func() { _ = fin.Close() }()
	}

	reader := header.NewReader(fin, req.RSCodecs)
	result, err := reader.ReadHeader()
	if err != nil {
		return fmt.Errorf("read header: %w", err)
	}

	ctx.Header = result.Header

	// Handle decode errors
	if result.DecodeError != nil {
		if req.ForceDecrypt {
			// Continue but mark as damaged
		} else {
			return fmt.Errorf("header damaged: %w", result.DecodeError)
		}
	}

	// Update total size with comment length
	ctx.Total -= int64(len(ctx.Header.Comments)) * 3

	// Check for legacy v1
	ctx.IsLegacyV1 = ctx.Header.IsLegacyV1()

	// Determine if keyfiles are needed based on header
	ctx.UseKeyfiles = ctx.Header.Flags.UseKeyfiles

	return nil
}

func decryptDeriveKeys(ctx *OperationContext, req *DecryptRequest) error { //nolint:unparam // (ctx, req) signature shared by all decrypt phases; req unused here by design
	ctx.SetStatus("Deriving key...")

	key, err := deriveVolumeKey(ctx.passwordBytes.Bytes(), ctx.Header.Salt, ctx.Header.Flags.Paranoid)
	if err != nil {
		return err
	}
	// SEC-05/WR-01: on the full-RS retry this re-runs, orphaning the prior key; setKey
	// zeros the old backing array before reassigning (no-op on the first pass).
	ctx.setKey(key)

	return nil
}

func decryptProcessKeyfiles(ctx *OperationContext, req *DecryptRequest) error {
	if !ctx.UseKeyfiles {
		ctx.KeyfileHash = make([]byte, 32)
		return nil
	}

	if len(req.Keyfiles) == 0 {
		return perrors.NewValidationError("keyfiles", "keyfiles required but none provided")
	}

	ctx.SetStatus("Reading keyfiles...")

	result, err := keyfile.Process(req.Keyfiles, ctx.Header.Flags.KeyfileOrdered, func(p float32) {
		ctx.UpdateProgress(p, "")
	})
	if err != nil {
		return err
	}

	// SEC-05/WR-01: on the full-RS retry this re-runs, orphaning the prior keyfile
	// key; setKeyfileKey zeros the old backing array before reassigning.
	ctx.setKeyfileKey(result.Key)
	ctx.KeyfileHash = result.Hash

	return nil
}

func decryptVerifyAuth(ctx *OperationContext, req *DecryptRequest) error {
	ctx.SetStatus("Calculating values...")

	if ctx.IsLegacyV1 {
		// v1: HKDF initialized AFTER keyfile XOR
		// First verify password using SHA3-512(key)
		authResult := header.VerifyV1Header(ctx.Key.Bytes(), ctx.Header)

		if !authResult.Valid {
			if req.ForceDecrypt {
				// Continue anyway
			} else {
				return header.NewPasswordError()
			}
		}

		// Verify keyfiles
		if ctx.UseKeyfiles {
			if !header.VerifyKeyfileHash(ctx.KeyfileHash, ctx.Header.KeyfileHash) {
				if req.ForceDecrypt {
					// Continue anyway
				} else {
					return header.NewKeyfileError(ctx.Header.Flags.KeyfileOrdered)
				}
			}
		}

		// For v1, XOR keyfile key into main key BEFORE HKDF, owning the result first.
		if ctx.UseKeyfiles && ctx.KeyfileKey != nil {
			// DATA-02: a legacy v1 volume may have been authored with an
			// even-count duplicate keyfile set whose unordered XOR cancels to
			// all-zeros. Original Picocrypt did not block this, so the volume
			// is already decryptable (its effective key is just the password
			// key). We must NOT block here like the v2 path does (D-11) — we
			// only WARN, mirroring the encrypt-side detection (D-10/D-12). This
			// sits AFTER the v1 SHA3-512(key) password verifier above, so it
			// does not let a wrong-password/tampered volume through.
			if keyfile.IsDuplicateKeyfileKey(ctx.KeyfileKey.Bytes()) {
				log.Warn("duplicate keyfiles detected (keys cancel out)")
				ctx.SetStatus("Warning: duplicate keyfiles detected (keys cancel out)...")
			}
			// XORWithKey returns a NEW slice; setKey zeros the orphaned Argon2
			// backing array and adopts the result. No two-step window.
			ctx.setKey(keyfile.XORWithKey(ctx.Key.Bytes(), ctx.KeyfileKey.Bytes()))
		}
		// (no keyfiles: ctx.Key already holds the password key — self-assign-safe)

		// Initialize HKDF with the (possibly XORed) owned key.
		hkdfStream := crypto.NewHKDFStream(ctx.Key.Bytes(), ctx.Header.HKDFSalt)
		ctx.SubkeyReader = crypto.NewSubkeyReader(hkdfStream)
	} else {
		// v2: HKDF initialized BEFORE keyfile XOR
		hkdfStream := crypto.NewHKDFStream(ctx.Key.Bytes(), ctx.Header.HKDFSalt)
		ctx.SubkeyReader = crypto.NewSubkeyReader(hkdfStream)

		// Read header subkey for verification
		subkeyHeader, err := ctx.SubkeyReader.HeaderSubkey()
		if err != nil {
			return err
		}
		defer crypto.SecureZero(subkeyHeader)

		// Verify header MAC
		authResult := header.VerifyV2Header(subkeyHeader, ctx.Header, ctx.KeyfileHash)

		if !authResult.Valid {
			if req.ForceDecrypt {
				// Continue anyway
			} else {
				// Could be password or tampered header
				return header.NewV2PasswordOrTamperError()
			}
		}

		// Verify keyfiles separately for better error messages
		if ctx.UseKeyfiles {
			if !header.VerifyKeyfileHash(ctx.KeyfileHash, ctx.Header.KeyfileHash) {
				if req.ForceDecrypt {
					// Continue anyway
				} else {
					return header.NewKeyfileError(ctx.Header.Flags.KeyfileOrdered)
				}
			}
		}

		// For v2, XOR keyfile key AFTER HKDF init
		if ctx.UseKeyfiles && ctx.KeyfileKey != nil {
			if keyfile.IsDuplicateKeyfileKey(ctx.KeyfileKey.Bytes()) {
				return perrors.ErrDuplicateKeyfiles
			}
			// SEC-05/WR-01: XORWithKey returns a NEW slice; setKey zeros the orphaned
			// Argon2 backing array before reassigning.
			ctx.setKey(keyfile.XORWithKey(ctx.Key.Bytes(), ctx.KeyfileKey.Bytes()))
		}
	}

	return nil
}

// decryptDeriveProcessVerify runs the derive-keys -> process-keyfiles ->
// verify-auth sequence, trying each password normalization form (NFC/NFD/raw)
// until one authenticates against the volume MAC (#19). Only a
// wrong-password/tamper failure triggers the next form; any other error (keyfile
// mismatch, subkey read, etc.) is independent of the password and returned
// immediately. The winning form stays on ctx.passwordBytes so the verify-first
// and RS-retry re-derivations reuse it. ForceDecrypt has no auth gate to choose
// a form, so it uses the password exactly as typed (a single attempt, preserving
// historical behavior).
func decryptDeriveProcessVerify(ctx *OperationContext, req *DecryptRequest) error {
	candidates := pwnorm.Candidates(req.Password)
	if req.ForceDecrypt {
		// Own a copy so setPasswordBytes adopts an independent slice (it may zero
		// the predecessor); never alias the caller's req.Password backing array.
		candidates = [][]byte{append([]byte(nil), req.Password...)}
	}

	var lastErr error
	for i, cand := range candidates {
		ctx.setPasswordBytes(cand)

		if err := decryptDeriveKeys(ctx, req); err != nil {
			return err
		}
		if err := decryptProcessKeyfiles(ctx, req); err != nil {
			return err
		}
		err := decryptVerifyAuth(ctx, req)
		if err == nil {
			return nil
		}
		if !header.IsPasswordError(err) || i == len(candidates)-1 {
			return err
		}
		lastErr = err
	}
	return lastErr
}

// reDeriveForRetry resets the key-derivation state before a full-RS decode retry.
//
// IN-03: both the decryptFinalize retry and the verify-first (DATA-01) retry must
// re-run the SAME three-step sequence — decryptDeriveKeys → decryptProcessKeyfiles
// → decryptVerifyAuth — in this exact order so the HKDF stream and keyfile XOR
// reset correctly (re-derive the key BEFORE any v1/v2 keyfile XOR so it is never
// double-XORed, re-set the keyfile key/hash, and rebuild the SubkeyReader). This is
// a pure extraction of the previously-duplicated sequence: a single source of truth
// keeps the two AUDIT-CRITICAL retry paths in lockstep. It performs NO additional
// work and changes NO behavior, MAC, output, or on-disk format.
func reDeriveForRetry(ctx *OperationContext, req *DecryptRequest) error {
	if err := decryptDeriveKeys(ctx, req); err != nil {
		return err
	}
	if err := decryptProcessKeyfiles(ctx, req); err != nil {
		return err
	}
	return decryptVerifyAuth(ctx, req)
}

// verifyFirstProgressDelta returns how many bytes to advance the verify-first pass's
// progress counter for a read of n on-disk bytes.
//
// VER-03 (D-13/D-14, mechanism a): advance by the ACTUAL bytes read, n, for BOTH the
// Reed-Solomon and plain cases. ctx.Total is the raw on-disk ciphertext byte count
// (filesize - headerSize - comments*3, decrypt.go:160,192) and the verify loop reads
// exactly those on-disk bytes — so `done` must track n to stay faithful to ctx.Total.
// The previous code advanced by a FIXED full-block size for RS volumes, which
// over-counts on the final partial read and pushes `done` past ctx.Total. util.Statify
// masked the visible fraction with its <=1.0 clamp, but the counter was unfaithful;
// advancing by n is monotonic, never overshoots ctx.Total, and reaches it exactly at
// EOF (== 50% in pass-1 terms). This is verify-pass-only and display-only: it does not
// touch the decrypt-pass increment (decrypt.go), the MAC, output bytes, the on-disk
// format, or util.Statify.
func verifyFirstProgressDelta(n int) int64 {
	return int64(n)
}

// decryptVerifyMACFirst performs a verification-only pass to check MAC before decryption.
// This addresses security audit recommendation PCC-004: the ciphertext is authenticated
// BEFORE any decryption occurs, ensuring we never apply crypto to attacker-controlled data.
//
// Trade-off: This doubles the I/O time since we read the file twice.
// The MAC is computed over ciphertext, so we can verify without decrypting.
//
// It runs the fast RS decode first (matching the decrypt pass's first pass); on a
// MAC mismatch with Reed-Solomon enabled it retries once with full RS correction
// (DATA-01) via decryptVerifyMACFirstWithDecode.
func decryptVerifyMACFirst(ctx *OperationContext, req *DecryptRequest) error {
	return decryptVerifyMACFirstWithDecode(ctx, req, true)
}

// decryptVerifyMACFirstWithDecode is the verify-first pass body, parameterized by
// fastDecode (sibling shape to decryptPayloadWithFastDecode):
//   - fastDecode=true:  skip RS error correction (fast path, matches the decrypt
//     pass's first pass). This is what the single call site uses.
//   - fastDecode=false: full RS error correction — the DATA-01 one-shot retry,
//     entered only on a MAC mismatch when Reed-Solomon is enabled.
//
// DATA-01 / Pitfall 4 (LOCKED guard rule): the retry guard is LOCAL — the
// fastDecode recursion parameter. It MUST NOT touch or reuse ctx.TriedFullRSDecode,
// which is owned exclusively by decryptFinalize; reusing it would disable the
// decrypt-pass retry or risk infinite recursion. The fastDecode=false invocation
// never recurses again, so the retry is one-shot (T-03-05).
func decryptVerifyMACFirstWithDecode(ctx *OperationContext, req *DecryptRequest, fastDecode bool) error {
	ctx.SetStatus("Verifying integrity (pass 1 of 2)...")

	// Read remaining subkeys (same order as decryptPayload)
	macSubkey, err := ctx.SubkeyReader.MACSubkey()
	if err != nil {
		return err
	}
	defer crypto.SecureZero(macSubkey)

	// Skip serpent key read to maintain HKDF stream position
	serpentKey, err := ctx.SubkeyReader.SerpentKey()
	if err != nil {
		return err
	}
	defer crypto.SecureZero(serpentKey)

	// Create MAC for verification
	mac, err := crypto.NewMAC(macSubkey, ctx.Header.Flags.Paranoid)
	if err != nil {
		return err
	}

	// Open input file
	fin, closeInput, err := ctx.openInput()
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	if closeInput {
		defer func() { _ = fin.Close() }()
	}

	// Skip past header
	headerSize := header.HeaderSize(len(ctx.Header.Comments))
	if _, err := fin.Seek(int64(headerSize), 0); err != nil {
		return fmt.Errorf("seek past header: %w", err)
	}

	// Verification loop - read ciphertext and update MAC without decrypting
	ctx.SetCanCancel(true)
	startTime := time.Now()
	var done int64 // display-only progress counter (drives util.Statify)
	// WR-02: `read` is a dedicated on-disk byte counter used SOLELY to detect the
	// final chunk for RS unpadding (isLast). It is deliberately decoupled from the
	// display-only `done` counter: decodeWithRSFast only unpads the last RS chunk
	// when isLast && padded, and a wrong isLast would unpad the wrong block and
	// corrupt the MAC input (turning a valid volume into a false ErrAuthFailed). By
	// tracking the actual bytes read here, isLast stays correct even if `done`'s
	// display semantics ever change (e.g. a future fixed-block increment), and the
	// fast first pass and the full-RS verify retry detect the final chunk identically.
	var read int64

	reedsolo := ctx.Header.Flags.ReedSolomon
	padded := ctx.Header.Flags.Padded

	// Pre-allocate buffer outside loop to reduce GC pressure
	var srcBufSize int
	if reedsolo {
		srcBufSize = encoding.RSEncodedBlockSize
	} else {
		srcBufSize = util.MiB
	}
	src := make([]byte, srcBufSize)

	reader := newPayloadReader(io.Reader(fin))

	for {
		if ctx.IsCancelled() {
			return ctx.CancellationError()
		}

		n, readErr := io.ReadFull(reader, src)
		if n > 0 {
			srcData := src[:n]
			var data []byte

			// Advance the on-disk byte counter BEFORE deriving isLast so the check
			// reflects this read's bytes (matches the prior `done+int64(n)` basis,
			// since done was advanced by the actual bytes read on earlier iterations).
			read += int64(n)
			isLast := read >= ctx.Total

			// Decode Reed-Solomon if enabled. fastDecode mirrors the decrypt pass:
			// true skips RS error correction (fast path); false (the DATA-01 retry)
			// applies full RS correction to repair correctable damage.
			if reedsolo {
				var decErr error
				data, decErr = decodeWithRSFast(srcData, req.RSCodecs, isLast, padded, req.ForceDecrypt, fastDecode)
				if decErr != nil && !req.ForceDecrypt {
					return decErr
				}
			} else {
				data = srcData
			}

			// Update MAC with ciphertext (no decryption!)
			mac.Write(data)

			done += verifyFirstProgressDelta(n) // display only

			progress, speed, eta := util.Statify(done, ctx.Total, startTime)
			ctx.UpdateProgress(progress/2, fmt.Sprintf("%.2f%% (verifying)", progress*50)) // Show 0-50% for pass 1
			ctx.SetStatus(fmt.Sprintf("Verifying at %.2f MiB/s (ETA: %s)", speed, eta))

			// No rekey handling here: the verify pass holds no cipher to rekey. It
			// MACs the identical ciphertext bytes with the identical keyed MAC
			// subkey as the decrypt pass, and Rekey() only reseeds the cipher
			// nonce/IV (never the MAC), so the verify MAC matches the decrypt-pass
			// MAC across the 60 GiB rekey boundary without any rekeying.
		}

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read input: %w", readErr)
		}
	}

	// Verify MAC
	computedMAC := mac.Sum(nil)
	if subtle.ConstantTimeCompare(computedMAC, ctx.Header.AuthTag) != 1 {
		if req.ForceDecrypt {
			// Continue anyway - user forced it
			ctx.SetStatus("MAC verification failed, continuing anyway...")
		} else if ctx.Header.Flags.ReedSolomon && fastDecode {
			// DATA-01: the fast verify pass skips RS error correction, so
			// correctable damage (<= 4 errors / 136-byte block) yields wrong
			// ciphertext -> MAC mismatch. Before rejecting, retry the verify pass
			// ONCE with full RS correction (fastDecode=false), mirroring
			// decryptFinalize's guarded retry. Only reject if the full-RS verify
			// ALSO fails — a genuinely forged MAC (damage beyond the RS budget)
			// still returns ErrAuthFailed (PCC-004 fail-closed; T-03-04).
			//
			// State reset before recursing: the verify pass consumed MACSubkey()
			// and SerpentKey() from ctx.SubkeyReader (one-shot reads), so re-derive
			// keys + rebuild the HKDF stream first — otherwise the recursive read
			// errors with "subkey already consumed". The verify pass writes no
			// output, so there is no staged plaintext to reset.
			ctx.SetStatus("Repairing (verifying)...")
			if err := reDeriveForRetry(ctx, req); err != nil {
				return err
			}
			// One-shot: fastDecode=false never recurses again (T-03-05).
			return decryptVerifyMACFirstWithDecode(ctx, req, false)
		} else {
			return perrors.ErrAuthFailed
		}
	}

	ctx.SetStatus("Integrity verified, decrypting...")
	return nil
}

func decryptPayload(ctx *OperationContext, req *DecryptRequest) error {
	return decryptPayloadWithFastDecode(ctx, req, true) // First pass: fast decode (skip RS error correction)
}

// decryptPayloadWithFastDecode performs the actual decryption.
// When fastDecode is true, RS decoding just returns first 128 bytes (no error correction).
// This matches the original Picocrypt behavior for performance.
func decryptPayloadWithFastDecode(ctx *OperationContext, req *DecryptRequest, fastDecode bool) error {
	// Read remaining subkeys
	macSubkey, err := ctx.SubkeyReader.MACSubkey()
	if err != nil {
		return err
	}
	defer crypto.SecureZero(macSubkey)

	serpentKey, err := ctx.SubkeyReader.SerpentKey()
	if err != nil {
		return err
	}
	defer crypto.SecureZero(serpentKey)

	// Create MAC
	mac, err := crypto.NewMAC(macSubkey, ctx.Header.Flags.Paranoid)
	if err != nil {
		return err
	}

	// Create cipher suite
	cipherSuite, err := crypto.NewCipherSuite(
		ctx.Key.Bytes(),
		ctx.Header.Nonce,
		serpentKey,
		ctx.Header.SerpentIV,
		mac,
		ctx.SubkeyReader.Reader(),
		ctx.Header.Flags.Paranoid,
	)
	if err != nil {
		return err
	}
	// RS-03: zero the previous suite's key material before replacing it on retry.
	// On the full-RS-decode retry this function runs a second time; without this
	// the prior XChaCha20/Serpent key + MAC state would linger until ctx.Close()
	// at the very end (mirror OperationContext.Close, context.go:266-269).
	if ctx.CipherSuite != nil {
		ctx.CipherSuite.Close()
	}
	ctx.CipherSuite = cipherSuite

	// Open files
	fin, closeInput, err := ctx.openInput()
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	if closeInput {
		defer func() { _ = fin.Close() }()
	}

	// Skip past header
	headerSize := header.HeaderSize(len(ctx.Header.Comments))
	if _, err := fin.Seek(int64(headerSize), 0); err != nil {
		return fmt.Errorf("seek past header: %w", err)
	}

	if ctx.stagedOutput == nil {
		if err := ctx.beginStagedOutput(); err != nil {
			return fmt.Errorf("create output: %w", err)
		}
	} else if err := ctx.resetStagedOutput(); err != nil {
		return fmt.Errorf("reset output: %w", err)
	}
	fout, err := ctx.stagedOutputFile()
	if err != nil {
		return err
	}

	// Decrypt loop
	ctx.SetCanCancel(true)
	startTime := time.Now()
	var done int64
	var counter int64

	reedsolo := ctx.Header.Flags.ReedSolomon
	padded := ctx.Header.Flags.Padded

	// Pre-allocate buffers outside loop to reduce GC pressure
	// RS-encoded buffer is larger: 1 MiB * 136/128 = ~1.0625 MiB
	var srcBufSize int
	if reedsolo {
		srcBufSize = encoding.RSEncodedBlockSize
	} else {
		srcBufSize = util.MiB
	}
	src := make([]byte, srcBufSize) // Variable size due to RS encoding
	dst := util.GetMiBBuffer()      // Decrypted data is always <= 1 MiB
	defer util.PutMiBBuffer(dst)

	reader := newPayloadReader(io.Reader(fin))

	for {
		if ctx.IsCancelled() {
			return ctx.CancellationError()
		}

		n, readErr := io.ReadFull(reader, src)
		if n > 0 {
			srcData := src[:n]
			var data []byte

			// Decode Reed-Solomon if enabled
			if reedsolo {
				var decErr error
				data, decErr = decodeWithRSFast(srcData, req.RSCodecs, done+int64(n) >= ctx.Total, padded, req.ForceDecrypt, fastDecode)
				if decErr != nil && !req.ForceDecrypt {
					return decErr
				}
			} else {
				data = srcData
			}

			dstData := dst[:len(data)]

			// Decrypt: MAC -> XChaCha20 -> Serpent
			ctx.CipherSuite.Decrypt(dstData, data)

			if _, err := fout.Write(dstData); err != nil {
				return fmt.Errorf("write plaintext: %w", err)
			}

			if reedsolo {
				done += int64(encoding.RSEncodedBlockSize)
			} else {
				done += int64(n)
			}
			counter += int64(util.MiB)

			progress, speed, eta := util.Statify(done, ctx.Total, startTime)
			ctx.UpdateProgress(progress, fmt.Sprintf("%.2f%%", progress*100))
			if fastDecode {
				ctx.SetStatus(fmt.Sprintf("Decrypting at %.2f MiB/s (ETA: %s)", speed, eta))
			} else {
				ctx.SetStatus(fmt.Sprintf("Repairing at %.2f MiB/s (ETA: %s)", speed, eta))
			}

			// Rekey every 60 GiB
			if counter >= crypto.RekeyThreshold {
				if err := ctx.CipherSuite.Rekey(); err != nil {
					return err
				}
				counter = 0
			}
		}

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read input: %w", readErr)
		}
	}

	// Sync before verifying MAC to ensure all data is written
	if err := fout.Sync(); err != nil {
		return fmt.Errorf("sync output: %w", err)
	}

	return nil
}

func decryptFinalize(ctx *OperationContext, req *DecryptRequest) error {
	ctx.SetStatus("Comparing values...")

	// Verify MAC
	computedMAC := ctx.CipherSuite.Sum()
	if subtle.ConstantTimeCompare(computedMAC, ctx.Header.AuthTag) != 1 {
		// MAC verification failed
		// If Reed-Solomon is enabled, retry with full RS error correction (fastDecode=false)
		reedsolo := ctx.Header.Flags.ReedSolomon
		if reedsolo && !ctx.TriedFullRSDecode {
			// RS-03: state reset invariant — the full-RS retry below re-runs the
			// decrypt pipeline from a clean state so a second pass cannot bleed
			// state into (or corrupt) the output. Every mutated piece of state is
			// reset before the retry decode:
			//   - ctx.Key:         re-derived by decryptDeriveKeys BEFORE any v1/v2
			//                      keyfile XOR, so the key is never double-XORed.
			//   - ctx.KeyfileKey/Hash: re-set by decryptProcessKeyfiles.
			//   - ctx.SubkeyReader (HKDF stream): rebuilt by decryptVerifyAuth.
			//   - ctx.CipherSuite: freshly built in decryptPayloadWithFastDecode;
			//                      the previous suite is now Close()'d (key zeroed)
			//                      before reassignment (see that function).
			//   - input offset:    fresh os.Open + Seek(headerSize) per call.
			//   - output:          the same operation-owned stage is truncated and
			//                      rewound through its retained handle.
			// The Argon2id re-derivation is intentionally KEPT (D-07); reducing
			// Argon2 passes is Out of Scope — correctness over perf in a paranoid
			// tool. Do NOT cache derived material or skip the re-derive.
			ctx.TriedFullRSDecode = true

			// Re-derive keys (needed to reset HKDF stream); see reDeriveForRetry.
			if err := reDeriveForRetry(ctx, req); err != nil {
				return err
			}

			// Retry with full RS decode (fastDecode=false)
			if err := decryptPayloadWithFastDecode(ctx, req, false); err != nil {
				return err
			}

			// Verify MAC again
			return decryptFinalize(ctx, req)
		}

		if req.ForceDecrypt {
			// Continue but mark as kept
			ctx.Kept = true
			if req.Kept != nil {
				*req.Kept = true
			}
		} else {
			return perrors.ErrCorruptData
		}
	}

	if err := req.ValidateOutputSafety(); err != nil {
		return err
	}

	shouldUnzip := false
	if req.AutoUnzip {
		var err error
		shouldUnzip, err = isStagedOutputZip(ctx)
		if err != nil {
			return err
		}
	}

	// A non-same-level extraction has a dedicated output directory. Build it
	// directly from the still-owned plaintext stage so the directory can be
	// reserved exclusively before any plaintext entry is written. The encrypted
	// input remains untouched throughout extraction.
	if shouldUnzip && !req.SameLevel {
		if err := autoUnzipUnpublishedOutput(ctx, req); err != nil {
			return err
		}
		if err := ctx.cleanupRecombinedFile(); err != nil {
			return fmt.Errorf("cleanup recombined input: %w", err)
		}
		return nil
	}

	var (
		autoUnzipRoot       *os.Root
		autoUnzipParentPath string
		autoUnzipTargetName string
		autoUnzipRootInfo   os.FileInfo
	)
	if shouldUnzip {
		var err error
		autoUnzipRoot, autoUnzipParentPath, autoUnzipTargetName, autoUnzipRootInfo, err = openStagedOutputParent(ctx.stagedOutput, req.OutputFile)
		if err != nil {
			return err
		}
	}

	if err := ctx.publishStagedOutput(); err != nil {
		return closePinnedAutoUnzipRoot(autoUnzipRoot, fmt.Errorf("publish output: %w", err))
	}

	if err := ctx.cleanupRecombinedFile(); err != nil {
		return closePinnedAutoUnzipRoot(
			autoUnzipRoot,
			fmt.Errorf("cleanup recombined input: %w", err),
		)
	}

	if shouldUnzip {
		return autoUnzipDecryptedOutput(
			ctx,
			req,
			autoUnzipRoot,
			autoUnzipParentPath,
			autoUnzipTargetName,
			autoUnzipRootInfo,
		)
	}

	return nil
}

func autoUnzipUnpublishedOutput(ctx *OperationContext, req *DecryptRequest) error {
	archive, err := ctx.stagedOutputFile()
	if err != nil {
		return fmt.Errorf("open staged auto-unzip archive: %w", err)
	}
	extractDir, distinctArchivePath, err := autoUnzipExtractionRoot(req.OutputFile)
	if err != nil {
		return err
	}

	outputInfo, err := ctx.stagedOutput.ReserveSiblingDirectory(extractDir)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("auto-unzip extraction root already exists: %s: %w", extractDir, os.ErrExist)
		}
		return fmt.Errorf("reserve auto-unzip output directory: %w", err)
	}

	ctx.SetStatus("Unzipping...")
	unpackErr := fileops.Unpack(fileops.UnpackOptions{
		ZipPath:             req.OutputFile,
		ZipFile:             archive,
		ExtractDir:          extractDir,
		ExpectedExtractRoot: outputInfo,
		Progress: func(p float32, info string) {
			ctx.UpdateProgress(p, info)
		},
		Status: func(s string) {
			ctx.SetStatus(s)
		},
		Cancel: ctx.IsCancelled,
	})
	if unpackErr == nil {
		unpackErr = verifyAutoUnzipExtractionRoot(extractDir, outputInfo)
	}
	if unpackErr == nil {
		if !distinctArchivePath {
			return nil
		}
		parentRoot, _, targetName, _, err := openStagedOutputParent(
			ctx.stagedOutput,
			req.OutputFile,
		)
		if err != nil {
			return err
		}
		if err := ctx.publishStagedOutput(); err != nil {
			return closePinnedAutoUnzipRoot(
				parentRoot,
				fmt.Errorf("publish decrypted archive before final auto-unzip cleanup: %w", err),
			)
		}
		removeErr := removeOwnedAutoUnzipArchiveAt(
			parentRoot,
			targetName,
			ctx.publishedOutputInfo,
		)
		closeErr := closePinnedAutoUnzipRoot(parentRoot, removeErr)
		return errors.Join(
			closeErr,
			verifyAutoUnzipExtractionRoot(extractDir, outputInfo),
		)
	}

	removeErr := ctx.stagedOutput.RemoveSiblingDirectory(extractDir, outputInfo)
	if distinctArchivePath {
		publishErr := ctx.publishStagedOutput()
		var recoveryErr error
		if removeErr != nil {
			recoveryErr = fmt.Errorf(
				"could not roll back the auto-unzip extraction root %s: %w",
				extractDir,
				removeErr,
			)
		}
		if publishErr != nil {
			recoveryErr = errors.Join(
				recoveryErr,
				fmt.Errorf("restore decrypted archive at %s: %w", req.OutputFile, publishErr),
			)
		}
		return errors.Join(fmt.Errorf("unzip: %w", unpackErr), recoveryErr)
	}

	if removeErr == nil {
		if err := ctx.publishStagedOutput(); err != nil {
			return errors.Join(
				fmt.Errorf("unzip: %w", unpackErr),
				fmt.Errorf("restore decrypted archive at %s: %w", req.OutputFile, err),
			)
		}
		return fmt.Errorf("unzip: %w", unpackErr)
	}
	return errors.Join(
		fmt.Errorf("unzip: %w", unpackErr),
		fmt.Errorf(
			"could not restore the decrypted archive because the extraction directory was not safely removable: %w",
			removeErr,
		),
	)
}

func verifyAutoUnzipExtractionRoot(path string, expected os.FileInfo) error {
	current, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect completed auto-unzip output: %w", err)
	}
	if expected == nil || !current.IsDir() || !os.SameFile(expected, current) {
		return errors.New("auto-unzip output directory changed during extraction")
	}
	return nil
}

func autoUnzipExtractionRoot(outputPath string) (string, bool, error) {
	if !strings.HasSuffix(outputPath, ".zip") {
		return outputPath, false, nil
	}
	base := strings.TrimSuffix(filepath.Base(outputPath), ".zip")
	if base == "" || base == "." {
		return "", false, errors.New("auto-unzip output must have a name before the .zip suffix")
	}
	return filepath.Join(filepath.Dir(outputPath), base), true, nil
}

func openStagedOutputParent(
	stage *fileops.StagedFile,
	outputPath string,
) (*os.Root, string, string, os.FileInfo, error) {
	if stage == nil || stage.TargetParentInfo() == nil {
		return nil, "", "", nil, errors.New("staged output parent identity is unavailable")
	}
	absoluteOutput, err := filepath.Abs(filepath.Clean(outputPath))
	if err != nil {
		return nil, "", "", nil, fmt.Errorf("resolve staged output path: %w", err)
	}
	parentPath := filepath.Dir(absoluteOutput)
	root, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, "", "", nil, fmt.Errorf("open staged output parent: %w", err)
	}
	rootInfo, err := root.Stat(".")
	if err != nil {
		_ = root.Close()
		return nil, "", "", nil, fmt.Errorf("inspect staged output parent: %w", err)
	}
	if !os.SameFile(stage.TargetParentInfo(), rootInfo) {
		_ = root.Close()
		return nil, "", "", nil, errors.New("output directory changed before auto-unzip")
	}
	return root, parentPath, filepath.Base(absoluteOutput), rootInfo, nil
}

func closePinnedAutoUnzipRoot(root *os.Root, primary error) error {
	if root == nil {
		return primary
	}
	if err := root.Close(); err != nil {
		return errors.Join(primary, fmt.Errorf("close auto-unzip output directory: %w", err))
	}
	return primary
}

func autoUnzipDecryptedOutput(
	ctx *OperationContext,
	req *DecryptRequest,
	parentRoot *os.Root,
	parentPath, targetName string,
	parentInfo os.FileInfo,
) (retErr error) {
	if parentRoot == nil || parentInfo == nil || targetName == "" {
		return errors.New("pinned output parent is unavailable for same-level auto-unzip")
	}
	defer func() {
		retErr = closePinnedAutoUnzipRoot(parentRoot, retErr)
	}()
	expected := ctx.publishedOutputInfo
	if expected == nil {
		return errors.New("published output identity is unavailable for auto-unzip")
	}
	if err := verifyAutoUnzipParentPath(parentPath, parentInfo); err != nil {
		return err
	}

	archive, err := parentRoot.Open(targetName)
	if err != nil {
		return fmt.Errorf("open auto-unzip archive: %w", err)
	}
	defer func() {
		if archive != nil {
			if err := archive.Close(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close auto-unzip archive: %w", err))
			}
		}
	}()
	archiveInfo, err := archive.Stat()
	if err != nil {
		return fmt.Errorf("inspect auto-unzip archive: %w", err)
	}
	pathInfo, err := parentRoot.Lstat(targetName)
	if err != nil {
		return fmt.Errorf("inspect auto-unzip archive path: %w", err)
	}
	if !pathInfo.Mode().IsRegular() ||
		!os.SameFile(expected, archiveInfo) ||
		!os.SameFile(expected, pathInfo) {
		return errors.New("auto-unzip output path changed before extraction")
	}

	ctx.SetStatus("Unzipping...")
	unpackErr := fileops.Unpack(fileops.UnpackOptions{
		ZipPath:             req.OutputFile,
		ZipFile:             archive,
		ExtractDir:          parentPath,
		ExtractRoot:         parentRoot,
		ExpectedExtractRoot: parentInfo,
		SameLevel:           true,
		Progress: func(p float32, info string) {
			ctx.UpdateProgress(p, info)
		},
		Status: func(s string) {
			ctx.SetStatus(s)
		},
		Cancel: ctx.IsCancelled,
	})
	closeErr := archive.Close()
	archive = nil
	if unpackErr != nil {
		var closeContextErr error
		if closeErr != nil {
			closeContextErr = fmt.Errorf("close auto-unzip archive: %w", closeErr)
		}
		return errors.Join(
			fmt.Errorf("unzip: %w", unpackErr),
			closeContextErr,
		)
	}
	if closeErr != nil {
		return fmt.Errorf("close auto-unzip archive: %w", closeErr)
	}
	if err := verifyAutoUnzipParentPath(parentPath, parentInfo); err != nil {
		return err
	}
	if err := removeOwnedAutoUnzipArchiveAt(parentRoot, targetName, expected); err != nil {
		return fmt.Errorf("remove unpacked archive: %w", err)
	}
	if err := verifyAutoUnzipParentPath(parentPath, parentInfo); err != nil {
		return err
	}
	return nil
}

func verifyAutoUnzipParentPath(parentPath string, expected os.FileInfo) error {
	current, err := os.Stat(parentPath)
	if err != nil {
		return fmt.Errorf("inspect auto-unzip output parent: %w", err)
	}
	if expected == nil || !os.SameFile(expected, current) {
		return errors.New("auto-unzip output parent changed during extraction")
	}
	return nil
}

func removeOwnedAutoUnzipArchiveAt(root *os.Root, name string, expected os.FileInfo) error {
	if root == nil || name == "" || expected == nil {
		return os.ErrInvalid
	}
	current, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("auto-unzip archive disappeared before removal")
	}
	if err != nil {
		return fmt.Errorf("inspect auto-unzip archive: %w", err)
	}
	if !current.Mode().IsRegular() || !os.SameFile(expected, current) {
		return errors.New("auto-unzip archive path changed; refusing to remove it")
	}
	if err := root.Remove(name); err != nil {
		return fmt.Errorf("remove auto-unzip archive: %w", err)
	}
	return nil
}

func isStagedOutputZip(ctx *OperationContext) (bool, error) {
	file, err := ctx.stagedOutputFile()
	if err != nil {
		return false, fmt.Errorf("open staged output for ZIP detection: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		return false, fmt.Errorf("inspect staged output for ZIP detection: %w", err)
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("staged output for ZIP detection is not a regular file")
	}
	return hasZipSignature(file)
}

func hasZipSignature(reader io.ReaderAt) (bool, error) {
	sig := make([]byte, 4)
	if _, err := io.ReadFull(io.NewSectionReader(reader, 0, int64(len(sig))), sig); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return false, nil
		}
		return false, fmt.Errorf("read output for ZIP detection: %w", err)
	}

	if sig[0] != 'P' || sig[1] != 'K' {
		return false, nil
	}

	// ZIP signatures:
	// 0x03 0x04 = local file header
	// 0x05 0x06 = empty archive end record
	// 0x07 0x08 = spanned/split archive
	return (sig[2] == 0x03 && sig[3] == 0x04) ||
		(sig[2] == 0x05 && sig[3] == 0x06) ||
		(sig[2] == 0x07 && sig[3] == 0x08), nil
}

// decodeWithRSFast delegates to the shared encoding codec, translating the
// encoding-layer sentinel to perrors.ErrCorruptData so existing volume callers
// and IsCorrupt() keep matching. forceDecode is honored (desktop ForceDecrypt).
func decodeWithRSFast(data []byte, rs *encoding.RSCodecs, isLast, padded, forceDecode, fastDecode bool) ([]byte, error) {
	out, err := encoding.DecodeRSPayloadBlock(data, rs, isLast, padded, forceDecode, fastDecode)
	if errors.Is(err, encoding.ErrCorruptData) {
		return out, perrors.ErrCorruptData
	}
	return out, err
}
