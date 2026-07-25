// Package wasm provides memory-based encryption/decryption for WASM builds.
package wasm

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/keyfile"
	"Picocrypt-NG/internal/util"
	"bytes"
	"crypto/subtle"
	"errors"

	pwnorm "Picocrypt-NG/internal/password"
)

// Error codes matching website convention
const (
	ErrUnsupported       = 1  // split chunks, or legacy-v1 keyfile volumes
	ErrCorruptedHeader   = 2  // RS decode failure
	ErrWrongPassword     = 3  // Auth verification failed
	ErrModifiedData      = 4  // Payload MAC mismatch
	ErrRandomFailure     = 5  // Random generation failed (encrypt only)
	ErrKeyfilesRequired  = 7  // volume needs keyfiles, none provided
	ErrKeyfilesIncorrect = 8  // provided keyfiles don't match the stored hash
	ErrKeyfilesDuplicate = 9  // keyfiles XOR to an all-zero key
	ErrModifiedButKept   = 10 // payload MAC failed; output kept on user-forced decrypt (untrusted)
	// Encrypt-only: the password-derived outer deniability wrapper cannot be
	// protected by inner-volume keyfiles.
	ErrDeniabilityPasswordRequired = 11
	// Encrypt-only: v2 keyfile writers are frozen until every secret
	// operational key is bound to the keyfile in the reviewed v3 format.
	ErrKeyfileWritesDisabled = 12
	// Encrypt-only: a new password-only volume needs a non-empty password.
	ErrEncryptionPasswordRequired = 13
)

// DecryptResult is the successful output of DecryptVolume. On error the int
// code is non-zero and the result is the zero value.
type DecryptResult struct {
	Plaintext []byte
	Comments  string // plaintext header comments ("" if none)
	Kept      bool   // true iff returned under ErrModifiedButKept (untrusted, force-decrypt)
}

// DecryptOptions configures an in-memory decryption.
type DecryptOptions struct {
	Keyfiles [][]byte // required iff the volume's header sets UseKeyfiles
	Force    bool     // keep best-effort output despite a payload MAC failure (untrusted)
}

// DecryptVolume decrypts a Picocrypt volume from memory.
// Returns (DecryptResult, 0) on success, or (zero, errorCode) on failure.
func DecryptVolume(volumeData, password []byte, opts DecryptOptions) (DecryptResult, int) {
	// Initialize RS codecs
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		return DecryptResult{}, ErrCorruptedHeader
	}

	// Deniability: a wrapped volume has no readable header (random salt/nonce
	// prefix), so detect it first, strip the outer XChaCha20 layer, and decrypt
	// the recovered inner .pcv. Force is intentionally ignored for deniable
	// volumes (desktop convention: the unauthenticated wrapper has no payload MAC
	// to force). Recursion is one level: inner is a real .pcv whose leading bytes
	// decode to a valid version, so isDeniable(inner) is false.
	if isDeniable(volumeData, rsCodecs) {
		inner, code := unwrapDeniability(volumeData, password, rsCodecs)
		if code != 0 {
			return DecryptResult{}, code
		}
		defer crypto.SecureZero(inner)
		return DecryptVolume(inner, password, DecryptOptions{Keyfiles: opts.Keyfiles})
	}

	// Create reader from volume data
	reader := bytes.NewReader(volumeData)

	// Read header
	headerReader := header.NewReader(reader, rsCodecs)
	result, err := headerReader.ReadHeader()
	if err != nil {
		if errors.Is(err, header.ErrUnsupportedVersion) {
			return DecryptResult{}, ErrUnsupported
		}
		return DecryptResult{}, ErrCorruptedHeader
	}
	hdr := result.Header

	// Check for unsupported features
	if hasUnsupportedWASMFeature(hdr.Flags) {
		return DecryptResult{}, ErrUnsupported
	}

	// Keyfiles: required iff the header says so. Computed once (password-independent).
	keyfileHash := make([]byte, 32)
	defer zeroWASMSensitiveBuffer(wasmZeroingDecryptKeyfileHash, keyfileHash)
	var keyfileKey []byte
	if hdr.Flags.UseKeyfiles {
		// v1-legacy keyfile volumes use a different key timing (HKDF AFTER the
		// keyfile XOR) that the WASM path does not implement; fail closed rather
		// than silently produce wrong plaintext. Rare combo → direct to desktop.
		if hdr.IsLegacyV1() {
			return DecryptResult{}, ErrUnsupported
		}
		if len(opts.Keyfiles) == 0 {
			return DecryptResult{}, ErrKeyfilesRequired
		}
		res, code := processWASMKeyfiles(opts.Keyfiles, hdr.Flags.KeyfileOrdered)
		if code != 0 {
			return DecryptResult{}, code
		}
		// Constant-time check against the stored hash before trying passwords,
		// so wrong keyfiles report distinctly from a wrong password.
		if !header.VerifyKeyfileHash(res.Hash, hdr.KeyfileHash) {
			crypto.SecureZero(res.Key)
			return DecryptResult{}, ErrKeyfilesIncorrect
		}
		keyfileKey = res.Key
		copy(keyfileHash, res.Hash)
		defer zeroWASMSensitiveBuffer(wasmZeroingDecryptKeyfileKey, keyfileKey)
	}

	isLegacyV1 := hdr.IsLegacyV1()

	// Derive the key, trying each password normalization form (NFC/NFD/raw) until
	// one authenticates against the header (#19). ASCII passwords yield a single
	// candidate, so there is no extra KDF work for the common case.
	var key []byte
	var subkeyReader *crypto.SubkeyReader
	for _, cand := range pwnorm.Candidates(password) {
		k, err := deriveWASMKey(cand, hdr.Salt, hdr.Flags.Paranoid)
		zeroWASMSensitiveBuffer(wasmZeroingDecryptPasswordBytes, cand)
		if err != nil {
			return DecryptResult{}, ErrCorruptedHeader
		}
		valid, sr, errCode := verifyWASMHeader(k, hdr, keyfileHash, isLegacyV1)
		if errCode != 0 {
			crypto.SecureZero(k)
			return DecryptResult{}, errCode
		}
		if valid {
			key = k
			subkeyReader = sr
			break
		}
		crypto.SecureZero(k)
	}
	if key == nil {
		return DecryptResult{}, ErrWrongPassword
	}
	defer crypto.SecureZero(key)

	// Read remaining subkeys
	macSubkey, err := subkeyReader.MACSubkey()
	if err != nil {
		return DecryptResult{}, ErrCorruptedHeader
	}

	serpentKey, err := subkeyReader.SerpentKey()
	if err != nil {
		return DecryptResult{}, ErrCorruptedHeader
	}

	// Create MAC
	mac, err := crypto.NewMAC(macSubkey, hdr.Flags.Paranoid)
	zeroWASMSensitiveBuffer(wasmZeroingDecryptMACSubkey, macSubkey)
	if err != nil {
		return DecryptResult{}, ErrCorruptedHeader
	}

	// Derive cipher key: XOR with keyfile key when keyfiles are used.
	// HKDF/subkeys still derive from the password key.
	cipherKey := key
	if keyfileKey != nil {
		cipherKey = keyfile.XORWithKey(key, keyfileKey)
		// Register the wipe the instant the secret exists — BEFORE the fallible
		// NewCipherSuite call — so cipherKey is zeroed on EVERY return path,
		// including a NewCipherSuite error (where Close() below is never set up).
		// On success CipherSuite.Close() also wipes it (it aliases cs.key) and,
		// being registered later, runs first in LIFO order; this defer is then a
		// harmless second wipe. It is the SOLE wipe on the error path.
		defer zeroWASMSensitiveBuffer(wasmZeroingDecryptCipherKey, cipherKey)
	}

	// Create cipher suite
	cipherSuite, err := newCipherSuite(
		cipherKey,
		hdr.Nonce,
		serpentKey,
		hdr.SerpentIV,
		mac,
		subkeyReader.Reader(),
		hdr.Flags.Paranoid,
	)
	zeroWASMSensitiveBuffer(wasmZeroingDecryptSerpentKey, serpentKey)
	if err != nil {
		return DecryptResult{}, ErrCorruptedHeader
	}
	defer cipherSuite.Close()

	// Calculate payload size
	headerSize := header.HeaderSize(len(hdr.Comments))
	payloadSize := len(volumeData) - headerSize
	if payloadSize <= 0 {
		return DecryptResult{}, ErrCorruptedHeader
	}

	// Read payload from remaining bytes
	payload := volumeData[headerSize:]

	// Pass 1: fast path (RS strips parity without correction; plain stream decrypt).
	reedSolomon := hdr.Flags.ReedSolomon
	var counter int64
	var plaintext []byte
	if reedSolomon {
		plaintext, err = decryptRSPayload(payload, cipherSuite, rsCodecs, hdr.Flags.Padded, false, true)
	} else {
		plaintext, err = decryptPlainPayload(payload, cipherSuite, &counter)
	}

	if err == nil {
		computedMAC := cipherSuite.Sum()
		macValid := subtle.ConstantTimeCompare(computedMAC, hdr.AuthTag) == 1
		zeroWASMSensitiveBuffer(wasmZeroingDecryptComputedMAC, computedMAC)
		if macValid {
			return DecryptResult{Plaintext: plaintext, Comments: hdr.Comments}, 0
		}
		// RS guarded retry: correctable damage makes the fast pass yield a wrong
		// MAC. Rebuild the cipher suite and re-decrypt ONCE with full correction.
		if reedSolomon {
			zeroWASMSensitiveBuffer(wasmZeroingDecryptPlaintextChunk, plaintext)
			retryCS, code := buildDecryptCipherSuite(key, cipherKey, hdr, isLegacyV1)
			if code != 0 {
				return DecryptResult{}, code
			}
			defer retryCS.Close()
			plaintext, err = decryptRSPayload(payload, retryCS, rsCodecs, hdr.Flags.Padded, false, false)
			if err == nil {
				retryMAC := retryCS.Sum()
				macValid = subtle.ConstantTimeCompare(retryMAC, hdr.AuthTag) == 1
				zeroWASMSensitiveBuffer(wasmZeroingDecryptComputedMAC, retryMAC)
				if macValid {
					return DecryptResult{Plaintext: plaintext, Comments: hdr.Comments}, 0
				}
			} else {
				plaintext = nil // uncorrectable; only a forced salvage can recover
			}
		}
	}

	// Payload did not verify. Without force, fail closed (unchanged behavior).
	if !opts.Force {
		if plaintext != nil {
			zeroWASMSensitiveBuffer(wasmZeroingDecryptPlaintextChunk, plaintext)
		}
		return DecryptResult{}, ErrModifiedData
	}

	// Forced best-effort recovery — UNTRUSTED output under a distinct code.
	// A non-nil plaintext here is the best effort already computed: pass-1 bytes
	// (non-RS) or the full-RS-corrected-but-unauthenticated retry; both are kept
	// as-is. Only a nil plaintext (RS uncorrectable, or a stream error) needs a
	// dedicated forceDecode salvage pass.
	if plaintext == nil {
		// Nothing coherent yet: a non-RS stream error cannot be recovered; an RS
		// payload gets one forceDecode pass (raw bytes on uncorrectable blocks).
		if !reedSolomon {
			return DecryptResult{}, ErrModifiedData
		}
		salvageCS, code := buildDecryptCipherSuite(key, cipherKey, hdr, isLegacyV1)
		if code != 0 {
			return DecryptResult{}, code
		}
		defer salvageCS.Close()
		plaintext, err = decryptRSPayload(payload, salvageCS, rsCodecs, hdr.Flags.Padded, true, false)
		if err != nil {
			return DecryptResult{}, ErrModifiedData
		}
	}
	return DecryptResult{Plaintext: plaintext, Comments: hdr.Comments, Kept: true}, ErrModifiedButKept
}

// verifyWASMHeader checks whether key authenticates the volume header and, on
// success, returns the HKDF subkey reader positioned for the remaining subkey
// reads. valid is false for a wrong key (a candidate password form that does not
// match); errCode is non-zero only for a hard failure (corrupted header), not
// for a wrong password.
func verifyWASMHeader(key []byte, hdr *header.VolumeHeader, keyfileHash []byte, isLegacyV1 bool) (valid bool, sr *crypto.SubkeyReader, errCode int) {
	if isLegacyV1 {
		// v1: verify password via SHA3-512(key); HKDF uses the plain key.
		if !header.VerifyV1Header(key, hdr).Valid {
			return false, nil, 0
		}
		hkdfStream := crypto.NewHKDFStream(key, hdr.HKDFSalt)
		return true, crypto.NewSubkeyReader(hkdfStream), 0
	}

	// v2: initialize HKDF, then verify the header MAC.
	hkdfStream := crypto.NewHKDFStream(key, hdr.HKDFSalt)
	reader := crypto.NewSubkeyReader(hkdfStream)
	subkeyHeader, err := reader.HeaderSubkey()
	if err != nil {
		return false, nil, ErrCorruptedHeader
	}
	authValid := header.VerifyV2Header(subkeyHeader, hdr, keyfileHash).Valid
	zeroWASMSensitiveBuffer(wasmZeroingDecryptHeaderSubkey, subkeyHeader)
	if !authValid {
		return false, nil, 0
	}
	return true, reader, 0
}

// hasUnsupportedWASMFeature flags header combinations the WASM path cannot handle.
// Reed-Solomon (and its companion Padded flag) are now supported. A Padded flag
// WITHOUT ReedSolomon is a combination desktop never emits -> treat as corrupt.
func hasUnsupportedWASMFeature(flags header.Flags) bool {
	return flags.Padded && !flags.ReedSolomon
}

// decryptRSPayload decrypts an RS128-framed payload block-by-block. fastDecode=true
// strips parity without correction (fast first pass); false applies full RS
// correction (repairs <=4 errors per 136-byte block). forceDecode=true returns raw
// bytes on uncorrectable blocks (user force-decrypt) instead of erroring.
// DecodeRSPayloadBlock returns a freshly-allocated slice, so paranoid Decrypt
// (which mutates src) never touches the caller's payload, keeping it pristine for
// a retry pass.
func decryptRSPayload(payload []byte, cs *crypto.CipherSuite, rs *encoding.RSCodecs, padded, forceDecode, fastDecode bool) ([]byte, error) {
	plaintext := make([]byte, 0, len(payload))
	var counter int64
	blockSize := encoding.RSEncodedBlockSize
	for offset := 0; offset < len(payload); offset += blockSize {
		end := min(offset+blockSize, len(payload))
		isLast := end >= len(payload)
		data, err := encoding.DecodeRSPayloadBlock(payload[offset:end], rs, isLast, padded, forceDecode, fastDecode)
		if err != nil {
			return nil, err
		}
		dst := make([]byte, len(data))
		cs.Decrypt(dst, data)
		plaintext = append(plaintext, dst...)
		zeroWASMSensitiveBuffer(wasmZeroingDecryptPlaintextChunk, dst)
		counter += int64(util.MiB)
		if counter >= crypto.RekeyThreshold {
			if err := cs.Rekey(); err != nil {
				return nil, err
			}
			counter = 0
		}
	}
	return plaintext, nil
}

// buildDecryptCipherSuite re-derives the HKDF subkeys from the authenticated key
// and constructs a fresh cipher suite for a (re)decrypt pass. v2 consumes the
// header subkey first; v1 does not. cipherKey is aliased by the returned suite
// (its Close zeroes it). Returns a non-zero code on any derivation failure.
func buildDecryptCipherSuite(key, cipherKey []byte, hdr *header.VolumeHeader, isLegacyV1 bool) (*crypto.CipherSuite, int) {
	sr := crypto.NewSubkeyReader(crypto.NewHKDFStream(key, hdr.HKDFSalt))
	if !isLegacyV1 {
		subkeyHeader, err := sr.HeaderSubkey()
		if err != nil {
			return nil, ErrCorruptedHeader
		}
		zeroWASMSensitiveBuffer(wasmZeroingDecryptHeaderSubkey, subkeyHeader)
	}
	macSubkey, err := sr.MACSubkey()
	if err != nil {
		return nil, ErrCorruptedHeader
	}
	serpentKey, err := sr.SerpentKey()
	if err != nil {
		zeroWASMSensitiveBuffer(wasmZeroingDecryptMACSubkey, macSubkey)
		return nil, ErrCorruptedHeader
	}
	mac, err := crypto.NewMAC(macSubkey, hdr.Flags.Paranoid)
	zeroWASMSensitiveBuffer(wasmZeroingDecryptMACSubkey, macSubkey)
	if err != nil {
		zeroWASMSensitiveBuffer(wasmZeroingDecryptSerpentKey, serpentKey)
		return nil, ErrCorruptedHeader
	}
	cs, err := newCipherSuite(cipherKey, hdr.Nonce, serpentKey, hdr.SerpentIV, mac, sr.Reader(), hdr.Flags.Paranoid)
	zeroWASMSensitiveBuffer(wasmZeroingDecryptSerpentKey, serpentKey)
	if err != nil {
		return nil, ErrCorruptedHeader
	}
	return cs, 0
}

// decryptPlainPayload decrypts non-RS payload in chunks
func decryptPlainPayload(payload []byte, cs *crypto.CipherSuite, counter *int64) ([]byte, error) {
	plaintext := make([]byte, 0, len(payload))
	chunkSize := util.MiB

	for offset := 0; offset < len(payload); offset += chunkSize {
		end := min(offset+chunkSize, len(payload))

		chunk := payload[offset:end]
		dst := make([]byte, len(chunk))
		cs.Decrypt(dst, chunk)
		plaintext = append(plaintext, dst...)
		zeroWASMSensitiveBuffer(wasmZeroingDecryptPlaintextChunk, dst)

		*counter += int64(len(chunk))

		// Rekey every 60 GiB
		if *counter >= crypto.RekeyThreshold {
			if err := cs.Rekey(); err != nil {
				return nil, err
			}
			*counter = 0
		}
	}

	return plaintext, nil
}
