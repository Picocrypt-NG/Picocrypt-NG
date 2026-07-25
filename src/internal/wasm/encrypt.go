package wasm

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/keyfile"
	"Picocrypt-NG/internal/util"
	"bytes"
	"io"

	pwnorm "Picocrypt-NG/internal/password"
)

var (
	writeAuthValues = header.WriteAuthValues
	newCipherSuite  = crypto.NewCipherSuite
)

type wasmZeroingBufferKind string

const (
	wasmZeroingPasswordBytes         wasmZeroingBufferKind = "password bytes"
	wasmZeroingHeaderSubkey          wasmZeroingBufferKind = "header subkey"
	wasmZeroingMACSubkey             wasmZeroingBufferKind = "mac subkey"
	wasmZeroingSerpentKey            wasmZeroingBufferKind = "serpent key"
	wasmZeroingCiphertextChunk       wasmZeroingBufferKind = "ciphertext chunk"
	wasmZeroingCiphertextBuffer      wasmZeroingBufferKind = "ciphertext buffer"
	wasmZeroingKeyfileHash           wasmZeroingBufferKind = "keyfile hash"
	wasmZeroingHeaderKeyHash         wasmZeroingBufferKind = "header auth value"
	wasmZeroingAuthTag               wasmZeroingBufferKind = "payload auth value"
	wasmZeroingHeaderBuffer          wasmZeroingBufferKind = "header buffer"
	wasmZeroingDecryptPasswordBytes  wasmZeroingBufferKind = "decrypt password bytes"
	wasmZeroingDecryptKeyfileHash    wasmZeroingBufferKind = "decrypt keyfile hash"
	wasmZeroingDecryptHeaderSubkey   wasmZeroingBufferKind = "decrypt header subkey"
	wasmZeroingDecryptMACSubkey      wasmZeroingBufferKind = "decrypt mac subkey"
	wasmZeroingDecryptSerpentKey     wasmZeroingBufferKind = "decrypt serpent key"
	wasmZeroingDecryptPlaintextChunk wasmZeroingBufferKind = "decrypt plaintext chunk"
	wasmZeroingDecryptComputedMAC    wasmZeroingBufferKind = "decrypt computed mac"
	wasmZeroingKeyfileKey            wasmZeroingBufferKind = "keyfile key"
	wasmZeroingCipherKey             wasmZeroingBufferKind = "keyfile cipher key"
	wasmZeroingDecryptKeyfileKey     wasmZeroingBufferKind = "decrypt keyfile key"
	wasmZeroingDecryptCipherKey      wasmZeroingBufferKind = "decrypt keyfile cipher key"
	wasmZeroingDeniabilityKey        wasmZeroingBufferKind = "deniability key"
	wasmZeroingDeniabilityKDFInput   wasmZeroingBufferKind = "deniability kdf input"
)

type wasmZeroingEvent struct {
	Kind       wasmZeroingBufferKind
	Len        int
	WasNonZero bool
	Zeroed     bool
}

// wasmZeroingObserver is a package-local test seam. It is nil in production and
// records only aggregate zeroing state, never buffer contents.
var wasmZeroingObserver func(wasmZeroingEvent)

func zeroWASMSensitiveBuffer(kind wasmZeroingBufferKind, b []byte) {
	if len(b) == 0 {
		return
	}
	wasNonZero := hasNonZeroByte(b)
	crypto.SecureZero(b)
	zeroed := !hasNonZeroByte(b)
	if wasmZeroingObserver != nil {
		wasmZeroingObserver(wasmZeroingEvent{
			Kind:       kind,
			Len:        len(b),
			WasNonZero: wasNonZero,
			Zeroed:     zeroed,
		})
	}
}

func hasNonZeroByte(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return true
		}
	}
	return false
}

type byteSliceWriterAt struct {
	data []byte
}

func (w byteSliceWriterAt) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 || off > int64(len(w.data)) {
		return 0, io.ErrShortWrite
	}
	start := int(off)
	if len(p) > len(w.data)-start {
		return 0, io.ErrShortWrite
	}
	copy(w.data[start:], p)
	return len(p), nil
}

// EncryptOptions configures an in-memory encryption. Zero value = normal,
// no-comment volume (the pre-P0 behavior).
type EncryptOptions struct {
	Paranoid       bool     // 8 Argon2 passes, Serpent-CTR + XChaCha20, HMAC-SHA3
	Comments       string   // plaintext header comments (NOT encrypted); len <= header.MaxCommentLen
	Keyfiles       [][]byte // legacy read factor; non-empty is rejected by the v2 writer
	KeyfileOrdered bool     // true = order matters (sequential hash); false = XOR
	ReedSolomon    bool     // RS128 error-correction framing of the payload
	Deniability    bool     // wrap the finished volume; requires a non-empty password
}

// EncryptVolume encrypts plaintext data into a Picocrypt volume.
// Returns (ciphertext, 0) on success, or (nil, errorCode) on failure.
func EncryptVolume(plaintext, password []byte, opts EncryptOptions) ([]byte, int) {
	if len(opts.Keyfiles) > 0 {
		return nil, ErrKeyfileWritesDisabled
	}
	if opts.Deniability && len(password) == 0 {
		return nil, ErrDeniabilityPasswordRequired
	}
	if len(password) == 0 {
		return nil, ErrEncryptionPasswordRequired
	}

	// Initialize RS codecs
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		return nil, ErrRandomFailure
	}

	// Generate random cryptographic values
	salt, err := crypto.RandomBytes(header.SaltSize)
	if err != nil {
		return nil, ErrRandomFailure
	}

	hkdfSalt, err := crypto.RandomBytes(header.HKDFSaltSize)
	if err != nil {
		return nil, ErrRandomFailure
	}

	serpentIV, err := crypto.RandomBytes(header.SerpentIVSize)
	if err != nil {
		return nil, ErrRandomFailure
	}

	nonce, err := crypto.RandomBytes(header.NonceSize)
	if err != nil {
		return nil, ErrRandomFailure
	}

	// Create header; flags/comments come from opts.
	const miB = 1 << 20
	hdr := header.NewVolumeHeader(salt, hkdfSalt, serpentIV, nonce)
	hdr.Flags = header.Flags{
		Paranoid:       opts.Paranoid,
		UseKeyfiles:    len(opts.Keyfiles) > 0,
		KeyfileOrdered: len(opts.Keyfiles) > 0 && opts.KeyfileOrdered,
		ReedSolomon:    opts.ReedSolomon,
		Padded:         opts.ReedSolomon && len(plaintext)%miB >= miB-128,
	}
	hdr.Comments = opts.Comments

	// Derive key from the NFC-normalized password (#19) so web-encrypted
	// volumes are cross-platform-decryptable regardless of how it was typed.
	passwordBytes := pwnorm.EncodeForKDF(password)
	key, err := deriveWASMKey(passwordBytes, salt, opts.Paranoid)
	zeroWASMSensitiveBuffer(wasmZeroingPasswordBytes, passwordBytes)
	if err != nil {
		return nil, ErrRandomFailure
	}
	defer crypto.SecureZero(key)

	// Keyfiles (password-independent). Zero key/hash material on the way out.
	var keyfileKey []byte
	keyfileHash := make([]byte, 32)
	if len(opts.Keyfiles) > 0 {
		res, code := processWASMKeyfiles(opts.Keyfiles, opts.KeyfileOrdered)
		if code != 0 {
			return nil, code
		}
		keyfileKey = res.Key
		copy(keyfileHash, res.Hash)
		defer zeroWASMSensitiveBuffer(wasmZeroingKeyfileKey, keyfileKey)
	}
	keyfileHashZeroed := false
	defer func() {
		if !keyfileHashZeroed {
			zeroWASMSensitiveBuffer(wasmZeroingKeyfileHash, keyfileHash)
		}
	}()

	// Initialize HKDF (v2 order: HKDF before keyfile XOR)
	hkdfStream := crypto.NewHKDFStream(key, hkdfSalt)
	subkeyReader := crypto.NewSubkeyReader(hkdfStream)

	// Read header subkey for v2 MAC
	subkeyHeader, err := subkeyReader.HeaderSubkey()
	if err != nil {
		return nil, ErrRandomFailure
	}

	// Compute header MAC
	hdr.KeyHash = header.ComputeV2HeaderMAC(subkeyHeader, hdr, keyfileHash)
	headerKeyHash := hdr.KeyHash
	headerKeyHashZeroed := false
	defer func() {
		if !headerKeyHashZeroed {
			zeroWASMSensitiveBuffer(wasmZeroingHeaderKeyHash, headerKeyHash)
		}
	}()
	zeroWASMSensitiveBuffer(wasmZeroingHeaderSubkey, subkeyHeader)
	hdr.KeyfileHash = keyfileHash

	// Read remaining subkeys
	macSubkey, err := subkeyReader.MACSubkey()
	if err != nil {
		return nil, ErrRandomFailure
	}

	serpentKey, err := subkeyReader.SerpentKey()
	if err != nil {
		return nil, ErrRandomFailure
	}

	// Create MAC
	mac, err := crypto.NewMAC(macSubkey, opts.Paranoid)
	zeroWASMSensitiveBuffer(wasmZeroingMACSubkey, macSubkey)
	if err != nil {
		return nil, ErrRandomFailure
	}

	// XOR password key with keyfile key to produce the cipher key.
	// HKDF subkeys (MAC, Serpent) stay seeded from the password key only.
	cipherKey := key
	if keyfileKey != nil {
		cipherKey = keyfile.XORWithKey(key, keyfileKey)
		// Register the wipe the instant the secret exists — BEFORE the fallible
		// NewCipherSuite call — so cipherKey is zeroed on EVERY return path,
		// including a NewCipherSuite error (where Close() below is never set up).
		// On success CipherSuite.Close() also wipes it (it aliases cs.key) and,
		// being registered later, runs first in LIFO order; this defer is then a
		// harmless second wipe. It is the SOLE wipe on the error path.
		defer zeroWASMSensitiveBuffer(wasmZeroingCipherKey, cipherKey)
	}

	// Create cipher suite
	cipherSuite, err := newCipherSuite(
		cipherKey,
		nonce,
		serpentKey,
		serpentIV,
		mac,
		subkeyReader.Reader(),
		opts.Paranoid,
	)
	zeroWASMSensitiveBuffer(wasmZeroingSerpentKey, serpentKey)
	if err != nil {
		return nil, ErrRandomFailure
	}
	defer cipherSuite.Close()

	// Write header to buffer
	var headerBuf bytes.Buffer
	headerWriter := header.NewWriter(&headerBuf, rsCodecs)
	if _, err := headerWriter.WriteHeader(hdr); err != nil {
		return nil, ErrRandomFailure
	}
	headerBufferZeroed := false
	defer func() {
		if !headerBufferZeroed {
			zeroWASMSensitiveBuffer(wasmZeroingHeaderBuffer, headerBuf.Bytes())
		}
	}()

	// Encrypt payload
	var ciphertextBuf bytes.Buffer
	ciphertextBufferZeroed := false
	defer func() {
		if !ciphertextBufferZeroed {
			zeroWASMSensitiveBuffer(wasmZeroingCiphertextBuffer, ciphertextBuf.Bytes())
		}
	}()
	chunkSize := util.MiB
	var counter int64

	for offset := 0; offset < len(plaintext); offset += chunkSize {
		end := min(offset+chunkSize, len(plaintext))

		// Copy chunk: paranoid Encrypt mutates src (Serpent intermediate), which
		// would corrupt the caller's plaintext buffer if we passed a slice of it.
		chunk := make([]byte, end-offset)
		copy(chunk, plaintext[offset:end])
		dst := make([]byte, len(chunk))
		cipherSuite.Encrypt(dst, chunk)
		crypto.SecureZero(chunk)
		if opts.ReedSolomon {
			enc, encErr := encoding.EncodeRSPayloadBlock(dst, rsCodecs)
			if encErr != nil {
				zeroWASMSensitiveBuffer(wasmZeroingCiphertextChunk, dst)
				return nil, ErrRandomFailure
			}
			ciphertextBuf.Write(enc)
			zeroWASMSensitiveBuffer(wasmZeroingCiphertextChunk, enc)
		} else {
			ciphertextBuf.Write(dst)
		}
		zeroWASMSensitiveBuffer(wasmZeroingCiphertextChunk, dst)

		counter += int64(len(chunk))

		// Rekey every 60 GiB
		if counter >= crypto.RekeyThreshold {
			if err := cipherSuite.Rekey(); err != nil {
				return nil, ErrModifiedData
			}
			counter = 0
		}
	}

	// Get final MAC
	authTag := cipherSuite.Sum()
	authTagZeroed := false
	defer func() {
		if !authTagZeroed {
			zeroWASMSensitiveBuffer(wasmZeroingAuthTag, authTag)
		}
	}()
	hdr.AuthTag = authTag

	// Now we need to patch the auth values into the header
	// The header was written with placeholders, we need to update them
	headerBytes := headerBuf.Bytes()
	if err := writeAuthValues(
		byteSliceWriterAt{data: headerBytes},
		header.AuthValuesOffset(len(hdr.Comments)),
		hdr.KeyHash,
		hdr.KeyfileHash,
		authTag,
		rsCodecs,
	); err != nil {
		return nil, ErrModifiedData
	}
	zeroWASMSensitiveBuffer(wasmZeroingKeyfileHash, keyfileHash)
	keyfileHashZeroed = true
	zeroWASMSensitiveBuffer(wasmZeroingHeaderKeyHash, hdr.KeyHash)
	headerKeyHashZeroed = true
	zeroWASMSensitiveBuffer(wasmZeroingAuthTag, authTag)
	authTagZeroed = true

	// Combine header and encrypted payload
	ciphertextBytes := ciphertextBuf.Bytes()
	result := make([]byte, 0, len(headerBytes)+len(ciphertextBytes))
	result = append(result, headerBytes...)
	result = append(result, ciphertextBytes...)
	zeroWASMSensitiveBuffer(wasmZeroingHeaderBuffer, headerBytes)
	headerBufferZeroed = true
	zeroWASMSensitiveBuffer(wasmZeroingCiphertextBuffer, ciphertextBytes)
	ciphertextBufferZeroed = true

	if opts.Deniability {
		wrapped, code := wrapDeniability(result, password)
		crypto.SecureZero(result) // inner .pcv ciphertext, no longer needed
		if code != 0 {
			return nil, code
		}
		return wrapped, 0
	}
	return result, 0
}
