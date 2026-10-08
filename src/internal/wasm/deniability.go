package wasm

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/util"

	pwnorm "Picocrypt-NG/internal/password"

	"golang.org/x/crypto/chacha20"
)

// Outer deniability-wrapper sizes (distinct from the inner volume's header
// salt/nonce). Frozen to match desktop volume.AddDeniability.
const (
	deniabilitySaltSize  = 16
	deniabilityNonceSize = 24
)

// wrapDeniability wraps a finished inner .pcv in the outer XChaCha20 deniability
// layer: salt(16) ‖ nonce(24) ‖ keystream-XOR(inner). The outer key is derived
// with normal-params Argon2id over the NFC-normalized password — byte-identical
// to desktop volume.AddDeniability. Returns (wrapped, 0) or (nil, ErrRandomFailure).
func wrapDeniability(inner, password []byte) ([]byte, int) {
	salt, err := crypto.RandomBytes(deniabilitySaltSize)
	if err != nil {
		return nil, ErrRandomFailure
	}
	nonce, err := crypto.RandomBytes(deniabilityNonceSize)
	if err != nil {
		return nil, ErrRandomFailure
	}

	kdfInput := pwnorm.EncodeForKDF(password)
	key, err := deriveWASMKey(kdfInput, salt, false)
	zeroWASMSensitiveBuffer(wasmZeroingDeniabilityKDFInput, kdfInput)
	if err != nil {
		return nil, ErrRandomFailure
	}
	defer zeroWASMSensitiveBuffer(wasmZeroingDeniabilityKey, key)

	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, ErrRandomFailure
	}

	out := make([]byte, 0, len(salt)+len(nonce)+len(inner))
	out = append(out, salt...)
	out = append(out, nonce...)

	// XOR the inner volume in MiB chunks, mirroring desktop's rekey boundary.
	// Under the WASM 1 GiB size cap the 60 GiB rekey threshold is never reached;
	// the counter/rekey branch is kept only for byte-format fidelity with desktop.
	var counter int64
	for offset := 0; offset < len(inner); offset += util.MiB {
		end := min(offset+util.MiB, len(inner))
		dst := make([]byte, end-offset)
		cipher.XORKeyStream(dst, inner[offset:end])
		out = append(out, dst...)
		counter += int64(end - offset)
		if counter >= crypto.RekeyThreshold {
			cipher, nonce, err = crypto.DeniabilityRekey(key, nonce)
			if err != nil {
				return nil, ErrRandomFailure
			}
			counter = 0
		}
	}
	return out, 0
}

// isDeniable reports whether volume looks like a deniability-wrapped volume.
// A regular volume starts with an RS5-encoded version; a deniable wrapper starts
// with random salt/nonce. A version-decode failure is ambiguous (deniable wrapper
// vs. a damaged regular header), resolved by checking whether the following
// comment-length and flags fields still look like a regular header.
// Byte-slice port of volume.IsDeniable (no file I/O).
func isDeniable(volume []byte, rs *encoding.RSCodecs) bool {
	const minDeniableSize = deniabilitySaltSize + deniabilityNonceSize + header.BaseHeaderSize
	if len(volume) < minDeniableSize {
		return false
	}
	// Copy before Decode: the FEC codec may operate on its input buffer.
	versionEnc := append([]byte(nil), volume[:header.VersionEncSize]...)
	versionDec, err := encoding.Decode(rs.RS5, versionEnc, false)
	if err != nil {
		return !looksLikeRegularHeaderAfterDamagedVersion(volume, rs)
	}
	if header.MatchVersion(versionDec) {
		return false
	}
	return !looksLikeRegularHeaderAfterDamagedVersion(volume, rs)
}

func looksLikeRegularHeaderAfterDamagedVersion(volume []byte, rs *encoding.RSCodecs) bool {
	commentLenOff := header.VersionEncSize
	if len(volume) < commentLenOff+header.CommentLenEncSize {
		return false
	}
	commentLenEnc := append([]byte(nil), volume[commentLenOff:commentLenOff+header.CommentLenEncSize]...)
	commentLenDec, err := encoding.Decode(rs.RS5, commentLenEnc, false)
	if err != nil {
		return false
	}
	commentsLen, ok := parseHeaderCommentLen(commentLenDec)
	if !ok {
		return false
	}
	flagsOff := header.VersionEncSize + header.CommentLenEncSize + commentsLen*3
	if len(volume) < flagsOff+header.FlagsEncSize {
		return false
	}
	flagsEnc := append([]byte(nil), volume[flagsOff:flagsOff+header.FlagsEncSize]...)
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
	n := 0
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

// selectDeniabilityKey returns the outer key for the first password normalization
// form (NFC/NFD/raw) whose keystream decodes a valid inner volume version from
// probe (the encrypted version field at offset salt+nonce). The deniable wrapper
// has no MAC, so the inner-version match is the only key check. Non-winning keys
// and every candidate buffer are zeroed. Returns ErrWrongPassword if none match.
func selectDeniabilityKey(password, salt, nonce, probe []byte, rs *encoding.RSCodecs) ([]byte, int) {
	candidates := pwnorm.Candidates(password)
	defer crypto.SecureZeroMultiple(candidates...)
	for _, cand := range candidates {
		key, err := deriveWASMKey(cand, salt, false)
		zeroWASMSensitiveBuffer(wasmZeroingDeniabilityKDFInput, cand)
		if err != nil {
			continue // degenerate all-zero key (effectively never); treat as non-match
		}
		cipher, cerr := chacha20.NewUnauthenticatedCipher(key, nonce)
		if cerr != nil {
			zeroWASMSensitiveBuffer(wasmZeroingDeniabilityKey, key)
			continue
		}
		dec := make([]byte, len(probe))
		cipher.XORKeyStream(dec, probe)
		if versionDec, derr := encoding.Decode(rs.RS5, dec, false); derr == nil && header.MatchVersion(versionDec) {
			return key, 0
		}
		zeroWASMSensitiveBuffer(wasmZeroingDeniabilityKey, key)
	}
	return nil, ErrWrongPassword
}

// unwrapDeniability strips the outer deniability layer and returns the inner .pcv
// bytes. salt(16) ‖ nonce(24) prefix selects the key (via selectDeniabilityKey);
// the rest is XOR-decrypted. selectDeniabilityKey is the sole auth guard.
func unwrapDeniability(volume, password []byte, rs *encoding.RSCodecs) ([]byte, int) {
	if len(volume) < deniabilitySaltSize+deniabilityNonceSize+header.VersionEncSize {
		return nil, ErrWrongPassword
	}
	salt := volume[:deniabilitySaltSize]
	nonce := append([]byte(nil), volume[deniabilitySaltSize:deniabilitySaltSize+deniabilityNonceSize]...)
	probeStart := deniabilitySaltSize + deniabilityNonceSize
	probe := append([]byte(nil), volume[probeStart:probeStart+header.VersionEncSize]...)

	key, code := selectDeniabilityKey(password, salt, nonce, probe, rs)
	if code != 0 {
		return nil, code
	}
	defer zeroWASMSensitiveBuffer(wasmZeroingDeniabilityKey, key)

	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, ErrCorruptedHeader
	}

	encrypted := volume[probeStart:]
	inner := make([]byte, 0, len(encrypted))
	var counter int64
	for offset := 0; offset < len(encrypted); offset += util.MiB {
		end := min(offset+util.MiB, len(encrypted))
		dst := make([]byte, end-offset)
		cipher.XORKeyStream(dst, encrypted[offset:end])
		inner = append(inner, dst...)
		counter += int64(end - offset)
		if counter >= crypto.RekeyThreshold { // dead under the 1 GiB cap (fidelity only)
			cipher, nonce, err = crypto.DeniabilityRekey(key, nonce)
			if err != nil {
				return nil, ErrCorruptedHeader
			}
			counter = 0
		}
	}

	return inner, 0
}
