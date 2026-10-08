package crypto

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/hex"
	"testing"
)

func TestRandomBytesAcceptsSuccessfulCryptoRandOutput(t *testing.T) {
	// Do not parallelize this test: crypto/rand.Reader is process-global.
	want := make([]byte, 16)
	originalReader := cryptorand.Reader
	cryptorand.Reader = bytes.NewReader(want)
	t.Cleanup(func() {
		cryptorand.Reader = originalReader
	})

	data, err := RandomBytes(len(want))
	if err != nil {
		t.Fatalf("RandomBytes rejected successful crypto/rand output: %v", err)
	}
	if !bytes.Equal(data, want) {
		t.Fatalf("RandomBytes returned %x, want exact crypto/rand output %x", data, want)
	}
}

func TestRandomBytesRejectsInvalidLength(t *testing.T) {
	for _, n := range []int{0, -1} {
		data, err := RandomBytes(n)
		if err == nil {
			t.Errorf("RandomBytes(%d) returned no error", n)
		}
		if data != nil {
			t.Errorf("RandomBytes(%d) returned %x, want nil", n, data)
		}
	}
}

func TestDeriveKey(t *testing.T) {
	password := []byte("test-password")
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}

	// Normal mode
	key1, err := DeriveKey(password, salt, false)
	if err != nil {
		t.Fatalf("DeriveKey(paranoid=false) failed: %v", err)
	}
	if len(key1) != Argon2KeySize {
		t.Errorf("Key length = %d; want %d", len(key1), Argon2KeySize)
	}

	// Paranoid mode
	key2, err := DeriveKey(password, salt, true)
	if err != nil {
		t.Fatalf("DeriveKey(paranoid=true) failed: %v", err)
	}
	if len(key2) != Argon2KeySize {
		t.Errorf("Key length = %d; want %d", len(key2), Argon2KeySize)
	}

	// Keys should be different (different parameters)
	if bytes.Equal(key1, key2) {
		t.Error("Normal and paranoid keys should be different")
	}

	// Frozen KAT: pins the exact Argon2id parameters and KDF choice.
	// KAT independently derived via argon2.IDKey with kdf.go params
	// (passes/memory/threads/keysize) for normal(4,1<<20,4,32) and
	// paranoid(8,1<<20,8,32); NOT captured from DeriveKey. Any change to
	// passes/memory/threads/keysize or IDKey->other KDF turns this red.
	const (
		wantNormal   = "6aa5327cce3126fc935fddfd3eccf45db2479880e33196e235d261c7dbd8d369"
		wantParanoid = "f57a11e75223311f35e8b21def3a0abd579985c9f6a2ea61fb35d1282bf6966d"
	)
	if got := hex.EncodeToString(key1); got != wantNormal {
		t.Errorf("normal key = %s; want %s", got, wantNormal)
	}
	if got := hex.EncodeToString(key2); got != wantParanoid {
		t.Errorf("paranoid key = %s; want %s", got, wantParanoid)
	}
}

func TestSubkeyReader(t *testing.T) {
	key := make([]byte, 32)
	salt := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
		salt[i] = byte(255 - i)
	}

	hkdf := NewHKDFStream(key, salt)
	reader := NewSubkeyReader(hkdf)

	// Read header subkey
	headerKey, err := reader.HeaderSubkey()
	if err != nil {
		t.Fatalf("HeaderSubkey() failed: %v", err)
	}
	if len(headerKey) != SubkeyHeaderSize {
		t.Errorf("Header subkey length = %d; want %d", len(headerKey), SubkeyHeaderSize)
	}

	// Should fail on second call
	_, err = reader.HeaderSubkey()
	if err == nil {
		t.Error("Second HeaderSubkey() should fail")
	}

	// Read MAC subkey
	macKey, err := reader.MACSubkey()
	if err != nil {
		t.Fatalf("MACSubkey() failed: %v", err)
	}
	if len(macKey) != SubkeyMACSize {
		t.Errorf("MAC subkey length = %d; want %d", len(macKey), SubkeyMACSize)
	}

	// Read Serpent key
	serpentKey, err := reader.SerpentKey()
	if err != nil {
		t.Fatalf("SerpentKey() failed: %v", err)
	}
	if len(serpentKey) != SubkeySerpentSize {
		t.Errorf("Serpent key length = %d; want %d", len(serpentKey), SubkeySerpentSize)
	}
}

func TestSubkeyReaderOrdering(t *testing.T) {
	key := make([]byte, 32)
	salt := make([]byte, 32)

	hkdf := NewHKDFStream(key, salt)
	reader := NewSubkeyReader(hkdf)

	// Try to read Serpent key before MAC key (should fail)
	_, err := reader.SerpentKey()
	if err == nil {
		t.Error("SerpentKey() before MACSubkey() should fail")
	}
}

func TestNewMAC(t *testing.T) {
	subkey := make([]byte, 32)
	for i := range subkey {
		subkey[i] = byte(i)
	}

	// Normal mode (BLAKE2b)
	mac1, err := NewMAC(subkey, false)
	if err != nil {
		t.Fatalf("NewMAC(paranoid=false) failed: %v", err)
	}
	mac1.Write([]byte("test data"))
	sum1 := mac1.Sum(nil)
	if len(sum1) != MACSize {
		t.Errorf("MAC size = %d; want %d", len(sum1), MACSize)
	}

	// Paranoid mode (HMAC-SHA3)
	mac2, err := NewMAC(subkey, true)
	if err != nil {
		t.Fatalf("NewMAC(paranoid=true) failed: %v", err)
	}
	mac2.Write([]byte("test data"))
	sum2 := mac2.Sum(nil)
	if len(sum2) != MACSize {
		t.Errorf("MAC size = %d; want %d", len(sum2), MACSize)
	}

	// Different modes should produce different MACs
	if bytes.Equal(sum1, sum2) {
		t.Error("BLAKE2b and HMAC-SHA3 should produce different MACs")
	}

	// Frozen KAT: pins algorithm + keying, not just length.
	// KAT independently derived via blake2b.New512(subkey) (normal) and
	// hmac.New(sha3.New512, subkey) (paranoid); pins algorithm+keying, not
	// just length. Catches blake2b<->hmac swap, sha3->sha2, dropped keying.
	const (
		wantNormal   = "3d76683e318a5304020e1fe66936a97fa28fc42e6381598bcf968a7bc9fae95eda2135fa80da23d7f0e69fd16ffefbd92f6184cc0c4858299cf7203cdeeffa79"
		wantParanoid = "8930fc46f4b9a861a01fb882a5cc401228a4e2c3e500edd3f92bb29d177a6dd30ff14bb5b5ddccd6f6dc85c277ba2a39ae205ab832ac3c4189e448864a6412ae"
	)
	if got := hex.EncodeToString(sum1); got != wantNormal {
		t.Errorf("normal (BLAKE2b-keyed) MAC = %s; want %s", got, wantNormal)
	}
	if got := hex.EncodeToString(sum2); got != wantParanoid {
		t.Errorf("paranoid (HMAC-SHA3-512) MAC = %s; want %s", got, wantParanoid)
	}
}

func TestDeniabilityRekey(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 24)
	for i := range key {
		key[i] = byte(i)
	}
	for i := range nonce {
		nonce[i] = byte(i * 2)
	}

	cipher, newNonce, err := DeniabilityRekey(key, nonce)
	if err != nil {
		t.Fatalf("DeniabilityRekey() failed: %v", err)
	}

	if cipher == nil {
		t.Error("Cipher should not be nil")
	}

	if len(newNonce) != 24 {
		t.Errorf("New nonce length = %d; want 24", len(newNonce))
	}

	// Known-answer: deniability rekey derives the nonce as SHA3-256(oldNonce)[:24].
	// This pins the exact hash function (SHA3-256, not SHA3-512/BLAKE2/etc.) and the
	// truncation length, so a regression in the hash selection turns the test red.
	// Computed independently via crypto/sha3 over nonce[i]=byte(i*2).
	const wantDenyNonce = "8a60ad32d225f2bc1256300009bba2ab79d38807f02db12d"
	if got := hex.EncodeToString(newNonce); got != wantDenyNonce {
		t.Errorf("DeniabilityRekey nonce = %s; want %s (SHA3-256(oldNonce)[:24])", got, wantDenyNonce)
	}

	// New nonce should be different from old
	if bytes.Equal(nonce, newNonce) {
		t.Error("New nonce should be different from old nonce")
	}

	// Same inputs should produce same outputs (deterministic)
	_, newNonce2, _ := DeniabilityRekey(key, nonce)
	if !bytes.Equal(newNonce, newNonce2) {
		t.Error("DeniabilityRekey should be deterministic")
	}
}

func TestNormalModeCipherKAT(t *testing.T) {
	// Normal-mode (paranoid=false) CipherSuite.Encrypt over an all-zero plaintext
	// yields the raw XChaCha20 keystream. With a fixed key and nonce that keystream
	// is deterministic, so this pins the exact cipher: a swapped/misconfigured
	// stream cipher (or an accidental Serpent layer) produces different bytes and
	// fails the test. The expected value was captured from the real code and
	// independently confirmed to equal an unauthenticated XChaCha20 keystream over
	// 64 zero bytes for key=0x01*32, nonce=0x02*24.
	const wantKeystream = "b6bb0ee1dfec94dd5ebe93cf321db795e112a340f10d8a821569fa381fc5e69dcfdf41c006df49785248aa7a4c11392b0d10e3155689f8b2d84e5216c840054b"

	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x01
	}
	nonce := make([]byte, 24)
	for i := range nonce {
		nonce[i] = 0x02
	}
	// Unused in normal mode but required by the constructor signature.
	serpentKey := make([]byte, 32)
	serpentIV := make([]byte, 16)
	hkdfSalt := make([]byte, 32)

	mac, _ := NewMAC(make([]byte, 32), false)
	hkdf := NewHKDFStream(key, hkdfSalt)

	suite, err := NewCipherSuite(key, nonce, serpentKey, serpentIV, mac, hkdf, false)
	if err != nil {
		t.Fatalf("NewCipherSuite() failed: %v", err)
	}

	dst := make([]byte, 64)
	suite.Encrypt(dst, make([]byte, 64))

	if got := hex.EncodeToString(dst); got != wantKeystream {
		t.Errorf("normal-mode keystream = %s; want %s", got, wantKeystream)
	}
}

func TestCipherSuiteRekey(t *testing.T) {
	// Fixed fixtures make the post-rekey keystream a stable golden. Encrypting an
	// all-zero plaintext yields the raw keystream, so these vectors pin that
	// Rekey actually reinitializes the cipher(s) with the fresh HKDF-derived
	// nonce/IV. A no-op Rekey, a forgotten cs.chacha reassignment, or a skipped
	// Serpent-IV read all change these bytes and turn the test red.
	tests := []struct {
		name     string
		paranoid bool
		wantHex  string // post-rekey keystream over 32 zero bytes
	}{
		{"normal", false, "af4d335462f511d0ac2c0086d0660c7e19ba7e657ac48528c30ed65171cc5547"},
		{"paranoid", true, "c52f9d93f8b02d8f39aac6957d46afc6ec28b018c1c7c7b83d4fcc7493b96f5e"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, 32)
			serpentKey := make([]byte, 32)
			for i := range key {
				key[i] = byte(i)
				serpentKey[i] = byte(i + 32)
			}
			nonce := make([]byte, 24)
			serpentIV := make([]byte, 16)
			hkdfSalt := make([]byte, 32)

			mac, _ := NewMAC(make([]byte, 32), tt.paranoid)
			hkdf := NewHKDFStream(key, hkdfSalt)

			suite, err := NewCipherSuite(key, nonce, serpentKey, serpentIV, mac, hkdf, tt.paranoid)
			if err != nil {
				t.Fatalf("NewCipherSuite() failed: %v", err)
			}

			if err := suite.Rekey(); err != nil {
				t.Fatalf("Rekey() failed: %v", err)
			}

			// Encrypt zero plaintext -> ciphertext is the post-rekey keystream.
			got := make([]byte, 32)
			suite.Encrypt(got, make([]byte, 32))

			if gotHex := hex.EncodeToString(got); gotHex != tt.wantHex {
				t.Errorf("post-rekey keystream = %s; want %s", gotHex, tt.wantHex)
			}
		})
	}
}

func TestCipherSuiteRekeyMultiple(t *testing.T) {
	key := make([]byte, 32)
	serpentKey := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
		serpentKey[i] = byte(i + 32)
	}
	nonce := make([]byte, 24)
	serpentIV := make([]byte, 16)
	hkdfSalt := make([]byte, 32)

	mac, _ := NewMAC(make([]byte, 32), true)
	hkdf := NewHKDFStream(key, hkdfSalt)

	suite, err := NewCipherSuite(key, nonce, serpentKey, serpentIV, mac, hkdf, true)
	if err != nil {
		t.Fatalf("NewCipherSuite() failed: %v", err)
	}

	// Golden keystream block produced immediately after each successive rekey
	// (paranoid: Serpent-CTR -> XChaCha20 over 16 zero bytes). Pins that every
	// rekey reinitializes both ciphers from the advancing HKDF stream; a rekey
	// that fails to advance or to reinstall a cipher would repeat a block or
	// diverge from these vectors.
	want := []string{
		"c52f9d93f8b02d8f39aac6957d46afc6",
		"be44c5e694339a0781c97c06303f934f",
		"259fab0e64eb4f740ce2267fe04f5199",
		"44f85e251feeebfc28a063e5714e58c5",
		"154f0defa2d72f1f1a53393320f42010",
	}

	var prev []byte
	for i := range 5 {
		if err := suite.Rekey(); err != nil {
			t.Fatalf("Rekey() #%d failed: %v", i+1, err)
		}

		// Encrypt zero plaintext -> ciphertext is this cycle's keystream block.
		got := make([]byte, 16)
		suite.Encrypt(got, make([]byte, 16))

		if gotHex := hex.EncodeToString(got); gotHex != want[i] {
			t.Errorf("cycle %d keystream = %s; want %s", i, gotHex, want[i])
		}
		if prev != nil && bytes.Equal(got, prev) {
			t.Errorf("cycle %d keystream equals previous cycle (rekey did not advance)", i)
		}
		prev = got // got is freshly allocated each iteration
	}
}

func TestCipherSuiteClose(t *testing.T) {
	nonce := make([]byte, 24)
	serpentIV := make([]byte, 16)
	hkdfSalt := make([]byte, 32)

	// Test close in both modes
	for _, paranoid := range []bool{false, true} {
		t.Run(func() string {
			if paranoid {
				return "paranoid"
			}
			return "normal"
		}(), func(t *testing.T) {
			// Distinct nonzero key/serpentKey so the zero-check is meaningful:
			// byte 0 must change from 1 to 0 (key[i]=byte(i) would leave byte 0
			// already zero and make a no-op Close indistinguishable).
			key := make([]byte, 32)
			serpentKey := make([]byte, 32)
			for i := range key {
				key[i] = byte(i + 1)
				serpentKey[i] = byte(i + 32)
			}

			mac, _ := NewMAC(make([]byte, 32), paranoid)
			hkdf := NewHKDFStream(key, hkdfSalt)

			suite, err := NewCipherSuite(key, nonce, serpentKey, serpentIV, mac, hkdf, paranoid)
			if err != nil {
				t.Fatalf("NewCipherSuite() failed: %v", err)
			}

			// cs.key aliases the caller's key slice (NewCipherSuite stores it
			// directly), so capture the backing array to prove Close zeros the
			// bytes, not merely that it nils the field.
			keyBacking := suite.key

			suite.Close()

			// SecureZero(cs.key) must have wiped the key material.
			if !bytes.Equal(keyBacking, make([]byte, 32)) {
				t.Errorf("Close() did not zero key material: %x", keyBacking)
			}
			// All sensitive references must be cleared.
			if suite.key != nil {
				t.Error("Close() should nil cs.key")
			}
			if suite.chacha != nil {
				t.Error("Close() should nil cs.chacha")
			}
			if suite.mac != nil {
				t.Error("Close() should nil cs.mac")
			}
			if paranoid {
				if suite.serpent != nil {
					t.Error("Close() should nil cs.serpent")
				}
				if suite.serpentS != nil {
					t.Error("Close() should nil cs.serpentS")
				}
			}

			// Multiple Close() calls should be safe (idempotent).
			suite.Close()
			suite.Close()
		})
	}
}

func TestCipherSuiteCloseNil(t *testing.T) {
	// Close on nil should not panic
	var suite *CipherSuite
	suite.Close()
}

// TestCipherAliasingParanoid pins the supported usage: separate dst/src buffers
// in paranoid mode. Paranoid Encrypt writes Serpent output to dst then reads it
// back via copy(src, dst) before the ChaCha20 pass; aliased buffers (dst==src)
// would corrupt the output silently — that contract violation is NOT tested here
// (undefined behaviour). This test verifies that the CORRECT usage (non-aliased
// buffers) round-trips plaintext exactly.
func TestCipherAliasingParanoid(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 24)
	serpentKey := make([]byte, 32)
	serpentIV := make([]byte, 16)
	hkdfSalt := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
		serpentKey[i] = byte(i + 33)
	}
	for i := range nonce {
		nonce[i] = byte(i + 65)
	}
	for i := range serpentIV {
		serpentIV[i] = byte(i + 89)
	}

	plaintext := []byte("paranoid-mode aliasing contract: separate buffers only")

	macKey := make([]byte, 32)

	// --- Encrypt with separate dst / src ---
	encMAC, _ := NewMAC(macKey, true)
	hkdfEnc := NewHKDFStream(key, hkdfSalt)
	encSuite, err := NewCipherSuite(key, nonce, serpentKey, serpentIV, encMAC, hkdfEnc, true)
	if err != nil {
		t.Fatalf("NewCipherSuite(encrypt) failed: %v", err)
	}

	src := make([]byte, len(plaintext))
	copy(src, plaintext)
	ciphertext := make([]byte, len(plaintext)) // separate backing array — the required contract
	encSuite.Encrypt(ciphertext, src)

	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("Encrypt: ciphertext must differ from plaintext")
	}

	// --- Decrypt with separate dst / src ---
	decMAC, _ := NewMAC(macKey, true)
	hkdfDec := NewHKDFStream(key, hkdfSalt)
	decSuite, err := NewCipherSuite(key, nonce, serpentKey, serpentIV, decMAC, hkdfDec, true)
	if err != nil {
		t.Fatalf("NewCipherSuite(decrypt) failed: %v", err)
	}

	encData := make([]byte, len(ciphertext))
	copy(encData, ciphertext)
	recovered := make([]byte, len(encData)) // separate backing array — the required contract
	decSuite.Decrypt(recovered, encData)

	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("Decrypt round-trip failed: got %q; want %q", recovered, plaintext)
	}

	// MACs must match (Encrypt-then-MAC on both sides over identical ciphertext bytes).
	if !bytes.Equal(encSuite.Sum(), decSuite.Sum()) {
		t.Error("Encrypt/Decrypt MAC mismatch with separate buffers")
	}
}

func TestCipherSuiteEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 24)
	serpentKey := make([]byte, 32)
	serpentIV := make([]byte, 16)
	hkdfSalt := make([]byte, 32)

	for i := range key {
		key[i] = byte(i)
		serpentKey[i] = byte(i + 32)
	}
	for i := range nonce {
		nonce[i] = byte(i + 64)
	}
	for i := range serpentIV {
		serpentIV[i] = byte(i + 88)
	}

	plaintext := []byte("Hello, World! This is a test message for encryption.")

	// Test both normal and paranoid modes
	for _, paranoid := range []bool{false, true} {
		t.Run(func() string {
			if paranoid {
				return "paranoid"
			}
			return "normal"
		}(), func(t *testing.T) {
			// Create MAC for encryption
			macKey := make([]byte, 32)
			encMAC, _ := NewMAC(macKey, paranoid)

			// Create cipher suite for encryption
			hkdfEnc := NewHKDFStream(key, hkdfSalt)
			encSuite, err := NewCipherSuite(key, nonce, serpentKey, serpentIV, encMAC, hkdfEnc, paranoid)
			if err != nil {
				t.Fatalf("NewCipherSuite() failed: %v", err)
			}

			// Make a copy of plaintext for encryption (encrypt modifies src in paranoid mode)
			src := make([]byte, len(plaintext))
			copy(src, plaintext)

			// Encrypt
			ciphertext := make([]byte, len(plaintext))
			encSuite.Encrypt(ciphertext, src)

			// Ciphertext should be different from original plaintext
			if bytes.Equal(ciphertext, plaintext) {
				t.Error("Ciphertext should be different from plaintext")
			}

			// Create MAC for decryption (fresh instance)
			decMAC, _ := NewMAC(macKey, paranoid)

			// Create cipher suite for decryption
			hkdfDec := NewHKDFStream(key, hkdfSalt)
			decSuite, err := NewCipherSuite(key, nonce, serpentKey, serpentIV, decMAC, hkdfDec, paranoid)
			if err != nil {
				t.Fatalf("NewCipherSuite() failed: %v", err)
			}

			// Make a copy of ciphertext for decryption (decrypt modifies src in paranoid mode)
			encData := make([]byte, len(ciphertext))
			copy(encData, ciphertext)

			// Decrypt
			decrypted := make([]byte, len(encData))
			decSuite.Decrypt(decrypted, encData)

			// Decrypted should match original plaintext
			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("Decrypted = %q; want %q", decrypted, plaintext)
			}

			// MACs should match
			encSum := encSuite.Sum()
			decSum := decSuite.Sum()
			if !bytes.Equal(encSum, decSum) {
				t.Error("Encryption and decryption MACs should match")
			}
		})
	}
}
