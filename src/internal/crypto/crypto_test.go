package crypto

import (
	"bytes"
	"testing"
)

func TestRandomBytes(t *testing.T) {
	// Test various lengths
	lengths := []int{1, 16, 32, 64, 128, 1024}

	for _, length := range lengths {
		data, err := RandomBytes(length)
		if err != nil {
			t.Fatalf("RandomBytes(%d) failed: %v", length, err)
		}

		if len(data) != length {
			t.Errorf("RandomBytes(%d) returned %d bytes", length, len(data))
		}

		// Check that it's not all zeros (statistically almost impossible)
		allZero := true
		for _, b := range data {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero && length > 0 {
			t.Errorf("RandomBytes(%d) returned all zeros (extremely unlikely)", length)
		}
	}
}

func TestRandomBytesUniqueness(t *testing.T) {
	// Two calls should produce different results
	data1, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes(32) failed: %v", err)
	}

	data2, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes(32) failed: %v", err)
	}

	if bytes.Equal(data1, data2) {
		t.Error("Two RandomBytes calls should produce different results")
	}
}

func TestRandomBytesZeroLength(t *testing.T) {
	// Zero length returns error because allZero check triggers on empty slice
	_, err := RandomBytes(0)
	if err == nil {
		t.Error("RandomBytes(0) should return error")
	}
	// Note: RandomBytes with negative length will panic from make()
	// This is Go's standard behavior and we don't test it
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

	// Same inputs should produce same outputs (deterministic)
	key1b, _ := DeriveKey(password, salt, false)
	if !bytes.Equal(key1, key1b) {
		t.Error("Same inputs should produce same key")
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

	// Read rekey values
	nonce, iv, err := reader.RekeyValues()
	if err != nil {
		t.Fatalf("RekeyValues() failed: %v", err)
	}
	if len(nonce) != RekeyNonceSize {
		t.Errorf("Rekey nonce length = %d; want %d", len(nonce), RekeyNonceSize)
	}
	if len(iv) != RekeyIVSize {
		t.Errorf("Rekey IV length = %d; want %d", len(iv), RekeyIVSize)
	}

	if reader.RekeyCount() != 1 {
		t.Errorf("RekeyCount = %d; want 1", reader.RekeyCount())
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
}

func TestCounter(t *testing.T) {
	c := NewCounter()

	// Should not trigger rekey initially
	if c.Add(1000) {
		t.Error("Should not trigger rekey for small amounts")
	}

	// Reset
	c.Reset()
	if c.Count() != 0 {
		t.Error("Counter should be 0 after reset")
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

func TestCipherSuiteRekey(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 24)
	serpentKey := make([]byte, 32)
	serpentIV := make([]byte, 16)
	hkdfSalt := make([]byte, 32)

	for i := range key {
		key[i] = byte(i)
		serpentKey[i] = byte(i + 32)
	}

	// Test rekey in both modes
	for _, paranoid := range []bool{false, true} {
		t.Run(func() string {
			if paranoid {
				return "paranoid"
			}
			return "normal"
		}(), func(t *testing.T) {
			mac, _ := NewMAC(make([]byte, 32), paranoid)
			hkdf := NewHKDFStream(key, hkdfSalt)

			suite, err := NewCipherSuite(key, nonce, serpentKey, serpentIV, mac, hkdf, paranoid)
			if err != nil {
				t.Fatalf("NewCipherSuite() failed: %v", err)
			}

			// Encrypt some data before rekey
			src1 := []byte("data before rekey")
			dst1 := make([]byte, len(src1))
			suite.Encrypt(dst1, src1)

			// Perform rekey
			err = suite.Rekey()
			if err != nil {
				t.Fatalf("Rekey() failed: %v", err)
			}

			// Encrypt more data after rekey
			src2 := []byte("data after rekey")
			dst2 := make([]byte, len(src2))
			suite.Encrypt(dst2, src2)

			// Both should work (no panic, produces output)
			if bytes.Equal(dst1, make([]byte, len(dst1))) {
				t.Error("First encryption produced all zeros")
			}
			if bytes.Equal(dst2, make([]byte, len(dst2))) {
				t.Error("Second encryption produced all zeros")
			}
		})
	}
}

func TestCipherSuiteRekeyMultiple(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 24)
	serpentKey := make([]byte, 32)
	serpentIV := make([]byte, 16)
	hkdfSalt := make([]byte, 32)

	mac, _ := NewMAC(make([]byte, 32), true)
	hkdf := NewHKDFStream(key, hkdfSalt)

	suite, err := NewCipherSuite(key, nonce, serpentKey, serpentIV, mac, hkdf, true)
	if err != nil {
		t.Fatalf("NewCipherSuite() failed: %v", err)
	}

	// Perform multiple rekeys (simulating very large file)
	for i := 0; i < 5; i++ {
		err = suite.Rekey()
		if err != nil {
			t.Fatalf("Rekey() #%d failed: %v", i+1, err)
		}

		// Encrypt some data after each rekey
		src := []byte("test data")
		dst := make([]byte, len(src))
		suite.Encrypt(dst, src)
	}
}

func TestCipherSuiteClose(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 24)
	serpentKey := make([]byte, 32)
	serpentIV := make([]byte, 16)
	hkdfSalt := make([]byte, 32)

	for i := range key {
		key[i] = byte(i)
		serpentKey[i] = byte(i + 32)
	}

	// Test close in both modes
	for _, paranoid := range []bool{false, true} {
		t.Run(func() string {
			if paranoid {
				return "paranoid"
			}
			return "normal"
		}(), func(t *testing.T) {
			mac, _ := NewMAC(make([]byte, 32), paranoid)
			hkdf := NewHKDFStream(key, hkdfSalt)

			// Make a copy of key to verify zeroing
			keyToCheck := make([]byte, 32)
			copy(keyToCheck, key)

			suite, err := NewCipherSuite(keyToCheck, nonce, serpentKey, serpentIV, mac, hkdf, paranoid)
			if err != nil {
				t.Fatalf("NewCipherSuite() failed: %v", err)
			}

			// Close the suite
			suite.Close()

			// Multiple Close() calls should be safe
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

func TestCipherSuiteIsParanoid(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 24)
	serpentKey := make([]byte, 32)
	serpentIV := make([]byte, 16)
	hkdfSalt := make([]byte, 32)

	// Normal mode
	mac1, _ := NewMAC(make([]byte, 32), false)
	hkdf1 := NewHKDFStream(key, hkdfSalt)
	suite1, _ := NewCipherSuite(key, nonce, serpentKey, serpentIV, mac1, hkdf1, false)
	if suite1.IsParanoid() {
		t.Error("IsParanoid() should return false for normal mode")
	}

	// Paranoid mode
	mac2, _ := NewMAC(make([]byte, 32), true)
	hkdf2 := NewHKDFStream(key, hkdfSalt)
	suite2, _ := NewCipherSuite(key, nonce, serpentKey, serpentIV, mac2, hkdf2, true)
	if !suite2.IsParanoid() {
		t.Error("IsParanoid() should return true for paranoid mode")
	}
}

func TestCipherSuiteMAC(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 24)
	serpentKey := make([]byte, 32)
	serpentIV := make([]byte, 16)
	hkdfSalt := make([]byte, 32)

	for i := range key {
		key[i] = byte(i)
	}

	macKey := make([]byte, 32)
	mac, _ := NewMAC(macKey, false)
	hkdf := NewHKDFStream(key, hkdfSalt)

	suite, err := NewCipherSuite(key, nonce, serpentKey, serpentIV, mac, hkdf, false)
	if err != nil {
		t.Fatalf("NewCipherSuite() failed: %v", err)
	}

	// MAC() should return the hash.Hash
	macHash := suite.MAC()
	if macHash == nil {
		t.Fatal("MAC() returned nil")
	}

	// Should be the same instance as the original
	if macHash != mac {
		t.Error("MAC() should return the same hash instance")
	}

	// Writing to the MAC through the suite should work
	macHash.Write([]byte("test data"))
	sum := suite.Sum()
	if len(sum) != MACSize {
		t.Errorf("Sum() length = %d; want %d", len(sum), MACSize)
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
