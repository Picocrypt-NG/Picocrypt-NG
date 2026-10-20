package wasm

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/header"
	"bytes"
	"hash"
	"io"
	"testing"
)

func TestWASMEncryptionWipesOwnedNormalizedPasswordOnKDFPanic(t *testing.T) {
	for _, test := range []struct {
		name string
		run  func([]byte) ([]byte, int)
	}{
		{"volume", func(password []byte) ([]byte, int) {
			return EncryptVolume([]byte("caller-owned plaintext"), password, EncryptOptions{})
		}},
		{"deniability wrapper", func(password []byte) ([]byte, int) {
			return wrapDeniability([]byte("caller-owned inner volume"), password)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			password := []byte("cafe\u0301 password")
			var normalized []byte
			const failure = "KDF panic"
			t.Cleanup(swapWASMTestKDF(func(input, _ []byte, _ bool) ([]byte, error) {
				normalized = input
				if !bytes.Equal(input, []byte("caf\u00e9 password")) {
					t.Fatal("KDF did not receive the live NFC-normalized password")
				}
				if &input[0] == &password[0] {
					t.Fatal("normalization did not give the operation an independent buffer")
				}
				panic(failure)
			}))
			func() {
				defer func() {
					if recovered := recover(); recovered != failure {
						t.Fatalf("panic = %v; want injected KDF panic", recovered)
					}
				}()
				test.run(password)
				t.Fatal("encryption returned after a KDF panic")
			}()
			if !bytes.Equal(normalized, make([]byte, len(normalized))) {
				t.Fatal("KDF panic left the owned normalized password in its backing array")
			}
			if !bytes.Equal(password, []byte("cafe\u0301 password")) {
				t.Fatal("KDF panic cleanup changed the caller-owned password")
			}
		})
	}
}

func TestWASMWipesOwnedSerpentKeyOnCipherInitializationPanic(t *testing.T) {
	for _, paranoid := range []bool{false, true} {
		for _, decrypt := range []bool{false, true} {
			name := "standard"
			if paranoid {
				name = "paranoid"
			}
			if decrypt {
				name = "decrypt " + name
			} else {
				name = "encrypt " + name
			}
			t.Run(name, func(t *testing.T) {
				password := []byte("caller-owned password")
				plaintext := []byte("cipher initialization cleanup")
				ciphertext, code := EncryptVolume(plaintext, password, EncryptOptions{Paranoid: paranoid})
				if code != 0 {
					t.Fatalf("prepare encrypted volume: code %d", code)
				}
				var keyBorrow, serpentBorrow []byte
				const failure = "cipher initialization panic"
				previous := newCipherSuite
				newCipherSuite = func(key, _ []byte, serpentKey, _ []byte, _ hash.Hash, _ io.Reader, _ bool) (*crypto.CipherSuite, error) {
					keyBorrow, serpentBorrow = key, serpentKey
					if !hasNonZeroByte(key) || !hasNonZeroByte(serpentKey) {
						t.Fatal("cipher initialization received an already-wiped key")
					}
					panic(failure)
				}
				t.Cleanup(func() { newCipherSuite = previous })
				func() {
					defer func() {
						if recovered := recover(); recovered != failure {
							t.Fatalf("panic = %v; want injected cipher panic", recovered)
						}
					}()
					if decrypt {
						DecryptVolume(ciphertext, password, DecryptOptions{})
					} else {
						EncryptVolume(plaintext, password, EncryptOptions{Paranoid: paranoid})
					}
					t.Fatal("operation returned after a cipher initialization panic")
				}()
				if !bytes.Equal(keyBorrow, make([]byte, len(keyBorrow))) {
					t.Error("cipher initialization panic left the owned derived key in its backing array")
				}
				if !bytes.Equal(serpentBorrow, make([]byte, len(serpentBorrow))) {
					t.Error("cipher initialization panic left the owned Serpent key in its backing array")
				}
				if !bytes.Equal(password, []byte("caller-owned password")) || !bytes.Equal(plaintext, []byte("cipher initialization cleanup")) {
					t.Error("cipher initialization cleanup changed a caller-owned input")
				}
			})
		}
	}
}

func TestWASMRSRetryAndSalvageWipeOwnedSerpentKeyOnCipherInitializationPanic(t *testing.T) {
	for _, test := range []struct {
		name    string
		errors  int
		force   bool
		panicAt int
	}{
		{name: "correctable retry", errors: 4, panicAt: 2},
		{name: "forced salvage", errors: 9, force: true, panicAt: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			password := []byte("RS pass credential lifetime")
			ciphertext, code := EncryptVolume(bytes.Repeat([]byte{0x75}, 4096), password, EncryptOptions{ReedSolomon: true, Paranoid: true})
			if code != 0 {
				t.Fatalf("prepare encrypted volume: code %d", code)
			}
			// The fast pass sees corrupted ciphertext; full correction either
			// repairs four errors or rejects nine and reaches forced salvage.
			for i := range test.errors {
				ciphertext[header.HeaderSize(0)+i] ^= 0xff
			}
			originalCiphertext := bytes.Clone(ciphertext)
			var firstSerpentBorrow, passSerpentBorrow []byte
			calls := 0
			const failure = "RS pass cipher initialization panic"
			previous := newCipherSuite
			newCipherSuite = func(key, nonce, serpentKey, serpentIV []byte, mac hash.Hash, hkdf io.Reader, paranoid bool) (*crypto.CipherSuite, error) {
				calls++
				if calls == 1 {
					firstSerpentBorrow = serpentKey
				}
				if calls == test.panicAt {
					passSerpentBorrow = serpentKey
					if bytes.Equal(serpentKey, make([]byte, len(serpentKey))) {
						t.Fatal("RS pass received an already-wiped Serpent key")
					}
					if &serpentKey[0] == &firstSerpentBorrow[0] {
						t.Fatal("RS pass did not derive an independent Serpent key buffer")
					}
					panic(failure)
				}
				return previous(key, nonce, serpentKey, serpentIV, mac, hkdf, paranoid)
			}
			t.Cleanup(func() { newCipherSuite = previous })
			func() {
				defer func() {
					if recovered := recover(); recovered != failure {
						t.Fatalf("panic = %v; want injected RS pass cipher panic", recovered)
					}
				}()
				DecryptVolume(ciphertext, password, DecryptOptions{Force: test.force})
				t.Fatal("decryption returned after an RS pass cipher initialization panic")
			}()
			if !bytes.Equal(passSerpentBorrow, make([]byte, len(passSerpentBorrow))) {
				t.Error("RS pass cipher initialization panic left its fresh Serpent key in its backing array")
			}
			if !bytes.Equal(password, []byte("RS pass credential lifetime")) || !bytes.Equal(ciphertext, originalCiphertext) {
				t.Error("RS pass panic cleanup changed a caller-owned input")
			}
		})
	}
}
