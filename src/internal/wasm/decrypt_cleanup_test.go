package wasm

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/util"
	"bytes"
	"fmt"
	"testing"
)

func requireWASMWipe(t *testing.T, events []wasmZeroingEvent, kind wasmZeroingBufferKind, length int) {
	t.Helper()
	for _, event := range events {
		if event.Kind == kind && event.Len == length && event.WasNonZero && event.Zeroed {
			return
		}
	}
	t.Fatalf("missing nonzero-before/zero-after %s wipe of %d bytes; events: %+v", kind, length, events)
}

// The full-RS retry recovers an authentic first MiB before later damage makes
// decoding fail. Its aggregate must be wiped separately from the fast pass and
// the per-block temporary; neither of those wipes owns the retry's allocation.
func TestWASMRSDecodeFailureWipesAccumulatedPlaintext(t *testing.T) {
	for _, paranoid := range []bool{false, true} {
		t.Run(fmt.Sprintf("paranoid=%v", paranoid), func(t *testing.T) {
			original := bytes.Repeat([]byte("known recovered plaintext prefix\n"), 2*util.MiB/32+17)
			password := []byte("rs-prefix-cleanup")
			vol, code := EncryptVolume(original, password, EncryptOptions{ReedSolomon: true, Paranoid: paranoid})
			if code != 0 {
				t.Fatalf("encrypt code %d", code)
			}
			clean, code := DecryptVolume(vol, password, DecryptOptions{})
			if code != 0 || !bytes.Equal(clean.Plaintext, original) {
				t.Fatalf("clean control failed: code=%d, length=%d", code, len(clean.Plaintext))
			}
			secondBlock := header.HeaderSize(0) + encoding.RSEncodedBlockSize
			for i := range 9 {
				vol[secondBlock+i] ^= 0xff
			}
			borrowed := bytes.Clone(vol)
			var events []wasmZeroingEvent
			restore := observeWASMZeroingForTest(func(event wasmZeroingEvent) { events = append(events, event) })
			defer restore()
			res, code := DecryptVolume(vol, password, DecryptOptions{})
			if code != ErrModifiedData || res.Plaintext != nil || res.Comments != "" || res.Kept {
				t.Fatalf("damaged payload must fail closed: code=%d result=%+v", code, res)
			}
			if !bytes.Equal(vol, borrowed) {
				t.Error("decryption changed caller-owned ciphertext")
			}
			// The fast pass produced the entire original length. Exactly one MiB
			// can only be the completed prefix in the failing full-RS retry.
			requireWASMWipe(t, events, wasmZeroingDecryptAggregate, util.MiB)
		})
	}
}

func cleanupTestCipherSuite(t *testing.T, paranoid bool) *crypto.CipherSuite {
	t.Helper()
	mac, err := crypto.NewMAC(bytes.Repeat([]byte{0x42}, 32), paranoid)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := crypto.NewCipherSuite(
		bytes.Repeat([]byte{0x17}, 32), bytes.Repeat([]byte{0x23}, 24),
		bytes.Repeat([]byte{0x31}, 32), bytes.Repeat([]byte{0x49}, 16),
		mac, bytes.NewReader(nil), paranoid,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cs.Close)
	return cs
}

// A real exhausted HKDF stream makes Rekey fail after real plaintext has been
// recovered. The existing counter reaches this path without allocating 60 GiB.
func TestWASMPlainRekeyFailureWipesAccumulatedPlaintext(t *testing.T) {
	for _, paranoid := range []bool{false, true} {
		t.Run(fmt.Sprintf("paranoid=%v", paranoid), func(t *testing.T) {
			original := bytes.Repeat([]byte("recovered plaintext\n"), 17)
			payload := make([]byte, len(original))
			cleanupTestCipherSuite(t, paranoid).Encrypt(payload, bytes.Clone(original))
			borrowed := bytes.Clone(payload)
			counter := int64(0)
			plain, err := decryptPlainPayload(payload, cleanupTestCipherSuite(t, paranoid), &counter)
			if err != nil || !bytes.Equal(plain, original) {
				t.Fatalf("positive control failed: %v", err)
			}
			if !bytes.Equal(payload, borrowed) {
				t.Error("positive control changed caller-owned ciphertext")
			}
			// Restore for the failure test, even when running against the defect.
			copy(payload, borrowed)
			counter = crypto.RekeyThreshold - int64(len(payload))
			var events []wasmZeroingEvent
			restore := observeWASMZeroingForTest(func(event wasmZeroingEvent) { events = append(events, event) })
			defer restore()
			plain, err = decryptPlainPayload(payload, cleanupTestCipherSuite(t, paranoid), &counter)
			if err == nil || plain != nil {
				t.Fatalf("rekey failure returned plaintext: len=%d err=%v", len(plain), err)
			}
			if !bytes.Equal(payload, borrowed) {
				t.Error("failed decryption changed caller-owned ciphertext")
			}
			requireWASMWipe(t, events, wasmZeroingDecryptAggregate, len(original))
		})
	}
}

func TestWASMDecryptSuccessfulOutputRemainsOwnedByCaller(t *testing.T) {
	for _, paranoid := range []bool{false, true} {
		for _, rs := range []bool{false, true} {
			t.Run(fmt.Sprintf("paranoid=%v/rs=%v", paranoid, rs), func(t *testing.T) {
				// Cross a chunk boundary to exercise scratch reuse and its short tail.
				original := bytes.Repeat([]byte{0x12, 0x34, 0x56}, util.MiB/3+19)
				vol, code := EncryptVolume(original, []byte("ownership"), EncryptOptions{Paranoid: paranoid, ReedSolomon: rs})
				if code != 0 {
					t.Fatalf("encrypt code %d", code)
				}
				borrowed := bytes.Clone(vol)
				var events []wasmZeroingEvent
				restore := observeWASMZeroingForTest(func(event wasmZeroingEvent) { events = append(events, event) })
				defer restore()
				res, code := DecryptVolume(vol, []byte("ownership"), DecryptOptions{})
				if code != 0 || res.Kept || !bytes.Equal(res.Plaintext, original) {
					t.Fatalf("successful output must survive cleanup: code=%d kept=%v length=%d", code, res.Kept, len(res.Plaintext))
				}
				if !bytes.Equal(vol, borrowed) {
					t.Error("decryption changed caller-owned ciphertext")
				}
				for _, event := range events {
					if event.Kind == wasmZeroingDecryptAggregate {
						t.Error("successful aggregate was wiped before transfer")
					}
				}
				if paranoid || rs {
					requireWASMWipe(t, events, wasmZeroingDecryptStaging, util.MiB)
				}
			})
		}
	}
}

// Force's <136-byte RS tail is a borrowed decoder result. Its decryption and
// staging cleanup must preserve the input and transfer the real salvage bytes.
func TestWASMRSForceShortTailDoesNotAliasInput(t *testing.T) {
	for _, paranoid := range []bool{false, true} {
		t.Run(fmt.Sprintf("paranoid=%v", paranoid), func(t *testing.T) {
			original := []byte("known force salvage plaintext")
			password := []byte("short-tail")
			vol, code := EncryptVolume(original, password, EncryptOptions{Paranoid: paranoid, ReedSolomon: true})
			if code != 0 {
				t.Fatalf("encrypt code %d", code)
			}
			const tailLength = 17
			vol = vol[:header.HeaderSize(0)+tailLength]
			borrowed := bytes.Clone(vol)
			closed, code := DecryptVolume(vol, password, DecryptOptions{})
			if code != ErrModifiedData || closed.Plaintext != nil || closed.Kept {
				t.Fatalf("truncated payload must fail closed without Force: code=%d", code)
			}
			var events []wasmZeroingEvent
			restore := observeWASMZeroingForTest(func(event wasmZeroingEvent) { events = append(events, event) })
			defer restore()
			res, code := DecryptVolume(vol, password, DecryptOptions{Force: true})
			if code != ErrModifiedButKept || !res.Kept || !bytes.Equal(res.Plaintext, original[:tailLength]) {
				t.Fatalf("Force must keep the actual prefix: code=%d kept=%v plaintext=%q", code, res.Kept, res.Plaintext)
			}
			if !bytes.Equal(vol, borrowed) {
				t.Error("short-tail salvage changed caller-owned ciphertext")
			}
			requireWASMWipe(t, events, wasmZeroingDecryptStaging, tailLength)
		})
	}
}

func TestWASMDecryptEmptyPayloadOwnership(t *testing.T) {
	for _, paranoid := range []bool{false, true} {
		t.Run(fmt.Sprintf("paranoid=%v", paranoid), func(t *testing.T) {
			var counter int64
			plain, err := decryptPlainPayload(nil, cleanupTestCipherSuite(t, paranoid), &counter)
			if err != nil || len(plain) != 0 || counter != 0 {
				t.Fatalf("empty plain payload: len=%d counter=%d err=%v", len(plain), counter, err)
			}
			rs, err := encoding.NewRSCodecs()
			if err != nil {
				t.Fatal(err)
			}
			plain, err = decryptRSPayload(nil, cleanupTestCipherSuite(t, paranoid), rs, false, false, true)
			if err != nil || len(plain) != 0 {
				t.Fatalf("empty RS payload: len=%d err=%v", len(plain), err)
			}
			res, code := DecryptVolume(nil, []byte("empty"), DecryptOptions{})
			if code != ErrCorruptedHeader || res.Plaintext != nil || res.Comments != "" || res.Kept {
				t.Fatalf("empty volume must not become a successful payload: code=%d", code)
			}
		})
	}
}
