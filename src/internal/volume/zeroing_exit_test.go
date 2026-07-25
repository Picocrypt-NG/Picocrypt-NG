package volume

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// recordingKDF wraps the fast-test volume-key derivation, retaining the backing
// slice header of EVERY key it returns. Production assigns each returned slice to
// ctx.Key (decrypt.go:223); on a mid-operation reassignment (v1/v2 keyfile XOR at
// :303/:343, or the full-RS retry re-derive at :223) the predecessor backing array
// is orphaned — OperationContext.Close() (context.go:254-286) can no longer reach
// it because the field has already moved on (and is nil'd at :261).
//
// Pitfall 2 (capture-before-close): the test must hold the backing-slice reference
// BEFORE the reassignment/Close, never read ctx.Key afterwards (it is nil post-Close
// and an intermediate value mid-operation). Recording every returned slice here is
// exactly that capture: the SEC-05 fix must zero each orphaned predecessor.
type recordingKDF struct {
	captured [][]byte
	base     func(password, salt []byte, paranoid bool) ([]byte, error)
}

func (r *recordingKDF) derive(password, salt []byte, paranoid bool) ([]byte, error) {
	key, err := r.base(password, salt, paranoid)
	if err != nil {
		return nil, err
	}
	r.captured = append(r.captured, key)
	return key, nil
}

// useRecordingKDF swaps deriveVolumeKey for a recording wrapper (reusing the
// fast_kdf_test.go:45 save/swap/restore idiom) and returns the recorder plus a
// restore func to defer. deriveDeniabilityKey is left at its fast-test value.
func useRecordingKDF(
	t *testing.T,
	base func(password, salt []byte, paranoid bool) ([]byte, error),
) (*recordingKDF, func()) {
	t.Helper()
	rec := &recordingKDF{base: base}
	restore := useTestKDF(rec.derive, fastTestDeniabilityKey)
	return rec, restore
}

// assertAllZero fails if any byte of b is non-zero. The label identifies which
// captured key backing array leaked.
func assertAllZero(t *testing.T, label string, b []byte) {
	t.Helper()
	if len(b) == 0 {
		t.Fatalf("%s: captured slice is empty/nil — capture seam did not record the backing array", label)
	}
	for i, v := range b {
		if v != 0 {
			t.Fatalf("%s: captured key backing array NOT zeroed at byte %d (=%#x) — orphaned predecessor leaked (SEC-05/WR-01)", label, i, v)
		}
	}
}

// TestKeyMaterialZeroed proves SEC-05 (+ inherited WR-01): every []byte key
// backing array that OperationContext.Close() structurally cannot reach because it
// was reassigned mid-operation is securely zeroed at the reassignment point.
//
// Both required paths (D-05) are covered:
//   - Close path: a keyfile volume reassigns ctx.Key = XORWithKey(...) (a NEW
//     32-byte slice, processor.go:216), orphaning the Argon2 backing array; Close()
//     only zeros the final XOR-result key, never the orphaned Argon2 array.
//   - Full-RS retry path (WR-01): a correctable-RS volume forces reDeriveForRetry
//     (decrypt.go:360) → decryptDeriveKeys re-assigns ctx.Key (:223), orphaning the
//     first-pass key. Before the fix that predecessor leaks; after it is zeroed.
//
// The seam captures the backing slice via the deriveVolumeKey recording wrapper
// BEFORE any Close/reassign (Pitfall 2). The fast KDF is already active via TestMain.
func TestKeyMaterialZeroed(t *testing.T) {
	t.Run("close path orphans the Argon2 key on keyfile XOR", func(t *testing.T) {
		rsCodecs, err := encoding.NewRSCodecs()
		if err != nil {
			t.Fatalf("NewRSCodecs: %v", err)
		}

		tmpDir := t.TempDir()
		keyfilePath := filepath.Join(findTestdata(t), "keyfile_alpha.bin")
		encryptedPath := filepath.Join(findTestdata(t), "pico_test_v2_keyfile_single.txt.pcv")

		// The frozen pre-2.19 fixture exercises the still-supported reader without
		// reopening the disabled v2 keyfile writer.
		rec, restore := useRecordingKDF(t, productionTestVolumeKey)
		defer restore()

		decryptedPath := filepath.Join(tmpDir, "close_out.txt")
		decReq := &DecryptRequest{
			InputFile:  encryptedPath,
			OutputFile: decryptedPath,
			Password:   []byte(goldenPassword),
			Keyfiles:   []string{keyfilePath},
			Reporter:   &GoldenTestReporter{},
			RSCodecs:   rsCodecs,
		}
		if err := Decrypt(context.Background(), decReq); err != nil {
			t.Fatalf("Decrypt (keyfile): %v", err)
		}

		// Correctness floor: the volume must still round-trip (the XOR-result live
		// key was NOT wiped) — guards against over-zeroing.
		got, err := os.ReadFile(decryptedPath)
		if err != nil {
			t.Fatalf("read decrypted output: %v", err)
		}
		if string(got) != expectedContent {
			t.Fatalf("decrypted content mismatch (keyfile live key wiped?)")
		}

		// Exactly one Argon2 derivation on the non-retry close path; that backing
		// array is orphaned when ctx.Key becomes the XOR result.
		if len(rec.captured) == 0 {
			t.Fatal("recording seam captured no key — deriveVolumeKey wrapper not wired")
		}
		assertAllZero(t, "close path: orphaned Argon2 key", rec.captured[0])
	})

	t.Run("full-RS retry orphans the per-pass Argon2 key (keyfile volume)", func(t *testing.T) {
		rsCodecs, err := encoding.NewRSCodecs()
		if err != nil {
			t.Fatalf("NewRSCodecs: %v", err)
		}

		tmpDir := t.TempDir()
		plaintext := legacyKeyfileRSPlaintext()

		// A keyfile is essential here: without it the no-keyfile retry path
		// self-assigns ctx.Key (same backing array the first cipher suite holds and
		// RS-03's CipherSuite.Close() incidentally zeros), so that path would NOT
		// isolate the WR-01 leak. WITH a keyfile, ctx.Key becomes the XOR result and
		// the Argon2 backing array is genuinely orphaned at the v2 XOR (:343) on each
		// pass — unreachable by the cipher suite (which holds the XOR result) or by
		// Close(). The retry re-derive (:223) and keyfile re-process (:247) also run.
		keyfilePath := filepath.Join(findTestdata(t), "keyfile_alpha.bin")
		pcvPath := materializeGoldenBase64Fixture(t, goldenLegacyKeyfileRSFixture, goldenLegacyKeyfileRSSHA256)
		// 4 byte errors in block 0's data region: repairable by the full RS pass,
		// wrong under the fast pass -> MAC mismatch -> full-RS retry re-derive.
		corruptOneRSBlock(t, pcvPath, 0, 4)

		rec, restore := useRecordingKDF(t, productionTestVolumeKey)
		defer restore()

		reporter := &repairingReporter{}
		outputPath := filepath.Join(tmpDir, "retry_zeroed_out.bin")
		decReq := &DecryptRequest{
			InputFile:    pcvPath,
			OutputFile:   outputPath,
			Password:     []byte(goldenPassword),
			Keyfiles:     []string{keyfilePath},
			ForceDecrypt: false,
			Reporter:     reporter,
			RSCodecs:     rsCodecs,
		}
		if err := Decrypt(context.Background(), decReq); err != nil {
			t.Fatalf("Decrypt after correctable RS damage: %v", err)
		}

		// Non-vacuous: the full-RS retry must actually have fired, which is what
		// triggers the second deriveVolumeKey call and orphans the first-pass key.
		if !reporter.sawRepairing {
			t.Fatal("full-RS retry did not fire (no \"Repairing\" status); retry-path capture would be vacuous")
		}
		if len(rec.captured) < 2 {
			t.Fatalf("expected >=2 Argon2 derivations across the retry, got %d", len(rec.captured))
		}

		// Correctness floor: the retry must reproduce the plaintext (live retry key
		// not wiped).
		got, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("read decrypted output: %v", err)
		}
		if len(got) != len(plaintext) {
			t.Fatalf("decrypted length = %d; want %d", len(got), len(plaintext))
		}
		for i := range plaintext {
			if got[i] != plaintext[i] {
				t.Fatalf("decrypted byte %d = %#x; want %#x (retry state bleed?)", i, got[i], plaintext[i])
			}
		}

		// EVERY per-pass Argon2 backing array (orphaned at its v2 XOR :343, and the
		// first one re-orphaned by the retry re-derive :223) must read all-zero.
		for i, key := range rec.captured {
			assertAllZero(t, fmt.Sprintf("full-RS retry: orphaned Argon2 key pass %d", i), key)
		}
	})

	t.Run("live key survives the no-keyfile decrypt then Close zeros it", func(t *testing.T) {
		// No keyfile: the v2 path never reassigns ctx.Key after derivation, so the
		// SINGLE Argon2-derived slice the recorder captures IS the FINAL live ctx.Key
		// that survives to Close(). Asserting it zeroed confirms the live key is wiped
		// on the normal exit path. Note this slice is zeroed by BOTH CipherSuite.Close()
		// (NewCipherSuite shares ctx.Key's backing array) and OperationContext.Close()'s
		// SecureZeroMultiple, so it does not isolate the latter; the dedicated guard for
		// context.go's SecureZeroMultiple is the sibling "Close zeros the FINAL live
		// key/..." subtest below (which fails if that call is removed).
		rsCodecs, err := encoding.NewRSCodecs()
		if err != nil {
			t.Fatalf("NewRSCodecs: %v", err)
		}

		tmpDir := t.TempDir()
		const password = "live-key-zeroed-pw"
		plaintext := []byte("live-key fixture: no keyfile, ctx.Key self-assigned and zeroed by Close().")
		inputPath := filepath.Join(tmpDir, "live_in.txt")
		if err := os.WriteFile(inputPath, plaintext, 0o600); err != nil {
			t.Fatalf("write input: %v", err)
		}

		encryptedPath := filepath.Join(tmpDir, "live_in.txt.pcv")
		encReq := &EncryptRequest{
			InputFile:  inputPath,
			OutputFile: encryptedPath,
			Password:   []byte(password),
			Reporter:   &GoldenTestReporter{},
			RSCodecs:   rsCodecs,
		}
		if err := Encrypt(context.Background(), encReq); err != nil {
			t.Fatalf("Encrypt: %v", err)
		}

		rec, restore := useRecordingKDF(t, fastTestVolumeKey)
		defer restore()

		decryptedPath := filepath.Join(tmpDir, "live_out.txt")
		decReq := &DecryptRequest{
			InputFile:  encryptedPath,
			OutputFile: decryptedPath,
			Password:   []byte(password),
			Reporter:   &GoldenTestReporter{},
			RSCodecs:   rsCodecs,
		}
		if err := Decrypt(context.Background(), decReq); err != nil {
			t.Fatalf("Decrypt: %v", err)
		}

		got, err := os.ReadFile(decryptedPath)
		if err != nil {
			t.Fatalf("read decrypted output: %v", err)
		}
		if string(got) != string(plaintext) {
			t.Fatalf("decrypted content mismatch (live key wiped before use?)")
		}

		if len(rec.captured) != 1 {
			t.Fatalf("expected exactly 1 Argon2 derivation (no keyfile, no retry), got %d", len(rec.captured))
		}
		assertAllZero(t, "no-keyfile: FINAL live ctx.Key after Close()", rec.captured[0])
	})

	t.Run("Close zeros the FINAL live key/keyfileKey/keyfileHash/passwordBytes", func(t *testing.T) {
		// Direct Close() contract over ALL FOUR key fields it must wipe at
		// context.go's Close(): the three *crypto.Secret fields (Key/KeyfileKey/
		// passwordBytes) zeroed via the ctx.secrets registry, plus the NON-SECRET
		// KeyfileHash cleared defensively. Distinct backing arrays per field so each
		// assertion is independent; deleting the registry sweep leaves every Secret
		// non-zero, and dropping the KeyfileHash SecureZero leaves it non-zero.
		// The Secret fields are populated through the setters so they are registered
		// in ctx.secrets exactly as the production pipeline registers them.
		ctx := &OperationContext{
			KeyfileHash: bytes.Repeat([]byte{0x33}, 32),
		}
		ctx.setKey(bytes.Repeat([]byte{0x11}, crypto.Argon2KeySize))
		ctx.setKeyfileKey(bytes.Repeat([]byte{0x22}, crypto.Argon2KeySize))
		ctx.setPasswordBytes(bytes.Repeat([]byte{0x44}, 12))

		// Hold the backing arrays BEFORE Close() drops the fields (Pitfall 2).
		// Bytes() borrows the live backing array, which Close() zeros in place.
		key := ctx.Key.Bytes()
		keyfileKey := ctx.KeyfileKey.Bytes()
		keyfileHash := ctx.KeyfileHash
		passwordBytes := ctx.passwordBytes.Bytes()

		ctx.Close()

		assertAllZero(t, "FINAL live key", key)
		assertAllZero(t, "FINAL live keyfileKey", keyfileKey)
		assertAllZero(t, "FINAL live keyfileHash", keyfileHash)
		assertAllZero(t, "FINAL live passwordBytes", passwordBytes)
	})
}
