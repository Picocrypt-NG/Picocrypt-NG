package wasm

import (
	"Picocrypt-NG/internal/header"
	"bytes"
	"strings"
	"testing"
)

// Force must NOT turn a wrong password into kept garbage: header auth gates it.
func TestForceDecryptDoesNotBypassWrongPassword(t *testing.T) {
	vol, code := EncryptVolume([]byte("secret payload"), []byte("correct-horse"), EncryptOptions{})
	if code != 0 {
		t.Fatalf("encrypt code %d", code)
	}
	res, c := DecryptVolume(vol, []byte("wrong-password"), DecryptOptions{Force: true})
	if c != ErrWrongPassword {
		t.Fatalf("got code %d, want ErrWrongPassword(%d); force must not bypass auth", c, ErrWrongPassword)
	}
	if res.Plaintext != nil {
		t.Fatal("no plaintext may be returned for a wrong password, even with force")
	}
	if res.Kept {
		t.Fatal("Kept must be false when auth fails")
	}
}

// A clean volume verifies normally even with force on (force never degrades the happy path).
func TestForceDecryptCleanVolumeUnaffected(t *testing.T) {
	plaintext := []byte("clean volume, force flag on")
	pw := []byte("pw-clean-force")
	vol, code := EncryptVolume(plaintext, pw, EncryptOptions{})
	if code != 0 {
		t.Fatalf("encrypt code %d", code)
	}
	res, c := DecryptVolume(vol, pw, DecryptOptions{Force: true})
	if c != 0 {
		t.Fatalf("clean+force: got code %d, want 0", c)
	}
	if res.Kept {
		t.Fatal("Kept must be false for a cleanly verified volume")
	}
	if !bytes.Equal(res.Plaintext, plaintext) {
		t.Fatal("plaintext mismatch on clean decrypt")
	}
}

// Non-RS: a flipped payload byte breaks the MAC. force=off fails closed; force=on
// keeps the ACTUAL corrupted decryption (stream cipher => exactly one plaintext
// byte flips by the same mask). Anti-vacuity: fails if salvage returns zeros, the
// pristine plaintext, or garbage.
func TestForceDecryptNonRSKeepsCorruptedBytes(t *testing.T) {
	plaintext := []byte(strings.Repeat("force-decrypt-nonrs-", 50))
	pw := []byte("pw-force-nonrs")
	vol, code := EncryptVolume(plaintext, pw, EncryptOptions{})
	if code != 0 {
		t.Fatalf("encrypt code %d", code)
	}
	const flipIdx = 5
	const mask = 0xFF
	tampered := append([]byte(nil), vol...)
	tampered[header.HeaderSize(0)+flipIdx] ^= mask

	if _, c := DecryptVolume(tampered, pw, DecryptOptions{}); c != ErrModifiedData {
		t.Fatalf("force=off: got code %d, want ErrModifiedData(%d)", c, ErrModifiedData)
	}

	res, c := DecryptVolume(tampered, pw, DecryptOptions{Force: true})
	if c != ErrModifiedButKept {
		t.Fatalf("force=on: got code %d, want ErrModifiedButKept(%d)", c, ErrModifiedButKept)
	}
	if !res.Kept {
		t.Fatal("Kept must be true on a forced keep")
	}
	if len(res.Plaintext) != len(plaintext) {
		t.Fatalf("kept len %d, want %d", len(res.Plaintext), len(plaintext))
	}
	for i := range plaintext {
		want := plaintext[i]
		if i == flipIdx {
			want ^= mask
		}
		if res.Plaintext[i] != want {
			t.Fatalf("kept byte %d = %#x, want %#x", i, res.Plaintext[i], want)
		}
	}
}

// RS volume, damage beyond the RS128 budget (>4 byte-errors in one 136-byte block):
// force=off fails closed; force=on salvages best-effort. Anti-vacuity: the
// undamaged region (beyond the first 128-byte data chunk) matches the original
// exactly, while the damaged first chunk does NOT equal the pristine plaintext.
func TestForceDecryptRSOverBudgetKeeps(t *testing.T) {
	plaintext := []byte(strings.Repeat("rs-force-", 2000)) // 18000 bytes, multi-chunk
	pw := []byte("pw-force-rs")
	vol, code := EncryptVolume(plaintext, pw, EncryptOptions{ReedSolomon: true})
	if code != 0 {
		t.Fatalf("encrypt code %d", code)
	}
	payloadStart := header.HeaderSize(0)
	tampered := append([]byte(nil), vol...)
	for i := range 9 { // 9 > 4 -> uncorrectable in the first RS block
		tampered[payloadStart+i] ^= 0xFF
	}

	if _, c := DecryptVolume(tampered, pw, DecryptOptions{}); c != ErrModifiedData {
		t.Fatalf("force=off: got code %d, want ErrModifiedData(%d)", c, ErrModifiedData)
	}

	res, c := DecryptVolume(tampered, pw, DecryptOptions{Force: true})
	if c != ErrModifiedButKept {
		t.Fatalf("force=on: got code %d, want ErrModifiedButKept(%d)", c, ErrModifiedButKept)
	}
	if !res.Kept {
		t.Fatal("Kept must be true on a forced keep")
	}
	if len(res.Plaintext) != len(plaintext) {
		t.Fatalf("kept len %d, want %d", len(res.Plaintext), len(plaintext))
	}
	if !bytes.Equal(res.Plaintext[128:], plaintext[128:]) {
		t.Fatal("undamaged region beyond the first RS data chunk must be intact")
	}
	if bytes.Equal(res.Plaintext[:128], plaintext[:128]) {
		t.Fatal("first RS chunk should reflect corruption, not be pristine")
	}
}

// RS + legacy keyfiles + force: the salvage cipher suite must be rebuilt with
// the keyfile-XOR'd cipher key and v2 subkey ordering. The frozen fixture keeps
// this reader path covered without reopening the disabled v2 writer. It also
// proves force does NOT bypass the keyfile requirement (force gates only the
// payload MAC).
func TestForceDecryptLegacyRSKeyfileVolumeKeeps(t *testing.T) {
	useProductionTestWASMKDF(t)

	plaintext := legacyWASMKeyfileRSPlaintext()
	pw := []byte("test")
	kfs := [][]byte{readWASMGoldenFixture(t, "keyfile_alpha.bin")}
	vol := readWASMLegacyKeyfileRSFixture(t)
	hdr := readHeaderForTest(t, vol)
	if !hdr.Flags.ReedSolomon || !hdr.Flags.UseKeyfiles {
		t.Fatalf(
			"legacy fixture flags: ReedSolomon=%v UseKeyfiles=%v; want both true",
			hdr.Flags.ReedSolomon,
			hdr.Flags.UseKeyfiles,
		)
	}
	payloadStart := header.HeaderSize(len(hdr.Comments))
	tampered := append([]byte(nil), vol...)
	for i := range 9 { // > RS128 budget -> uncorrectable -> salvage path
		tampered[payloadStart+i] ^= 0xFF
	}

	// force=on but keyfiles missing: must still demand keyfiles, not salvage.
	if _, c := DecryptVolume(tampered, pw, DecryptOptions{Force: true}); c != ErrKeyfilesRequired {
		t.Fatalf("force + no keyfiles: got %d, want ErrKeyfilesRequired(%d)", c, ErrKeyfilesRequired)
	}
	// force=off with correct keyfiles: fail closed.
	if _, c := DecryptVolume(tampered, pw, DecryptOptions{Keyfiles: kfs}); c != ErrModifiedData {
		t.Fatalf("force=off: got %d, want ErrModifiedData(%d)", c, ErrModifiedData)
	}
	// force=on with correct keyfiles: best-effort salvage through the keyfile suite.
	res, c := DecryptVolume(tampered, pw, DecryptOptions{Keyfiles: kfs, Force: true})
	if c != ErrModifiedButKept {
		t.Fatalf("force=on: got %d, want ErrModifiedButKept(%d)", c, ErrModifiedButKept)
	}
	if !res.Kept || len(res.Plaintext) != len(plaintext) {
		t.Fatalf("kept=%v len=%d (want true, %d)", res.Kept, len(res.Plaintext), len(plaintext))
	}
	if !bytes.Equal(res.Plaintext[128:], plaintext[128:]) {
		t.Fatal("undamaged region must be intact (keyfile salvage subkey ordering)")
	}
}

// RS + paranoid + force: exercises the salvage path with the paranoid cipher
// cascade (Serpent-CTR + XChaCha20, HMAC-SHA3) re-derived for the salvage suite.
func TestForceDecryptParanoidRSKeeps(t *testing.T) {
	plaintext := []byte(strings.Repeat("paranoid-rs-force-", 1200))
	pw := []byte("pw-paranoid-rs-force")
	vol, code := EncryptVolume(plaintext, pw, EncryptOptions{Paranoid: true, ReedSolomon: true})
	if code != 0 {
		t.Fatalf("encrypt code %d", code)
	}
	payloadStart := header.HeaderSize(0)
	tampered := append([]byte(nil), vol...)
	for i := range 9 { // > RS128 budget -> uncorrectable -> salvage path
		tampered[payloadStart+i] ^= 0xFF
	}

	if _, c := DecryptVolume(tampered, pw, DecryptOptions{}); c != ErrModifiedData {
		t.Fatalf("force=off: got %d, want ErrModifiedData(%d)", c, ErrModifiedData)
	}
	res, c := DecryptVolume(tampered, pw, DecryptOptions{Force: true})
	if c != ErrModifiedButKept {
		t.Fatalf("force=on: got %d, want ErrModifiedButKept(%d)", c, ErrModifiedButKept)
	}
	if !res.Kept || len(res.Plaintext) != len(plaintext) {
		t.Fatalf("kept=%v len=%d (want true, %d)", res.Kept, len(res.Plaintext), len(plaintext))
	}
	if !bytes.Equal(res.Plaintext[128:], plaintext[128:]) {
		t.Fatal("undamaged region must be intact (paranoid RS salvage)")
	}
}
