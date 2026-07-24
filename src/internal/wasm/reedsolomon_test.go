package wasm

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/volume"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// desktopDecrypt decrypts a WASM-produced volume via the shared desktop engine,
// proving the on-disk RS framing is byte-compatible.
func desktopDecrypt(t *testing.T, volumeData []byte, password string) []byte {
	t.Helper()
	tmp := t.TempDir()
	in := filepath.Join(tmp, "v.pcv")
	out := filepath.Join(tmp, "v.out")
	if err := os.WriteFile(in, volumeData, 0o600); err != nil {
		t.Fatalf("write volume: %v", err)
	}
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}
	if err := volume.Decrypt(context.Background(), &volume.DecryptRequest{
		InputFile: in, OutputFile: out, Password: []byte(password), RSCodecs: rs,
	}); err != nil {
		t.Fatalf("desktop Decrypt: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	return got
}

func TestWASMReedSolomonEncryptDesktopDecrypt(t *testing.T) {
	useProductionTestWASMKDF(t)

	const miB = 1 << 20
	password := "rs-encrypt-interop"
	sizes := []int{1, 200, miB - 129, miB - 128, miB - 1, miB, miB + 17, 2*miB - 1}
	for _, n := range sizes {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			plaintext := make([]byte, n)
			for i := range plaintext {
				plaintext[i] = byte(i*13 + 1)
			}
			vol, code := EncryptVolume(plaintext, []byte(password), EncryptOptions{ReedSolomon: true})
			if code != 0 {
				t.Fatalf("n=%d EncryptVolume code %d", n, code)
			}
			// Header must advertise RS; Padded iff the final partial block fills a full block.
			hdr := readHeaderForTest(t, vol)
			if !hdr.Flags.ReedSolomon {
				t.Fatalf("n=%d: ReedSolomon flag not set", n)
			}
			wantPadded := n%miB >= miB-128
			if hdr.Flags.Padded != wantPadded {
				t.Fatalf("n=%d: Padded=%v want %v", n, hdr.Flags.Padded, wantPadded)
			}
			got := desktopDecrypt(t, vol, password)
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("n=%d: desktop decrypt mismatch (%d vs %d bytes)", n, len(got), n)
			}
		})
	}
}

func readHeaderForTest(t *testing.T, volumeData []byte) *header.VolumeHeader {
	t.Helper()
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}
	res, err := header.NewReader(bytes.NewReader(volumeData), rs).ReadHeader()
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	return res.Header
}

func TestWASMReedSolomonRoundtrip(t *testing.T) {
	const miB = 1 << 20
	password := "rs-roundtrip"
	for _, n := range []int{1, 200, miB - 128, miB - 1, miB, miB + 5, 2 * miB} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			plaintext := make([]byte, n)
			for i := range plaintext {
				plaintext[i] = byte(i*5 + 9)
			}
			vol, code := EncryptVolume(plaintext, []byte(password), EncryptOptions{ReedSolomon: true})
			if code != 0 {
				t.Fatalf("n=%d encrypt code %d", n, code)
			}
			res, code := DecryptVolume(vol, []byte(password), DecryptOptions{})
			if code != 0 {
				t.Fatalf("n=%d decrypt code %d", n, code)
			}
			if !bytes.Equal(res.Plaintext, plaintext) {
				t.Fatalf("n=%d roundtrip mismatch", n)
			}
		})
	}
}

func TestWASMReedSolomonRepairsCorrectableDamage(t *testing.T) {
	password := "rs-repair"
	plaintext := make([]byte, 4096)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	vol, code := EncryptVolume(plaintext, []byte(password), EncryptOptions{ReedSolomon: true})
	if code != 0 {
		t.Fatalf("encrypt code %d", code)
	}
	// Corrupt 4 bytes inside the first payload chunk's DATA region (first 128 of the
	// first 136-byte block) so the fast pass yields a wrong MAC and the full-RS retry
	// must repair it. RS128 corrects up to 4 errors per 136-byte block.
	payloadStart := header.HeaderSize(0)
	for i := range 4 {
		vol[payloadStart+i] ^= 0xFF
	}
	res, code := DecryptVolume(vol, []byte(password), DecryptOptions{})
	if code != 0 {
		t.Fatalf("expected repair, got code %d", code)
	}
	if !bytes.Equal(res.Plaintext, plaintext) {
		t.Fatal("repaired plaintext mismatch")
	}
}

func TestWASMReedSolomonUncorrectableFailsClosed(t *testing.T) {
	password := "rs-uncorrectable"
	plaintext := make([]byte, 4096)
	vol, code := EncryptVolume(plaintext, []byte(password), EncryptOptions{ReedSolomon: true})
	if code != 0 {
		t.Fatalf("encrypt code %d", code)
	}
	// 9 byte-errors in one 136-byte block: beyond the RS budget -> unrecoverable.
	payloadStart := header.HeaderSize(0)
	for i := range 9 {
		vol[payloadStart+i] ^= 0xFF
	}
	_, code = DecryptVolume(vol, []byte(password), DecryptOptions{})
	if code != ErrModifiedData {
		t.Fatalf("want ErrModifiedData(%d), got %d", ErrModifiedData, code)
	}
}

func TestWASMReedSolomonDesktopEncryptWASMDecrypt(t *testing.T) {
	useProductionTestWASMKDF(t)

	password := "desktop-rs-to-wasm"
	plaintext := []byte("Desktop-encrypted RS volume must decrypt in WASM unchanged.")
	tmp := t.TempDir()
	in := filepath.Join(tmp, "p.txt")
	out := filepath.Join(tmp, "p.pcv")
	if err := os.WriteFile(in, plaintext, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}
	if err := volume.Encrypt(context.Background(), &volume.EncryptRequest{
		InputFile: in, OutputFile: out, Password: []byte(password),
		ReedSolomon: true, RSCodecs: rs,
	}); err != nil {
		t.Fatalf("desktop Encrypt: %v", err)
	}
	vol, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read volume: %v", err)
	}
	res, code := DecryptVolume(vol, []byte(password), DecryptOptions{})
	if code != 0 {
		t.Fatalf("WASM decrypt code %d", code)
	}
	if !bytes.Equal(res.Plaintext, plaintext) {
		t.Fatal("desktop->WASM RS decrypt mismatch")
	}
}

func TestWASMReedSolomonParanoidRoundtrip(t *testing.T) {
	password := "rs-paranoid"
	plaintext := make([]byte, 5000)
	for i := range plaintext {
		plaintext[i] = byte(i * 3)
	}
	vol, code := EncryptVolume(plaintext, []byte(password), EncryptOptions{ReedSolomon: true, Paranoid: true})
	if code != 0 {
		t.Fatalf("encrypt code %d", code)
	}
	res, code := DecryptVolume(vol, []byte(password), DecryptOptions{})
	if code != 0 {
		t.Fatalf("decrypt code %d", code)
	}
	if !bytes.Equal(res.Plaintext, plaintext) {
		t.Fatal("paranoid RS roundtrip mismatch")
	}
}

// Correctable payload damage must still take the full-RS retry for a legacy
// keyfile volume. A frozen pre-containment fixture keeps this compatibility
// path covered without a test-only bypass of the disabled v2 keyfile writer.
func TestWASMReedSolomonRepairsLegacyKeyfileVolume(t *testing.T) {
	useProductionTestWASMKDF(t)

	plaintext := legacyWASMKeyfileRSPlaintext()
	volumeData := readWASMLegacyKeyfileRSFixture(t)
	hdr := readHeaderForTest(t, volumeData)
	if !hdr.Flags.ReedSolomon || !hdr.Flags.UseKeyfiles {
		t.Fatalf(
			"legacy fixture flags: ReedSolomon=%v UseKeyfiles=%v; want both true",
			hdr.Flags.ReedSolomon,
			hdr.Flags.UseKeyfiles,
		)
	}

	// Four damaged bytes are correctable, but they make the fast-pass MAC fail,
	// so success proves the authenticated full-RS retry ran with the keyfile key.
	tampered := append([]byte(nil), volumeData...)
	payloadStart := header.HeaderSize(len(hdr.Comments))
	for i := range 4 {
		tampered[payloadStart+i] ^= 0xFF
	}

	res, code := DecryptVolume(
		tampered,
		[]byte("test"),
		DecryptOptions{Keyfiles: [][]byte{readWASMGoldenFixture(t, "keyfile_alpha.bin")}},
	)
	if code != 0 {
		t.Fatalf("decrypt correctly repairable legacy RS+keyfile fixture code %d", code)
	}
	if !bytes.Equal(res.Plaintext, plaintext) {
		t.Fatal("repaired legacy RS+keyfile plaintext mismatch")
	}
}

// TestWASMReedSolomonRepairsMultiBlockDamage proves that RS repair works when
// damage falls in the SECOND on-disk RS block (i.e. > 1 MiB of plaintext so
// at least two full RS blocks exist). This forces the full-RS retry (Pass-2)
// to walk past the first block and repair the second, which the
// single-block repair test cannot exercise.
func TestWASMReedSolomonRepairsMultiBlockDamage(t *testing.T) {
	const miB = 1 << 20
	password := "rs-multi-block-repair"
	plaintext := make([]byte, miB+50000)
	for i := range plaintext {
		plaintext[i] = byte(i*7 + 3)
	}
	vol, code := EncryptVolume(plaintext, []byte(password), EncryptOptions{ReedSolomon: true})
	if code != 0 {
		t.Fatalf("encrypt code %d", code)
	}
	// Corrupt 4 bytes inside the DATA region of the second on-disk RS block.
	// The second block starts immediately after the header and the first RS block.
	// Flipping bytes here causes the fast-pass MAC to mismatch, forcing Pass-2
	// (full RS correction) which repairs the damage and recovers the plaintext.
	secondBlockStart := header.HeaderSize(0) + encoding.RSEncodedBlockSize
	for i := range 4 {
		vol[secondBlockStart+i] ^= 0xFF
	}
	res, code := DecryptVolume(vol, []byte(password), DecryptOptions{})
	if code != 0 {
		t.Fatalf("expected repair of second-block damage, got code %d", code)
	}
	if !bytes.Equal(res.Plaintext, plaintext) {
		t.Fatal("repaired multi-block plaintext mismatch")
	}
}
