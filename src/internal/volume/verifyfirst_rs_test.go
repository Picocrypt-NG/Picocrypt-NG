package volume

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"context"
	"os"
	"path/filepath"
	"testing"

	perrors "Picocrypt-NG/internal/errors"
)

// TestVerifyFirstCorrectableRS proves DATA-01: with VerifyFirst enabled, a
// Reed-Solomon volume carrying damage WITHIN the RS128 correction budget
// (<= 4 byte errors per 136-byte block) must decrypt to the original plaintext
// instead of being rejected as corrupt.
//
// Root cause (D-07): the verify-first pass decodes with
// decodeWithRSFast(fastDecode=true) -> no RS error correction -> correctable
// damage yields wrong ciphertext -> MAC mismatch -> ErrAuthFailed fires BEFORE
// decryptFinalize's full-RS retry can run. The fix (D-08) re-runs the verify
// pass with full RS correction on MAC mismatch before rejecting.
//
// Reuses the shared helpers encryptRSVolume and corruptOneRSBlock (D-09).
func TestVerifyFirstCorrectableRS(t *testing.T) {
	t.Run("correctable damage decrypts under verify-first", func(t *testing.T) {
		rsCodecs, err := encoding.NewRSCodecs()
		if err != nil {
			t.Fatalf("NewRSCodecs: %v", err)
		}

		const password = "verify-first-correctable-pw"
		// Multi-block plaintext so block 0 is a full, non-trailing data block
		// (no padding interaction with the flips) — mirrors TestFullRSDecodeRetryStateReset.
		plaintext := make([]byte, 4*encoding.RS128DataSize)
		for i := range plaintext {
			plaintext[i] = byte(i*13 + 7)
		}

		pcvPath := encryptRSVolume(t, plaintext, password)
		// 4 byte errors in block 0's data region: repairable by the full RS pass,
		// wrong under the fast pass -> verify-first MAC mismatch -> full-RS verify retry.
		corruptOneRSBlock(t, pcvPath, 0, 4)

		// The "Repairing" status only fires from the full-RS decode pass
		// (decryptPayloadWithFastDecode, fastDecode=false). Under verify-first the
		// fix triggers the full-RS VERIFY retry, then the normal decrypt pass also
		// retries with full RS in decryptFinalize -> "Repairing" proves a full-RS
		// path actually ran (non-vacuous guard).
		reporter := &repairingReporter{}
		outputPath := filepath.Join(filepath.Dir(pcvPath), "vf_correctable_out.bin")
		decReq := &DecryptRequest{
			InputFile:    pcvPath,
			OutputFile:   outputPath,
			Password:     []byte(password),
			VerifyFirst:  true,
			ForceDecrypt: false,
			Reporter:     reporter,
			RSCodecs:     rsCodecs,
		}

		if err := Decrypt(context.Background(), decReq); err != nil {
			t.Fatalf("Decrypt under verify-first after correctable RS damage: %v (DATA-01: should repair, not reject)", err)
		}

		got, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("read decrypted output: %v", err)
		}
		if len(got) != len(plaintext) {
			t.Fatalf("decrypted length = %d; want %d", len(got), len(plaintext))
		}
		for i := range plaintext {
			if got[i] != plaintext[i] {
				t.Fatalf("decrypted byte %d = %#x; want %#x (verify-first RS repair corrupted output?)", i, got[i], plaintext[i])
			}
		}

		if !reporter.sawRepairing {
			t.Fatal("no \"Repairing\" status observed; full-RS path did not fire — test would be vacuous")
		}
	})

	t.Run("beyond-budget damage still fails closed under verify-first", func(t *testing.T) {
		rsCodecs, err := encoding.NewRSCodecs()
		if err != nil {
			t.Fatalf("NewRSCodecs: %v", err)
		}

		const password = "verify-first-forged-pw"
		plaintext := make([]byte, 4*encoding.RS128DataSize)
		for i := range plaintext {
			plaintext[i] = byte(i*7 + 3)
		}

		pcvPath := encryptRSVolume(t, plaintext, password)
		// Damage BEYOND the RS128 4-error/block budget: even full RS correction
		// cannot repair this, so the MAC must still mismatch and verify-first must
		// fail closed with ErrAuthFailed — proving the retry does not blindly accept
		// forged/over-damaged volumes (anti-weakening, PCC-004).
		corruptRSBlockBeyondBudget(t, pcvPath, 0)

		outputPath := filepath.Join(filepath.Dir(pcvPath), "vf_forged_out.bin")
		decReq := &DecryptRequest{
			InputFile:    pcvPath,
			OutputFile:   outputPath,
			Password:     []byte(password),
			VerifyFirst:  true,
			ForceDecrypt: false,
			Reporter:     &GoldenTestReporter{},
			RSCodecs:     rsCodecs,
		}

		err = Decrypt(context.Background(), decReq)
		if err == nil {
			t.Fatal("Decrypt under verify-first accepted beyond-budget damage; want auth/corrupt error (verify-first must fail closed)")
		}
		// Verify-first rejects at the MAC pass with ErrAuthFailed (the full-RS verify
		// retry also fails, so it returns ErrAuthFailed without ever decrypting).
		if !perrors.Is(err, perrors.ErrAuthFailed) && !perrors.Is(err, perrors.ErrCorruptData) {
			t.Fatalf("Decrypt error = %v; want ErrAuthFailed or ErrCorruptData (fail-closed)", err)
		}
		// No plaintext must be emitted on a fail-closed verify-first.
		if _, statErr := os.Stat(outputPath); statErr == nil {
			t.Fatal("output file exists after fail-closed verify-first; no plaintext should be emitted (PCC-004)")
		}
	})
}

// corruptRSBlockBeyondBudget flips far more than 4 bytes across the entire
// 136-byte RS128 block at blockIndex (data + parity), guaranteeing damage that
// exceeds the RS128 4-error correction budget so full RS correction cannot
// repair it. Used to assert verify-first still fails closed.
func corruptRSBlockBeyondBudget(t *testing.T, pcvPath string, blockIndex int) {
	t.Helper()

	data, err := os.ReadFile(pcvPath)
	if err != nil {
		t.Fatalf("read pcv: %v", err)
	}

	payloadStart := header.HeaderSize(0)
	blockStart := payloadStart + blockIndex*encoding.RS128EncodedSize
	if blockStart+encoding.RS128EncodedSize > len(data) {
		t.Fatalf("corruptRSBlockBeyondBudget: block %d [%d,%d) exceeds file size %d",
			blockIndex, blockStart, blockStart+encoding.RS128EncodedSize, len(data))
	}

	// Flip every byte of the 136-byte encoded block: ~136 errors >> the 4-error
	// RS128 budget, so this is irrecoverable.
	for i := range encoding.RS128EncodedSize {
		data[blockStart+i] ^= 0xFF
	}

	if err := os.WriteFile(pcvPath, data, 0o600); err != nil {
		t.Fatalf("write corrupted pcv: %v", err)
	}
}
