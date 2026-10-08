package volume

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repairingReporter is a minimal ProgressReporter that records whether it ever
// observed a "Repairing" status. decryptPayloadWithFastDecode emits "Repairing
// at ..." only on the full-RS retry (fastDecode==false, decrypt.go:576) versus
// "Decrypting at ..." on the fast first pass — so a seen-Repairing signal proves
// the full-RS decode retry actually fired (guards against the vacuous-test
// pitfall where the fast pass coincidentally still passes the MAC).
type repairingReporter struct {
	sawRepairing bool
	cancelled    bool
}

func (r *repairingReporter) SetStatus(text string) {
	if strings.Contains(text, "Repairing") {
		r.sawRepairing = true
	}
}

func (r *repairingReporter) SetProgress(fraction float32, info string) {}

func (r *repairingReporter) SetCanCancel(can bool) {}

func (r *repairingReporter) Update() {}

func (r *repairingReporter) IsCancelled() bool {
	return r.cancelled
}

// encryptRSVolume encrypts plaintext into a Reed-Solomon-enabled .pcv and returns
// its path. Mirrors the TestRoundTripReedSolomon encrypt setup.
//
// Shared with TestVerifyFirstCorrectableRS: keep this helper
// and corruptOneRSBlock reusable to build a .pcv with
// correctable RS128 damage. Do not specialize them to a single test.
func encryptRSVolume(t *testing.T, plaintext []byte, password string) string {
	t.Helper()

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}

	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "rs_input.bin")
	if err := os.WriteFile(inputPath, plaintext, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "rs_input.bin.pcv")
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    []byte(password),
		ReedSolomon: true,
		Reporter:    &GoldenTestReporter{},
		RSCodecs:    rsCodecs,
	}
	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt (RS): %v", err)
	}
	return encryptedPath
}

// corruptOneRSBlock flips nFlips (<= 4) bytes WITHIN the first 128 (data) bytes
// of the 136-byte RS128 payload block at blockIndex, then writes the volume back.
//
// Flipping inside the data region (not parity) and keeping nFlips within the
// RS128 4-error/136-block budget makes the damage repairable by the FULL RS pass
// but visible to (and unrepaired by) the FAST pass — which is exactly what forces
// the full-RS-decode retry to fire AND succeed.
//
// Shared with TestVerifyFirstCorrectableRS — see encryptRSVolume.
func corruptOneRSBlock(t *testing.T, pcvPath string, blockIndex, nFlips int) {
	t.Helper()
	if nFlips < 1 || nFlips > 4 {
		t.Fatalf("corruptOneRSBlock: nFlips=%d out of RS128 [1,4] budget", nFlips)
	}

	data, err := os.ReadFile(pcvPath)
	if err != nil {
		t.Fatalf("read pcv: %v", err)
	}

	// Payload starts right after the header. These fixtures are authored with no
	// comments, so the payload offset is BaseHeaderSize (= HeaderSize(0)).
	payloadStart := header.HeaderSize(0)
	blockStart := payloadStart + blockIndex*encoding.RS128EncodedSize
	if blockStart+encoding.RS128DataSize > len(data) {
		t.Fatalf("corruptOneRSBlock: block %d data region [%d,%d) exceeds file size %d",
			blockIndex, blockStart, blockStart+encoding.RS128DataSize, len(data))
	}

	// Flip nFlips distinct, spread-out bytes inside the 128-byte data region.
	for k := range nFlips {
		pos := blockStart + k*31 // 31 keeps positions distinct within [0,128)
		data[pos] ^= 0xFF
	}

	if err := os.WriteFile(pcvPath, data, 0o600); err != nil {
		t.Fatalf("write corrupted pcv: %v", err)
	}
}

// TestFullRSDecodeRetryStateReset forces the full-RS-decode retry via correctable
// RS damage and asserts the retried decrypt reproduces the original plaintext with
// no cross-pass state bleed (D-06/D-08). The recording reporter must observe a
// "Repairing" status, proving the retry actually fired (non-vacuous).
func TestFullRSDecodeRetryStateReset(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}

	const password = "retry-state-reset-pw"
	// Plaintext large enough to span multiple RS128 blocks so block 0 is a
	// full, non-trailing data block (no padding interaction with the flips).
	plaintext := make([]byte, 4*encoding.RS128DataSize)
	for i := range plaintext {
		plaintext[i] = byte(i*13 + 7)
	}

	pcvPath := encryptRSVolume(t, plaintext, password)
	// 4 byte errors within block 0's data region: repairable by the full pass,
	// wrong under the fast pass -> MAC mismatch -> full-RS retry.
	corruptOneRSBlock(t, pcvPath, 0, 4)

	reporter := &repairingReporter{}
	outputPath := filepath.Join(filepath.Dir(pcvPath), "rs_retry_out.bin")
	decReq := &DecryptRequest{
		InputFile:    pcvPath,
		OutputFile:   outputPath,
		Password:     []byte(password),
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt after correctable RS damage: %v", err)
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
			t.Fatalf("decrypted byte %d = %#x; want %#x (state bleed across retry?)", i, got[i], plaintext[i])
		}
	}

	if !reporter.sawRepairing {
		t.Fatal("full-RS retry did not fire (no \"Repairing\" status observed); test would be vacuous")
	}
}
