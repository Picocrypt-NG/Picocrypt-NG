package volume

import (
	"Picocrypt-NG/internal/encoding"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Password forms built from explicit code points (never source literals, which
// an editor could silently re-normalize). These are the UAX #15 worked vectors
// behind issue #19: the same visible password in two byte forms.
var (
	composedPassword   = string([]rune{0x00E9})         // é  NFC -> C3 A9
	decomposedPassword = string([]rune{0x0065, 0x0301}) // é  NFD -> 65 CC 81
	wantNFCBytes       = []byte{0xc3, 0xa9}
)

// captureKDF installs a KDF hook recording the password bytes handed to the
// volume / deniability key derivation, while still producing a real (fast,
// byte-sensitive) key so the surrounding logic runs normally.
func captureKDF(volumePW, deniabilityPW *[]byte) func() {
	return useTestKDF(
		func(pw, salt []byte, paranoid bool) ([]byte, error) {
			if volumePW != nil {
				*volumePW = append([]byte(nil), pw...)
			}
			return fastTestVolumeKey(pw, salt, paranoid)
		},
		func(pw, salt []byte) []byte {
			if deniabilityPW != nil {
				*deniabilityPW = append([]byte(nil), pw...)
			}
			return fastTestDeniabilityKey(pw, salt)
		},
	)
}

// countingKDF installs a hook that counts volume-key derivations (used to assert
// how many password-form candidates were tried).
func countingKDF(count *int) func() {
	return useTestKDF(
		func(pw, salt []byte, paranoid bool) ([]byte, error) {
			*count++
			return fastTestVolumeKey(pw, salt, paranoid)
		},
		fastTestDeniabilityKey,
	)
}

// legacyKDF installs an ENCRYPT hook that derives the volume key from fixedPW
// regardless of the (normalized) input — simulating a pre-normalization volume
// whose stored key came from raw, un-normalized password bytes.
func legacyKDF(fixedPW []byte) func() {
	return useTestKDF(
		func(_, salt []byte, paranoid bool) ([]byte, error) {
			return fastTestVolumeKey(fixedPW, salt, paranoid)
		},
		fastTestDeniabilityKey,
	)
}

func writeTempInput(t *testing.T) string {
	t.Helper()
	in := filepath.Join(t.TempDir(), "pt.txt")
	if err := os.WriteFile(in, []byte("plaintext"), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	return in
}

// roundTripVolume encrypts plain with encPW then decrypts with decPW, returning
// the decrypt error (nil on success). On success it also asserts the recovered
// plaintext matches. Encrypt failures are fatal (not the behavior under test).
func roundTripVolume(t *testing.T, encPW, decPW string, deniability bool) error {
	t.Helper()
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("RS codecs: %v", err)
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "pt.txt")
	plain := []byte("secret cross-platform payload")
	if err := os.WriteFile(in, plain, 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	vol := filepath.Join(dir, "v.txt.pcv")
	out := filepath.Join(dir, "out.txt")

	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile: in, OutputFile: vol, Password: []byte(encPW), Deniability: deniability,
		Reporter: &GoldenTestReporter{}, RSCodecs: rsCodecs,
	}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if err := Decrypt(context.Background(), &DecryptRequest{
		InputFile: vol, OutputFile: out, Password: []byte(decPW), Deniability: deniability,
		Reporter: &GoldenTestReporter{}, RSCodecs: rsCodecs,
	}); err != nil {
		return err
	}

	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("recovered plaintext = %q, want %q", got, plain)
	}
	return nil
}

// --- Encrypt-side normalization ---

// TestEncryptNormalizesPasswordToNFC asserts the encrypt path feeds the KDF the
// NFC form, so a volume created from a decomposed password is byte-identical to
// one created from the composed form — the core of the #19 fix.
func TestEncryptNormalizesPasswordToNFC(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("RS codecs: %v", err)
	}
	in := writeTempInput(t)
	out := filepath.Join(filepath.Dir(in), "v.txt.pcv")

	var fedToKDF []byte
	restore := captureKDF(&fedToKDF, nil)
	defer restore()

	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile: in, OutputFile: out, Password: []byte(decomposedPassword),
		Reporter: &GoldenTestReporter{}, RSCodecs: rsCodecs,
	}); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !bytes.Equal(fedToKDF, wantNFCBytes) {
		t.Errorf("encrypt fed KDF % x, want NFC % x", fedToKDF, wantNFCBytes)
	}
}

// TestEncryptDeniabilityNormalizesPasswordToNFC asserts BOTH the inner volume
// key and the outer deniability-wrapper key derive from the NFC form (the
// deniability layer has no readable header, so it relies on a canonical form).
func TestEncryptDeniabilityNormalizesPasswordToNFC(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("RS codecs: %v", err)
	}
	in := writeTempInput(t)
	out := filepath.Join(filepath.Dir(in), "v.txt.pcv")

	var fedToVolume, fedToDeniability []byte
	restore := captureKDF(&fedToVolume, &fedToDeniability)
	defer restore()

	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile: in, OutputFile: out, Password: []byte(decomposedPassword), Deniability: true,
		Reporter: &GoldenTestReporter{}, RSCodecs: rsCodecs,
	}); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !bytes.Equal(fedToVolume, wantNFCBytes) {
		t.Errorf("inner volume key fed KDF % x, want NFC % x", fedToVolume, wantNFCBytes)
	}
	if !bytes.Equal(fedToDeniability, wantNFCBytes) {
		t.Errorf("deniability wrapper fed KDF % x, want NFC % x", fedToDeniability, wantNFCBytes)
	}
}

// --- Decrypt-side try-both ---

// TestDecryptTriesNormalizationFormsRoundTrip is the core #19 fix: a volume
// encrypted from either composed or decomposed input must decrypt from either
// form. Without decrypt-side try-both, decrypting an NFC-stored volume with the
// decomposed form fails.
func TestDecryptTriesNormalizationFormsRoundTrip(t *testing.T) {
	forms := []struct {
		name string
		pw   string
	}{
		{"NFC", composedPassword},
		{"NFD", decomposedPassword},
	}
	for _, enc := range forms {
		for _, dec := range forms {
			t.Run(enc.name+"_encrypt_"+dec.name+"_decrypt", func(t *testing.T) {
				if err := roundTripVolume(t, enc.pw, dec.pw, false); err != nil {
					t.Errorf("cross-form round-trip failed: %v", err)
				}
			})
		}
	}
}

// TestDecryptDeniabilityTriesNormalizationForms verifies the deniability
// unwrap path also tries multiple forms (it selects the key by probing the
// decrypted inner header).
func TestDecryptDeniabilityTriesNormalizationForms(t *testing.T) {
	if err := roundTripVolume(t, decomposedPassword, composedPassword, true); err != nil {
		t.Errorf("deniable encrypt(NFD) -> decrypt(NFC): %v", err)
	}
	if err := roundTripVolume(t, composedPassword, decomposedPassword, true); err != nil {
		t.Errorf("deniable encrypt(NFC) -> decrypt(NFD): %v", err)
	}
}

// TestDecryptOpensLegacyNFDVolumeViaNFDCandidate simulates a pre-normalization
// volume whose stored key came from raw decomposed bytes. Typing the composed
// form must still open it: the NFC candidate fails and the NFD candidate matches.
func TestDecryptOpensLegacyNFDVolumeViaNFDCandidate(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("RS codecs: %v", err)
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "pt.txt")
	plain := []byte("legacy nfd-origin payload")
	if err := os.WriteFile(in, plain, 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	vol := filepath.Join(dir, "v.txt.pcv")
	out := filepath.Join(dir, "out.txt")

	// Stored key derives from the raw NFD bytes regardless of normalization.
	restoreEnc := legacyKDF([]byte(decomposedPassword))
	encErr := Encrypt(context.Background(), &EncryptRequest{
		InputFile: in, OutputFile: vol, Password: []byte(composedPassword),
		Reporter: &GoldenTestReporter{}, RSCodecs: rsCodecs,
	})
	restoreEnc() // restore the byte-sensitive KDF for decryption
	if encErr != nil {
		t.Fatalf("encrypt: %v", encErr)
	}

	// User types the composed form; only the NFD candidate reproduces the key.
	if err := Decrypt(context.Background(), &DecryptRequest{
		InputFile: vol, OutputFile: out, Password: []byte(composedPassword),
		Reporter: &GoldenTestReporter{}, RSCodecs: rsCodecs,
	}); err != nil {
		t.Fatalf("legacy NFD volume failed to open via NFD candidate: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("recovered plaintext = %q, want %q", got, plain)
	}
}

// TestDecryptOpensLegacyRawVolumeViaRawCandidate simulates a legacy volume whose
// password bytes were neither NFC nor NFD (combining marks in non-canonical
// order). Only the raw candidate reproduces the key, so dropping raw from the
// candidate set would lock such volumes out.
func TestDecryptOpensLegacyRawVolumeViaRawCandidate(t *testing.T) {
	nonCanonical := string([]rune{0x0065, 0x0301, 0x0323}) // e + acute + dot-below
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("RS codecs: %v", err)
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "pt.txt")
	plain := []byte("legacy non-canonical payload")
	if err := os.WriteFile(in, plain, 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	vol := filepath.Join(dir, "v.txt.pcv")
	out := filepath.Join(dir, "out.txt")

	restoreEnc := legacyKDF([]byte(nonCanonical))
	encErr := Encrypt(context.Background(), &EncryptRequest{
		InputFile: in, OutputFile: vol, Password: []byte(nonCanonical),
		Reporter: &GoldenTestReporter{}, RSCodecs: rsCodecs,
	})
	restoreEnc()
	if encErr != nil {
		t.Fatalf("encrypt: %v", encErr)
	}

	if err := Decrypt(context.Background(), &DecryptRequest{
		InputFile: vol, OutputFile: out, Password: []byte(nonCanonical),
		Reporter: &GoldenTestReporter{}, RSCodecs: rsCodecs,
	}); err != nil {
		t.Fatalf("legacy raw volume failed to open via raw candidate: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("recovered plaintext = %q, want %q", got, plain)
	}
}

// TestDecryptWrongNonASCIIPasswordFails ensures try-both never accepts a wrong
// password: after exhausting every candidate form, decryption must fail.
func TestDecryptWrongNonASCIIPasswordFails(t *testing.T) {
	wrong := string([]rune{0x00FC}) // ü, a different non-ASCII password
	if err := roundTripVolume(t, composedPassword, wrong, false); err == nil {
		t.Fatal("decrypt with a wrong non-ASCII password must fail after trying all forms")
	}
}

// TestDecryptASCIIPasswordTriesSingleCandidate locks the performance invariant:
// an ASCII password collapses to exactly one candidate form, so even a WRONG
// ASCII password — which exhausts the whole candidate list — runs the (1 GiB)
// KDF exactly once, not three times. A CORRECT password would short-circuit on
// the first candidate and mask a regression in the candidate count, so this
// deliberately uses a wrong password to make the count observable.
func TestDecryptASCIIPasswordTriesSingleCandidate(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("RS codecs: %v", err)
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "pt.txt")
	if err := os.WriteFile(in, []byte("ascii payload"), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	vol := filepath.Join(dir, "v.txt.pcv")
	out := filepath.Join(dir, "out.txt")

	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile: in, OutputFile: vol, Password: []byte("ascii-password"),
		Reporter: &GoldenTestReporter{}, RSCodecs: rsCodecs,
	}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	var derivations int
	restore := countingKDF(&derivations)
	defer restore()
	// Wrong ASCII password: the candidate loop runs to exhaustion, so the
	// derivation count equals the number of candidate forms.
	if err := Decrypt(context.Background(), &DecryptRequest{
		InputFile: vol, OutputFile: out, Password: []byte("wrong-ascii-password"),
		Reporter: &GoldenTestReporter{}, RSCodecs: rsCodecs,
	}); err == nil {
		t.Fatal("decrypt with a wrong password unexpectedly succeeded")
	}
	if derivations != 1 {
		t.Errorf("wrong ASCII password ran %d KDF derivations, want exactly 1 candidate form", derivations)
	}
}

// TestDecryptForceDecryptUsesPasswordAsTyped verifies ForceDecrypt derives the
// key from the password EXACTLY AS TYPED (no normalization). ForceDecrypt
// bypasses authentication, so there is no MAC to choose a normalization form; it
// must therefore preserve the historical raw-bytes behavior. Counting
// derivations cannot catch a regression here (ForceDecrypt always stops at the
// first candidate regardless), so this captures the bytes handed to the KDF and
// asserts they are the raw, un-normalized form — not NFC.
func TestDecryptForceDecryptUsesPasswordAsTyped(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("RS codecs: %v", err)
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "pt.txt")
	if err := os.WriteFile(in, []byte("payload"), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	vol := filepath.Join(dir, "v.txt.pcv")
	out := filepath.Join(dir, "out.txt")

	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile: in, OutputFile: vol, Password: []byte(composedPassword),
		Reporter: &GoldenTestReporter{}, RSCodecs: rsCodecs,
	}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	var fedToKDF []byte
	restore := captureKDF(&fedToKDF, nil)
	defer restore()
	// Decomposed form under ForceDecrypt: the KDF must see the raw decomposed
	// bytes, not the NFC form that try-both would normalize to.
	_ = Decrypt(context.Background(), &DecryptRequest{
		InputFile: vol, OutputFile: out, Password: []byte(decomposedPassword), ForceDecrypt: true,
		Reporter: &GoldenTestReporter{}, RSCodecs: rsCodecs,
	})
	if !bytes.Equal(fedToKDF, []byte(decomposedPassword)) {
		t.Errorf("ForceDecrypt fed KDF % x, want raw as-typed % x (no normalization)", fedToKDF, []byte(decomposedPassword))
	}
}
