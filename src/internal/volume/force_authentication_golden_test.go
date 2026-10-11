package volume

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Frozen ciphertext and plaintext keep the trust oracle independent of the
// current writer, including when the ciphertext MAC still verifies.
func TestGoldenForceAuthenticationOutcome(t *testing.T) {
	restore := useProductionTestKDF()
	defer restore()
	fixtures := findTestdata(t)
	codecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		fixture   string
		keyfile   string
		force     bool
		mutate    func(*header.VolumeHeader)
		wantError bool
		wantKept  bool
		wantPlain bool
	}{
		{name: "correct_keyfile", fixture: "pico_test_v2_keyfile_single.txt.pcv", keyfile: "keyfile_alpha.bin", wantPlain: true},
		{name: "correct_keyfile_force", fixture: "pico_test_v2_keyfile_single.txt.pcv", keyfile: "keyfile_alpha.bin", force: true, wantPlain: true},
		{name: "wrong_keyfile_rejected", fixture: "pico_test_v2_keyfile_single.txt.pcv", keyfile: "keyfile_beta.bin", wantError: true},
		{name: "wrong_keyfile_force", fixture: "pico_test_v2_keyfile_single.txt.pcv", keyfile: "keyfile_beta.bin", force: true, wantKept: true},
		{name: "v2_header_mac_bypassed", fixture: "pico_test_v2.txt.pcv", force: true, mutate: func(h *header.VolumeHeader) { h.Nonce[0] ^= 1 }, wantKept: true},
		{name: "v2_keyfile_hash_bypassed", fixture: "pico_test_v2_keyfile_single.txt.pcv", keyfile: "keyfile_alpha.bin", force: true, mutate: func(h *header.VolumeHeader) { h.KeyfileHash[0] ^= 1 }, wantKept: true, wantPlain: true},
		{name: "v1_password_verifier_bypassed", fixture: "pico_test_v1.txt.pcv", force: true, mutate: func(h *header.VolumeHeader) { h.KeyHash[0] ^= 1 }, wantKept: true, wantPlain: true},
	}
	for _, verifyFirst := range []bool{false, true} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("%s/verify_first_%t", tc.name, verifyFirst), func(t *testing.T) {
				dir := t.TempDir()
				input := filepath.Join(dir, "volume.pcv")
				output := filepath.Join(dir, "plaintext")
				encoded, err := os.ReadFile(filepath.Join(fixtures, tc.fixture))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(input, encoded, 0o600); err != nil {
					t.Fatal(err)
				}
				if tc.mutate != nil {
					original := encoded
					parsed, err := header.NewReader(bytes.NewReader(encoded), codecs).ReadHeader()
					if err != nil || parsed.DecodeError != nil {
						t.Fatalf("read frozen header: %v", err)
					}
					originalTag := append([]byte(nil), parsed.Header.AuthTag...)
					tc.mutate(parsed.Header)
					file, err := os.OpenFile(input, os.O_RDWR, 0)
					if err != nil {
						t.Fatal(err)
					}
					n, err := header.NewWriter(file, codecs).WriteHeader(parsed.Header)
					if err == nil {
						err = header.WriteAuthValues(file, header.AuthValuesOffset(len(parsed.Header.Comments)), parsed.Header.KeyHash, parsed.Header.KeyfileHash, parsed.Header.AuthTag, codecs)
					}
					err = errors.Join(err, file.Close())
					if err != nil || n != header.HeaderSize(len(parsed.Header.Comments)) {
						t.Fatalf("write modified header: size=%d error=%v", n, err)
					}
					encoded, err = os.ReadFile(input)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(encoded[n:], original[n:]) {
						t.Fatal("modified header changed frozen ciphertext payload")
					}
					reread, err := header.NewReader(bytes.NewReader(encoded), codecs).ReadHeader()
					if err != nil || reread.DecodeError != nil {
						t.Fatalf("modified header has a decoding error: %v", err)
					}
					if !bytes.Equal(reread.Header.AuthTag, originalTag) {
						t.Fatal("modified header changed the frozen payload MAC")
					}
				}
				var keyfiles []string
				if tc.keyfile != "" {
					keyfiles = []string{filepath.Join(fixtures, tc.keyfile)}
				}
				kept := false
				err = Decrypt(t.Context(), &DecryptRequest{
					InputFile: input, OutputFile: output, Password: []byte(goldenPassword),
					Keyfiles: keyfiles, ForceDecrypt: tc.force, VerifyFirst: verifyFirst,
					RSCodecs: codecs, Reporter: &GoldenTestReporter{}, Kept: &kept,
				})
				if tc.wantError {
					var authError *header.AuthError
					if !errors.As(err, &authError) {
						t.Fatalf("authentication rejection = %v; want AuthError", err)
					}
					if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("rejected authentication published output: %v", err)
					}
				} else {
					if err != nil {
						t.Fatalf("decrypt: %v", err)
					}
					plain, err := os.ReadFile(output)
					if err != nil {
						t.Fatal(err)
					}
					if bytes.Equal(plain, []byte(expectedContent)) != tc.wantPlain {
						t.Errorf("plaintext matches frozen original = %t; want %t", bytes.Equal(plain, []byte(expectedContent)), tc.wantPlain)
					}
				}
				if kept != tc.wantKept {
					t.Errorf("untrusted output = %t; want %t", kept, tc.wantKept)
				}
				if after, err := os.ReadFile(input); err != nil || !bytes.Equal(after, encoded) {
					t.Fatalf("encrypted source changed: %v", err)
				}
				entries, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					if entry.Name() == "volume.pcv" || !tc.wantError && entry.Name() == "plaintext" {
						continue
					}
					t.Errorf("decryption left unexpected staging file %q", entry.Name())
				}
			})
		}
	}
}
