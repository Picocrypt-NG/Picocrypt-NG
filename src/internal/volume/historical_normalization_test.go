package volume

import (
	"Picocrypt-NG/internal/encoding"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyDecryptRetainsHistoricalUnicode15Password(t *testing.T) {
	for _, test := range []struct {
		name                     string
		verifyFirst, deniability bool
	}{
		{name: "authenticated"},
		{name: "verify-first", verifyFirst: true},
		{name: "deniability", deniability: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			rs, err := encoding.NewRSCodecs()
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			input, volume, output := filepath.Join(dir, "source"), filepath.Join(dir, "legacy.pcv"), filepath.Join(dir, "recovered")
			plaintext := []byte("legacy Unicode 15 NFC compatibility payload")
			if err := os.WriteFile(input, plaintext, 0o600); err != nil {
				t.Fatal(err)
			}
			// The historical NFC bytes are frozen independently of the current
			// normalizer. Use the real legacy writer/MAC/ciphers with the
			// package's established byte-sensitive fast KDF lane.
			if err := Encrypt(context.Background(), &EncryptRequest{
				InputFile: input, OutputFile: volume, Password: []byte{0xc3, 0x80},
				Deniability: test.deniability, RSCodecs: rs, Reporter: &GoldenTestReporter{},
			}); err != nil {
				t.Fatal(err)
			}
			originalVolume, err := os.ReadFile(volume)
			if err != nil {
				t.Fatal(err)
			}
			var aliases [][]byte
			restore := useTestKDF(
				func(pw, salt []byte, paranoid bool) ([]byte, error) {
					aliases = append(aliases, pw)
					return fastTestVolumeKey(pw, salt, paranoid)
				},
				func(pw, salt []byte) []byte {
					aliases = append(aliases, pw)
					return fastTestDeniabilityKey(pw, salt)
				},
			)
			defer restore()
			err = Decrypt(context.Background(), &DecryptRequest{
				InputFile: volume, OutputFile: output,
				Password:    []byte{0xf0, 0x90, 0x81, 0x81, 0xcc, 0x80},
				Deniability: test.deniability, VerifyFirst: test.verifyFirst,
				RSCodecs: rs, Reporter: &GoldenTestReporter{},
			})
			if err != nil {
				t.Fatalf("same historically typed password no longer opens legacy MAC: %v", err)
			}
			got, err := os.ReadFile(output)
			if err != nil || !bytes.Equal(got, plaintext) {
				t.Fatalf("recovered plaintext mismatch: %v", err)
			}
			for i, alias := range aliases {
				if !bytes.Equal(alias, make([]byte, len(alias))) {
					t.Fatalf("derived candidate %d survived terminal cleanup: %x", i, alias)
				}
			}
			wrongOutput := filepath.Join(dir, "wrong-password-output")
			err = Decrypt(context.Background(), &DecryptRequest{
				InputFile: volume, OutputFile: wrongOutput,
				Password:    []byte{0xf0, 0x90, 0x81, 0x81, 0xcc, 0x80, '!'},
				Deniability: test.deniability, VerifyFirst: test.verifyFirst,
				RSCodecs: rs, Reporter: &GoldenTestReporter{},
			})
			if err == nil {
				t.Fatal("wrong historical password passed authentication")
			}
			if _, err := os.Stat(wrongOutput); !os.IsNotExist(err) {
				t.Fatalf("wrong password published output: %v", err)
			}
			retained, err := os.ReadFile(volume)
			if err != nil || !bytes.Equal(retained, originalVolume) {
				t.Fatalf("recovery changed encrypted source: %v", err)
			}
		})
	}
}
