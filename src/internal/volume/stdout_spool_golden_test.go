package volume

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/fileops"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// Frozen, pre-change volumes keep the stdout transport independent of the
// current writer and protect legacy KDF/format/keyfile/deniability compatibility.
func TestGoldenLegacyStdoutEncryptedStaging(t *testing.T) {
	defer useProductionTestKDF()()
	codecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatal(err)
	}
	corpus := findTestdata(t)
	for _, tc := range []struct {
		name        string
		fixture     string
		deniability bool
		verifyFirst bool
		keyfileRS   bool
	}{
		{name: "v1", fixture: "pico_test_v1.txt.pcv"},
		{name: "v2-verify-first", fixture: "pico_test_v2.txt.pcv", verifyFirst: true},
		{name: "v1-deniable-paranoid-RS", fixture: "pico_test_v1_deny_paranoid_rs.txt.pcv", deniability: true},
		{name: "v2-keyfile-RS-retry", keyfileRS: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			volumePath := filepath.Join(dir, "input.pcv")
			want := []byte(expectedContent)
			var keyfiles []string
			if tc.keyfileRS {
				fixture := readGoldenBase64Fixture(t, goldenLegacyKeyfileRSFixture, goldenLegacyKeyfileRSSHA256)
				if err := os.WriteFile(volumePath, fixture, 0o600); err != nil {
					t.Fatal(err)
				}
				corruptOneRSBlock(t, volumePath, 0, 4)
				want = legacyKeyfileRSPlaintext()
				keyfiles = []string{filepath.Join(corpus, "keyfile_alpha.bin")}
			} else {
				copyFile(t, filepath.Join(corpus, tc.fixture), volumePath)
			}
			before, err := os.ReadFile(volumePath)
			if err != nil {
				t.Fatal(err)
			}
			var output *fileops.EncryptedSpool
			defer func() { _ = output.Close() }()
			reporter := &repairingReporter{}
			req := &DecryptRequest{
				InputFile: volumePath, OutputFile: filepath.Join(dir, "stdout"), Password: []byte(goldenPassword),
				Keyfiles: keyfiles, Deniability: tc.deniability, VerifyFirst: tc.verifyFirst,
				Reporter: reporter, RSCodecs: codecs, EncryptedOutput: &output,
			}
			if err := Decrypt(t.Context(), req); err != nil {
				t.Fatal(err)
			}
			if output == nil {
				t.Fatal("compatible legacy decrypt did not transfer encrypted stdout")
			}
			reader, err := output.OpenReader()
			if err != nil {
				t.Fatal(err)
			}
			got, readErr := io.ReadAll(reader)
			if err := errors.Join(readErr, reader.Close()); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("frozen legacy plaintext changed through stdout staging")
			}
			if tc.keyfileRS && !reporter.sawRepairing {
				t.Fatal("frozen keyfile RS fixture did not exercise the retry")
			}
			after, err := os.ReadFile(volumePath)
			if err != nil || !bytes.Equal(after, before) {
				t.Fatalf("stdout decrypt changed the encrypted source: %v", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 2 {
				t.Fatalf("stdout decrypt left a plaintext target or intermediate input: %v, %v", entries, err)
			}
			for _, entry := range entries {
				if entry.Name() != "input.pcv" && filepath.Join(dir, entry.Name()) != output.Path() {
					t.Fatalf("unexpected stdout staging entry: %s", entry.Name())
				}
			}
		})
	}
}
