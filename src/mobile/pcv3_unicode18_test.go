//go:build android || linux

package mobile

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
)

func TestPCV3MobileUnicode18NormalAndD1(t *testing.T) {
	// U+20C2 is new in Unicode 18. NormalizationTest-18.0.0.txt line
	// 18205 supplies the suffix and independent NFC-equivalent read password.
	const password = "unicode18-\u20C2-a\u0315\u0300\u05AE\u1ADEb"
	const canonicalPassword = "unicode18-\u20C2-\u00E0\u05AE\u1ADE\u0315b"
	for _, mode := range []struct{ name, write, read string }{
		{"normal", "write-normal", "read-normal"},
		{"d1", "write-d1", "read-d1"},
	} {
		t.Run(mode.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				directory := t.TempDir()
				payload := []byte("Unicode 18 mobile credential\x00payload")
				source := filepath.Join(directory, "plain.bin")
				if err := os.WriteFile(source, payload, 0o600); err != nil {
					t.Fatal(err)
				}
				volume := filepath.Join(directory, "volume.pcv")
				opened := pcv3MobileObserveDescriptors(t)
				writePassword := []byte(password)
				start := StartPCV3(pcv3WriteTestEnvelope(mode.write, "password", "none", "standard", false, "", source, volume, nil), writePassword)
				if start == nil || start.Code() != "" || start.Operation() == nil {
					t.Fatalf("Unicode-18 mobile write start = %#v", start)
				}
				if !allZero(writePassword) {
					t.Fatal("mobile write retained the caller password")
				}
				writeOperation := start.Operation()
				t.Cleanup(func() { cleanupOperation(writeOperation.ID()) })
				synctest.Wait()
				writeSnapshot := writeOperation.Snapshot()
				if writeSnapshot.Outcome() != "success" || writeSnapshot.CompletionClass() != "clean" || writeSnapshot.PublicationState() != "published-durable" || writeSnapshot.WarningCount() != 0 {
					t.Fatalf("Unicode-18 mobile write = %s", pcv3MobileSnapshotText(writeSnapshot))
				}
				if writeOperation.Output() == nil {
					t.Fatal("mobile creation lost its retained ciphertext authority")
				}

				plaintext := filepath.Join(directory, "opened.bin")
				readPassword := []byte(canonicalPassword)
				read := StartPCV3(pcv3TestEnvelope(mode.read, "password", "none", volume, plaintext, nil), readPassword)
				if read == nil || read.Code() != "" || read.Operation() == nil {
					t.Fatalf("Unicode-18 mobile read start = %#v", read)
				}
				if !allZero(readPassword) {
					t.Fatal("mobile read retained the caller password")
				}
				readOperation := read.Operation()
				t.Cleanup(func() { cleanupOperation(readOperation.ID()) })
				synctest.Wait()
				readSnapshot := readOperation.Snapshot()
				if readSnapshot.Outcome() != "success" || readSnapshot.CompletionClass() != "clean" || readSnapshot.PublicationState() != "published-durable" || readSnapshot.WarningCount() != 0 {
					t.Fatalf("Unicode-18 mobile NFC-equivalent read = %s", pcv3MobileSnapshotText(readSnapshot))
				}
				if got, err := os.ReadFile(plaintext); err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("Unicode-18 mobile plaintext = %x, %v", got, err)
				}
				if got, err := os.ReadFile(source); err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("Unicode-18 operation changed source = %x, %v", got, err)
				}
				for _, operation := range []*PCV3Operation{readOperation, writeOperation} {
					output := operation.Output()
					if output == nil {
						t.Fatal("Unicode-18 operation lost its retained output authority")
					}
					if result := output.Discard(); result == nil || result.Code() != "discarded" || result.CleanupIncomplete() {
						t.Fatalf("Unicode-18 output discard = %#v", result)
					}
					if code := operation.Release(); code != "" {
						t.Fatalf("Unicode-18 operation release = %q", code)
					}
				}
				pcv3MobileRequireDescriptorsClosed(t, *opened)
				pcv3MobileRequireNoResidue(t, directory, []string{"plain.bin"})
			})
		})
	}
}
