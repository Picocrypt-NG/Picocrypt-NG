package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPCV3CLIUnicode18NormalAndD1(t *testing.T) {
	// U+20C2 is new in Unicode 18. NormalizationTest-18.0.0.txt line
	// 18205 supplies the suffix and the independent NFC read password.
	const password = "unicode18-\u20C2-a\u0315\u0300\u05AE\u1ADEb"
	const canonicalPassword = "unicode18-\u20C2-\u00E0\u05AE\u1ADE\u0315b"
	binary := buildCLITestBinary(t)
	for _, mode := range []struct {
		name        string
		deniability bool
	}{
		{"normal", false},
		{"d1", true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			directory := t.TempDir()
			payload := []byte("Unicode 18 CLI credential\x00payload")
			source := writePCV3CLIFixture(t, directory, "plain.bin", payload)
			volume := filepath.Join(directory, "volume.pcv")
			output := filepath.Join(directory, "opened.bin")
			writeArgs := []string{"encrypt", source, "-o", volume, "--pcv3", "-p", password, "--quiet"}
			readArgs := []string{"decrypt", volume, "-o", output, "--pcv3-factors=password", "-p", canonicalPassword, "--quiet"}
			if mode.deniability {
				writeArgs = append(writeArgs, "--deniability")
				readArgs = append(readArgs, "--pcv3-format=d1")
			}
			requireNativePCV3Published(t, runCLITestCommand(t, binary, writeArgs...), "")
			ciphertext, err := os.ReadFile(volume)
			if err != nil {
				t.Fatalf("read CLI-created ciphertext: %v", err)
			}
			requireNativePCV3Published(t, runCLITestCommand(t, binary, readArgs...), "")
			for path, want := range map[string][]byte{source: payload, output: payload, volume: ciphertext} {
				if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, want) {
					t.Fatalf("Unicode-18 CLI changed %s or produced different bytes: %x, %v", filepath.Base(path), got, err)
				}
			}
			entries, err := os.ReadDir(directory)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".picocrypt-pcv3-") {
					t.Fatalf("Unicode-18 CLI left publication residue %q", entry.Name())
				}
			}
		})
	}
}
