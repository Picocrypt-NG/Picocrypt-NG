package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyCLIReportsFormatLimitationsOnStderrEvenWhenQuiet(t *testing.T) {
	for _, test := range []struct {
		name, file, warning string
		keyfile, stdout     bool
	}{
		{"v1 file", "pico_test_v1.txt.pcv", "Legacy v1 does not authenticate the header", false, false},
		{"v1 stdout", "pico_test_v1.txt.pcv", "Legacy v1 does not authenticate the header", false, true},
		{"v2 keyfile", "pico_test_v2_keyfile_single.txt.pcv", "keyfile does not contribute to legacy v2 authentication", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			resetDecryptFlagsForDirTest()
			t.Cleanup(resetDecryptFlagsForDirTest)
			dir := t.TempDir()
			stdout, err := os.Create(filepath.Join(dir, "stdout"))
			if err != nil {
				t.Fatal(err)
			}
			stderr, err := os.Create(filepath.Join(dir, "stderr"))
			if err != nil {
				t.Fatal(err)
			}
			oldOut, oldErr := os.Stdout, os.Stderr
			os.Stdout, os.Stderr = stdout, stderr
			t.Cleanup(func() { os.Stdout, os.Stderr = oldOut, oldErr; _ = stdout.Close(); _ = stderr.Close() })
			fixtureRoot := filepath.Join("..", "..", "testdata", "golden")
			output := filepath.Join(dir, "output")
			decOutput, decPassword, decQuiet = output, "test", true
			if test.stdout {
				decOutput = "-"
			}
			if test.keyfile {
				decKeyfiles = []string{filepath.Join(fixtureRoot, "keyfile_alpha.bin")}
			}
			if err := decryptCmd.RunE(decryptCmd, []string{filepath.Join(fixtureRoot, test.file)}); err != nil {
				t.Fatal(err)
			}
			diagnostic, err := os.ReadFile(stderr.Name())
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(diagnostic), test.warning) {
				t.Fatalf("quiet legacy completion lost security warning: %q", diagnostic)
			}
			if test.stdout {
				output = stdout.Name()
			}
			plaintext, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plaintext, []byte("There is a test file for Picocrypt validation.\n")) {
				t.Fatalf("warning contaminated plaintext output: %q", plaintext)
			}
		})
	}
}
