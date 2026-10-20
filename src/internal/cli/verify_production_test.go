//go:build pcv3_production_kdf

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyD1CLIIndependentProductionFixturesCreateNoOutput(t *testing.T) {
	fixtures := filepath.Join("..", "pcv3operation", "internal", "pcv3", "testdata", "d1", "independent")
	password, err := os.ReadFile(filepath.Join(fixtures, "password.bin"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []string{"d1.pcv", "d1-standard.pcv"} {
		t.Run(fixture, func(t *testing.T) {
			original, err := os.ReadFile(filepath.Join(fixtures, fixture))
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			t.Setenv("TMPDIR", dir)
			t.Setenv("TEMP", dir)
			previousTempDir := TempDirOverride
			TempDirOverride = dir
			t.Cleanup(func() { TempDirOverride = previousTempDir })
			source := filepath.Join(dir, "volume.pcv")
			if err := os.WriteFile(source, original, 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := newVerifyCommand()
			cmd.SetArgs([]string{source, "--deniability", "--pcv3-factors=combined", "--pcv3-keyfile-order=ordered", "-p", string(password), "-k", filepath.Join(fixtures, "keyfile-alpha.bin"), "-k", filepath.Join(fixtures, "keyfile-beta.bin"), "--quiet"})
			var stdout, stderr bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			if err := cmd.Execute(); err != nil {
				t.Fatalf("independent CLI verify: %v stderr=%s", err, stderr.String())
			}
			if stdout.Len() != 0 || !strings.Contains(stderr.String(), "front=passed tail=passed pair=passed payload=passed") {
				t.Fatalf("incorrect verification result or stdout: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
			after, err := os.ReadFile(source)
			if err != nil || !bytes.Equal(after, original) {
				t.Fatal("CLI verification changed source")
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 {
				t.Fatal("CLI verification created output/staging")
			}
		})
	}
}
