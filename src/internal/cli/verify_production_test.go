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
	for _, test := range []struct {
		name, fixture string
		policy, order string
		verified      bool
	}{
		{"paranoid combined ordered", "d1.pcv", "combined", "ordered", true},
		{"standard combined ordered", "d1-standard.pcv", "combined", "ordered", true},
		{"wrong order", "d1-standard.pcv", "combined", "unordered", false},
		{"wrong policy", "d1-standard.pcv", "password", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			original, err := os.ReadFile(filepath.Join(fixtures, test.fixture))
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
			args := []string{source, "--deniability", "--pcv3-factors=" + test.policy, "-p", string(password), "--quiet"}
			if test.order != "" {
				args = append(args, "--pcv3-keyfile-order="+test.order,
					"-k", filepath.Join(fixtures, "keyfile-alpha.bin"), "-k", filepath.Join(fixtures, "keyfile-beta.bin"))
			}
			cmd := newVerifyCommand()
			cmd.SetArgs(args)
			var stdout, stderr bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			verificationErr := cmd.Execute()
			if test.verified {
				if verificationErr != nil || !strings.Contains(stderr.String(), "front=passed tail=passed pair=passed payload=passed") {
					t.Fatalf("independent CLI verify: %v stderr=%s", verificationErr, stderr.String())
				}
			} else if verificationErr == nil ||
				verificationErr.Error() != "D1 could not be fully verified; credentials or volume damage may prevent authentication" ||
				!strings.Contains(stderr.String(), "front=not authenticated tail=not authenticated pair=unchecked payload=unchecked") {
				t.Fatalf("unexpected verification result for explicitly selected factors: %v stderr=%s", verificationErr, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("verification wrote stdout: %q", stdout.String())
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
