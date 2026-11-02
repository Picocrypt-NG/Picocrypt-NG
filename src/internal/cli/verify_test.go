package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyD1CLIRequiresExplicitD1AndRejectsOutputAuthority(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{"explicit D1 required", []string{"volume.pcv", "--pcv3-factors=password", "-p", "TEST ONLY"}, "verify requires explicit --deniability for PCV3 D1"},
		{"no output authority", []string{"volume.pcv", "--deniability", "--output=leak"}, "unknown flag: --output"},
		{"no forced verification", []string{"volume.pcv", "--deniability", "--force"}, "unknown flag: --force"},
		{"no unverified suite hint", []string{"volume.pcv", "--deniability", "--pcv3-d1-suite=standard"}, "unknown flag: --pcv3-d1-suite"},
		{"regular path required", []string{"-", "--deniability", "--pcv3-factors=password", "-p", "TEST ONLY"}, "D1 verification requires a regular file path"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cmd := newVerifyCommand()
			cmd.SetArgs(test.args)
			var out, errOut bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&errOut)
			if err := cmd.Execute(); err == nil || err.Error() != test.want {
				t.Fatalf("unsafe verify request %v returned %v; want validation error %q", test.args, err, test.want)
			}
			if out.Len() != 0 {
				t.Fatal("verification wrote stdout")
			}
		})
	}
	if !detectCLIMode([]string{"verify", "--deniability", "volume.pcv"}) {
		t.Fatal("verify did not select CLI mode")
	}
}

func TestVerifyD1CLIDamageLeavesNoOutputAndPreservesSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "volume.pcv")
	before := []byte("TEST ONLY truncated D1 source")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newVerifyCommand()
	cmd.SetArgs([]string{"--deniability", "--pcv3-factors=password", "-p", "TEST ONLY", path})
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	err := cmd.Execute()
	if err == nil || out.Len() != 0 {
		t.Fatalf("damaged input yielded success or stdout: err=%v stdout=%q", err, out.String())
	}
	if strings.Contains(errOut.String(), "wrong password") {
		t.Fatal("verification invented a credential/damage distinction")
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(after, before) {
		t.Fatal("verification changed source")
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil || len(entries) != 1 {
		t.Fatal("verification created an output file")
	}
}
