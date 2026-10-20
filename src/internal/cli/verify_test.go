package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyD1CLIRequiresExplicitD1AndRejectsOutputAuthority(t *testing.T) {
	for _, args := range [][]string{
		{"volume.pcv", "--pcv3-factors=password", "-p", "TEST ONLY"},
		{"volume.pcv", "--deniability", "--output=leak"},
		{"volume.pcv", "--deniability", "--force"},
		{"volume.pcv", "--deniability", "--pcv3-d1-suite=standard"},
		{"-", "--deniability", "--pcv3-factors=password", "-p", "TEST ONLY"},
	} {
		cmd := newVerifyCommand()
		cmd.SetArgs(args)
		var out, errOut bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		if err := cmd.Execute(); err == nil {
			t.Fatalf("unsafe verify request accepted: %v", args)
		}
		if out.Len() != 0 {
			t.Fatal("verification wrote stdout")
		}
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
