package workflowpolicy

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
)

// This is a supply-chain update tripwire, not product-behavior coverage.
func TestMaintainedArgon2CopyMatchesSelectedXCryptoModule(t *testing.T) {
	const modulePath = "golang.org/x/crypto"
	const provenancePath = "src/internal/argon2/UPSTREAM.json"
	var provenance struct {
		Module  string `json:"module"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal([]byte(mustReadRepoFile(t, provenancePath)), &provenance); err != nil {
		t.Fatalf("read maintained Argon2 provenance: %v", err)
	}
	if provenance.Module != modulePath || provenance.Version == "" {
		t.Fatalf("invalid maintained Argon2 module/version in %s", provenancePath)
	}
	command := exec.Command("go", "list", "-m", "-json", modulePath)
	command.Dir = filepath.Join(repoRoot(t), "src")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("resolve selected Argon2 upstream module: %v\n%s", err, output)
	}
	var selected struct {
		Path    string
		Version string
		Replace *struct{ Path string }
	}
	if err := json.Unmarshal(output, &selected); err != nil {
		t.Fatalf("decode selected Argon2 upstream module: %v", err)
	}
	if selected.Path != provenance.Module || selected.Version != provenance.Version || selected.Replace != nil {
		t.Fatalf("review/rebase the maintained Argon2 copy after an upstream module change: selected %s@%s (replacement=%t), recorded %s@%s; update %s after review", selected.Path, selected.Version, selected.Replace != nil, provenance.Module, provenance.Version, provenancePath)
	}
}
