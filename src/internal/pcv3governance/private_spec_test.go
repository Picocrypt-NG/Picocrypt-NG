//go:build pcv3_private_spec

package pcv3governance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"testing"
)

const privateSpecPathEnv = "PCV3_PRIVATE_SPEC_PATH"

func TestPrivateSpecMatchesGovernanceBaseline(t *testing.T) {
	path, ok := os.LookupEnv(privateSpecPathEnv)
	if !ok || path == "" {
		t.Fatalf("%s is required", privateSpecPathEnv)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatal("open private PCV3 specification")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		t.Fatal("inspect private PCV3 specification")
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		t.Fatal("private PCV3 specification must be a regular file")
	}
	specification, err := io.ReadAll(file)
	defer clear(specification)
	closeErr := file.Close()
	if err != nil {
		t.Fatal("read private PCV3 specification")
	}
	if closeErr != nil {
		t.Fatal("close private PCV3 specification")
	}

	const revisionPrefix = "- Document revision: "
	var revision []byte
	revisionCount := 0
	for line := range bytes.SplitSeq(specification, []byte{'\n'}) {
		if bytes.HasPrefix(line, []byte(revisionPrefix)) {
			revision = bytes.TrimSpace(line[len(revisionPrefix):])
			revisionCount++
		}
	}
	if revisionCount != 1 {
		t.Fatal("private PCV3 specification must contain exactly one document revision")
	}

	baseline := candidateBaseline(t)
	sum := sha256.Sum256(specification)
	if hex.EncodeToString(sum[:]) != baseline.specSHA256 {
		t.Fatal("private PCV3 specification digest does not match governance baseline")
	}
	if string(revision) != baseline.specRevision {
		t.Fatal("private PCV3 specification revision does not match governance baseline")
	}
}
