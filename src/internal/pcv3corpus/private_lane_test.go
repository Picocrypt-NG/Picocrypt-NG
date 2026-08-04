//go:build pcv3_private_corpus

package pcv3corpus

import (
	"os"
	"testing"
)

func TestPrivateCorpusContract(t *testing.T) {
	root, ok := os.LookupEnv("PCV3_PRIVATE_CORPUS_ROOT")
	if !ok || root == "" {
		t.Fatal("PCV3 private corpus root is required")
	}
	custodyID, ok := os.LookupEnv("PCV3_PRIVATE_CORPUS_CUSTODY_ID")
	if !ok || custodyID == "" {
		t.Fatal("PCV3 private corpus custody ID is required")
	}
	if custodyID != testCustodyID {
		t.Fatal("PCV3 private corpus custody ID is not approved")
	}

	corpus, err := Load(root, custodyID)
	if err != nil {
		t.Fatalf("PCV3 private corpus contract failed: %v", err)
	}
	if corpus == nil {
		t.Fatal("PCV3 private corpus contract returned no verified corpus")
	}
	if !corpus.isCurrentPhase4() {
		t.Fatal("PCV3 private corpus is not the required cumulative Phase-4 contract")
	}
}
