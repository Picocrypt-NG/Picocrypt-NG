package volume

import (
	"Picocrypt-NG/internal/fileops"
	"errors"
	"strings"
	"testing"
)

func TestZIPSelectionAdmissionPrecedesDerivedMapAllocation(t *testing.T) {
	budget := fileops.NewZIPResourceBudget()
	path := strings.Repeat("x", 1<<20)
	files := make([]string, 40)
	for i := range files {
		files[i] = path
	}
	if _, e := reserveZIPSelection(budget, &EncryptRequest{}, files); !errors.Is(e, fileops.ErrZIPMetadataLimit) {
		t.Fatalf("oversized selection admitted: %v", e)
	}
	if budget.CurrentBytes() != 0 {
		t.Fatal("failed admission leaked charge")
	}
}
