package mobile

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/volume"
	"os"
	"path/filepath"
	"testing"
)

func TestPCV3WriteRequestReleasesTransferredInputMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := source.Stat()
	if err != nil {
		t.Fatal(err)
	}
	budget := fileops.NewZIPResourceBudget()
	charge, err := fileops.ReserveZIPInputPath(budget, len(path))
	if err != nil {
		t.Fatal(err)
	}
	var metadata fileops.ZIPInputMetadataReservation
	identity, err := metadata.FromFileInfo(budget, path, info)
	if err != nil {
		t.Fatal(err)
	}
	request := &pcv3WriteRequest{source: source, input: volume.EncryptInputRequest{ZIPBudget: budget, InputIdentities: []fileops.ZIPInputIdentity{identity}}, inputMetadata: &metadata, inputCharge: charge}
	if budget.CurrentBytes() <= charge {
		t.Fatal("fixture did not retain directory metadata")
	}
	if releasePCV3WriteRequest(request) {
		t.Fatal("ordinary transferred-input cleanup failed")
	}
	if budget.CurrentBytes() != 0 {
		t.Fatalf("worker cleanup retained input metadata=%d", budget.CurrentBytes())
	}
	if _, err := source.Stat(); err == nil {
		t.Fatal("worker did not close its owned source")
	}
	if releasePCV3WriteRequest(request) || budget.CurrentBytes() != 0 {
		t.Fatal("repeated cleanup retired another owner's charge")
	}
}
