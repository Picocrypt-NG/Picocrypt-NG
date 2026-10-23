//go:build windows

package pcv3publication

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsRetainedDeletePendingIsNotConfirmedAbsence(t *testing.T) {
	target := filepath.Join(t.TempDir(), "retained")
	retained := publishRetainedTestFile(t, target, []byte("delete pending is still live"))
	extra, err := duplicateIdentityFile(retained.file)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	retained.syncDirectory = func(*os.File) error {
		return errors.New("TEST ONLY directory barrier refused")
	}
	err = retained.RemoveExact()
	if !errors.Is(err, ErrCleanupIncomplete) || errors.Is(err, ErrCleanupDurabilityUncertain) {
		t.Fatalf("delete-pending cleanup = %v; want unconfirmed live removal only", err)
	}
	if retained.Live() {
		t.Fatal("delete-pending cleanup retained a reusable capability")
	}
	if err := extra.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("last duplicate close did not finish deletion: %v", err)
	}
}
