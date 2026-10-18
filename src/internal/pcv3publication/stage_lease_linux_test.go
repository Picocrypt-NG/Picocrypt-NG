//go:build linux && !android

package pcv3publication

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxStageLeaseSurvivesWritableClose(t *testing.T) {
	stage, err := Create(filepath.Join(t.TempDir(), "output"), nil, PolicyNoReplace)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stage.Cleanup() })
	probe, err := stage.sourceRoot.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if err := stage.File().Close(); err != nil {
		t.Fatal(err)
	}
	requireDirectoryLeaseHeld(t, probe)
}

func TestLinuxStageLeaseTransfersToRetainedOwner(t *testing.T) {
	stage, err := createRetainedTestStage(t, filepath.Join(t.TempDir(), "output"), []byte("complete ciphertext"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stage.Cleanup() })
	probe, err := stage.sourceRoot.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	publication, retained := stage.PublishWriteRetained(context.Background())
	if publication.State() != StatePublishedDurable || retained == nil {
		t.Fatalf("retain complete output: %v, %v", publication, retained)
	}
	t.Cleanup(func() { _ = retained.Close() })
	if err := stage.Cleanup(); err != nil {
		t.Fatal(err)
	}
	requireDirectoryLeaseHeld(t, probe)
	if err := retained.Close(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(probe.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("released retained owner still holds its operation lease: %v", err)
	}
}

func requireDirectoryLeaseHeld(t *testing.T, probe *os.File) {
	t.Helper()
	err := unix.Flock(int(probe.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("operation lost its kernel lease while custody remained: %v", err)
	}
}
