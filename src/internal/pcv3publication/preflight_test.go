package pcv3publication

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCapabilityProbeRefusesUnsupportedWithoutOutputOrResidue(t *testing.T) {
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	parent, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	err = checkCapability(root, parent, platformOperations{atomicPublish: func(*os.File, string, string, Policy) error { return errors.ErrUnsupported }})
	if !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("probe = %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("residue = %v, %v", entries, err)
	}
}

func TestCapabilityProbeNativePreservesOccupiedDestinationAndCleansProbes(t *testing.T) {
	directory := t.TempDir()
	sentinel := filepath.Join(directory, "existing")
	if err := os.WriteFile(sentinel, []byte("must survive"), 0o600); err != nil {
		t.Fatal(err)
	}
	stage, err := Create(filepath.Join(directory, "output"), nil, PolicyNoReplace)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()
	if err := stage.CheckCapability(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(sentinel)
	if err != nil || string(data) != "must survive" {
		t.Fatalf("existing changed: %q %v", data, err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 2 {
		t.Fatalf("probe residue: %v %v", entries, err)
	}
}

func TestCapabilityProbeRejectsReplacingPrimitive(t *testing.T) {
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	parent, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	err = checkCapability(root, parent, platformOperations{atomicPublish: func(_ *os.File, source, target string, _ Policy) error { return root.Rename(source, target) }})
	if !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("unsafe replace accepted: %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("residue: %v %v", entries, err)
	}
}
