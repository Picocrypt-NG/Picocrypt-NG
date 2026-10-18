//go:build linux || darwin

package pcv3publication

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPrivateStageDirectoryRelocationPreservesForeignReplacement(t *testing.T) {
	for _, publish := range []bool{false, true} {
		t.Run(map[bool]string{false: "cleanup", true: "publish"}[publish], func(t *testing.T) {
			parent := t.TempDir()
			target := filepath.Join(parent, "output")
			stage, err := Create(target, nil, PolicyNoReplace)
			if err != nil {
				t.Fatal(err)
			}
			defer stage.Cleanup()
			source := filepath.Dir(stage.File().Name())
			if source == parent {
				t.Fatal("stage is exposed directly in the shared destination directory")
			}
			info, err := os.Lstat(source)
			if err != nil || info.Mode().Perm() != 0o700 {
				t.Fatalf("private directory permissions: %v %v", info, err)
			}
			payload := []byte("owned authenticated payload")
			if _, err := stage.File().Write(payload); err != nil {
				t.Fatal(err)
			}
			moved := filepath.Join(parent, "relocated")
			if err := os.Rename(source, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(source, 0o700); err != nil {
				t.Fatal(err)
			}
			foreign := filepath.Join(source, "foreign")
			if err := os.WriteFile(foreign, []byte("foreign bytes"), 0o600); err != nil {
				t.Fatal(err)
			}
			if publish {
				if got := stage.Publish(context.Background()); got.State() != StatePublishedDurable {
					t.Fatalf("pinned publication: %v", got)
				}
				requireFileBytes(t, target, payload)
			}
			if err := stage.Cleanup(); !errors.Is(err, ErrCleanupIncomplete) {
				t.Fatalf("unretired relocated directory must remain uncertain: %v", err)
			}
			requireFileBytes(t, foreign, []byte("foreign bytes"))
			entries, err := os.ReadDir(moved)
			if err != nil || len(entries) != 0 {
				t.Fatalf("original private directory retains bytes: %v %v", entries, err)
			}
		})
	}
}

func TestRetainedRemovalRefusesSharedWritableParent(t *testing.T) {
	parent := t.TempDir()
	retained := publishRetainedTestFile(t, filepath.Join(parent, "output"), []byte("preserved published bytes"))
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := retained.RemoveExact(); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("untrusted public removal: %v", err)
	}
	requireFileBytes(t, filepath.Join(parent, "output"), []byte("preserved published bytes"))
}

func TestCapabilityProbeRefusesUnsafeParentWithoutExternalEffects(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	stage, err := Create(filepath.Join(parent, "target"), nil, PolicyNoReplace)
	if runtime.GOOS == "darwin" {
		if stage != nil || requireResultError(t, err).Code() != CodePolicyUnsupported {
			t.Fatal("Darwin accepted an untrusted parent")
		}
		entries, readErr := os.ReadDir(parent)
		if readErr != nil || len(entries) != 0 {
			t.Fatalf("refusal left effects: %v %v", entries, readErr)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()
	if _, err := stage.File().Write([]byte("stage unchanged")); err != nil {
		t.Fatal(err)
	}
	if err := stage.CheckCapability(); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("unsafe namespace preflight: %v", err)
	}
	requireFileBytes(t, stage.stagePath, []byte("stage unchanged"))
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 {
		t.Fatalf("external probe residue: %v %v", entries, err)
	}
}

func TestCapabilityProbeUsesDistinctPinnedDirectoriesAndPreservesOriginal(t *testing.T) {
	parent := t.TempDir()
	stage, err := Create(filepath.Join(parent, "target"), nil, PolicyNoReplace)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()
	if _, err := stage.File().Write([]byte("owned payload")); err != nil {
		t.Fatal(err)
	}
	operations := nativeOperations()
	atomic := operations.atomicPublish
	calls := 0
	operations.atomicPublish = func(source, destination, original *os.File, old, target string, policy Policy) error {
		sourceInfo, err := source.Stat()
		if err != nil {
			t.Fatal(err)
		}
		destinationInfo, err := destination.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if os.SameFile(sourceInfo, destinationInfo) {
			t.Fatal("preflight never exercised source-to-destination publication")
		}
		calls++
		return atomic(source, destination, original, old, target, policy)
	}
	if err := checkCapabilityBetween(stage.sourceRoot, stage.sourceParent, stage.root, stage.parent, operations); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("collision and publication were not both exercised: %d", calls)
	}
	requireFileBytes(t, stage.stagePath, []byte("owned payload"))
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 {
		t.Fatalf("destination probe residue: %v %v", entries, err)
	}
}

func TestOwnedStickyParentSupportsSafeProbeCleanup(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	stage, err := Create(filepath.Join(parent, "target"), nil, PolicyNoReplace)
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.CheckCapability(); err != nil {
		t.Fatal(err)
	}
	if err := stage.Cleanup(); err != nil {
		t.Fatal(err)
	}
	requireNoStageEntries(t, parent)
}

func TestCleanupPrivateDirectoryReplacementAtUnlinkBoundaryPreservesForeignBytes(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	stage, err := Create(target, nil, PolicyNoReplace)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Cleanup()
	if _, err := stage.File().Write([]byte("owned plaintext")); err != nil {
		t.Fatal(err)
	}
	private := filepath.Dir(stage.stagePath)
	moved := filepath.Join(parent, "relocated")
	originalRemove := stage.operations.removeStage
	stage.operations.removeStage = func(root *os.Root, name string) error {
		if name != stage.stageName {
			t.Fatalf("unexpected removal: %s", name)
		}
		if err := os.Rename(private, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(private, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(private, "foreign"), []byte("foreign survives probe-to-unlink"), 0o600); err != nil {
			t.Fatal(err)
		}
		return originalRemove(root, name)
	}
	if err := stage.Cleanup(); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("relocated private directory retirement: %v", err)
	}
	requireFileBytes(t, filepath.Join(private, "foreign"), []byte("foreign survives probe-to-unlink"))
	entries, err := os.ReadDir(moved)
	if err != nil || len(entries) != 0 {
		t.Fatalf("pinned cleanup did not remove owned plaintext: %v %v", entries, err)
	}
}
