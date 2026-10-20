//go:build linux && !android

package pcv3publication

import (
	"Picocrypt-NG/internal/pcv3result"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The opt-in path must be a dedicated VFAT scratch mount with umask=0000.
// VFAT ignores individual mkdir modes, so Create must refuse before exposing
// a writable plaintext stage and report the unretired empty directory.
func TestPrivateCustodyRefusesRealVFATBeforeStageExposure(t *testing.T) {
	filesystem := os.Getenv("PICOCRYPT_CUSTODY_UNSUPPORTED_FS")
	if filesystem == "" {
		t.Skip("requires a dedicated real VFAT mount with umask=0000")
	}
	var filesystemInfo unix.Statfs_t
	if err := unix.Statfs(filesystem, &filesystemInfo); err != nil {
		t.Fatal(err)
	}
	if filesystemInfo.Type != unix.MSDOS_SUPER_MAGIC {
		t.Fatalf("filesystem magic = %#x; require real VFAT", filesystemInfo.Type)
	}
	parent, err := os.MkdirTemp(filesystem, "picocrypt-custody-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(parent); err != nil {
			t.Errorf("remove dedicated test fixtures: %v", err)
		}
	})
	info, err := os.Lstat(parent)
	if err != nil || info == nil || info.Mode().Perm() != 0o777 {
		t.Fatalf("VFAT must ignore requested 0700 directory mode: %v %v", info, err)
	}
	t.Logf("kernel filesystem magic=%#x requested directory mode=0700 actual=%04o", filesystemInfo.Type, info.Mode().Perm())
	source := filepath.Join(parent, "source")
	foreign := filepath.Join(parent, "foreign")
	for path, payload := range map[string]string{source: "preserve source bytes", foreign: "preserve foreign bytes"} {
		if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(parent, "target")
	stage, err := Create(target, []string{source}, PolicyNoReplace)
	if stage != nil {
		_ = stage.Cleanup()
		t.Fatal("VFAT exposed a writable stage without owner-only directory custody")
	}
	requireResult(t, requireResultError(t, err), StateNotPublished, pcv3result.OutcomeOperationFailed, pcv3result.StageOutputPublication, CodeStageFailure)
	if !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("unretired directory cleanup uncertainty was hidden: %v", err)
	}
	requireAbsent(t, target)
	requireFileBytes(t, source, []byte("preserve source bytes"))
	requireFileBytes(t, foreign, []byte("preserve foreign bytes"))
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	privateDirectories := 0
	for _, entry := range entries {
		if entry.Name() == "source" || entry.Name() == "foreign" {
			continue
		}
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), stageNamePrefix+"private-") {
			t.Fatalf("refusal left an unexpected file or directory: %s", entry.Name())
		}
		privateDirectories++
		children, err := os.ReadDir(filepath.Join(parent, entry.Name()))
		if err != nil || len(children) != 0 {
			t.Fatalf("refusal created plaintext-stage or journal residue: %v %v", children, err)
		}
	}
	if privateDirectories != 1 {
		t.Fatalf("failed mode verification residue = %d directories; want one empty owned directory", privateDirectories)
	}
	t.Log("Create refused before stage exposure; target absent; source and foreign bytes preserved; empty directory cleanup uncertainty observable")
}
