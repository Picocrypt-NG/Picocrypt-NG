//go:build linux && !android

package pcv3publication

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

type desktopCleanupChild struct {
	Stage  string
	Target string
}

func TestDesktopCleanupChild(t *testing.T) {
	parent := os.Getenv("PICOCRYPT_DESKTOP_CLEANUP_CHILD")
	if parent == "" {
		return
	}
	boundary := os.Getenv("PICOCRYPT_DESKTOP_CLEANUP_BOUNDARY")
	stage, err := Create(filepath.Join(parent, "output"), nil, PolicyNoReplace)
	if err != nil {
		t.Fatal(err)
	}
	persistLeasedTestJournal(t, stage)
	if _, err := stage.File().Write([]byte("complete owned output")); err != nil {
		t.Fatal(err)
	}
	stop := func() {
		data, err := json.Marshal(desktopCleanupChild{Stage: stage.stagePath, Target: filepath.Join(parent, "output")})
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println(string(data))
		select {}
	}
	if boundary == "writer closed" {
		if err := stage.File().Close(); err != nil {
			t.Fatal(err)
		}
		stop()
	}
	if boundary == "private stage" {
		stop()
	}
	if boundary == "retained output" {
		stage.operations.syncDirectory = func(*os.File) error { return errors.New("directory barrier refused after publication") }
		result, retained := stage.PublishWriteRetained(context.Background())
		if result.State() != StatePublishedDurabilityUncertain || retained == nil {
			t.Fatalf("retain committed output: %v, %v", result, retained)
		}
		_ = stage.Cleanup()
		stop()
	}
	atomic := stage.operations.atomicPublish
	stage.operations.atomicPublish = func(source, parent, original *os.File, old, target string, policy Policy) error {
		if boundary == "before rename" {
			stop()
		}
		err := atomic(source, parent, original, old, target, policy)
		if err == nil && boundary == "after rename" {
			stop()
		}
		return err
	}
	if os.Getenv("PICOCRYPT_DESKTOP_CLEANUP_WRITE") == "1" {
		_ = stage.PublishWrite(context.Background())
	} else {
		_ = stage.Publish(context.Background())
	}
	t.Fatal("child did not reach its crash boundary")
}

func startDesktopCleanupChild(t *testing.T, parent, boundary string, write bool) (desktopCleanupChild, func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDesktopCleanupChild$")
	cmd.Env = append(os.Environ(), "PICOCRYPT_DESKTOP_CLEANUP_CHILD="+parent, "PICOCRYPT_DESKTOP_CLEANUP_BOUNDARY="+boundary)
	if write {
		cmd.Env = append(cmd.Env, "PICOCRYPT_DESKTOP_CLEANUP_WRITE=1")
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	waited := false
	kill := func() {
		t.Helper()
		if waited {
			return
		}
		_ = cmd.Process.Kill()
		err := cmd.Wait()
		waited = true
		cancel()
		if err == nil {
			t.Fatal("child exited normally instead of being killed")
		}
	}
	t.Cleanup(kill)
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		kill()
		t.Fatal("child failed before reaching a real filesystem boundary")
	}
	var child desktopCleanupChild
	if err := json.Unmarshal(scanner.Bytes(), &child); err != nil {
		kill()
		t.Fatal(err)
	}
	return child, kill
}

func TestDesktopRecoveryPreservesLiveLeaseThenCleansKilledOwner(t *testing.T) {
	for _, boundary := range []string{"private stage", "writer closed", "before rename"} {
		t.Run(boundary, func(t *testing.T) {
			parent := t.TempDir()
			source := filepath.Join(parent, "selected-source")
			if err := os.WriteFile(source, []byte("selected source must survive"), 0o600); err != nil {
				t.Fatal(err)
			}
			protected, err := os.Open(source)
			if err != nil {
				t.Fatal(err)
			}
			defer protected.Close()
			child, kill := startDesktopCleanupChild(t, parent, boundary, true)
			state, err := CleanupOrphanedStages(parent, []*os.File{protected})
			if err != nil || state != CleanupJournalActive {
				t.Fatalf("live owner recovery = %v, %v", state, err)
			}
			requireFileBytes(t, child.Stage, []byte("complete owned output"))
			kill()
			state, err = CleanupOrphanedStages(parent, []*os.File{protected})
			if err != nil || state != CleanupJournalCleaned {
				t.Fatalf("killed owner recovery = %v, %v", state, err)
			}
			requireNoStageEntries(t, parent)
			requireAbsent(t, child.Target)
			requireFileBytes(t, source, []byte("selected source must survive"))
		})
	}
}

func TestDesktopRecoveryPreservesPublicOutputAfterProcessKill(t *testing.T) {
	for _, write := range []bool{false, true} {
		t.Run(map[bool]string{false: "authenticated plaintext", true: "ciphertext"}[write], func(t *testing.T) {
			parent := t.TempDir()
			child, kill := startDesktopCleanupChild(t, parent, "after rename", write)
			kill()
			// A previously published output may already be the next selected input.
			selected, err := os.Open(child.Target)
			if err != nil {
				t.Fatal(err)
			}
			defer selected.Close()
			state, err := CleanupOrphanedStages(parent, []*os.File{selected})
			if err != nil || state != CleanupJournalCleaned {
				t.Fatalf("post-rename recovery = %v, %v", state, err)
			}
			requireFileBytes(t, child.Target, []byte("complete owned output"))
			requireNoStageEntries(t, parent)
		})
	}
}

func TestDesktopRecoveryMixedOwnersPreservesActiveState(t *testing.T) {
	parent := t.TempDir()
	live, killLive := startDesktopCleanupChild(t, parent, "private stage", false)
	dead, killDead := startDesktopCleanupChild(t, parent, "private stage", false)
	killDead()
	state, err := CleanupOrphanedStages(parent, nil)
	if err != nil || state != CleanupJournalActive {
		t.Fatalf("mixed-owner recovery = %v, %v", state, err)
	}
	requireFileBytes(t, live.Stage, []byte("complete owned output"))
	requireAbsent(t, dead.Stage)
	killLive()
	state, err = CleanupOrphanedStages(parent, nil)
	if err != nil || state != CleanupJournalCleaned {
		t.Fatalf("remaining orphan recovery = %v, %v", state, err)
	}
	requireNoStageEntries(t, parent)
}

func TestDesktopRecoveryPreservesLeaseTransferredToRetainedOutput(t *testing.T) {
	parent := t.TempDir()
	child, kill := startDesktopCleanupChild(t, parent, "retained output", true)
	state, err := CleanupOrphanedStages(parent, nil)
	if err != nil || state != CleanupJournalActive {
		t.Fatalf("retained output lost its transferred lease: %v, %v", state, err)
	}
	requireFileBytes(t, child.Target, []byte("complete owned output"))
	kill()
	state, err = CleanupOrphanedStages(parent, nil)
	if err != nil || state != CleanupJournalCleaned {
		t.Fatalf("killed retained owner recovery: %v, %v", state, err)
	}
	requireFileBytes(t, child.Target, []byte("complete owned output"))
	requireNoStageEntries(t, parent)
}

func TestDesktopRecoveryRefusesProtectedPrivateObjects(t *testing.T) {
	for _, object := range []string{"stage", "journal", "private directory", "destination", "source directory ancestor", "closed descriptor", "nil descriptor"} {
		t.Run(object, func(t *testing.T) {
			base := t.TempDir()
			parent := filepath.Join(base, "destination")
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			child, kill := startDesktopCleanupChild(t, parent, "private stage", false)
			kill()
			path := map[string]string{
				"stage":                     child.Stage,
				"journal":                   filepath.Join(filepath.Dir(child.Stage), cleanupJournalName),
				"private directory":         filepath.Dir(child.Stage),
				"destination":               parent,
				"source directory ancestor": base,
				"closed descriptor":         child.Stage,
			}[object]
			var protected *os.File
			if path != "" {
				var err error
				protected, err = os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer protected.Close()
				if object == "closed descriptor" {
					_ = protected.Close()
				}
			}
			state, err := CleanupOrphanedStages(parent, []*os.File{protected})
			if state != CleanupJournalIncomplete || !errors.Is(err, ErrCleanupIncomplete) {
				t.Fatalf("protected object recovery = %v, %v", state, err)
			}
			requireFileBytes(t, child.Stage, []byte("complete owned output"))
			if _, err := os.Stat(filepath.Join(filepath.Dir(child.Stage), cleanupJournalName)); err != nil {
				t.Fatal("protected candidate lost its recovery journal")
			}
		})
	}
}
