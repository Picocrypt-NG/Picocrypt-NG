package pcv3

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3publication"
	"errors"
	"os"
	"testing"
)

func TestArchiveSAFAbortSeparatesRemovedStageDurabilityFromUnconfirmedRemoval(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{"confirmed-cleanup", nil},
		{"deletion-barrier", pcv3publication.ErrCleanupDurabilityUncertain},
		{"both-facts", errors.Join(pcv3publication.ErrCleanupIncomplete, pcv3publication.ErrCleanupDurabilityUncertain)},
	} {
		t.Run(test.name, func(t *testing.T) {
			archive := buildArchiveSAFZIP(t, []archiveSAFZIPEntry{{name: "file", data: []byte("body")}})
			handoff, parent, target := newArchiveSAFHandoffFromZIP(t, archive, true)
			begin := handoff.BeginSAF()
			if begin == nil || begin.Kind() != NativeArchiveSAFBeginSession {
				t.Fatalf("real archive did not produce a session: %#v", begin)
			}
			session := begin.Session()
			t.Cleanup(func() { _ = session.Abort() })
			stagePath := findArchiveSAFStagePath(t, parent)
			realCleanup := session.state.cleanupStage
			var realCleanupErr error
			session.state.cleanupStage = func(stage *pcv3publication.Stage) error {
				realCleanupErr = realCleanup(stage)
				return errors.Join(realCleanupErr, test.err)
			}
			result := session.Abort()
			if realCleanupErr != nil && (!errors.Is(realCleanupErr, pcv3publication.ErrCleanupDurabilityUncertain) ||
				errors.Is(realCleanupErr, pcv3publication.ErrCleanupIncomplete)) {
				t.Fatalf("real stage removal failed before injected barrier outcome: %v", realCleanupErr)
			}
			wantIncomplete := test.name == "both-facts"
			wantUncertain := test.err != nil || realCleanupErr != nil
			if result == nil || result.AttemptedEver() || result.CleanupIncomplete() != wantIncomplete ||
				result.CleanupDurabilityUncertain() != wantUncertain {
				t.Fatalf("Abort cleanup facts = %#v; want incomplete=%t durability-uncertain=%t, no provider attempt", result, wantIncomplete, wantUncertain)
			}
			wantState := fileops.UnpackStateNotPublished
			if wantIncomplete || wantUncertain {
				wantState = fileops.UnpackStatePublicationIndeterminate
			}
			if result.State() != wantState || session.Abort() != result || session.Finish() != result {
				t.Fatalf("cleanup classification changed the closed one-shot publication state: %#v", result)
			}
			for _, path := range []string{stagePath, target} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("cleanup left an owned stage or granted provider publication at %q: %v", path, err)
				}
			}
		})
	}
}

func TestArchiveSAFFinishKeepsDeletionDurabilitySeparateFromProviderHandoff(t *testing.T) {
	payload := []byte("provider bytes stay exact despite an unconfirmed cleanup barrier")
	archive := buildArchiveSAFZIP(t, []archiveSAFZIPEntry{{name: "file", data: payload}})
	handoff, parent, target := newArchiveSAFHandoffFromZIP(t, archive, true)
	session := armNativeArchiveSAFSession(t, handoff)
	t.Cleanup(func() { _ = session.Abort() })
	stagePath := findArchiveSAFStagePath(t, parent)
	realCleanup := session.state.cleanupStage
	session.state.cleanupStage = func(stage *pcv3publication.Stage) error {
		return errors.Join(realCleanup(stage), pcv3publication.ErrCleanupDurabilityUncertain)
	}
	if step := session.Attempt(0); step == nil || step.Kind() != NativeArchiveSAFStepAttempted {
		t.Fatalf("provider attempt = %#v", step)
	}
	destination, err := os.CreateTemp(t.TempDir(), "provider-*")
	if err != nil {
		t.Fatal(err)
	}
	if step := session.Write(0, destination); step == nil || step.Kind() != NativeArchiveSAFStepReady {
		t.Fatalf("provider write = %#v", step)
	}
	result := session.Finish()
	if result == nil || result.State() != fileops.UnpackStatePublishedDurabilityUncertain ||
		!result.AttemptedEver() || result.CleanupIncomplete() || !result.CleanupDurabilityUncertain() {
		t.Fatalf("finished provider and cleanup facts = %#v; want confirmed live cleanup, uncertain deletion persistence", result)
	}
	if got, err := os.ReadFile(destination.Name()); err != nil || string(got) != string(payload) {
		t.Fatalf("provider bytes changed during cleanup: %q, %v", got, err)
	}
	for _, path := range []string{stagePath, target} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("finished cleanup left its private stage or published a raw target: %q: %v", path, err)
		}
	}
}
