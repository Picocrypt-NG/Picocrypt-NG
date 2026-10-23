package pcv3

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeReadSnapshotSeparatesCleanupDurability(t *testing.T) {
	for _, test := range []struct {
		name       string
		err        error
		incomplete bool
		uncertain  bool
	}{
		{name: "clean"},
		{name: "live residue", err: pcv3publication.ErrCleanupIncomplete, incomplete: true},
		{name: "removed durability", err: pcv3publication.ErrCleanupDurabilityUncertain, uncertain: true},
		{name: "both", err: errors.Join(pcv3publication.ErrCleanupIncomplete, pcv3publication.ErrCleanupDurabilityUncertain), incomplete: true, uncertain: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			sink := &nativeReadSink{}
			sink.retainPublicationError(test.err)
			result := &NativeReadResult{outcome: OutcomeSuccess, code: CodeSuccess}
			sink.snapshot(result)
			if result.CleanupIncomplete() != test.incomplete || result.CleanupDurabilityUncertain() != test.uncertain {
				t.Fatalf("cleanup snapshot = incomplete %v durability %v; want %v/%v", result.CleanupIncomplete(), result.CleanupDurabilityUncertain(), test.incomplete, test.uncertain)
			}
			if result.Outcome() != OutcomeSuccess || result.Code() != CodeSuccess || result.PublicationAttempted() {
				t.Fatal("cleanup observation changed authentication or publication truth")
			}
			archive := &NativeArchiveResult{state: fileops.UnpackStatePublishedDurable}
			archive.retainCleanupError(test.err)
			if archive.CleanupIncomplete() != test.incomplete || archive.CleanupDurabilityUncertain() != test.uncertain || archive.State() != fileops.UnpackStatePublishedDurable {
				t.Fatal("archive cleanup lost an independent cause or changed publication")
			}
		})
	}
}

func TestNativeReadPanicKeepsCleanupDurabilityOpaqueAndConservative(t *testing.T) {
	fixture := requireNormalFixture(t, loadNormalFixtureManifest(t).FixturesByID(), "normal-standard-password-only-small")
	volume := readNormalFixtureArtifact(t, fixture.Volume)
	source := newNormalFixtureSource(t, fixture, volume)
	sink := &nativeReadSink{target: filepath.Join(t.TempDir(), "output")}
	sink.retainPublicationError(pcv3publication.ErrCleanupDurabilityUncertain)
	const canary = "TEST ONLY private panic details"
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		runNativeReadSession(context.Background(), source, int64(len(volume)), probeNormalBehavior(t, source, int64(len(volume))),
			newNormalFixtureCredentialProvider(t, fixture.Keys), sink,
			func(*NativeReadOutput) error { panic(canary) })
	}()
	if !fileops.PanicCleanupIncomplete(recovered) {
		t.Fatal("panic discarded the pre-existing cleanup uncertainty")
	}
	if strings.Contains(fmt.Sprint(recovered), canary) {
		t.Fatal("cleanup panic exposed original private details")
	}
}
