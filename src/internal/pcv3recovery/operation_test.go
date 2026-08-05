package pcv3recovery

import (
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3artifact"
	"Picocrypt-NG/internal/pcv3publication"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestRunPublishesCompleteRecoveredPlaintextWithoutSemanticRelabelling(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "recovered.bin")
	semantic := operationSemantic{
		outcome: pcv3.OutcomeAuthenticatedDegraded, provenance: pcv3.ForceProvenanceVerified,
		stage: pcv3.StageWrapAuth, plaintextLength: 5,
		ranges: []operationRange{{recordIndex: 0, start: 0, end: 5, state: pcv3.RecoveryRangeVerified}},
		final:  pcv3.RecoveryFinalVerified,
	}
	runner := fixedCoreRunner(semantic, [][]byte{[]byte("hello")}, nil)

	result := runWithCore(context.Background(), &Request{Target: target}, runner)
	if result.Outcome() != pcv3.OutcomeAuthenticatedDegraded ||
		result.ForceProvenance() != pcv3.ForceProvenanceVerified ||
		result.Stage() != pcv3.StageWrapAuth {
		t.Fatalf("semantic result = %v/%v/%v; durable publication must not relabel Force-verified recovery", result.Outcome(), result.ForceProvenance(), result.Stage())
	}
	if !result.PublicationAttempted() || result.PublicationState() != pcv3publication.StatePublishedDurable {
		t.Fatalf("publication = %v/%v; want attempted/durable", result.PublicationAttempted(), result.PublicationState())
	}
	assertFileBytesAndMode(t, target, []byte("hello"), 0o600)
	assertNoRecoveryStageResidue(t, directory)
}

func TestRunPublishesOneCanonicalArtifactForPartialEvidence(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "evidence.pcv3-recovery")
	semantic := operationSemantic{
		outcome: pcv3.OutcomeForcePartial, provenance: pcv3.ForceProvenancePartial,
		stage: pcv3.StageRecordAuth, plaintextLength: 9,
		ranges: []operationRange{
			{recordIndex: 0, start: 0, end: 4, state: pcv3.RecoveryRangeVerified},
			{recordIndex: 1, start: 4, end: 9, state: pcv3.RecoveryRangeMissing},
		},
		final: pcv3.RecoveryFinalMissing,
	}
	runner := fixedCoreRunner(semantic, [][]byte{[]byte("safe")}, nil)

	result := runWithCore(context.Background(), &Request{Target: target}, runner)
	if result.Outcome() != pcv3.OutcomeForcePartial ||
		result.PublicationState() != pcv3publication.StatePublishedDurable {
		t.Fatalf("operation = %v/%v; want Force-partial plus durable publication", result.Outcome(), result.PublicationState())
	}
	contents, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read published artifact: %v", err)
	}
	artifact, err := pcv3artifact.Parse(bytes.NewReader(contents), int64(len(contents)))
	if err != nil {
		t.Fatalf("parse published artifact: %v", err)
	}
	metadata := artifact.Metadata()
	if metadata.State != pcv3artifact.StatePartial || metadata.Role != pcv3artifact.RoleNone ||
		metadata.Final != pcv3artifact.FinalMissing || metadata.PlaintextLength != 9 ||
		metadata.RangeCount != 2 || metadata.EmittedSegmentCount != 1 {
		t.Fatalf("artifact metadata = %#v; want exact partial map", metadata)
	}
	var entries []pcv3artifact.Entry
	var segments [][]byte
	if err := artifact.VisitRanges(func(entry pcv3artifact.Entry, segment io.Reader) error {
		entries = append(entries, entry)
		if segment != nil {
			data, readErr := io.ReadAll(segment)
			if readErr != nil {
				return readErr
			}
			segments = append(segments, data)
		}
		return nil
	}); err != nil {
		t.Fatalf("visit artifact ranges: %v", err)
	}
	if len(entries) != 2 || len(segments) != 1 || !bytes.Equal(segments[0], []byte("safe")) ||
		entries[1].Status != pcv3artifact.RangeMissing || entries[1].SegmentLength != 0 {
		t.Fatalf("artifact entries/segments = %#v/%q; want verified bytes plus explicit missing interval", entries, segments)
	}
}

func TestRunNoOutputStatesNeverCreateDestination(t *testing.T) {
	for _, outcome := range []pcv3.Outcome{
		pcv3.OutcomeCredentialsOrDamage,
		pcv3.OutcomeAmbiguousVolume,
		pcv3.OutcomeOperationFailed,
	} {
		t.Run(outcome.String(), func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, "must-not-exist")
			semantic := operationSemantic{outcome: outcome, stage: pcv3.StageWrapAuth}
			result := runWithCore(context.Background(), &Request{Target: target}, fixedCoreRunner(semantic, nil, nil))
			if result.PublicationAttempted() || result.PublicationState() != 0 {
				t.Fatalf("no-output publication = %v/%v; want not attempted", result.PublicationAttempted(), result.PublicationState())
			}
			if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("no-output target exists or cannot be classified: %v", err)
			}
			assertNoRecoveryStageResidue(t, directory)
		})
	}
}

func TestRunNoReplaceAndProtectedAliasesRetainForeignBytes(t *testing.T) {
	tests := []struct {
		name          string
		protectTarget bool
	}{
		{name: "existing destination"},
		{name: "protected source alias", protectTarget: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, "foreign.bin")
			foreign := []byte("FOREIGN-SOURCE-BYTES")
			if err := os.WriteFile(target, foreign, 0o640); err != nil {
				t.Fatalf("seed foreign file: %v", err)
			}
			request := &Request{Target: target}
			if test.protectTarget {
				request.Protected = []string{target}
			}
			semantic := operationSemantic{
				outcome: pcv3.OutcomeAuthenticatedDegraded, provenance: pcv3.ForceProvenanceVerified,
				stage: pcv3.StageWrapAuth, plaintextLength: 3,
				ranges: []operationRange{{recordIndex: 0, start: 0, end: 3, state: pcv3.RecoveryRangeVerified}},
				final:  pcv3.RecoveryFinalVerified,
			}
			result := runWithCore(context.Background(), request, fixedCoreRunner(semantic, [][]byte{[]byte("new")}, nil))
			if !result.PublicationAttempted() || result.PublicationState() != pcv3publication.StateNotPublished {
				t.Fatalf("protected publication = %v/%v; want attempted/not-published", result.PublicationAttempted(), result.PublicationState())
			}
			assertFileBytesAndMode(t, target, foreign, 0o640)
			assertNoRecoveryStageResidue(t, directory)
		})
	}
}

func TestRunEmitterFailureCleansOnlyOwnedStageAndRetainsSource(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source.pcv")
	target := filepath.Join(directory, "evidence.pcv3-recovery")
	sourceBytes := []byte("TEST ONLY encrypted source")
	if err := os.WriteFile(source, sourceBytes, 0o600); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	semantic := operationSemantic{
		outcome: pcv3.OutcomeForcePartial, provenance: pcv3.ForceProvenancePartial,
		stage: pcv3.StageRecordAuth, plaintextLength: 4,
		ranges: []operationRange{{recordIndex: 0, start: 0, end: 4, state: pcv3.RecoveryRangeVerified}},
		final:  pcv3.RecoveryFinalMissing,
	}
	emitErr := errors.New("TEST ONLY sink fault")
	result := runWithCore(
		context.Background(),
		&Request{Target: target, Protected: []string{source}},
		fixedCoreRunner(semantic, nil, emitErr),
	)
	if !result.PublicationAttempted() || result.PublicationState() != pcv3publication.StateNotPublished {
		t.Fatalf("failed emission publication = %v/%v; want attempted/not-published", result.PublicationAttempted(), result.PublicationState())
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed emission left target: %v", err)
	}
	assertFileBytesAndMode(t, source, sourceBytes, 0o600)
	assertNoRecoveryStageResidue(t, directory)
}

func fixedCoreRunner(
	semantic operationSemantic,
	segments [][]byte,
	emitErr error,
) recoveryCoreRunner {
	return func(
		_ context.Context,
		_ *Request,
		output operationOutput,
	) (operationSemantic, error) {
		if !semantic.outputCapable() {
			return semantic, nil
		}
		err := output(semantic, pcv3.CapsuleRolePrimary, func(sink operationSegmentSink) error {
			if emitErr != nil {
				return emitErr
			}
			segmentIndex := 0
			for _, recoveryRange := range semantic.ranges {
				if recoveryRange.state == pcv3.RecoveryRangeMissing {
					continue
				}
				if segmentIndex >= len(segments) {
					return errors.New("TEST ONLY missing segment")
				}
				if err := sink(recoveryRange, segments[segmentIndex]); err != nil {
					return err
				}
				segmentIndex++
			}
			if segmentIndex != len(segments) {
				return errors.New("TEST ONLY extra segment")
			}
			return nil
		})
		return semantic, err
	}
}

func assertFileBytesAndMode(t *testing.T, path string, want []byte, wantMode os.FileMode) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Base(path), err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s bytes = %q; want %q", filepath.Base(path), got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", filepath.Base(path), err)
	}
	if info.Mode().Perm() != wantMode {
		t.Fatalf("%s mode = %04o; want %04o", filepath.Base(path), info.Mode().Perm(), wantMode)
	}
}

func assertNoRecoveryStageResidue(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read destination directory: %v", err)
	}
	for _, entry := range entries {
		if len(entry.Name()) >= len(".picocrypt-pcv3-") &&
			entry.Name()[:len(".picocrypt-pcv3-")] == ".picocrypt-pcv3-" {
			t.Fatalf("owned recovery stage residue remains: %s", entry.Name())
		}
	}
}
