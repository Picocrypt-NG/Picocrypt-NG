package mobile

import (
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3artifact"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3publication"
	"Picocrypt-NG/internal/pcv3recovery"
	"context"
	"math"
	"os"
	"testing"
)

// frozenMobileArtifactInspection is an adapter-only immutable Metadata/Page
// source. It never substitutes a Result, publication result, or capability.
type frozenMobileArtifactInspection struct {
	metadata pcv3recovery.ArtifactInspectionMetadata
	ranges   []pcv3artifact.Range
}

var _ func(*pcv3operation.Result) *pcv3recovery.ArtifactInspection = (*pcv3operation.Result).ArtifactInspection

func (inspection *frozenMobileArtifactInspection) Metadata() pcv3recovery.ArtifactInspectionMetadata {
	if inspection == nil {
		return pcv3recovery.ArtifactInspectionMetadata{}
	}
	return inspection.metadata
}

func (inspection *frozenMobileArtifactInspection) Page(offset, limit uint64) ([]pcv3artifact.Range, bool) {
	if inspection == nil || limit == 0 || limit > 128 || offset >= uint64(len(inspection.ranges)) {
		return nil, false
	}
	end := offset + limit
	if end < offset {
		return nil, false
	}
	if end > uint64(len(inspection.ranges)) {
		end = uint64(len(inspection.ranges))
	}
	return append([]pcv3artifact.Range(nil), inspection.ranges[offset:end]...), true
}

type panicMobileArtifactArchiveAction struct{}

func (panicMobileArtifactArchiveAction) Extract(root *os.Root) pcv3operation.Presentation {
	if root != nil {
		_ = root.Close()
	}
	panic("archive extraction must not run")
}

func (panicMobileArtifactArchiveAction) Close() pcv3operation.Presentation {
	panic("archive close panic")
}

func TestPCV3ArtifactInspectionDoesNotWrapTypedNilCoreView(t *testing.T) {
	var coreInspection *pcv3recovery.ArtifactInspection
	if wrapped := newPCV3ArtifactInspection(coreInspection); wrapped != nil {
		t.Fatalf("typed-nil core inspection became mobile wrapper %#v", wrapped)
	}

	result := pcv3operation.Run(context.Background(), nil)
	if result == nil || result.ArtifactInspection() != nil {
		t.Fatalf("invalid request core result = %#v inspection=%#v; want real denied inspection", result, result.ArtifactInspection())
	}
	operation := startPCV3Operation()
	completePCV3Result(operation, result)
	if operation.ArtifactInspection() != nil {
		t.Fatal("real denied core inspection was fabricated at the mobile completion seam")
	}
	if code := operation.Release(); code != "" {
		t.Fatalf("denied inspection terminal release = %q", code)
	}
}

func TestPCV3ArtifactInspectionRemainsPathFreeAndReadableAfterRelease(t *testing.T) {
	view := &frozenMobileArtifactInspection{
		metadata: pcv3recovery.ArtifactInspectionMetadata{
			Kind:                 pcv3artifact.StatePartial,
			Role:                 pcv3artifact.RoleBackup,
			PlaintextLength:      math.MaxUint64,
			Final:                pcv3artifact.FinalMissing,
			RangeCount:           2,
			VerifiedRangeCount:   1,
			UnverifiedRangeCount: 0,
			MissingRangeCount:    1,
		},
		ranges: []pcv3artifact.Range{
			{RecordIndex: 0, Start: 0, End: 7, Status: pcv3artifact.RangeVerified},
			{RecordIndex: math.MaxUint64, Start: 7, End: math.MaxUint64, Status: pcv3artifact.RangeMissing},
		},
	}
	inspection := newPCV3ArtifactInspectionFromView(view)
	operation := startPCV3Operation()
	completePCV3PresentationWithInspection(
		operation,
		durableForcePartialPCV3Presentation(t),
		inspection,
	)

	if got := operation.ArtifactInspection(); got != inspection {
		t.Fatalf("operation inspection = %p; want attached passive view %p", got, inspection)
	}
	if inspection.Kind() != "partial" || inspection.Role() != "backup" ||
		inspection.PlaintextLength() != "18446744073709551615" ||
		inspection.FinalStatus() != "missing" || inspection.RangeCount() != "2" ||
		inspection.VerifiedCount() != "1" || inspection.UnverifiedCount() != "0" ||
		inspection.MissingCount() != "1" {
		t.Fatalf("inspection metadata was not preserved as closed decimal/path-free values")
	}

	page := inspection.Page("0", 128)
	if page == nil || page.Count() != 2 || page.RecordIndexAt(0) != "0" ||
		page.StartAt(0) != "0" || page.EndAt(0) != "7" || page.StatusAt(0) != "verified" ||
		page.RecordIndexAt(1) != "18446744073709551615" ||
		page.StartAt(1) != "7" || page.EndAt(1) != "18446744073709551615" ||
		page.StatusAt(1) != "missing" {
		t.Fatalf("inspection page = %#v; want exact decimal evidence", page)
	}
	if page.RecordIndexAt(-1) != "0" || page.StartAt(2) != "0" ||
		page.EndAt(2) != "0" || page.StatusAt(-1) != "unknown" || page.StatusAt(2) != "unknown" {
		t.Fatal("invalid page indexes gained evidence values")
	}
	if inspection.Page("not-a-decimal", 1) != nil || inspection.Page("+0", 1) != nil ||
		inspection.Page("18446744073709551616", 1) != nil ||
		inspection.Page("18446744073709551615", 1) != nil || inspection.Page("0", 129) != nil ||
		inspection.Page("0", -1) != nil {
		t.Fatal("malformed, overflowing, full-width out-of-range, or oversized page request was accepted")
	}

	if code := operation.Release(); code != "" {
		t.Fatalf("inspection blocked terminal release: %q", code)
	}
	if operation.ArtifactInspection() != nil {
		t.Fatal("released operation retained inspection lookup authority")
	}
	if afterRelease := inspection.Page("1", 1); afterRelease == nil ||
		afterRelease.RecordIndexAt(0) != "18446744073709551615" || afterRelease.StatusAt(0) != "missing" {
		t.Fatal("already captured inspection did not remain readable after release")
	}
}

func TestPCV3ArtifactInspectionRejectsArchiveCombination(t *testing.T) {
	inspection := newPCV3ArtifactInspectionFromView(&frozenMobileArtifactInspection{})
	action := &literalMobileArchiveAction{closeResult: closedPCV3MobileArchivePresentation(t, false)}
	operation := startPCV3Operation()
	completePCV3PresentationWithArchiveAndInspection(
		operation,
		mustPCV3Presentation(t, pcv3operation.PresentationSpec{
			Outcome:        pcv3.OutcomeSuccess,
			Stage:          pcv3.StageNone,
			Code:           pcv3.CodeSuccess,
			ArchivePending: true,
		}),
		action,
		inspection,
	)
	if operation.Archive() != nil || operation.ArtifactInspection() != nil || action.closeCalls.Load() != 1 {
		t.Fatal("contradictory archive and inspection minted an authority or passive view")
	}
	if code := operation.Release(); code != "" {
		t.Fatalf("closed contradictory terminal did not release: %q", code)
	}
}

func TestPCV3ArtifactInspectionContainsContradictoryArchiveClosePanic(t *testing.T) {
	inspection := newPCV3ArtifactInspectionFromView(&frozenMobileArtifactInspection{})
	operation := startPCV3Operation()
	escaped := false
	func() {
		defer func() { escaped = recover() != nil }()
		completePCV3PresentationWithArchiveAndInspection(
			operation,
			mustPCV3Presentation(t, pcv3operation.PresentationSpec{
				Outcome:        pcv3.OutcomeSuccess,
				Stage:          pcv3.StageNone,
				Code:           pcv3.CodeSuccess,
				ArchivePending: true,
			}),
			panicMobileArtifactArchiveAction{},
			inspection,
		)
	}()
	if escaped {
		t.Fatal("contradictory archive cleanup panic escaped the terminal completion boundary")
	}
	snapshot := operation.Snapshot()
	if snapshot.CompletionClass() != "no-output" || snapshot.Diagnostic() != "core-failure" ||
		snapshot.WarningCount() != 1 || snapshot.WarningAt(0) != "cleanup-incomplete" ||
		operation.Archive() != nil || operation.ArtifactInspection() != nil {
		t.Fatalf("panic containment terminal = %#v archive=%v inspection=%v", snapshot, operation.Archive(), operation.ArtifactInspection())
	}
	if code := operation.Release(); code != "" {
		t.Fatalf("panic-contained contradictory terminal release = %q", code)
	}
}

func durableForcePartialPCV3Presentation(t *testing.T) pcv3operation.Presentation {
	t.Helper()
	return mustPCV3Presentation(t, pcv3operation.PresentationSpec{
		Outcome:              pcv3.OutcomeForcePartial,
		Stage:                pcv3.StageRecordAuth,
		Code:                 pcv3.CodeForcePartial,
		ForceProvenance:      pcv3.ForceProvenancePartial,
		PublicationAttempted: true,
		PublicationState:     pcv3publication.StatePublishedDurable,
		PublicationStage:     pcv3.StageNone,
		PublicationCode:      pcv3publication.CodePublishedDurable,
	})
}
