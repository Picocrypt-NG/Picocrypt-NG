package mobile

import (
	"Picocrypt-NG/internal/header"
	"errors"
	"testing"
)

func TestLegacyResultMetadataSurvivesSnapshotAndCompletedCancellation(t *testing.T) {
	id := StartOperation()
	t.Cleanup(func() { cleanupOperation(id) })
	metadata := header.LegacyMetadata{Version: "v1.49", CommentAuthenticity: header.CommentUnverified, SecurityWarning: header.LegacyUnauthenticatedHeader}
	completeLegacyOperation(id, nil, false, metadata)
	for _, cancel := range []bool{false, true} {
		var got *ProgressResult
		var err error
		if cancel {
			got, err = CancelOperation(id)
		} else {
			got, err = GetProgress(id)
		}
		if err != nil {
			t.Fatal(err)
		}
		if !got.Done || got.Error != "" || got.LegacyVersion != "v1.49" || got.CommentAuthenticity != "unverified" || got.LegacySecurityWarning != "LEGACY_V1_UNAUTHENTICATED_HEADER" {
			t.Fatalf("lost terminal legacy trust: %+v", got)
		}
	}
}

func TestLegacyResultMetadataCannotEscapeFailureOrOverwriteEarlierTerminal(t *testing.T) {
	id := StartOperation()
	t.Cleanup(func() { cleanupOperation(id) })
	metadata := header.LegacyMetadata{Version: "v2.19", CommentAuthenticity: header.CommentAuthenticated}
	completeLegacyOperation(id, errors.New("cleanup failed"), false, metadata)
	completeLegacyOperation(id, nil, false, metadata)
	got, err := GetProgress(id)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Done || got.Error != "cleanup failed" || got.LegacyVersion != "" || got.CommentAuthenticity != "" || got.LegacySecurityWarning != "" {
		t.Fatalf("failed operation exposed authentication state: %+v", got)
	}
}
