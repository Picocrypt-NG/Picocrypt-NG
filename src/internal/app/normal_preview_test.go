package app

import (
	"Picocrypt-NG/internal/pcv3operation"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func selectedNormalPreview(t *testing.T) (*State, *os.File, pcv3operation.NormalPreview, uint64) {
	t.Helper()
	source, err := os.Open(filepath.Join("..", "pcv3operation", "internal", "pcv3", "testdata", "normal", "volumes", "normal-standard-combined-ordered-one.pcv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = source.Close() })
	info, err := source.Stat()
	if err != nil {
		t.Fatal(err)
	}
	preview, err := pcv3operation.PreviewNormal(context.Background(), source, info.Size())
	if err != nil {
		t.Fatal(err)
	}
	state, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(state.Reset)
	if !state.SetPCV3Ready(source, PCV3FormatNormal, source.Name(), "plain", info.Size()) {
		t.Fatal("ready")
	}
	ticket, _, _ := state.PCV3ReadyOutputSelection()
	return state, source, preview, ticket
}

func TestNormalPreviewRequiresExactReadySelection(t *testing.T) {
	state, source, preview, ticket := selectedNormalPreview(t)
	if state.SetPCV3NormalPreviewForReady(ticket+1, source, preview) {
		t.Fatal("stale ticket accepted")
	}
	other, err := os.Open(source.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	if state.SetPCV3NormalPreviewForReady(ticket, other, preview) {
		t.Fatal("reopened path substituted for held source")
	}
	if !state.SetPCV3NormalPreviewForReady(ticket, source, preview) {
		t.Fatal("current preview refused")
	}
	snap := state.UISnapshot()
	if snap.Comments != "TEST ONLY comment" || snap.CommentsPreviewState != CommentsPreviewUnverified || snap.PCV3Factor != PCV3FactorPolicyUnset {
		t.Fatal("preview text/trust/factor state")
	}
	state.SetWorking(true)
	if state.SetPCV3NormalPreviewForReady(ticket, source, preview) {
		t.Fatal("working preview accepted")
	}
}

func TestNormalPreviewInvalidationsCannotResurrectClaims(t *testing.T) {
	for _, kind := range []string{"reset", "checking", "failed", "legacy", "new ready", "D1", "transferred"} {
		t.Run(kind, func(t *testing.T) {
			state, source, preview, ticket := selectedNormalPreview(t)
			state.SetPCV3NormalPreviewForReady(ticket, source, preview)
			switch kind {
			case "reset":
				state.Reset()
			case "checking":
				state.SetPCV3RoutingChecking("new", 0)
			case "failed":
				state.SetPCV3RoutingFailed()
			case "legacy":
				state.SetPCV3LegacyEligible()
			case "new ready":
				state.SetPCV3Ready(source, PCV3FormatNormal, "new", "plain", 0)
			case "D1":
				state.SelectPCV3D1()
			case "transferred":
				state.SetPCV3Intent(PCV3ActionDecrypt, PCV3FactorPolicyPassword, PCV3KeyfileOrderUnset)
				state.Password = "mix"
				intent, ok := state.TakePCV3OperationIntent()
				if !ok {
					t.Fatal("handoff")
				}
				defer func() { _ = intent.Source.Close() }()
			}
			if state.SetPCV3NormalPreviewForReady(ticket, source, preview) {
				t.Fatal("obsolete preview accepted")
			}
			if kind != "transferred" {
				snap := state.UISnapshot()
				_, claims := snap.PCV3NormalPreview.Factors()
				if snap.Comments != "" || claims {
					t.Fatal("old preview survived invalidation")
				}
			}
		})
	}
}

func TestNormalPreviewIsNeverPromotedWhenReaderReleasesNoComment(t *testing.T) {
	state, source, preview, ticket := selectedNormalPreview(t)
	state.SetPCV3NormalPreviewForReady(ticket, source, preview)
	state.SetPCV3ResultComment(nil)
	snap := state.UISnapshot()
	if snap.Comments != "" || snap.CommentsPreviewState != CommentsPreviewUnavailable {
		t.Fatal("preview promoted without released comment")
	}
}
