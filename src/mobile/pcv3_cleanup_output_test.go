//go:build android || linux

package mobile

import (
	"os"
	"testing"
)

type literalMobileCleanupOutputAction struct{ result pcv3OutputActionResult }

func (action literalMobileCleanupOutputAction) Discard() pcv3OutputActionResult {
	return action.result
}

func (action literalMobileCleanupOutputAction) SaveTo(*os.File) pcv3OutputActionResult {
	return action.result
}

func TestPCV3MobileOutputPreservesIndependentCleanupFacts(t *testing.T) {
	for _, test := range []struct {
		code       string
		incomplete bool
		uncertain  bool
		save       bool
	}{
		{"saved", false, false, true},
		{"saved-cleanup-durability-uncertain", false, true, true},
		{"saved-cleanup-incomplete", true, true, true},
		{"discarded", false, false, false},
		{"discard-cleanup-durability-uncertain", false, true, false},
		{"discard-cleanup-incomplete", true, true, false},
	} {
		t.Run(test.code, func(t *testing.T) {
			operation := startPCV3Operation()
			action := literalMobileCleanupOutputAction{pcv3OutputActionResult{
				code: test.code, cleanupIncomplete: test.incomplete,
				cleanupDurabilityUncertain: test.uncertain,
			}}
			completePCV3PresentationWithOutputAndInspectionComment(operation, durablePCV3MobilePresentation(t), action, nil, "")
			output := operation.Output()
			if output == nil {
				t.Fatal("terminal owner did not expose its output capability")
			}
			var result *PCV3OutputResult
			if test.save {
				destination, err := os.CreateTemp(t.TempDir(), "provider-*")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = destination.Close() })
				fd := duplicateMobileTransferredFD(t, destination)
				result = output.SaveFD(fd)
				assertMobileTransferredFDClosed(t, fd)
			} else {
				result = output.Discard()
			}
			if result.Code() != test.code || result.CleanupIncomplete() != test.incomplete ||
				result.CleanupDurabilityUncertain() != test.uncertain {
				t.Fatalf("output result = %q/%t/%t; want %q/%t/%t", result.Code(), result.CleanupIncomplete(), result.CleanupDurabilityUncertain(), test.code, test.incomplete, test.uncertain)
			}
			if code := operation.Release(); code != "" {
				t.Fatalf("settled output retained operation custody: %q", code)
			}
		})
	}
}
