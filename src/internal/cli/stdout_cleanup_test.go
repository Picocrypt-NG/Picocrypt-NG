package cli

import (
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3publication"
	"slices"
	"strings"
	"testing"
)

func TestStdoutActionPreservesCleanupFactsWithoutReportingSavedBytesAsTransportFailure(t *testing.T) {
	for _, test := range []struct {
		name                         string
		code                         pcv3operation.OutputActionCode
		incomplete, uncertain, saved bool
	}{
		{"clean", pcv3operation.OutputActionSaved, false, false, true},
		{"removed without barrier", pcv3operation.OutputActionSavedCleanupDurabilityUncertain, false, true, true},
		{"incomplete", pcv3operation.OutputActionSavedCleanupIncomplete, true, false, true},
		{"both cleanup facts", pcv3operation.OutputActionSavedCleanupIncomplete, true, true, true},
		{"failed copy with deletion uncertainty", pcv3operation.OutputActionSaveFailedCleanupDurabilityUncertain, false, true, false},
		{"failed copy with both facts", pcv3operation.OutputActionSaveFailedCleanupIncomplete, true, true, false},
		{"expired", pcv3operation.OutputActionExpired, false, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := &pcv3CLIFixedResult{
				outcome: pcv3operation.OutcomeSuccess, code: pcv3operation.CodeSuccess,
				publicationAttempted: true, publicationState: pcv3publication.StatePublishedDurable,
				publicationCode: pcv3publication.CodePublishedDurable, class: pcv3operation.CompletionClean,
			}
			err := finishPCV3CLIStdoutAction(result, test.code, test.incomplete, test.uncertain)
			if (err == nil) != test.saved {
				t.Fatalf("saved=%v produced transport error %v", test.saved, err)
			}
			var want []pcv3operation.Warning
			if test.incomplete {
				want = append(want, pcv3operation.WarningCleanupIncomplete)
			}
			if test.uncertain {
				want = append(want, pcv3operation.WarningCleanupDurabilityUncertain)
			}
			if !slices.Equal(result.Warnings(), want) || result.PublicationState() != pcv3publication.StatePublishedDurable {
				t.Fatalf("stdout cleanup projection=%v publication=%v; want %v and durable publication", result.Warnings(), result.PublicationState(), want)
			}
			var terminal strings.Builder
			wantExit := 0
			if len(want) != 0 {
				wantExit = ExitPCV3Warning
			}
			if exit := renderPCV3CLIResult(&terminal, result); exit != wantExit {
				t.Fatalf("cleanup terminal exit=%d; want %d: %q", exit, wantExit, terminal.String())
			}
		})
	}
}
