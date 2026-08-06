package pcv3corpus

import (
	"strings"
	"testing"
)

// This is a mutation-runner policy contract, not product-behavior coverage.
func TestD1MutationRegistryIsClosedAndUnambiguous(t *testing.T) {
	contracts := D1MutationContracts()
	if len(contracts) != 9 {
		t.Fatalf("D1 mutation registry entries = %d; want exactly 9", len(contracts))
	}
	seenIDs := make(map[string]struct{}, len(contracts))
	seenMarkers := make(map[string]struct{}, len(contracts))
	for _, contract := range contracts {
		if !validD1MutationID(contract.ID()) {
			t.Fatalf("D1 mutation registry contains invalid ID %q", contract.ID())
		}
		if _, duplicate := seenIDs[contract.ID()]; duplicate {
			t.Fatalf("D1 mutation registry contains duplicate ID %q", contract.ID())
		}
		seenIDs[contract.ID()] = struct{}{}
		if !validD1AssertionMarker(contract.AssertionMarker()) {
			t.Fatalf("D1 mutation %q contains an invalid assertion marker", contract.ID())
		}
		if _, duplicate := seenMarkers[contract.AssertionMarker()]; duplicate {
			t.Fatalf("D1 mutation registry contains duplicate assertion marker for %q", contract.ID())
		}
		seenMarkers[contract.AssertionMarker()] = struct{}{}
		if !validLogicalPath(contract.SourcePath()) || !strings.HasSuffix(contract.SourcePath(), ".go") ||
			strings.HasSuffix(contract.SourcePath(), "_test.go") || !validD1TestName(contract.TestName()) ||
			contract.TimeoutSeconds() != d1MutationTimeoutSeconds {
			t.Fatalf("D1 mutation %q contains invalid execution policy", contract.ID())
		}
		switch contract.Package() {
		case "./internal/pcv3":
			if !strings.HasPrefix(contract.SourcePath(), "internal/pcv3/") ||
				strings.HasPrefix(contract.SourcePath(), "internal/pcv3credential/") {
				t.Fatalf("D1 mutation %q source does not belong to its package", contract.ID())
			}
		case "./internal/pcv3credential":
			if !strings.HasPrefix(contract.SourcePath(), "internal/pcv3credential/") {
				t.Fatalf("D1 mutation %q source does not belong to its package", contract.ID())
			}
		default:
			t.Fatalf("D1 mutation %q targets non-production package %q", contract.ID(), contract.Package())
		}
	}
}
