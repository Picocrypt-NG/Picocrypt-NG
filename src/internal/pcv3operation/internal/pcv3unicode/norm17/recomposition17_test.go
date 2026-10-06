package norm

import "testing"

func TestSupplementaryRecompositionsCannotFallThroughToPackedKeys(t *testing.T) {
	if len(supplementaryRecompositions) != 33 {
		t.Fatalf("supplementary recomposition count = %d, want frozen Unicode-17 count 33", len(supplementaryRecompositions))
	}

	recompMapOnce.Do(buildRecompMap)
	for key, result := range recompMap {
		if result > '\uFFFF' {
			t.Fatalf("packed recomposition key %#08x retained supplementary result U+%04X", key, result)
		}
	}
	for pair, result := range supplementaryRecompositions {
		if pair[0] <= '\uFFFF' && pair[1] <= '\uFFFF' {
			t.Fatalf("supplementary table contains BMP-only pair U+%04X U+%04X", pair[0], pair[1])
		}
		packedKey := uint32(uint16(pair[0]))<<16 | uint32(uint16(pair[1]))
		if packedResult, exists := recompMap[packedKey]; exists {
			t.Fatalf("supplementary pair U+%04X U+%04X -> U+%04X still aliases packed result U+%04X", pair[0], pair[1], result, packedResult)
		}
	}
}
