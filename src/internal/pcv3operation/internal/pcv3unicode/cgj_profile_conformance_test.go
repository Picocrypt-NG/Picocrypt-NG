//go:build pcv3_unicode_conformance

package pcv3unicode

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
	"testing"
)

// The outer profile rejects an increased CGJ count. Independently pin the
// Unicode-data invariant that ordinary canonical mappings preserve that count.
func TestUnicode18CanonicalMappingsPreserveCGJMultiplicity(t *testing.T) {
	const cgj = 0x034F
	scanner := bufio.NewScanner(bytes.NewReader(readPinnedUnicodeFile(t, "PCV3_UNICODE_UNICODE_DATA", literalUnicodeDataSHA256)))
	foundCGJ := false
	canonicalMappings := 0
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ";")
		if len(fields) < 6 {
			t.Fatal("UnicodeData.txt record lacks canonical decomposition fields")
		}
		scalar, err := strconv.ParseUint(fields[0], 16, 32)
		if err != nil {
			t.Fatalf("invalid UnicodeData scalar %q: %v", fields[0], err)
		}
		if scalar == cgj {
			foundCGJ = true
			if fields[3] != "0" || fields[5] != "" {
				t.Fatal("CGJ no longer has CCC=0 and no decomposition; review the credential-profile guard")
			}
		}
		if fields[5] == "" || strings.HasPrefix(fields[5], "<") {
			continue
		}
		canonicalMappings++
		if scalar == cgj {
			t.Fatal("a canonical decomposition removes CGJ; the count-based profile guard is no longer sound")
		}
		for _, token := range strings.Fields(fields[5]) {
			operand, err := strconv.ParseUint(token, 16, 32)
			if err != nil {
				t.Fatalf("invalid canonical decomposition operand %q: %v", token, err)
			}
			if operand == cgj {
				t.Fatalf("canonical U+%04X decomposition creates CGJ, or its inverse composition removes it", scalar)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan UnicodeData CGJ invariant: %v", err)
	}
	if !foundCGJ {
		t.Fatal("pinned UnicodeData omitted the CGJ record")
	}
	t.Logf("verified CGJ multiplicity is preserved by all %d canonical mappings; CGJ has CCC=0 and no decomposition", canonicalMappings)
}
