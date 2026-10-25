//go:build pcv3_unicode_conformance

package pcv3unicode

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

const normalizationTestMaxBytes = 4 << 20

func readPinnedUnicodeFile(t *testing.T, variable, checksum string) []byte {
	t.Helper()
	path, ok := os.LookupEnv(variable)
	if !ok || path == "" {
		t.Fatalf("%s is required for the Unicode conformance lane", variable)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open pinned Unicode normalization test: %v", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatalf("stat pinned Unicode normalization test: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Fatal("pinned Unicode normalization test is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, normalizationTestMaxBytes+1))
	if err != nil {
		t.Fatalf("read pinned Unicode normalization test: %v", err)
	}
	if len(data) > normalizationTestMaxBytes {
		t.Fatalf("pinned Unicode normalization test exceeds %d bytes", normalizationTestMaxBytes)
	}
	sum := sha256.Sum256(data)
	if actual := hex.EncodeToString(sum[:]); actual != checksum {
		t.Fatalf("pinned Unicode file SHA-256 = %s, want %s", actual, checksum)
	}
	return data
}

func parseNormalizationCodepoints(value string) ([]byte, error) {
	runes := make([]rune, 0, strings.Count(value, " ")+1)
	for _, token := range strings.Fields(value) {
		scalar, err := strconv.ParseUint(token, 16, 32)
		if err != nil {
			return nil, fmt.Errorf("parse scalar %q: %w", token, err)
		}
		r := rune(scalar)
		if !utf8.ValidRune(r) {
			return nil, fmt.Errorf("invalid Unicode scalar U+%04X", scalar)
		}
		runes = append(runes, r)
	}
	return []byte(string(runes)), nil
}

func TestUnicode18NormalizationConformance(t *testing.T) {
	scanner := bufio.NewScanner(bytes.NewReader(readPinnedUnicodeFile(t, "PCV3_UNICODE_NORMALIZATION_TEST", literalNormalizationTestSHA256)))
	partOne := false
	listedPartOne := make(map[rune]bool)
	tested := 0
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "@Part") {
			partOne = line == "@Part1"
			continue
		}
		fields := strings.Split(line, ";")
		if len(fields) < 5 {
			t.Fatalf("NormalizationTest.txt line %d has %d fields, want at least 5", lineNumber, len(fields))
		}
		columns := make([][]byte, 5)
		for i := range columns {
			decoded, err := parseNormalizationCodepoints(fields[i])
			if err != nil {
				t.Fatalf("NormalizationTest.txt line %d column %d: %v", lineNumber, i+1, err)
			}
			columns[i] = decoded
		}
		if partOne {
			r, size := utf8.DecodeRune(columns[0])
			if size != len(columns[0]) {
				t.Fatalf("NormalizationTest.txt Part 1 line %d is not a single scalar", lineNumber)
			}
			listedPartOne[r] = true
		}
		cases := []struct {
			input []byte
			want  []byte
		}{
			{columns[0], columns[1]},
			{columns[1], columns[1]},
			{columns[2], columns[1]},
			{columns[3], columns[3]},
			{columns[4], columns[3]},
		}
		for caseIndex, testCase := range cases {
			got, err := Canonicalize(testCase.input)
			if err != nil {
				t.Fatalf("NormalizationTest.txt line %d NFC case %d: %v", lineNumber, caseIndex+1, err)
			}
			if !bytes.Equal(got, testCase.want) {
				t.Fatalf("NormalizationTest.txt line %d NFC case %d = %x, want %x", lineNumber, caseIndex+1, got, testCase.want)
			}
			tested++
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan pinned Unicode normalization test: %v", err)
	}
	if tested == 0 {
		t.Fatal("pinned Unicode normalization test contained no conformance cases")
	}

	assigned := unicodeDataAssignedScalars(t)
	accepted, rejected := 0, 0
	for r := rune(0); r <= utf8.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		input := []byte(string(r))
		got, err := Canonicalize(input)
		if assigned[r] {
			if err != nil {
				t.Fatalf("UnicodeData-assigned U+%04X rejected: %v", r, err)
			}
			// NormalizationTest conformance rule 2 covers every assigned
			// scalar omitted from Part 1, not only the explicit row cases.
			if !listedPartOne[r] && !bytes.Equal(got, input) {
				t.Fatalf("unlisted U+%04X NFC = %x, want unchanged scalar %x", r, got, input)
			}
			accepted++
		} else {
			var rejection *Error
			if got != nil || !errors.As(err, &rejection) || rejection.Reason != RejectionUnassigned {
				t.Fatalf("UnicodeData-unassigned U+%04X = (%x, %v), want no result and typed unassigned rejection", r, got, err)
			}
			rejected++
		}
	}
	t.Logf("official NFC row checks: %d; UnicodeData scalar admission: %d assigned, %d unassigned", tested, accepted, rejected)
}

func unicodeDataAssignedScalars(t *testing.T) []bool {
	t.Helper()
	assigned := make([]bool, utf8.MaxRune+1)
	scanner := bufio.NewScanner(bytes.NewReader(readPinnedUnicodeFile(t, "PCV3_UNICODE_UNICODE_DATA", literalUnicodeDataSHA256)))
	var first rune
	pendingRange := false
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ";")
		if len(fields) < 2 {
			t.Fatal("UnicodeData.txt record lacks scalar and name")
		}
		value, err := strconv.ParseUint(fields[0], 16, 32)
		if err != nil || value > utf8.MaxRune {
			t.Fatalf("invalid UnicodeData.txt code point %q", fields[0])
		}
		r := rune(value)
		switch {
		case strings.HasSuffix(fields[1], ", First>"):
			if pendingRange {
				t.Fatal("nested UnicodeData.txt First/Last range")
			}
			first, pendingRange = r, true
		case strings.HasSuffix(fields[1], ", Last>"):
			if !pendingRange || r < first {
				t.Fatal("unmatched UnicodeData.txt Last range")
			}
			for scalar := first; scalar <= r; scalar++ {
				assigned[scalar] = true
			}
			pendingRange = false
		default:
			if pendingRange {
				t.Fatal("unterminated UnicodeData.txt First/Last range")
			}
			assigned[r] = true
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan pinned UnicodeData.txt: %v", err)
	}
	if pendingRange {
		t.Fatal("unterminated UnicodeData.txt First/Last range")
	}
	return assigned
}
