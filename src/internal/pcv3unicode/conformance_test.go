//go:build pcv3_unicode_conformance

package pcv3unicode

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

const normalizationTestMaxBytes = 4 << 20

func readNormalizationTest(t *testing.T) []byte {
	t.Helper()
	path, ok := os.LookupEnv("PCV3_UNICODE_NORMALIZATION_TEST")
	if !ok || path == "" {
		t.Fatal("PCV3_UNICODE_NORMALIZATION_TEST is required for the Unicode conformance lane")
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
	if actual := hex.EncodeToString(sum[:]); actual != literalNormalizationTestSHA256 {
		t.Fatalf("pinned Unicode normalization test SHA-256 = %s, want %s", actual, literalNormalizationTestSHA256)
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

func TestUnicode17NormalizationConformance(t *testing.T) {
	scanner := bufio.NewScanner(bytes.NewReader(readNormalizationTest(t)))
	tested := 0
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if line == "" || strings.HasPrefix(line, "@Part") {
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
}
