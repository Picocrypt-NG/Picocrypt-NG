package fileops

import (
	"Picocrypt-NG/internal/util"
	"math"
	"strings"
	"testing"
)

func TestParseZIPEntryPathPreservesExtractionCompatibleNormalization(t *testing.T) {
	tests := []struct {
		name      string
		entry     string
		directory bool
		want      string
		wantError bool
	}{
		{
			name:  "backslash remains a compatible separator",
			entry: `docs\readme.txt`,
			want:  "docs/readme.txt",
		},
		{
			name:  "double dots inside a filename remain local",
			entry: "docs/file..txt",
			want:  "docs/file..txt",
		},
		{
			name:      "directory slash remains for the existing extractor",
			entry:     "empty/",
			directory: true,
			want:      "empty/",
		},
		{
			name:  "absolute rejection remains the extraction-root responsibility",
			entry: "/absolute",
			want:  "/absolute",
		},
		{
			name:      "windows trimmed traversal remains rejected",
			entry:     "docs/.. /escape",
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseZIPEntryPath(
				test.entry,
				test.directory,
				ZIPPathExtractionCompatible,
			)
			if test.wantError {
				if err == nil {
					t.Fatalf("ParseZIPEntryPath(%q) succeeded; want rejection", test.entry)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf(
					"ParseZIPEntryPath(%q) = (%q, %v); want (%q, nil)",
					test.entry,
					got,
					err,
					test.want,
				)
			}
		})
	}
}

func TestParseZIPEntryPathAcceptsPortableExactByteBoundaries(t *testing.T) {
	path4096 := strings.Join([]string{
		strings.Repeat("a", 240), strings.Repeat("b", 240),
		strings.Repeat("c", 240), strings.Repeat("d", 240),
		strings.Repeat("e", 240), strings.Repeat("f", 240),
		strings.Repeat("g", 240), strings.Repeat("h", 240),
		strings.Repeat("i", 240), strings.Repeat("j", 240),
		strings.Repeat("k", 240), strings.Repeat("l", 240),
		strings.Repeat("m", 240), strings.Repeat("n", 240),
		strings.Repeat("o", 240), strings.Repeat("p", 240),
		strings.Repeat("q", 240),
	}, "/")
	if len(path4096) != 4096 {
		t.Fatalf("TEST ONLY 4096-byte path length = %d", len(path4096))
	}

	tests := []struct {
		name      string
		entry     string
		directory bool
		want      string
	}{
		{name: "ordinary file", entry: "docs/readme.txt", want: "docs/readme.txt"},
		{name: "directory trailing slash is canonicalized", entry: "empty/", directory: true, want: "empty"},
		{name: "255-byte component", entry: strings.Repeat("x", 255), want: strings.Repeat("x", 255)},
		{name: "4096-byte path", entry: path4096, want: path4096},
		{name: "128 components", entry: strings.Repeat("a/", 127) + "a", want: strings.Repeat("a/", 127) + "a"},
		{name: "254-byte UTF-8 component", entry: strings.Repeat("é", 127), want: strings.Repeat("é", 127)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseZIPEntryPath(test.entry, test.directory, ZIPPathPortableExact)
			if err != nil || got != test.want {
				t.Fatalf(
					"ParseZIPEntryPath(%q) = (%q, %v); want (%q, nil)",
					test.entry,
					got,
					err,
					test.want,
				)
			}
		})
	}
}

func TestParseZIPEntryPathRejectsNonPortableOrAmbiguousNames(t *testing.T) {
	path4097Parts := make([]string, 17)
	for index := range path4097Parts {
		path4097Parts[index] = strings.Repeat("a", 240)
	}
	path4097Parts[len(path4097Parts)-1] += "x"
	path4097 := strings.Join(path4097Parts, "/")
	if len(path4097) != 4097 {
		t.Fatalf("TEST ONLY 4097-byte path length = %d", len(path4097))
	}

	tests := []struct {
		name      string
		entry     string
		directory bool
	}{
		{name: "invalid UTF-8", entry: string([]byte{'a', 0xff})},
		{name: "NUL", entry: "a\x00b"},
		{name: "backslash", entry: `docs\readme.txt`},
		{name: "absolute", entry: "/absolute"},
		{name: "drive absolute", entry: "C:/absolute"},
		{name: "drive relative", entry: "C:relative"},
		{name: "slash UNC", entry: "//server/share"},
		{name: "backslash UNC", entry: `\\server\share`},
		{name: "empty", entry: ""},
		{name: "dot", entry: "."},
		{name: "dot dot", entry: ".."},
		{name: "empty component", entry: "a//b"},
		{name: "dot component", entry: "a/./b"},
		{name: "dot dot component", entry: "a/../b"},
		{name: "file trailing slash", entry: "file/"},
		{name: "repeated directory trailing slash", entry: "dir//", directory: true},
		{name: "4097-byte path", entry: path4097},
		{name: "256-byte component", entry: strings.Repeat("x", 256)},
		{name: "256-byte UTF-8 component", entry: strings.Repeat("é", 128)},
		{name: "129 components", entry: strings.Repeat("a/", 128) + "a"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got, err := ParseZIPEntryPath(test.entry, test.directory, ZIPPathPortableExact); err == nil {
				t.Fatalf("ParseZIPEntryPath(%q) = %q; want rejection", test.entry, got)
			}
		})
	}
}

func TestZIPDecompressionLimitOwnsRatioFloorAndOverflow(t *testing.T) {
	tests := []struct {
		name       string
		compressed uint64
		want       int64
		wantOK     bool
	}{
		{name: "empty compressed body receives floor", compressed: 0, want: util.MiB, wantOK: true},
		{name: "small body receives floor", compressed: 1, want: util.MiB, wantOK: true},
		{name: "ratio exceeds floor", compressed: 2048, want: 2_048_000, wantOK: true},
		{
			name:       "multiplication saturates without overflow",
			compressed: uint64(math.MaxInt64/util.MaxDecompressRatio + 1),
			want:       math.MaxInt64,
			wantOK:     true,
		},
		{name: "compressed size outside int64 is rejected", compressed: math.MaxUint64},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := ZIPDecompressionLimit(test.compressed)
			if got != test.want || ok != test.wantOK {
				t.Fatalf(
					"ZIPDecompressionLimit(%d) = (%d, %v); want (%d, %v)",
					test.compressed,
					got,
					ok,
					test.want,
					test.wantOK,
				)
			}
		})
	}
}
