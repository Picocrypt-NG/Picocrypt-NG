package fileops

import (
	"Picocrypt-NG/internal/util"
	"errors"
	"math"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	portableZIPPathMaxBytes      = 4096
	portableZIPComponentMaxBytes = 255
	portableZIPPathMaxDepth      = 128
)

var errUnsafeZIPEntryPath = errors.New("fileops: unsafe ZIP entry path")

// ZIPPathPolicy selects one closed path interpretation. Extraction-compatible
// preserves the existing local extractor contract. Portable-exact is the
// platform-independent contract used when archive components are handed to a
// provider rather than converted into OS paths.
type ZIPPathPolicy uint8

const (
	ZIPPathExtractionCompatible ZIPPathPolicy = iota + 1
	ZIPPathPortableExact
)

// ParseZIPEntryPath returns a slash-separated entry path under one closed
// policy. Portable-exact directory paths lose their single trailing slash so
// callers have one canonical component sequence.
func ParseZIPEntryPath(name string, isDir bool, policy ZIPPathPolicy) (string, error) {
	switch policy {
	case ZIPPathExtractionCompatible:
		if hasUnsafeWindowsTrimTraversalComponent(name) {
			return "", errUnsafeZIPEntryPath
		}
		return filepath.ToSlash(normalizeZipPath(name)), nil
	case ZIPPathPortableExact:
		return parsePortableExactZIPEntryPath(name, isDir)
	default:
		return "", errUnsafeZIPEntryPath
	}
}

func parsePortableExactZIPEntryPath(name string, isDir bool) (string, error) {
	if name == "" || !utf8.ValidString(name) || strings.IndexByte(name, 0) >= 0 ||
		strings.Contains(name, `\`) {
		return "", errUnsafeZIPEntryPath
	}

	canonical := name
	if strings.HasSuffix(canonical, "/") {
		if !isDir {
			return "", errUnsafeZIPEntryPath
		}
		canonical = strings.TrimSuffix(canonical, "/")
	}
	if canonical == "" || strings.HasPrefix(canonical, "/") ||
		isWindowsDrivePath(canonical) || len(canonical) > portableZIPPathMaxBytes {
		return "", errUnsafeZIPEntryPath
	}

	components := strings.Split(canonical, "/")
	if len(components) > portableZIPPathMaxDepth {
		return "", errUnsafeZIPEntryPath
	}
	for _, component := range components {
		if component == "" || component == "." || component == ".." ||
			len(component) > portableZIPComponentMaxBytes {
			return "", errUnsafeZIPEntryPath
		}
	}
	return canonical, nil
}

func isWindowsDrivePath(path string) bool {
	if len(path) < 2 || path[1] != ':' {
		return false
	}
	first := path[0]
	return first >= 'A' && first <= 'Z' || first >= 'a' && first <= 'z'
}

// ZIPDecompressionLimit is the sole overflow-safe ZIP expansion policy. The
// boolean is false when the compressed size cannot be represented as int64.
func ZIPDecompressionLimit(compressedSize uint64) (int64, bool) {
	compressed, ok := util.SafeUint64ToInt64(compressedSize)
	if !ok {
		return 0, false
	}
	var limit int64
	if compressed > math.MaxInt64/util.MaxDecompressRatio {
		limit = math.MaxInt64
	} else {
		limit = compressed * util.MaxDecompressRatio
	}
	if limit < util.MiB {
		limit = util.MiB
	}
	return limit, true
}
