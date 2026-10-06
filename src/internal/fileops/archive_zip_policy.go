package fileops

import (
	"Picocrypt-NG/internal/util"
	"archive/zip"
	"cmp"
	"errors"
	"math"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	portableZIPPathMaxBytes      = 4096
	portableZIPComponentMaxBytes = 255
	portableZIPPathMaxDepth      = 128
)

var errUnsafeZIPEntryPath = errors.New("fileops: unsafe ZIP entry path")

// ZIPSummary describes declared archive contents before extraction. An approved
// summary bounds the total plaintext that extraction may write.
type ZIPSummary struct {
	Files         int
	Directories   int
	UnpackedBytes int64
}

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

// ValidateZIPPayloadRanges rejects reuse of compressed payload bytes across
// entries. It reads local-header offsets without decompressing entry contents
// or changing their order. Empty payloads do not overlap other ranges.
func ValidateZIPPayloadRanges(files []*zip.File, opts ZIPReadOptions) error {
	budget := opts.Budget
	if budget == nil {
		budget = NewZIPResourceBudget()
	}
	charge, ok := zipResourceMultiply(uint64(len(files)), 16)
	if !ok {
		return ErrZIPMetadataLimit
	}
	if err := budget.Reserve(charge); err != nil {
		return err
	}
	defer budget.Release(charge)
	type payloadRange struct {
		start int64
		end   int64
	}
	ranges := make([]payloadRange, 0, len(files))
	for _, file := range files {
		if opts.Cancel != nil && opts.Cancel() {
			return errZIPCancelled
		}
		if file == nil {
			return errors.New("fileops: invalid ZIP payload range")
		}
		start, err := file.DataOffset()
		if err != nil || start < 0 {
			return errors.Join(errors.New("fileops: invalid ZIP payload offset"), err)
		}
		size, ok := util.SafeUint64ToInt64(file.CompressedSize64)
		if !ok || size > math.MaxInt64-start {
			return errors.New("fileops: ZIP payload range exceeds int64 max")
		}
		if size != 0 {
			ranges = append(ranges, payloadRange{start: start, end: start + size})
		}
	}
	slices.SortFunc(ranges, func(left, right payloadRange) int {
		return cmp.Compare(left.start, right.start)
	})
	if opts.Cancel != nil && opts.Cancel() {
		return errZIPCancelled
	}
	for index := 1; index < len(ranges); index++ {
		if ranges[index].start < ranges[index-1].end {
			return errors.New("fileops: overlapping ZIP payload ranges")
		}
	}
	return nil
}

// ZIPDecompressionLimit is the default expansion policy for extraction without
// an approved ZIPSummary. The boolean is false when compressed size exceeds int64.
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
