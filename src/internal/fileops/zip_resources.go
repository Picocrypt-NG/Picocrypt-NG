package fileops

import (
	"archive/zip"
	"errors"
	"io"
	"math"
	"runtime"
	"strconv"
	"sync"
)

// Cleanup must attempt every owned object even during an error flood, while
// retaining only a bounded diagnostic sample. Publication truth is tracked
// separately, so omitted diagnostics cannot turn uncertainty into success.
type zipCleanupErrors struct {
	entries [16]error
	count   int
	omitted bool
}

func (errs *zipCleanupErrors) add(err error) {
	if err == nil {
		return
	}
	if errs.count == len(errs.entries) {
		errs.omitted = true
		return
	}
	errs.entries[errs.count] = err
	errs.count++
}

func (errs *zipCleanupErrors) err() error {
	err := errors.Join(errs.entries[:errs.count]...)
	if errs.omitted {
		err = errors.Join(err, errors.New("fileops: additional cleanup errors omitted"))
	}
	return err
}

// ZIPReadOptions shares cancellation and one operation-local working budget.
// A nil Budget selects the trusted native platform policy.
type ZIPReadOptions struct {
	Cancel CancelFunc
	Budget *ZIPResourceBudget
}

// ZIPResourceBudget accounts simultaneously retained archive working memory.
// It is a conservative admission model, not a process RSS limit. Archive
// metadata and review callbacks cannot enlarge the trusted platform policy.
type ZIPResourceBudget struct {
	mu                   sync.Mutex
	limit, current, peak uint64
}

func NewZIPResourceBudget() *ZIPResourceBudget {
	limit := uint64(256 << 20)
	if runtime.GOOS == "android" {
		limit = 192 << 20
	}
	if strconv.IntSize == 32 {
		limit = 64 << 20
	}
	return &ZIPResourceBudget{limit: limit}
}

func (budget *ZIPResourceBudget) Reserve(bytes uint64) error {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if bytes > budget.limit-budget.current {
		return ErrZIPMetadataLimit
	}
	budget.current += bytes
	budget.peak = max(budget.peak, budget.current)
	return nil
}

// Release refuses an invalid retirement without reducing the live charge.
func (budget *ZIPResourceBudget) Release(bytes uint64) bool {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if bytes > budget.current {
		return false
	}
	budget.current -= bytes
	return true
}

func (budget *ZIPResourceBudget) CurrentBytes() uint64 {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	return budget.current
}

func (budget *ZIPResourceBudget) PeakBytes() uint64 {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	return budget.peak
}
func (budget *ZIPResourceBudget) LimitBytes() uint64 { return budget.limit }

func zipResourceMultiply(left, right uint64) (uint64, bool) {
	if left != 0 && right > math.MaxUint64/left {
		return 0, false
	}
	return left * right, true
}

func zipResourceAdd(left, right uint64) (uint64, bool) {
	if right > math.MaxUint64-left {
		return 0, false
	}
	return left + right, true
}

// ZIPReader owns the reader metadata charge, while borrowing its ReaderAt.
// Drop all entry views before Close; Close never closes the original source.
type ZIPReader struct {
	*zip.Reader
	budget  *ZIPResourceBudget
	charged uint64
}

func (reader *ZIPReader) Budget() *ZIPResourceBudget { return reader.budget }

func (reader *ZIPReader) Close() error {
	if reader == nil || reader.Reader == nil {
		return nil
	}
	reader.Reader = nil
	if !reader.budget.Release(reader.charged) {
		return ErrZIPMetadataLimit
	}
	reader.charged = 0
	return nil
}

func zipReaderRetainedBytes(reader *zip.Reader) (uint64, error) {
	// The 1.27.1 probe measures 216 bytes/short entry retained; 512 accounts
	// slice/object allocation classes and growth. 2*variable covers detached
	// metadata strings/Extra and allocator rounding, plus fixed runtime reserve.
	charge := uint64(2 << 20)
	// archive/zip can preallocate from a larger declared ZIP64 count while
	// accepting the actual count modulo 65536. Those unused pointer slots
	// remain live after parsing and must not be retired with the snapshot.
	sparePointers, ok := zipResourceMultiply(uint64(cap(reader.File)-len(reader.File)), uint64(strconv.IntSize/8))
	if !ok {
		return 0, ErrZIPMetadataLimit
	}
	charge, ok = zipResourceAdd(charge, sparePointers)
	if !ok {
		return 0, ErrZIPMetadataLimit
	}
	for _, file := range reader.File {
		variable := uint64(len(file.Name)) + uint64(len(file.Extra)) + uint64(len(file.Comment))
		cost, ok := zipResourceMultiply(variable, 2)
		if !ok {
			return 0, ErrZIPMetadataLimit
		}
		cost, ok = zipResourceAdd(cost, 512)
		if !ok {
			return 0, ErrZIPMetadataLimit
		}
		charge, ok = zipResourceAdd(charge, cost)
		if !ok {
			return 0, ErrZIPMetadataLimit
		}
	}
	return charge, nil
}

func zipUnpackWorkingBytes(reader *zip.Reader, rootBytes int) (uint64, error) {
	charge := uint64(8 << 20)
	add := func(base, pathBytes uint64) error {
		pathCharge, ok := zipResourceMultiply(pathBytes, 4)
		if !ok {
			return ErrZIPMetadataLimit
		}
		cost, ok := zipResourceAdd(base, pathCharge)
		if !ok {
			return ErrZIPMetadataLimit
		}
		charge, ok = zipResourceAdd(charge, cost)
		if !ok {
			return ErrZIPMetadataLimit
		}
		return nil
	}
	for _, entry := range reader.File {
		// Count input path prefixes without allocating normalization/split
		// copies. Cleaning cannot increase their length. Root-qualified copies,
		// capacity growth, FileInfo identity and durability indexes are included.
		if err := add(1024, uint64(len(entry.Name))+uint64(rootBytes)); err != nil {
			return 0, err
		}
		for index, character := range entry.Name {
			if character == '/' || character == '\\' {
				if err := add(768, uint64(index)+uint64(rootBytes)); err != nil {
					return 0, err
				}
			}
		}
		if entry.FileInfo().IsDir() && len(entry.Name) > 0 && entry.Name[len(entry.Name)-1] != '/' && entry.Name[len(entry.Name)-1] != '\\' {
			if err := add(768, uint64(len(entry.Name))+uint64(rootBytes)); err != nil {
				return 0, err
			}
		}
	}
	return charge, nil
}

func zipWriterWorkingBytes(opts ZipOptions) (uint64, error) {
	// Includes one reusable plaintext buffer, compressor/temporary-owner
	// workspace and allocator overlap. The historical stdlib writer probe
	// retained about 194 bytes/short header; 512 includes header/slice growth.
	charge := uint64(10 << 20)
	add := func(cost uint64) error {
		next, ok := zipResourceAdd(charge, cost)
		if !ok {
			return ErrZIPMetadataLimit
		}
		charge = next
		return nil
	}
	for _, path := range opts.Files {
		nameBytes := uint64(len(path)) + uint64(len(opts.RootDir))
		if override, ok := opts.EntryNames[path]; ok {
			nameBytes = uint64(len(override))
		}
		headerBytes, ok := zipResourceMultiply(nameBytes, 3)
		if !ok {
			return 0, ErrZIPMetadataLimit
		}
		selectionBytes, ok := zipResourceMultiply(uint64(len(path)), 2)
		if !ok {
			return 0, ErrZIPMetadataLimit
		}
		cost, ok := zipResourceAdd(576, headerBytes)
		if !ok {
			return 0, ErrZIPMetadataLimit
		}
		cost, ok = zipResourceAdd(cost, selectionBytes)
		if !ok {
			return 0, ErrZIPMetadataLimit
		}
		if err := add(cost); err != nil {
			return 0, err
		}
	}
	for path, name := range opts.EntryNames {
		bytes, ok := zipResourceAdd(uint64(len(path)), uint64(len(name)))
		if !ok {
			return 0, ErrZIPMetadataLimit
		}
		bytes, ok = zipResourceMultiply(bytes, 2)
		if !ok {
			return 0, ErrZIPMetadataLimit
		}
		bytes, ok = zipResourceAdd(bytes, 128)
		if !ok {
			return 0, ErrZIPMetadataLimit
		}
		if err := add(bytes); err != nil {
			return 0, err
		}
	}
	// These caller-owned collections are counted while held here. Their
	// creation must separately reserve before allocation in frontend discovery.
	return charge, nil
}

type zipCancelWriter struct {
	io.Writer
	cancel CancelFunc
}

func (writer *zipCancelWriter) Write(data []byte) (int, error) {
	if writer.cancel != nil && writer.cancel() {
		return 0, errZIPCancelled
	}
	return writer.Writer.Write(data)
}
