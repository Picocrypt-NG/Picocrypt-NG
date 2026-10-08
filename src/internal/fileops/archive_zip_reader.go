package fileops

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

const (
	zipMetadataPageBytes = 64 << 10
	zipDirectoryHeader   = 0x02014b50
	zipDirectoryEnd      = 0x06054b50
	zip64DirectoryEnd    = 0x06064b50
	zip64Locator         = 0x07064b50
)

// ErrZIPMetadataLimit means the archive exceeds the bounded metadata budget.
// Approval of an unpacked-byte budget does not bypass this resource limit.
var ErrZIPMetadataLimit = errors.New("fileops: ZIP metadata limit exceeded")

var errZIPCancelled = errors.New("operation cancelled")

type zipMetadataRegion struct {
	offset int64
	data   []byte
	pages  [][]byte
	length int64
}

type zipMetadataReader struct {
	source  io.ReaderAt
	cancel  CancelFunc
	regions []zipMetadataRegion
	budget  *ZIPResourceBudget
	charged uint64
}

func (reader *zipMetadataReader) ReadAt(data []byte, offset int64) (int, error) {
	if reader.cancel != nil && reader.cancel() {
		return 0, errZIPCancelled
	}
	n := 0
	for len(data) > 0 {
		limit := len(data)
		cached := false
		for _, region := range reader.regions {
			if offset >= region.offset && offset-region.offset < region.length {
				rel := offset - region.offset
				cachedData := region.data
				if cachedData == nil {
					cachedData = region.pages[rel/zipMetadataPageBytes]
					rel %= zipMetadataPageBytes
				}
				count := copy(data, cachedData[rel:min(int64(len(cachedData)), rel+region.length-(offset-region.offset))])
				n += count
				offset += int64(count)
				data = data[count:]
				cached = true
				break
			}
			if region.offset > offset && region.offset-offset < int64(limit) {
				limit = int(region.offset - offset)
			}
		}
		if cached {
			continue
		}
		count, err := reader.source.ReadAt(data[:limit], offset)
		n += count
		if err != nil {
			return n, err
		}
		if count != limit {
			return n, io.ErrUnexpectedEOF
		}
		offset += int64(count)
		data = data[count:]
	}
	return n, nil
}

// OpenZIPReader admits metadata before archive/zip eagerly allocates entries.
// It bounds both declared ZIP/ZIP64 counts and actual central-directory records,
// since archive/zip accepts classic counts modulo 65536 and scans beyond the
// declared directory size. Metadata is frozen until parsing finishes so a file
// changed between the two passes cannot bypass admission. Payloads stay on the
// original reader; this is not a content-authentication or immutable-file API.
func OpenZIPReader(source io.ReaderAt, size int64, opts ZIPReadOptions) (*ZIPReader, error) {
	if source == nil || size < 22 {
		return nil, zip.ErrFormat
	}
	budget := opts.Budget
	if budget == nil {
		budget = NewZIPResourceBudget()
	}
	reader := &zipMetadataReader{source: source, cancel: opts.Cancel, budget: budget}
	// Covers bounded parser workspace, ledger/page slice growth and GC
	// overlap beyond input-dependent charges. It is not an RSS guarantee.
	if err := reader.reserve(8 << 20); err != nil {
		return nil, err
	}
	keepCharge := false
	defer func() {
		if !keepCharge {
			budget.Release(reader.charged)
		}
		reader.regions = nil
	}()
	if err := reader.preflight(size); err != nil {
		return nil, err
	}
	archive, err := zip.NewReader(reader, size)
	if err != nil {
		return nil, err
	}
	if opts.Cancel != nil && opts.Cancel() {
		return nil, errZIPCancelled
	}
	retained, err := zipReaderRetainedBytes(archive)
	if err != nil || retained > reader.charged {
		return nil, ErrZIPMetadataLimit
	}
	// Go 1.27 keeps Extra as a subslice of its name+extra+comment buffer,
	// including a zero-length Extra. Detaching preserves all metadata while
	// allowing that large backing allocation to die. Preflight charges this copy.
	for _, file := range archive.File {
		if opts.Cancel != nil && opts.Cancel() {
			return nil, errZIPCancelled
		}
		file.Extra = bytes.Clone(file.Extra)
	}
	reader.regions = nil
	budget.Release(reader.charged - retained)
	reader.charged = retained
	keepCharge = true
	return &ZIPReader{Reader: archive, budget: budget, charged: retained}, nil
}

func (reader *zipMetadataReader) reserve(bytes uint64) error {
	if err := reader.budget.Reserve(bytes); err != nil {
		return err
	}
	reader.charged += bytes
	return nil
}

func (reader *zipMetadataReader) preflight(size int64) error {
	// Match archive/zip's bounded backwards search, including ZIP comments.
	tailSize := min(size, 65*1024)
	if err := reader.reserve(uint64(tailSize)); err != nil {
		return err
	}
	tail := make([]byte, int(tailSize))
	if _, err := reader.ReadAt(tail, size-tailSize); err != nil {
		return err
	}
	reader.regions = append(reader.regions, zipMetadataRegion{offset: size - tailSize, data: tail, length: tailSize})
	position := -1
	for i := len(tail) - 22; i >= 0; i-- {
		if binary.LittleEndian.Uint32(tail[i:]) == zipDirectoryEnd {
			if i+22+int(binary.LittleEndian.Uint16(tail[i+20:])) <= len(tail) {
				position = i
			}
			break
		}
	}
	if position < 0 {
		return zip.ErrFormat
	}
	end := tail[position:]
	endOffset := size - tailSize + int64(position)
	count := uint64(binary.LittleEndian.Uint16(end[10:]))
	directorySize := uint64(binary.LittleEndian.Uint32(end[12:]))
	directoryOffset := uint64(binary.LittleEndian.Uint32(end[16:]))
	if count == 0xffff || directorySize == 0xffffffff || directoryOffset == 0xffffffff {
		if endOffset >= 20 {
			var locator [20]byte
			if _, err := reader.ReadAt(locator[:], endOffset-20); err != nil {
				return err
			}
			if binary.LittleEndian.Uint32(locator[:]) == zip64Locator &&
				binary.LittleEndian.Uint32(locator[4:]) == 0 &&
				binary.LittleEndian.Uint32(locator[16:]) == 1 {
				offset := binary.LittleEndian.Uint64(locator[8:])
				if size < 56 || offset > uint64(size-56) {
					return zip.ErrFormat
				}
				if err := reader.reserve(56); err != nil {
					return err
				}
				data := make([]byte, 56)
				if _, err := reader.ReadAt(data, int64(offset)); err != nil {
					return err
				}
				if binary.LittleEndian.Uint32(data) != zip64DirectoryEnd {
					return zip.ErrFormat
				}
				reader.regions = append(reader.regions, zipMetadataRegion{offset: int64(offset), data: data, length: 56})
				endOffset = int64(offset)
				count = binary.LittleEndian.Uint64(data[32:])
				directorySize = binary.LittleEndian.Uint64(data[40:])
				directoryOffset = binary.LittleEndian.Uint64(data[48:])
			}
		}
	}
	// archive/zip can preallocate by declared count even when actual records
	// are fewer. Reject hostile declarations before calling that eager parser.
	declaredCharge, ok := zipResourceMultiply(count, 512)
	if !ok {
		return ErrZIPMetadataLimit
	}
	if err := reader.reserve(declaredCharge); err != nil {
		return err
	}
	if directoryOffset > uint64(size) || directorySize > uint64(endOffset) {
		return zip.ErrFormat
	}
	start := endOffset - int64(directorySize)
	if err := reader.snapshotDirectory(start, size); err != nil {
		return err
	}
	// archive/zip also accepts archives with a prepended executable or an
	// inaccurate base offset, preferring a valid header at the raw offset.
	// Admit both possible parsing locations before allowing that choice.
	if start > int64(directoryOffset) {
		if err := reader.snapshotDirectory(int64(directoryOffset), size); err != nil {
			return err
		}
	}
	return nil
}

func (reader *zipMetadataReader) snapshotDirectory(start, size int64) error {
	if start < 0 || start > size {
		return zip.ErrFormat
	}
	region := zipMetadataRegion{offset: start}
	// Every page has a fixed charged capacity. Lookup in ReadAt indexes pages
	// directly; catalog size never turns lookup into a scan over all pages.
	appendBytes := func(data []byte) error {
		for len(data) != 0 {
			index := int(region.length / zipMetadataPageBytes)
			used := int(region.length % zipMetadataPageBytes)
			if used == 0 {
				if err := reader.reserve(zipMetadataPageBytes + 96); err != nil {
					return err
				}
				region.pages = append(region.pages, make([]byte, zipMetadataPageBytes))
			}
			n := copy(region.pages[index][used:], data)
			region.length += int64(n)
			data = data[n:]
		}
		return nil
	}
	offset := start
	var scratch [zipMetadataPageBytes]byte
	for {
		var header [46]byte
		n, err := reader.ReadAt(header[:min(int64(len(header)), size-offset)], offset)
		if err != nil {
			return err
		}
		if n < len(header) || binary.LittleEndian.Uint32(header[:]) != zipDirectoryHeader {
			if err := appendBytes(header[:n]); err != nil {
				return err
			}
			break
		}
		variable := uint64(binary.LittleEndian.Uint16(header[28:])) +
			uint64(binary.LittleEndian.Uint16(header[30:])) + uint64(binary.LittleEndian.Uint16(header[32:]))
		if int64(46+variable) > size-offset {
			return zip.ErrFormat
		}
		// Conservative measured reader object/strings/transient-Extra allowance.
		// Both candidate catalogs are charged, even when archive/zip selects one.
		if err := reader.reserve(512 + 3*variable); err != nil {
			return err
		}
		if err := appendBytes(header[:]); err != nil {
			return err
		}
		offset += 46
		for left := int64(variable); left > 0; {
			n := min(left, int64(len(scratch)))
			if _, err := reader.ReadAt(scratch[:n], offset); err != nil {
				return err
			}
			if err := appendBytes(scratch[:n]); err != nil {
				return err
			}
			offset += n
			left -= n
		}
	}
	reader.regions = append(reader.regions, region)
	return nil
}
