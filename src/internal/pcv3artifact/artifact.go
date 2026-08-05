// Package pcv3artifact implements the plaintext application-level container
// used for partial and explicitly consented unverified PCV3 recovery evidence.
// It is not an encrypted PCV3 volume and conveys no authentication authority.
package pcv3artifact

import (
	"Picocrypt-NG/internal/util"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"strconv"
)

const (
	artifactMajor       byte   = 1
	artifactSchema      byte   = 1
	headerLength        uint64 = 80
	rangeEntryLength    uint64 = 40
	recordPlaintextMax  uint64 = 1 << 20
	segmentBufferLength        = 32 << 10
)

const artifactDiscriminator = "PICO-RECOVERY-3\x00"

// State identifies the semantic Force result represented by an artifact.
type State uint8

const (
	StatePartial            State = 1
	StateUnverifiedForensic State = 2
)

// Role records the explicitly selected capsule role when unverified evidence
// is present. RoleNone is canonical for verified/missing partial evidence.
type Role uint8

const (
	RoleNone    Role = 0
	RolePrimary Role = 1
	RoleBackup  Role = 2
)

// FinalStatus records the separately authenticated final-record evidence.
type FinalStatus uint8

const (
	FinalVerified   FinalStatus = 1
	FinalUnverified FinalStatus = 2
	FinalMissing    FinalStatus = 3
)

// RangeStatus identifies the evidence carried for one canonical data record.
type RangeStatus uint8

const (
	RangeVerified   RangeStatus = 1
	RangeUnverified RangeStatus = 2
	RangeMissing    RangeStatus = 3
)

// Range is an allowlisted semantic data-record descriptor. Physical offsets
// are derived by Encode and cannot be supplied by callers.
type Range struct {
	RecordIndex uint64
	Start       uint64
	End         uint64
	Status      RangeStatus
}

// Descriptor is the complete semantic evidence map accepted by Encode.
type Descriptor struct {
	State           State
	Role            Role
	Final           FinalStatus
	PlaintextLength uint64
	Ranges          []Range
}

// Metadata is the fixed artifact header after canonical validation.
type Metadata struct {
	State               State
	Role                Role
	Final               FinalStatus
	HeaderLength        uint64
	RangeEntryLength    uint64
	PlaintextLength     uint64
	RangeCount          uint64
	EmittedSegmentCount uint64
	TableOffset         uint64
	DataOffset          uint64
	TotalLength         uint64
}

// Entry is one canonical range table entry after canonical validation.
type Entry struct {
	RecordIndex   uint64
	Start         uint64
	End           uint64
	SegmentOffset uint64
	SegmentLength uint32
	Status        RangeStatus
}

// SegmentSource synchronously supplies each non-missing segment exactly once
// in canonical range order. The supplied reader must contain exactly the
// corresponding range length and reach EOF immediately afterward.
type SegmentSource func(yield func(recordIndex uint64, segment io.Reader) error) error

type errorKind uint8

const (
	errorInvalidDescriptor errorKind = iota + 1
	errorInvalidArtifact
	errorArtifactRead
	errorArtifactWrite
	errorInvalidSegment
	errorRangeVisitor
)

type artifactError struct {
	kind  errorKind
	cause error
}

func newArtifactError(kind errorKind, cause error) error {
	return &artifactError{kind: kind, cause: cause}
}

func (err *artifactError) Error() string {
	if err == nil {
		return "pcv3 artifact: operation failed"
	}
	switch err.kind {
	case errorInvalidDescriptor:
		return "pcv3 artifact: invalid evidence descriptor"
	case errorInvalidArtifact:
		return "pcv3 artifact: invalid artifact"
	case errorArtifactRead:
		return "pcv3 artifact: read failed"
	case errorArtifactWrite:
		return "pcv3 artifact: write failed"
	case errorInvalidSegment:
		return "pcv3 artifact: invalid segment stream"
	case errorRangeVisitor:
		return "pcv3 artifact: range visitor failed"
	default:
		return "pcv3 artifact: operation failed"
	}
}

func (err *artifactError) String() string { return err.Error() }

func (err *artifactError) GoString() string { return err.Error() }

func (err *artifactError) Format(state fmt.State, verb rune) {
	value := err.Error()
	if verb == 'q' {
		value = strconv.Quote(value)
	}
	_, _ = io.WriteString(state, value)
}

func (err *artifactError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

// Artifact is a validated, borrowed view of a recovery artifact. Parse does
// not take ownership of or close the ReaderAt.
type Artifact struct {
	source   io.ReaderAt
	size     int64
	metadata Metadata
}

// Metadata returns the validated fixed header fields.
func (artifact *Artifact) Metadata() Metadata {
	if artifact == nil {
		return Metadata{}
	}
	return artifact.metadata
}

// Parse validates the complete fixed layout before exposing an Artifact.
// Reads are limited to the fixed 80-byte header and individual 40-byte entries;
// segment bytes are not read until VisitRanges is called.
func Parse(source io.ReaderAt, size int64) (*Artifact, error) {
	if source == nil || size < int64(headerLength) {
		return nil, newArtifactError(errorInvalidArtifact, nil)
	}
	metadata, err := validateArtifact(source, size)
	if err != nil {
		return nil, err
	}
	return &Artifact{source: source, size: size, metadata: metadata}, nil
}

// VisitRanges calls visitor once for each canonical data-record entry. Missing
// entries receive a nil segment reader. Non-missing readers are bounded to the
// exact validated segment and cannot reach adjacent artifact bytes.
func (artifact *Artifact) VisitRanges(visitor func(Entry, io.Reader) error) error {
	if artifact == nil || artifact.source == nil || visitor == nil {
		return newArtifactError(errorInvalidArtifact, nil)
	}
	metadata, err := validateArtifact(artifact.source, artifact.size)
	if err != nil {
		return err
	}
	if metadata != artifact.metadata {
		return newArtifactError(errorInvalidArtifact, nil)
	}

	nextSegmentOffset := metadata.DataOffset
	for recordIndex := range metadata.RangeCount {
		entry, parseErr := readAndValidateEntry(
			artifact.source,
			metadata,
			recordIndex,
			nextSegmentOffset,
		)
		if parseErr != nil {
			return parseErr
		}
		if entry.Status != RangeMissing {
			nextSegmentOffset, _ = checkedAdd64(entry.SegmentOffset, uint64(entry.SegmentLength))
		}

		var segment io.Reader
		if entry.Status != RangeMissing {
			segmentOffset, ok := util.SafeUint64ToInt64(entry.SegmentOffset)
			if !ok {
				return newArtifactError(errorInvalidArtifact, nil)
			}
			segment = io.NewSectionReader(
				artifact.source,
				segmentOffset,
				int64(entry.SegmentLength),
			)
		}
		if visitErr := visitor(entry, segment); visitErr != nil {
			return newArtifactError(errorRangeVisitor, visitErr)
		}
	}
	return nil
}

// Encode writes one canonical artifact. It validates the entire semantic map
// and derived physical layout before its first write, then consumes segment
// readers exactly once in canonical range order.
func Encode(destination io.Writer, descriptor Descriptor, source SegmentSource) error {
	if destination == nil {
		return newArtifactError(errorArtifactWrite, nil)
	}
	if descriptor.Ranges != nil {
		descriptor.Ranges = append([]Range(nil), descriptor.Ranges...)
	}
	metadata, err := validateDescriptor(descriptor)
	if err != nil {
		return err
	}

	header := encodeHeader(metadata)
	if writeErr := writeAll(destination, header[:]); writeErr != nil {
		return writeErr
	}

	nextSegmentOffset := metadata.DataOffset
	for _, evidenceRange := range descriptor.Ranges {
		entry := Entry{
			RecordIndex: evidenceRange.RecordIndex,
			Start:       evidenceRange.Start,
			End:         evidenceRange.End,
			Status:      evidenceRange.Status,
		}
		if evidenceRange.Status != RangeMissing {
			entry.SegmentOffset = nextSegmentOffset
			entry.SegmentLength = uint32(evidenceRange.End - evidenceRange.Start) //nolint:gosec // Canonical validation bounds every range to 1 MiB.
			nextSegmentOffset, _ = checkedAdd64(nextSegmentOffset, uint64(entry.SegmentLength))
		}
		encoded := encodeEntry(entry)
		if writeErr := writeAll(destination, encoded[:]); writeErr != nil {
			return writeErr
		}
	}

	nextRange := 0
	advanceMissingRanges := func() {
		for nextRange < len(descriptor.Ranges) && descriptor.Ranges[nextRange].Status == RangeMissing {
			nextRange++
		}
	}
	advanceMissingRanges()
	streamActive := true
	var streamFailure error
	yield := func(recordIndex uint64, segment io.Reader) error {
		if !streamActive || streamFailure != nil || nextRange >= len(descriptor.Ranges) || segment == nil {
			streamFailure = newArtifactError(errorInvalidSegment, nil)
			return streamFailure
		}
		evidenceRange := descriptor.Ranges[nextRange]
		if recordIndex != evidenceRange.RecordIndex {
			streamFailure = newArtifactError(errorInvalidSegment, nil)
			return streamFailure
		}
		if copyErr := copyExactSegment(destination, segment, evidenceRange.End-evidenceRange.Start); copyErr != nil {
			streamFailure = copyErr
			return streamFailure
		}
		nextRange++
		advanceMissingRanges()
		return nil
	}

	if source == nil {
		streamActive = false
		if nextRange != len(descriptor.Ranges) {
			return newArtifactError(errorInvalidSegment, nil)
		}
		return nil
	}
	sourceErr := source(yield)
	streamActive = false
	if streamFailure != nil {
		return streamFailure
	}
	if sourceErr != nil {
		return newArtifactError(errorInvalidSegment, sourceErr)
	}
	if nextRange != len(descriptor.Ranges) {
		return newArtifactError(errorInvalidSegment, nil)
	}
	return nil
}

func validateDescriptor(descriptor Descriptor) (Metadata, error) {
	rangeCount := canonicalRangeCount(descriptor.PlaintextLength)
	if uint64(len(descriptor.Ranges)) != rangeCount {
		return Metadata{}, newArtifactError(errorInvalidDescriptor, nil)
	}

	emittedCount := uint64(0)
	totalSegmentLength := uint64(0)
	hasVerified := descriptor.Final == FinalVerified
	hasUnverified := descriptor.Final == FinalUnverified
	hasDamage := descriptor.Final != FinalVerified
	if !validFinalStatus(descriptor.Final) {
		return Metadata{}, newArtifactError(errorInvalidDescriptor, nil)
	}
	for index, evidenceRange := range descriptor.Ranges {
		recordIndex := uint64(index)
		start, end, ok := canonicalBounds(recordIndex, descriptor.PlaintextLength)
		if !ok || evidenceRange.RecordIndex != recordIndex || evidenceRange.Start != start ||
			evidenceRange.End != end || !validRangeStatus(evidenceRange.Status) {
			return Metadata{}, newArtifactError(errorInvalidDescriptor, nil)
		}
		switch evidenceRange.Status {
		case RangeVerified:
			hasVerified = true
		case RangeUnverified:
			hasUnverified = true
			hasDamage = true
		case RangeMissing:
			hasDamage = true
			continue
		}
		emittedCount, ok = checkedAdd64(emittedCount, 1)
		if !ok {
			return Metadata{}, newArtifactError(errorInvalidDescriptor, nil)
		}
		totalSegmentLength, ok = checkedAdd64(totalSegmentLength, end-start)
		if !ok {
			return Metadata{}, newArtifactError(errorInvalidDescriptor, nil)
		}
	}
	if !validSemanticState(
		descriptor.State,
		descriptor.Role,
		hasVerified,
		hasUnverified,
		hasDamage,
	) {
		return Metadata{}, newArtifactError(errorInvalidDescriptor, nil)
	}

	tableLength, ok := checkedMul64(rangeCount, rangeEntryLength)
	if !ok {
		return Metadata{}, newArtifactError(errorInvalidDescriptor, nil)
	}
	dataOffset, ok := checkedAdd64(headerLength, tableLength)
	if !ok {
		return Metadata{}, newArtifactError(errorInvalidDescriptor, nil)
	}
	totalLength, ok := checkedAdd64(dataOffset, totalSegmentLength)
	if !ok || totalLength > math.MaxInt64 {
		return Metadata{}, newArtifactError(errorInvalidDescriptor, nil)
	}
	return Metadata{
		State:               descriptor.State,
		Role:                descriptor.Role,
		Final:               descriptor.Final,
		HeaderLength:        headerLength,
		RangeEntryLength:    rangeEntryLength,
		PlaintextLength:     descriptor.PlaintextLength,
		RangeCount:          rangeCount,
		EmittedSegmentCount: emittedCount,
		TableOffset:         headerLength,
		DataOffset:          dataOffset,
		TotalLength:         totalLength,
	}, nil
}

func validateArtifact(source io.ReaderAt, size int64) (Metadata, error) {
	var header [headerLength]byte
	if err := readFixedAt(source, header[:], 0); err != nil {
		return Metadata{}, err
	}
	metadata, err := decodeHeader(header, size)
	if err != nil {
		return Metadata{}, err
	}

	nextSegmentOffset := metadata.DataOffset
	emittedCount := uint64(0)
	hasVerified := metadata.Final == FinalVerified
	hasUnverified := metadata.Final == FinalUnverified
	hasDamage := metadata.Final != FinalVerified
	for recordIndex := range metadata.RangeCount {
		entry, entryErr := readAndValidateEntry(source, metadata, recordIndex, nextSegmentOffset)
		if entryErr != nil {
			return Metadata{}, entryErr
		}
		switch entry.Status {
		case RangeVerified:
			hasVerified = true
		case RangeUnverified:
			hasUnverified = true
			hasDamage = true
		case RangeMissing:
			hasDamage = true
			continue
		}
		emittedCount++
		nextSegmentOffset, _ = checkedAdd64(entry.SegmentOffset, uint64(entry.SegmentLength))
	}
	if emittedCount != metadata.EmittedSegmentCount || nextSegmentOffset != metadata.TotalLength ||
		!validSemanticState(metadata.State, metadata.Role, hasVerified, hasUnverified, hasDamage) {
		return Metadata{}, newArtifactError(errorInvalidArtifact, nil)
	}
	return metadata, nil
}

func decodeHeader(header [headerLength]byte, size int64) (Metadata, error) {
	if string(header[0:16]) != artifactDiscriminator ||
		header[16] != artifactMajor || header[17] != artifactSchema || header[21] != 0 ||
		header[22] != 0 || header[23] != 0 {
		return Metadata{}, newArtifactError(errorInvalidArtifact, nil)
	}
	metadata := Metadata{
		State:               State(header[18]),
		Role:                Role(header[19]),
		Final:               FinalStatus(header[20]),
		HeaderLength:        uint64(binary.BigEndian.Uint32(header[24:28])),
		RangeEntryLength:    uint64(binary.BigEndian.Uint32(header[28:32])),
		PlaintextLength:     binary.BigEndian.Uint64(header[32:40]),
		RangeCount:          binary.BigEndian.Uint64(header[40:48]),
		EmittedSegmentCount: binary.BigEndian.Uint64(header[48:56]),
		TableOffset:         binary.BigEndian.Uint64(header[56:64]),
		DataOffset:          binary.BigEndian.Uint64(header[64:72]),
		TotalLength:         binary.BigEndian.Uint64(header[72:80]),
	}
	if metadata.HeaderLength != headerLength || metadata.RangeEntryLength != rangeEntryLength ||
		metadata.TableOffset != headerLength || metadata.RangeCount != canonicalRangeCount(metadata.PlaintextLength) ||
		metadata.EmittedSegmentCount > metadata.RangeCount || !validState(metadata.State) ||
		!validRole(metadata.Role) || !validFinalStatus(metadata.Final) {
		return Metadata{}, newArtifactError(errorInvalidArtifact, nil)
	}
	tableLength, ok := checkedMul64(metadata.RangeCount, rangeEntryLength)
	if !ok {
		return Metadata{}, newArtifactError(errorInvalidArtifact, nil)
	}
	dataOffset, ok := checkedAdd64(headerLength, tableLength)
	if !ok {
		return Metadata{}, newArtifactError(errorInvalidArtifact, nil)
	}
	totalLength, ok := util.SafeUint64ToInt64(metadata.TotalLength)
	if !ok || metadata.DataOffset != dataOffset || metadata.TotalLength < dataOffset ||
		totalLength != size {
		return Metadata{}, newArtifactError(errorInvalidArtifact, nil)
	}
	return metadata, nil
}

func readAndValidateEntry(
	source io.ReaderAt,
	metadata Metadata,
	recordIndex uint64,
	nextSegmentOffset uint64,
) (Entry, error) {
	entryRelativeOffset, ok := checkedMul64(recordIndex, rangeEntryLength)
	if !ok {
		return Entry{}, newArtifactError(errorInvalidArtifact, nil)
	}
	entryOffset, ok := checkedAdd64(metadata.TableOffset, entryRelativeOffset)
	if !ok || entryOffset > metadata.DataOffset || metadata.DataOffset-entryOffset < rangeEntryLength {
		return Entry{}, newArtifactError(errorInvalidArtifact, nil)
	}
	var encoded [rangeEntryLength]byte
	if err := readFixedAt(source, encoded[:], entryOffset); err != nil {
		return Entry{}, err
	}
	entry := Entry{
		RecordIndex:   binary.BigEndian.Uint64(encoded[0:8]),
		Start:         binary.BigEndian.Uint64(encoded[8:16]),
		End:           binary.BigEndian.Uint64(encoded[16:24]),
		SegmentOffset: binary.BigEndian.Uint64(encoded[24:32]),
		SegmentLength: binary.BigEndian.Uint32(encoded[32:36]),
		Status:        RangeStatus(encoded[36]),
	}
	start, end, ok := canonicalBounds(recordIndex, metadata.PlaintextLength)
	if !ok || entry.RecordIndex != recordIndex || entry.Start != start || entry.End != end ||
		!validRangeStatus(entry.Status) || encoded[37] != 0 || encoded[38] != 0 || encoded[39] != 0 {
		return Entry{}, newArtifactError(errorInvalidArtifact, nil)
	}
	if entry.Status == RangeMissing {
		if entry.SegmentOffset != 0 || entry.SegmentLength != 0 {
			return Entry{}, newArtifactError(errorInvalidArtifact, nil)
		}
		return entry, nil
	}
	length := end - start
	segmentEnd, ok := checkedAdd64(entry.SegmentOffset, uint64(entry.SegmentLength))
	if !ok || length > math.MaxUint32 || uint64(entry.SegmentLength) != length ||
		entry.SegmentOffset != nextSegmentOffset || segmentEnd > metadata.TotalLength {
		return Entry{}, newArtifactError(errorInvalidArtifact, nil)
	}
	return entry, nil
}

func encodeHeader(metadata Metadata) [headerLength]byte {
	var header [headerLength]byte
	copy(header[0:16], artifactDiscriminator)
	header[16] = artifactMajor
	header[17] = artifactSchema
	header[18] = byte(metadata.State)
	header[19] = byte(metadata.Role)
	header[20] = byte(metadata.Final)
	binary.BigEndian.PutUint32(header[24:28], uint32(headerLength))
	binary.BigEndian.PutUint32(header[28:32], uint32(rangeEntryLength))
	binary.BigEndian.PutUint64(header[32:40], metadata.PlaintextLength)
	binary.BigEndian.PutUint64(header[40:48], metadata.RangeCount)
	binary.BigEndian.PutUint64(header[48:56], metadata.EmittedSegmentCount)
	binary.BigEndian.PutUint64(header[56:64], metadata.TableOffset)
	binary.BigEndian.PutUint64(header[64:72], metadata.DataOffset)
	binary.BigEndian.PutUint64(header[72:80], metadata.TotalLength)
	return header
}

func encodeEntry(entry Entry) [rangeEntryLength]byte {
	var encoded [rangeEntryLength]byte
	binary.BigEndian.PutUint64(encoded[0:8], entry.RecordIndex)
	binary.BigEndian.PutUint64(encoded[8:16], entry.Start)
	binary.BigEndian.PutUint64(encoded[16:24], entry.End)
	binary.BigEndian.PutUint64(encoded[24:32], entry.SegmentOffset)
	binary.BigEndian.PutUint32(encoded[32:36], entry.SegmentLength)
	encoded[36] = byte(entry.Status)
	return encoded
}

func readFixedAt(source io.ReaderAt, destination []byte, offset uint64) error {
	if offset > math.MaxInt64 || uint64(len(destination)) > math.MaxInt64-offset {
		return newArtifactError(errorInvalidArtifact, nil)
	}
	read, err := source.ReadAt(destination, int64(offset))
	if read != len(destination) {
		return newArtifactError(errorArtifactRead, err)
	}
	return nil
}

func writeAll(destination io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := destination.Write(data)
		if written < 0 || written > len(data) {
			return newArtifactError(errorArtifactWrite, nil)
		}
		data = data[written:]
		if err != nil {
			return newArtifactError(errorArtifactWrite, err)
		}
		if written == 0 {
			return newArtifactError(errorArtifactWrite, io.ErrNoProgress)
		}
	}
	return nil
}

func copyExactSegment(destination io.Writer, source io.Reader, length uint64) error {
	remaining := length
	buffer := make([]byte, segmentBufferLength)
	for remaining > 0 {
		readLength := uint64(len(buffer))
		if remaining < readLength {
			readLength = remaining
		}
		readBuffer := buffer
		if readLength < uint64(len(buffer)) {
			readBuffer = buffer[:readLength]
		}
		read, err := source.Read(readBuffer)
		if read < 0 || uint64(read) > readLength {
			return newArtifactError(errorInvalidSegment, nil)
		}
		if read > 0 {
			if writeErr := writeAll(destination, buffer[:read]); writeErr != nil {
				return writeErr
			}
			remaining -= uint64(read)
		}
		if err != nil {
			if errors.Is(err, io.EOF) && remaining == 0 {
				return nil
			}
			return newArtifactError(errorInvalidSegment, err)
		}
		if read == 0 {
			return newArtifactError(errorInvalidSegment, io.ErrNoProgress)
		}
	}

	var extra [1]byte
	read, err := source.Read(extra[:])
	if read != 0 || (err != nil && !errors.Is(err, io.EOF)) || err == nil {
		return newArtifactError(errorInvalidSegment, err)
	}
	return nil
}

func canonicalRangeCount(plaintextLength uint64) uint64 {
	if plaintextLength == 0 {
		return 0
	}
	return (plaintextLength-1)/recordPlaintextMax + 1
}

func canonicalBounds(recordIndex, plaintextLength uint64) (uint64, uint64, bool) {
	start, ok := checkedMul64(recordIndex, recordPlaintextMax)
	if !ok || start >= plaintextLength {
		return 0, 0, false
	}
	remaining := plaintextLength - start
	if remaining > recordPlaintextMax {
		remaining = recordPlaintextMax
	}
	return start, start + remaining, true
}

func validSemanticState(
	state State,
	role Role,
	hasVerified bool,
	hasUnverified bool,
	hasDamage bool,
) bool {
	switch state {
	case StatePartial:
		if !hasVerified || !hasDamage {
			return false
		}
		if hasUnverified {
			return role == RolePrimary || role == RoleBackup
		}
		return role == RoleNone
	case StateUnverifiedForensic:
		return !hasVerified && hasUnverified && (role == RolePrimary || role == RoleBackup)
	default:
		return false
	}
}

func validState(state State) bool {
	return state == StatePartial || state == StateUnverifiedForensic
}

func validRole(role Role) bool {
	return role == RoleNone || role == RolePrimary || role == RoleBackup
}

func validFinalStatus(status FinalStatus) bool {
	return status == FinalVerified || status == FinalUnverified || status == FinalMissing
}

func validRangeStatus(status RangeStatus) bool {
	return status == RangeVerified || status == RangeUnverified || status == RangeMissing
}

func checkedAdd64(left, right uint64) (uint64, bool) {
	sum, carry := bits.Add64(left, right, 0)
	return sum, carry == 0
}

func checkedMul64(left, right uint64) (uint64, bool) {
	high, low := bits.Mul64(left, right)
	return low, high == 0
}
