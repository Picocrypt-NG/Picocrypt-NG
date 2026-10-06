// Package pcv3artifact implements the plaintext application-level container
// used for partial and explicitly consented unverified PCV3 recovery evidence.
// It is not an encrypted PCV3 volume and conveys no authentication authority.
package pcv3artifact

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3ranges"
	"Picocrypt-NG/internal/util"
	"context"
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

// Role records the explicitly selected physical recovery role when unverified
// evidence is present. RoleNone is canonical for verified/missing evidence.
type Role uint8

const (
	RoleNone    Role = 0
	RolePrimary Role = 1
	RoleBackup  Role = 2
	RoleD1Front Role = 3
	RoleD1Tail  Role = 4
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
	Ranges          *pcv3ranges.Map
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
func Parse(ctx context.Context, source io.ReaderAt, size int64) (*Artifact, error) {
	if source == nil || size < int64(headerLength) {
		return nil, newArtifactError(errorInvalidArtifact, nil)
	}
	metadata, err := validateArtifact(ctx, source, size)
	if err != nil {
		return nil, err
	}
	return &Artifact{source: source, size: size, metadata: metadata}, nil
}

// VisitRanges calls visitor once for each canonical data-record entry. Missing
// entries receive a nil segment reader. Non-missing readers are bounded to the
// exact validated segment and cannot reach adjacent artifact bytes.
func (artifact *Artifact) VisitRanges(ctx context.Context, visitor func(Entry, io.Reader) error) error {
	if artifact == nil || artifact.source == nil || visitor == nil {
		return newArtifactError(errorInvalidArtifact, nil)
	}
	metadata, err := validateArtifact(ctx, artifact.source, artifact.size)
	if err != nil {
		return err
	}
	if metadata != artifact.metadata {
		return newArtifactError(errorInvalidArtifact, nil)
	}

	nextSegmentOffset := metadata.DataOffset
	for recordIndex := range metadata.RangeCount {
		if err := ctx.Err(); err != nil {
			return err
		}
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

// Plan retains sealed evidence and checked wire-layout costs. No callback can
// change the semantic map after preparation.
type Plan struct {
	metadata Metadata
	ranges   *pcv3ranges.Map
}

// Metadata returns a copy of the checked wire-layout costs and evidence.
func (plan *Plan) Metadata() Metadata {
	if plan == nil {
		return Metadata{}
	}
	return plan.metadata
}

// Prepare validates classification and exact layout using immutable summaries.
// The map builder has already proved canonical range geometry and states.
func Prepare(descriptor Descriptor) (*Plan, error) {
	m := descriptor.Ranges
	if m == nil || m.PlaintextLength() != descriptor.PlaintextLength || !validFinalStatus(descriptor.Final) {
		return nil, newArtifactError(errorInvalidDescriptor, nil)
	}
	summary := m.Summary()
	if !validSemanticState(descriptor.State, descriptor.Role,
		summary.Verified > 0 || descriptor.Final == FinalVerified,
		summary.Unverified > 0 || descriptor.Final == FinalUnverified,
		summary.Unverified > 0 || summary.Missing > 0 || descriptor.Final != FinalVerified) {
		return nil, newArtifactError(errorInvalidDescriptor, nil)
	}
	tableLength, ok := checkedMul64(m.Count(), rangeEntryLength)
	if !ok {
		return nil, newArtifactError(errorInvalidDescriptor, nil)
	}
	dataOffset, ok := checkedAdd64(headerLength, tableLength)
	if !ok {
		return nil, newArtifactError(errorInvalidDescriptor, nil)
	}
	totalLength, ok := checkedAdd64(dataOffset, summary.RecoveredBytes)
	if !ok || totalLength > math.MaxInt64 {
		return nil, newArtifactError(errorInvalidDescriptor, nil)
	}
	metadata := Metadata{
		State: descriptor.State, Role: descriptor.Role, Final: descriptor.Final,
		HeaderLength: headerLength, RangeEntryLength: rangeEntryLength, PlaintextLength: m.PlaintextLength(),
		RangeCount: m.Count(), EmittedSegmentCount: summary.Verified + summary.Unverified,
		TableOffset: headerLength, DataOffset: dataOffset, TotalLength: totalLength,
	}
	frozen := *m
	return &Plan{metadata: metadata, ranges: &frozen}, nil
}

// Encode streams the unchanged header, table and segments in canonical order.
// Cancellation is checked before each bounded table batch and segment chunk.
func Encode(ctx context.Context, destination io.Writer, plan *Plan, source SegmentSource) error {
	if ctx == nil || plan == nil || plan.ranges == nil {
		return newArtifactError(errorInvalidDescriptor, nil)
	}
	frozen := *plan
	plan = &frozen
	if err := ctx.Err(); err != nil {
		return err
	}
	if destination == nil {
		return newArtifactError(errorArtifactWrite, nil)
	}
	metadata := plan.metadata
	header := encodeHeader(metadata)
	if err := writeAll(destination, header[:]); err != nil {
		return err
	}
	var table [40 * 1024]byte
	used := 0
	nextOffset := metadata.DataOffset
	for r := range plan.ranges.All() {
		if err := ctx.Err(); err != nil {
			return err
		}
		entry := Entry{RecordIndex: r.Index, Start: r.Start, End: r.End, Status: RangeStatus(r.State)}
		if r.State != pcv3ranges.Missing {
			entry.SegmentOffset = nextOffset
			entry.SegmentLength = uint32(r.End - r.Start) //nolint:gosec // Sealed canonical map ranges are at most 1 MiB.
			nextOffset += r.End - r.Start
		}
		encoded := encodeEntry(entry)
		copy(table[used:], encoded[:])
		used += len(encoded)
		if used == len(table) {
			if err := writeAll(destination, table[:used]); err != nil {
				return err
			}
			used = 0
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if used != 0 {
		if err := writeAll(destination, table[:used]); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	nextIndex := uint64(0)
	emitted := uint64(0)
	active := true
	var failure error
	yield := func(index uint64, segment io.Reader) error {
		if !active || failure != nil || segment == nil || emitted >= metadata.EmittedSegmentCount {
			failure = newArtifactError(errorInvalidSegment, nil)
			return failure
		}
		var r pcv3ranges.Range
		for nextIndex < metadata.RangeCount {
			if err := ctx.Err(); err != nil {
				failure = err
				return err
			}
			r, _ = plan.ranges.At(nextIndex)
			nextIndex++
			if r.State != pcv3ranges.Missing {
				break
			}
		}
		if r.State == pcv3ranges.Missing || r.Index != index {
			failure = newArtifactError(errorInvalidSegment, nil)
			return failure
		}
		failure = copyExactSegment(ctx, destination, segment, r.End-r.Start)
		if failure == nil {
			emitted++
		}
		return failure
	}
	var sourceErr error
	if source != nil {
		sourceErr = source(yield)
	}
	active = false
	if failure != nil {
		return failure
	}
	if sourceErr != nil {
		return newArtifactError(errorInvalidSegment, sourceErr)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if emitted != metadata.EmittedSegmentCount {
		return newArtifactError(errorInvalidSegment, nil)
	}
	return nil
}

func validateArtifact(ctx context.Context, source io.ReaderAt, size int64) (Metadata, error) {
	if ctx == nil {
		return Metadata{}, newArtifactError(errorInvalidArtifact, nil)
	}
	if err := ctx.Err(); err != nil {
		return Metadata{}, err
	}
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
		if err := ctx.Err(); err != nil {
			return Metadata{}, err
		}
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
	if source == nil || offset > math.MaxInt64 || uint64(len(destination)) > math.MaxInt64-offset {
		return newArtifactError(errorInvalidArtifact, nil)
	}
	if len(destination) == 0 {
		return nil
	}

	read := 0
	consecutiveNoProgress := 0
	callLimit := len(destination) + 2
	for range callLimit {
		count, err := source.ReadAt(destination[read:], int64(offset)+int64(read))
		if count < 0 || count > len(destination)-read {
			return newArtifactError(errorArtifactRead, errors.New("invalid reader progress"))
		}
		if count > 0 {
			read += count
			consecutiveNoProgress = 0
		} else if err == nil {
			consecutiveNoProgress++
			if consecutiveNoProgress == 2 {
				return newArtifactError(errorArtifactRead, io.ErrNoProgress)
			}
		}

		if read == len(destination) {
			if err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return newArtifactError(errorArtifactRead, err)
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return newArtifactError(errorArtifactRead, io.ErrUnexpectedEOF)
			}
			return newArtifactError(errorArtifactRead, err)
		}
	}
	return newArtifactError(errorArtifactRead, io.ErrNoProgress)
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

func copyExactSegment(ctx context.Context, destination io.Writer, source io.Reader, length uint64) error {
	remaining := length
	buffer := make([]byte, segmentBufferLength)
	defer pcv3crypto.SecureZero(buffer)
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
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
	defer pcv3crypto.SecureZero(extra[:])
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
			return validSelectedRole(role)
		}
		return role == RoleNone
	case StateUnverifiedForensic:
		return !hasVerified && hasUnverified && validSelectedRole(role)
	default:
		return false
	}
}

func validState(state State) bool {
	return state == StatePartial || state == StateUnverifiedForensic
}

func validRole(role Role) bool {
	return role == RoleNone || validSelectedRole(role)
}

func validSelectedRole(role Role) bool {
	return role == RolePrimary || role == RoleBackup ||
		role == RoleD1Front || role == RoleD1Tail
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
