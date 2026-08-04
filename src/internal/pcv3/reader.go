package pcv3

import (
	pcencoding "Picocrypt-NG/internal/encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	discriminatorLength            = 4
	primaryCapsuleOffset     int64 = 16
	minimumPrimaryReaderSize       = uint64(primaryCapsuleOffset) + backupCapsuleLength
	minimumFixedReaderSize         = uint64(primaryCapsuleOffset) + backupCapsuleLength + fixedSuffixLength
	trailerDecodedLength           = 16
)

var (
	errInvalidReader        = errors.New("pcv3: invalid ReaderAt")
	errInvalidReadProgress  = errors.New("pcv3: impossible ReaderAt progress")
	errReaderNoProgress     = errors.New("pcv3: ReaderAt made no progress")
	errReaderCallLimit      = errors.New("pcv3: ReaderAt call limit exceeded")
	errReaderOffsetOverflow = errors.New("pcv3: ReaderAt offset overflow")
)

// Component identifies one independently inspected fixed structural region.
type Component uint8

const (
	ComponentPrimary Component = iota
	ComponentTrailer
	ComponentBackup
	componentCount
)

// Structure is the bounded pre-KDF view of a claimed PCV3 source.
type Structure struct {
	preamble       Preamble
	candidates     [2]Candidate
	geometries     [2]Geometry
	candidateCount uint8
	issueStages    [componentCount]Stage
	observedSize   int64
}

// String deliberately does not disclose unauthenticated structural fields.
func (Structure) String() string {
	return "pcv3: unauthenticated structural view"
}

// GoString deliberately does not disclose unauthenticated structural fields.
func (structure Structure) GoString() string {
	return structure.String()
}

// Format keeps every fmt verb on the fixed, redacted representation.
func (structure Structure) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, structure.String())
}

// Preamble returns the validated PCV3 preamble.
func (structure Structure) Preamble() Preamble {
	return structure.preamble
}

// CandidateCount returns the number of independently viable capsule slots.
func (structure Structure) CandidateCount() int {
	return int(structure.candidateCount)
}

// CandidateAt returns one viable candidate in physical slot order.
func (structure Structure) CandidateAt(index int) (Candidate, bool) {
	if index < 0 || index >= int(structure.candidateCount) {
		return Candidate{}, false
	}
	return structure.candidates[index], true
}

// GeometryAt returns the checked geometry paired with CandidateAt(index).
func (structure Structure) GeometryAt(index int) (Geometry, bool) {
	if index < 0 || index >= int(structure.candidateCount) {
		return Geometry{}, false
	}
	return structure.geometries[index], true
}

// Issue reports the structural failure stage retained for one fixed component.
func (structure Structure) Issue(component Component) (Stage, bool) {
	if component >= componentCount || structure.issueStages[component] == 0 {
		return 0, false
	}
	return structure.issueStages[component], true
}

// Probe owns the discriminator read and delegates claimed PCV3 sources to
// Inspect without permitting a second read of the first four bytes.
func Probe(source io.ReaderAt, sourceSize int64) (Route, Structure, error) {
	var admitted [discriminatorLength]byte
	count, err := readExactAt(source, 0, admitted[:], StagePreamble)
	route := DetectPrefix(admitted[:count])
	if err != nil {
		var failure Failure
		if errors.As(err, &failure) && failure.Outcome() == OutcomeInvalidStructurePreKDF && route == RouteLegacyEligible {
			return route, Structure{}, nil
		}
		return route, Structure{}, err
	}
	if route == RouteLegacyEligible {
		return route, Structure{}, nil
	}

	structure, err := Inspect(source, sourceSize, admitted)
	return route, structure, err
}

// Inspect reads only the fixed PCV3 structural regions after Probe has
// admitted and supplied the discriminator.
func Inspect(source io.ReaderAt, sourceSize int64, admitted [discriminatorLength]byte) (Structure, error) {
	structure := Structure{observedSize: sourceSize}
	var remainder [preambleRemainderLength]byte
	if _, err := readExactAt(source, discriminatorLength, remainder[:], StagePreamble); err != nil {
		return structure, err
	}
	preamble, err := ParsePreamble(admitted, remainder[:])
	if err != nil {
		return structure, err
	}
	structure.preamble = preamble
	if sourceSize < 0 || uint64(sourceSize) < minimumPrimaryReaderSize {
		return structure, NewInvalidStructureError(StageTailGeometry)
	}
	codecs, err := pcencoding.NewRSCodecs()
	if err != nil {
		return structure, NewInputError(err)
	}

	var primary [backupCapsuleLength]byte
	if _, err := readExactAt(source, primaryCapsuleOffset, primary[:], StageCapsuleRS); err != nil {
		clear(primary[:])
		if terminal := structure.retainIssue(ComponentPrimary, err); terminal != nil {
			return structure, terminal
		}
	} else {
		candidate, geometry, inspectErr := inspectPrimaryCapsule(codecs, primary[:])
		if inspectErr != nil {
			if terminal := structure.retainIssue(ComponentPrimary, inspectErr); terminal != nil {
				return structure, terminal
			}
		} else {
			structure.addCandidate(candidate, geometry)
		}
	}

	if uint64(sourceSize) < minimumFixedReaderSize {
		structure.issueStages[ComponentTrailer] = StageTailGeometry
		structure.issueStages[ComponentBackup] = StageTailGeometry
		if structure.candidateCount != 0 {
			return structure, nil
		}
		return structure, NewInvalidStructureError(structure.earliestIssue())
	}

	trailerOffset := sourceSize - int64(trailerLength)
	var trailer [trailerLength]byte
	if _, err := readExactAt(source, trailerOffset, trailer[:], StageTailGeometry); err != nil {
		clear(trailer[:])
		if terminal := structure.retainIssue(ComponentTrailer, err); terminal != nil {
			return structure, terminal
		}
	} else if inspectErr := inspectTrailer(codecs, trailer[:]); inspectErr != nil {
		if terminal := structure.retainIssue(ComponentTrailer, inspectErr); terminal != nil {
			return structure, terminal
		}
	}

	backupOffset := sourceSize - int64(fixedSuffixLength)
	var backup [backupCapsuleLength]byte
	if _, err := readExactAt(source, backupOffset, backup[:], StageCapsuleRS); err != nil {
		clear(backup[:])
		if terminal := structure.retainIssue(ComponentBackup, err); terminal != nil {
			return structure, terminal
		}
	} else {
		candidate, geometry, inspectErr := inspectCapsule(codecs, backup[:], CapsuleRoleBackup, uint64(sourceSize))
		if inspectErr != nil {
			if terminal := structure.retainIssue(ComponentBackup, inspectErr); terminal != nil {
				return structure, terminal
			}
		} else {
			structure.addCandidate(candidate, geometry)
		}
	}

	if structure.candidateCount != 0 {
		return structure, nil
	}
	stage := structure.earliestIssue()
	if stage == 0 {
		stage = StageTailGeometry
	}
	return structure, NewInvalidStructureError(stage)
}

func (structure *Structure) addCandidate(candidate Candidate, geometry Geometry) {
	index := structure.candidateCount
	structure.candidates[index] = candidate
	structure.geometries[index] = geometry
	structure.candidateCount++
}

func (structure *Structure) retainIssue(component Component, err error) error {
	var failure Failure
	if !errors.As(err, &failure) || failure.Outcome() != OutcomeInvalidStructurePreKDF {
		return err
	}
	structure.issueStages[component] = failure.Stage()
	return nil
}

func (structure Structure) earliestIssue() Stage {
	var earliest Stage
	for _, stage := range structure.issueStages {
		if stage != 0 && (earliest == 0 || stage < earliest) {
			earliest = stage
		}
	}
	return earliest
}

func inspectCapsule(codecs *pcencoding.RSCodecs, encoded []byte, role CapsuleRole, sourceSize uint64) (Candidate, Geometry, error) {
	candidate, err := inspectCapsuleCandidate(codecs, encoded, role)
	if err != nil {
		return Candidate{}, Geometry{}, err
	}
	geometry, err := DeriveGeometry(candidate, sourceSize)
	if err != nil {
		return Candidate{}, Geometry{}, err
	}
	return candidate, geometry, nil
}

func inspectPrimaryCapsule(codecs *pcencoding.RSCodecs, encoded []byte) (Candidate, Geometry, error) {
	candidate, err := inspectCapsuleCandidate(codecs, encoded, CapsuleRolePrimary)
	if err != nil {
		return Candidate{}, Geometry{}, err
	}
	geometry, err := deriveCanonicalGeometry(candidate)
	if err != nil {
		return Candidate{}, Geometry{}, err
	}
	return candidate, geometry, nil
}

func inspectCapsuleCandidate(codecs *pcencoding.RSCodecs, encoded []byte, role CapsuleRole) (Candidate, error) {
	decoded, err := decodeCapsule(codecs, encoded)
	if err != nil {
		return Candidate{}, err
	}
	defer clear(decoded[:])
	candidate, err := ValidateDecodedCapsule(decoded[:], role)
	if err != nil {
		return Candidate{}, err
	}
	return candidate, nil
}

func decodeCapsule(codecs *pcencoding.RSCodecs, encoded []byte) ([decodedCapsuleLength]byte, error) {
	defer clear(encoded)
	var decoded [decodedCapsuleLength]byte
	if len(encoded) != int(backupCapsuleLength) {
		return decoded, NewInvalidStructureError(StageCapsuleRS)
	}
	for lane := range 5 {
		start := lane * codecs.RS64.Total()
		laneDecoded, err := pcencoding.Decode(codecs.RS64, encoded[start:start+codecs.RS64.Total()], false)
		if err != nil {
			clear(laneDecoded)
			clear(decoded[:])
			return decoded, NewInvalidStructureError(StageCapsuleRS)
		}
		copy(decoded[lane*codecs.RS64.Required():(lane+1)*codecs.RS64.Required()], laneDecoded)
		clear(laneDecoded)
	}
	return decoded, nil
}

func inspectTrailer(codecs *pcencoding.RSCodecs, encoded []byte) error {
	decoded, err := decodeTrailer(codecs, encoded)
	if err != nil {
		return err
	}
	defer clear(decoded[:])
	if string(decoded[:4]) != "PCVT" ||
		binary.BigEndian.Uint16(decoded[4:6]) != 3 ||
		binary.BigEndian.Uint16(decoded[6:8]) != 1 ||
		binary.BigEndian.Uint32(decoded[8:12]) != uint32(backupCapsuleLength) ||
		binary.BigEndian.Uint16(decoded[12:14]) != 1 ||
		binary.BigEndian.Uint16(decoded[14:16]) != 0 {
		return NewInvalidStructureError(StageTailGeometry)
	}
	return nil
}

func decodeTrailer(codecs *pcencoding.RSCodecs, encoded []byte) ([trailerDecodedLength]byte, error) {
	defer clear(encoded)
	var decoded [trailerDecodedLength]byte
	if len(encoded) != codecs.RS16.Total() {
		return decoded, NewInvalidStructureError(StageTailGeometry)
	}
	result, err := pcencoding.Decode(codecs.RS16, encoded, false)
	if err != nil {
		clear(result)
		return decoded, NewInvalidStructureError(StageTailGeometry)
	}
	copy(decoded[:], result)
	clear(result)
	return decoded, nil
}

func readExactAt(source io.ReaderAt, offset int64, dst []byte, structuralStage Stage) (int, error) {
	if source == nil || offset < 0 {
		return 0, NewInputError(errInvalidReader)
	}
	if uint64(offset) > uint64(1<<63-1)-uint64(len(dst)) {
		return 0, NewInputError(errReaderOffsetOverflow)
	}
	if len(dst) == 0 {
		return 0, nil
	}

	read := 0
	consecutiveNoProgress := 0
	callLimit := len(dst) + 2
	for range callLimit {
		count, err := source.ReadAt(dst[read:], offset+int64(read))
		if count < 0 || count > len(dst)-read {
			return read, NewInputError(errInvalidReadProgress)
		}
		if count > 0 {
			read += count
			consecutiveNoProgress = 0
		} else if err == nil {
			consecutiveNoProgress++
			if consecutiveNoProgress == 2 {
				return read, NewInputError(errReaderNoProgress)
			}
		}

		if read == len(dst) {
			if err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return read, nil
			}
			return read, NewInputError(err)
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return read, NewInvalidStructureError(structuralStage)
			}
			return read, NewInputError(err)
		}
	}
	return read, NewInputError(errReaderCallLimit)
}
