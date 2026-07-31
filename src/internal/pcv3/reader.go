package pcv3

import (
	"errors"
	"io"
)

const (
	discriminatorLength          = 4
	primaryCapsuleOffset   int64 = 16
	minimumFixedReaderSize       = uint64(primaryCapsuleOffset) + backupCapsuleLength + fixedSuffixLength
)

var (
	errInvalidReader        = errors.New("pcv3: invalid ReaderAt")
	errInvalidReadProgress  = errors.New("pcv3: impossible ReaderAt progress")
	errReaderNoProgress     = errors.New("pcv3: ReaderAt made no progress")
	errReaderCallLimit      = errors.New("pcv3: ReaderAt call limit exceeded")
	errReaderOffsetOverflow = errors.New("pcv3: ReaderAt offset overflow")
)

// Structure is the bounded pre-KDF view of a claimed PCV3 source.
type Structure struct {
	preamble Preamble
}

// Preamble returns the validated PCV3 preamble.
func (structure Structure) Preamble() Preamble {
	return structure.preamble
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
	var remainder [preambleRemainderLength]byte
	if _, err := readExactAt(source, discriminatorLength, remainder[:], StagePreamble); err != nil {
		return Structure{}, err
	}
	preamble, err := ParsePreamble(admitted, remainder[:])
	if err != nil {
		return Structure{}, err
	}
	if sourceSize < 0 || uint64(sourceSize) < minimumFixedReaderSize {
		return Structure{}, NewInvalidStructureError(StageTailGeometry)
	}

	var primary [backupCapsuleLength]byte
	if _, err := readExactAt(source, primaryCapsuleOffset, primary[:], StageCapsuleRS); err != nil {
		return Structure{}, err
	}

	trailerOffset := sourceSize - int64(trailerLength)
	var trailer [trailerLength]byte
	if _, err := readExactAt(source, trailerOffset, trailer[:], StageTailGeometry); err != nil {
		return Structure{}, err
	}

	backupOffset := sourceSize - int64(fixedSuffixLength)
	var backup [backupCapsuleLength]byte
	if _, err := readExactAt(source, backupOffset, backup[:], StageCapsuleRS); err != nil {
		return Structure{}, err
	}

	return Structure{preamble: preamble}, nil
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
	for calls := 0; calls < callLimit; calls++ {
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
