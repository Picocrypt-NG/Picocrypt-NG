package pcv3

import (
	pcencoding "Picocrypt-NG/internal/encoding"
	"errors"
	"fmt"
	"io"
)

const recoveryTailIntervalCount = 49

// RecoveryStructure is the bounded pre-KDF view used only by explicit PCV3
// recovery. Unlike Structure, a damaged raw preamble or suffix is retained as
// evidence instead of controlling routing or candidate geometry.
type RecoveryStructure struct {
	preamble         Preamble
	candidates       [2]Candidate
	geometries       [2]Geometry
	candidateCount   uint8
	preambleDamaged  bool
	suffixDamaged    bool
	observedSize     int64
	tailTruncation   uint8
	hasTailCandidate bool
}

func (RecoveryStructure) String() string {
	return "pcv3: unauthenticated recovery structure"
}

func (structure RecoveryStructure) GoString() string { return structure.String() }

func (structure RecoveryStructure) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, structure.String())
}

func (structure RecoveryStructure) Preamble() Preamble { return structure.preamble }

func (structure RecoveryStructure) CandidateCount() int {
	return int(structure.candidateCount)
}

func (structure RecoveryStructure) CandidateAt(index int) (Candidate, bool) {
	if index < 0 || index >= int(structure.candidateCount) {
		return Candidate{}, false
	}
	return structure.candidates[index], true
}

func (structure RecoveryStructure) GeometryAt(index int) (Geometry, bool) {
	if index < 0 || index >= int(structure.candidateCount) {
		return Geometry{}, false
	}
	return structure.geometries[index], true
}

func (structure RecoveryStructure) PreambleDamaged() bool {
	return structure.preambleDamaged
}

func (structure RecoveryStructure) SuffixDamaged() bool {
	return structure.suffixDamaged
}

func (structure *RecoveryStructure) addCandidate(candidate Candidate, geometry Geometry) {
	index := structure.candidateCount
	structure.candidates[index] = candidate
	structure.geometries[index] = geometry
	structure.candidateCount++
}

// InspectRecovery performs the explicit recovery admission pass. Its physical
// read set is fixed: one raw 16-byte preamble, the primary capsule, and the 49
// specification tail intervals. It never calls Probe and never scans.
func InspectRecovery(source io.ReaderAt, sourceSize int64) (RecoveryStructure, error) {
	structure := RecoveryStructure{
		observedSize:  sourceSize,
		suffixDamaged: true,
	}
	if source == nil || sourceSize < 0 {
		return structure, NewInputError(errInvalidReader)
	}

	var rawPreamble [discriminatorLength + preambleRemainderLength]byte
	if _, err := readExactAt(source, 0, rawPreamble[:], StagePreamble); err != nil {
		return structure, err
	}
	var discriminator [discriminatorLength]byte
	copy(discriminator[:], rawPreamble[:discriminatorLength])
	preamble, err := ParsePreamble(discriminator, rawPreamble[discriminatorLength:])
	if err != nil {
		structure.preambleDamaged = true
	} else {
		structure.preamble = preamble
	}

	codecs, err := pcencoding.NewRSCodecs()
	if err != nil {
		return structure, NewInputError(err)
	}

	var earliest Stage
	var primary [backupCapsuleLength]byte
	if _, readErr := readExactAt(source, primaryCapsuleOffset, primary[:], StageCapsuleRS); readErr != nil {
		if terminal := retainRecoveryStructuralFailure(readErr, &earliest); terminal != nil {
			return structure, terminal
		}
	} else {
		candidate, geometry, inspectErr := inspectPrimaryCapsule(codecs, primary[:])
		if inspectErr != nil {
			if terminal := retainRecoveryStructuralFailure(inspectErr, &earliest); terminal != nil {
				return structure, terminal
			}
		} else {
			structure.addCandidate(candidate, geometry)
		}
	}

	var tailScratch [backupCapsuleLength]byte
	var observedTrailer [trailerLength]byte
	for truncation := int64(0); truncation < recoveryTailIntervalCount; truncation++ {
		offset := sourceSize - int64(backupCapsuleLength) - truncation
		if offset < 0 {
			continue
		}
		if _, readErr := readExactAt(source, offset, tailScratch[:], StageCapsuleRS); readErr != nil {
			if terminal := retainRecoveryStructuralFailure(readErr, &earliest); terminal != nil {
				return structure, terminal
			}
			continue
		}
		if truncation == 0 {
			copy(observedTrailer[:], tailScratch[len(tailScratch)-len(observedTrailer):])
		}
		candidate, inspectErr := inspectCapsuleCandidate(codecs, tailScratch[:], CapsuleRoleBackup)
		if inspectErr != nil {
			if terminal := retainRecoveryStructuralFailure(inspectErr, &earliest); terminal != nil {
				return structure, terminal
			}
			continue
		}
		geometry, geometryErr := deriveCanonicalGeometry(candidate)
		if geometryErr != nil || geometry.backupCapsuleOffset != offset ||
			geometry.fileSize < sourceSize {
			if terminal := retainRecoveryStructuralFailure(geometryErr, &earliest); terminal != nil {
				return structure, terminal
			}
			continue
		}
		if structure.hasTailCandidate {
			return RecoveryStructure{observedSize: sourceSize},
				NewInvalidStructureError(StageCapsuleStructure)
		}
		structure.hasTailCandidate = true
		structure.tailTruncation = uint8(truncation) //nolint:gosec // Loop is bounded to 0..48.
		structure.addCandidate(candidate, geometry)
	}

	if structure.hasTailCandidate && uint64(structure.tailTruncation) == trailerLength {
		if trailerErr := inspectTrailer(codecs, observedTrailer[:]); trailerErr == nil {
			structure.suffixDamaged = false
		} else if terminal := retainRecoveryStructuralFailure(trailerErr, &earliest); terminal != nil {
			return structure, terminal
		}
	}
	if structure.candidateCount != 0 {
		return structure, nil
	}
	if earliest == StageNone {
		earliest = StageCapsuleStructure
	}
	return structure, NewInvalidStructureError(earliest)
}

func retainRecoveryStructuralFailure(err error, earliest *Stage) error {
	if err == nil {
		if *earliest == StageNone {
			*earliest = StageTailGeometry
		}
		return nil
	}
	var failure Failure
	if !errors.As(err, &failure) || failure.Outcome() != OutcomeInvalidStructurePreKDF {
		return err
	}
	*earliest = earlierAuthStage(*earliest, failure.Stage())
	return nil
}
