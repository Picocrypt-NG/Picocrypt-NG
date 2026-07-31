package pcv3

import (
	"Picocrypt-NG/internal/util"
)

const (
	backupCapsuleLength  uint64 = 960
	trailerLength        uint64 = 48
	fixedSuffixLength           = backupCapsuleLength + trailerLength
	recordDescriptorSize uint64 = 48
	recordTagSize        uint64 = 64
	nonRSPayloadOverhead        = recordDescriptorSize + recordTagSize
	fullRSPayloadRecord         = recordDescriptorSize +
		((recordPlaintextMax+recordTagSize+rs128DataLength-1)/rs128DataLength)*rs128CodewordLength
	finalRSPayloadRecord = recordDescriptorSize +
		((recordTagSize+rs128DataLength-1)/rs128DataLength)*rs128CodewordLength
)

// Geometry is the canonical, host-representable physical layout derived from
// one structurally valid but unauthenticated candidate.
type Geometry struct {
	metadataBlocks      uint64
	payloadBodyRS       bool
	recordCount         uint64
	frontHeaderLength   int64
	payloadLength       int64
	backupCapsuleOffset int64
	trailerOffset       int64
	fileSize            int64
}

// MetadataBlocks returns the number of encoded public-metadata blocks.
func (geometry Geometry) MetadataBlocks() uint64 {
	return geometry.metadataBlocks
}

// PayloadBodyRS reports whether record bodies use the payload RS layer.
func (geometry Geometry) PayloadBodyRS() bool {
	return geometry.payloadBodyRS
}

// RecordCount returns the number of non-final data records.
func (geometry Geometry) RecordCount() uint64 {
	return geometry.recordCount
}

// FrontHeaderLength returns both the payload start and encoded header length.
func (geometry Geometry) FrontHeaderLength() int64 {
	return geometry.frontHeaderLength
}

// PayloadLength returns the complete encoded payload region length.
func (geometry Geometry) PayloadLength() int64 {
	return geometry.payloadLength
}

// BackupCapsuleOffset returns the canonical backup capsule start.
func (geometry Geometry) BackupCapsuleOffset() int64 {
	return geometry.backupCapsuleOffset
}

// TrailerOffset returns the canonical final trailer start.
func (geometry Geometry) TrailerOffset() int64 {
	return geometry.trailerOffset
}

// FileSize returns the exact canonical whole-file length.
func (geometry Geometry) FileSize() int64 {
	return geometry.fileSize
}

// DeriveGeometry computes the canonical physical layout in O(1), rejects every
// arithmetic overflow, and converts to signed host offsets only after checking
// representability. It does not read or authenticate the source.
func DeriveGeometry(candidate Candidate, sourceSize uint64) (Geometry, error) {
	if !validLogicalCore(candidate.core) {
		return Geometry{}, NewInvalidStructureError(StageCapsuleStructure)
	}

	metadataBlocks, frontHeaderLength, ok := canonicalMetadataGeometry(candidate.core.commentLength)
	if !ok || frontHeaderLength != uint64(candidate.core.frontHeaderLength) {
		return Geometry{}, NewInvalidStructureError(StageCapsuleStructure)
	}

	payloadLength, ok := canonicalPayloadLength(
		candidate.core.plaintextLength,
		candidate.core.recordCount,
		candidate.PayloadBodyRS(),
	)
	if !ok {
		return Geometry{}, NewInvalidStructureError(StageTailGeometry)
	}
	backupOffset, ok := checkedAdd64(frontHeaderLength, payloadLength)
	if !ok {
		return Geometry{}, NewInvalidStructureError(StageTailGeometry)
	}
	trailerOffset, ok := checkedAdd64(backupOffset, backupCapsuleLength)
	if !ok {
		return Geometry{}, NewInvalidStructureError(StageTailGeometry)
	}
	expectedFileSize, ok := checkedAdd64(backupOffset, fixedSuffixLength)
	if !ok {
		return Geometry{}, NewInvalidStructureError(StageTailGeometry)
	}
	fileSize, ok := util.SafeUint64ToInt64(sourceSize)
	if !ok || sourceSize != expectedFileSize {
		return Geometry{}, NewInvalidStructureError(StageTailGeometry)
	}
	frontHeaderOffset, ok := util.SafeUint64ToInt64(frontHeaderLength)
	if !ok {
		return Geometry{}, NewInvalidStructureError(StageTailGeometry)
	}
	payloadSize, ok := util.SafeUint64ToInt64(payloadLength)
	if !ok {
		return Geometry{}, NewInvalidStructureError(StageTailGeometry)
	}
	backupCapsuleOffset, ok := util.SafeUint64ToInt64(backupOffset)
	if !ok {
		return Geometry{}, NewInvalidStructureError(StageTailGeometry)
	}
	trailerFileOffset, ok := util.SafeUint64ToInt64(trailerOffset)
	if !ok {
		return Geometry{}, NewInvalidStructureError(StageTailGeometry)
	}
	return Geometry{
		metadataBlocks:      metadataBlocks,
		payloadBodyRS:       candidate.PayloadBodyRS(),
		recordCount:         candidate.core.recordCount,
		frontHeaderLength:   frontHeaderOffset,
		payloadLength:       payloadSize,
		backupCapsuleOffset: backupCapsuleOffset,
		trailerOffset:       trailerFileOffset,
		fileSize:            fileSize,
	}, nil
}

func canonicalPayloadLength(plaintextLength, recordCount uint64, payloadBodyRS bool) (uint64, bool) {
	if recordCount != canonicalRecordCount(plaintextLength) || recordCount >= maximumRecordCount {
		return 0, false
	}
	if !payloadBodyRS {
		withFinal, ok := checkedAdd64(recordCount, 1)
		if !ok {
			return 0, false
		}
		overhead, ok := checkedMul64(withFinal, nonRSPayloadOverhead)
		if !ok {
			return 0, false
		}
		return checkedAdd64(plaintextLength, overhead)
	}

	fullRecords := plaintextLength / recordPlaintextMax
	partialLength := plaintextLength % recordPlaintextMax
	payloadLength, ok := checkedMul64(fullRecords, fullRSPayloadRecord)
	if !ok {
		return 0, false
	}
	if partialLength != 0 {
		bodyLength, ok := checkedAdd64(partialLength, recordTagSize)
		if !ok {
			return 0, false
		}
		blocks, ok := checkedCeilDiv64(bodyLength, rs128DataLength)
		if !ok {
			return 0, false
		}
		encodedBodyLength, ok := checkedMul64(blocks, rs128CodewordLength)
		if !ok {
			return 0, false
		}
		partialRecordLength, ok := checkedAdd64(recordDescriptorSize, encodedBodyLength)
		if !ok {
			return 0, false
		}
		payloadLength, ok = checkedAdd64(payloadLength, partialRecordLength)
		if !ok {
			return 0, false
		}
	}
	return checkedAdd64(payloadLength, finalRSPayloadRecord)
}
