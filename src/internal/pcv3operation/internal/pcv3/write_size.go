package pcv3

import (
	"errors"
	"math"
)

// WriteSizeMode selects only the two canonical native writer layouts.
type WriteSizeMode uint8

const (
	WriteSizeNormal WriteSizeMode = iota + 1
	WriteSizeD1
)

var errInvalidWriteSize = errors.New("pcv3: invalid write size")

// WriteCiphertextLength returns the exact writer length without constructing a
// candidate, touching credentials, allocating metadata, or authorizing output.
// Comment bytes are counted only; the writer still validates their UTF-8 data.
func WriteCiphertextLength(mode WriteSizeMode, plaintextLength uint64, commentBytes uint32, payloadBodyRS bool) (uint64, error) {
	if (mode != WriteSizeNormal && mode != WriteSizeD1) || commentBytes > maximumCommentLength {
		return 0, errInvalidWriteSize
	}
	_, frontLength, ok := canonicalMetadataGeometry(commentBytes)
	if !ok || frontLength > math.MaxUint32 {
		return 0, errInvalidWriteSize
	}
	payloadLength, ok := canonicalPayloadLength(plaintextLength, canonicalRecordCount(plaintextLength), payloadBodyRS)
	if !ok {
		return 0, errInvalidWriteSize
	}
	backupOffset, ok := checkedAdd64(frontLength, payloadLength)
	if !ok {
		return 0, errInvalidWriteSize
	}
	fileLength, ok := checkedAdd64(backupOffset, fixedSuffixLength)
	if !ok || fileLength > math.MaxInt64 {
		return 0, errInvalidWriteSize
	}
	if mode == WriteSizeD1 {
		outer, err := deriveD1OuterGeometry(fileLength)
		if err != nil {
			return 0, errInvalidWriteSize
		}
		fileLength, ok = checkedAdd64(outer.bodyLength, 2*d1BootstrapLength)
		if !ok || fileLength > math.MaxInt64 {
			return 0, errInvalidWriteSize
		}
	}
	return fileLength, nil
}
