package pcv3

import "encoding/binary"

const (
	formatMajor              uint16 = 3
	formatSchema             uint16 = 1
	payloadBodyRSFeatureMask uint16 = 1
	supportedFeatureMask            = payloadBodyRSFeatureMask

	frontHeaderBase         uint64 = 976
	metadataDecodedBase     uint64 = 80
	rs128DataLength         uint64 = 128
	rs128CodewordLength     uint64 = 136
	minimumMetadataBlocks   uint64 = 1
	maximumMetadataBlocks   uint64 = 782
	minimumFrontHeader             = frontHeaderBase + minimumMetadataBlocks*rs128CodewordLength
	maximumFrontHeader             = frontHeaderBase + maximumMetadataBlocks*rs128CodewordLength
	preambleRemainderLength        = 12
)

// Suite identifies a supported PCV3 cryptographic suite.
type Suite uint16

const (
	SuiteStandard Suite = iota + 1
	SuiteParanoid
)

// Preamble is the structurally valid, unauthenticated normal-PCV preamble.
type Preamble struct {
	suite             Suite
	featureFlags      uint16
	frontHeaderLength uint32
}

// Suite returns the claimed cryptographic suite.
func (preamble Preamble) Suite() Suite {
	return preamble.suite
}

// FeatureFlags returns the admitted feature bitmap.
func (preamble Preamble) FeatureFlags() uint16 {
	return preamble.featureFlags
}

// PayloadBodyRS reports whether record bodies use the payload RS layer.
func (preamble Preamble) PayloadBodyRS() bool {
	return preamble.featureFlags&payloadBodyRSFeatureMask != 0
}

// FrontHeaderLength returns the canonical encoded front-header length.
func (preamble Preamble) FrontHeaderLength() uint32 {
	return preamble.frontHeaderLength
}

// ParsePreamble validates the 12 bytes following an already-admitted PCV\x00
// discriminator. It performs no source read and does not authenticate the slot.
func ParsePreamble(admittedPrefix [4]byte, remainder []byte) (Preamble, error) {
	if string(admittedPrefix[:]) != normalDiscriminator {
		return Preamble{}, ErrInvalidFailureMapping
	}
	if len(remainder) != preambleRemainderLength {
		return Preamble{}, NewInvalidStructureError(StagePreamble)
	}

	major := binary.BigEndian.Uint16(remainder[0:2])
	schema := binary.BigEndian.Uint16(remainder[2:4])
	suite := Suite(binary.BigEndian.Uint16(remainder[4:6]))
	featureFlags := binary.BigEndian.Uint16(remainder[6:8])
	if major != formatMajor || schema != formatSchema ||
		!isSupportedSuite(suite) || featureFlags&^supportedFeatureMask != 0 {
		return Preamble{}, NewUnsupportedRoutingError()
	}

	frontHeaderLength := binary.BigEndian.Uint32(remainder[8:12])
	if _, ok := metadataBlocksFromFrontHeader(uint64(frontHeaderLength)); !ok {
		return Preamble{}, NewInvalidStructureError(StagePreamble)
	}

	return Preamble{
		suite:             suite,
		featureFlags:      featureFlags,
		frontHeaderLength: frontHeaderLength,
	}, nil
}

func isSupportedSuite(suite Suite) bool {
	return suite == SuiteStandard || suite == SuiteParanoid
}

func metadataBlocksFromFrontHeader(length uint64) (uint64, bool) {
	if length < minimumFrontHeader || length > maximumFrontHeader {
		return 0, false
	}
	encodedLength := length - frontHeaderBase
	if encodedLength%rs128CodewordLength != 0 {
		return 0, false
	}
	blocks := encodedLength / rs128CodewordLength
	return blocks, blocks >= minimumMetadataBlocks && blocks <= maximumMetadataBlocks
}

func canonicalMetadataGeometry(commentLength uint32) (blocks, frontHeaderLength uint64, ok bool) {
	decodedLength, ok := checkedAdd64(metadataDecodedBase, uint64(commentLength))
	if !ok {
		return 0, 0, false
	}
	blocks, ok = checkedCeilDiv64(decodedLength, rs128DataLength)
	if !ok {
		return 0, 0, false
	}
	encodedLength, ok := checkedMul64(blocks, rs128CodewordLength)
	if !ok {
		return 0, 0, false
	}
	frontHeaderLength, ok = checkedAdd64(frontHeaderBase, encodedLength)
	return blocks, frontHeaderLength, ok
}
