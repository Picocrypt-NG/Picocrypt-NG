package pcv3

import (
	"encoding/binary"
	"fmt"
)

const (
	decodedCapsuleLength = 320
	maximumCommentLength = 99_999
	recordPlaintextMax   = 1_048_576
	maximumRecordCount   = uint64(1) << 48
)

// CapsuleRole identifies the physical normal-PCV capsule slot.
type CapsuleRole uint8

const (
	CapsuleRolePrimary CapsuleRole = iota
	CapsuleRoleBackup
)

// PayloadKind identifies the plaintext representation carried by the volume.
type PayloadKind uint8

const (
	PayloadKindRaw PayloadKind = iota + 1
	PayloadKindArchive
)

// CredentialMode identifies the credential factors claimed by a capsule.
type CredentialMode uint8

const (
	CredentialModePassword CredentialMode = iota + 1
	CredentialModeKeyfiles
	CredentialModeCombined
)

// KeyfileMode identifies how multiple keyfiles are combined.
type KeyfileMode uint8

const (
	KeyfileModeNone KeyfileMode = iota
	KeyfileModeOrdered
	KeyfileModeUnordered
)

// KDFProfile identifies the fixed Argon2id profile selected by the suite.
type KDFProfile uint8

const (
	KDFProfileNormal KDFProfile = iota + 1
	KDFProfileParanoid
)

type logicalCore struct {
	magic              [4]byte
	major              uint16
	schema             uint16
	suite              Suite
	featureFlags       uint16
	frontHeaderLength  uint32
	volumeID           [32]byte
	payloadKind        PayloadKind
	recordProfile      uint8
	metadataProfile    uint8
	reserved           uint8
	plaintextLength    uint64
	recordCount        uint64
	xChaChaNoncePrefix [16]byte
	serpentIVPrefix    [8]byte
	commentLength      uint32
}

// Candidate is one structurally valid but unauthenticated decoded capsule.
// Its fixed byte fields remain package-private for later authentication.
type Candidate struct {
	core             logicalCore
	role             CapsuleRole
	credentialMode   CredentialMode
	keyfileMode      KeyfileMode
	kdfProfile       KDFProfile
	keyfileCount     uint16
	reserved         [2]byte
	argonSalt        [16]byte
	wrapNonce        [24]byte
	wrapSerpentIV    [16]byte
	wrappedVolumeKey [32]byte
	replicaTag       [64]byte
	wrapTag          [64]byte
}

// Role returns the physical slot this candidate was validated for.
func (candidate Candidate) Role() CapsuleRole {
	return candidate.role
}

// Suite returns the candidate's claimed cryptographic suite.
func (candidate Candidate) Suite() Suite {
	return candidate.core.suite
}

// FeatureFlags returns the candidate's admitted feature bitmap.
func (candidate Candidate) FeatureFlags() uint16 {
	return candidate.core.featureFlags
}

// PayloadBodyRS reports whether record bodies use the payload RS layer.
func (candidate Candidate) PayloadBodyRS() bool {
	return candidate.core.featureFlags&payloadBodyRSFeatureMask != 0
}

// FrontHeaderLength returns the candidate's encoded front-header length.
func (candidate Candidate) FrontHeaderLength() uint32 {
	return candidate.core.frontHeaderLength
}

// PayloadKind returns the candidate's plaintext representation.
func (candidate Candidate) PayloadKind() PayloadKind {
	return candidate.core.payloadKind
}

// PlaintextLength returns the claimed plaintext payload length.
func (candidate Candidate) PlaintextLength() uint64 {
	return candidate.core.plaintextLength
}

// RecordCount returns the claimed number of non-final data records.
func (candidate Candidate) RecordCount() uint64 {
	return candidate.core.recordCount
}

// CommentLength returns the public metadata comment byte length.
func (candidate Candidate) CommentLength() uint32 {
	return candidate.core.commentLength
}

// CredentialMode returns the candidate's structural credential tuple mode.
func (candidate Candidate) CredentialMode() CredentialMode {
	return candidate.credentialMode
}

// KeyfileMode returns the candidate's structural keyfile ordering mode.
func (candidate Candidate) KeyfileMode() KeyfileMode {
	return candidate.keyfileMode
}

// KDFProfile returns the candidate's suite-bound KDF profile.
func (candidate Candidate) KDFProfile() KDFProfile {
	return candidate.kdfProfile
}

// KeyfileCount returns the number of structural keyfile factors.
func (candidate Candidate) KeyfileCount() uint16 {
	return candidate.keyfileCount
}

// String deliberately does not disclose unauthenticated capsule fields.
func (Candidate) String() string {
	return "pcv3: unauthenticated structural candidate"
}

// GoString deliberately does not disclose unauthenticated capsule fields.
func (candidate Candidate) GoString() string {
	return candidate.String()
}

// Format keeps every fmt verb on the fixed, redacted representation.
func (candidate Candidate) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, candidate.String())
}

// ValidateDecodedCapsule validates one already-RS-decoded capsule against its
// physical slot. It performs no authentication or replica comparison.
func ValidateDecodedCapsule(decoded []byte, expectedRole CapsuleRole) (Candidate, error) {
	if !isSupportedCapsuleRole(expectedRole) {
		return Candidate{}, ErrInvalidFailureMapping
	}
	if len(decoded) != decodedCapsuleLength {
		return Candidate{}, NewInvalidStructureError(StageCapsuleStructure)
	}

	candidate := decodeCandidate(decoded)
	if !validLogicalCore(candidate.core) ||
		candidate.role != expectedRole ||
		!isSupportedCapsuleRole(candidate.role) ||
		!validCredentialTuple(candidate.credentialMode, candidate.keyfileMode, candidate.keyfileCount) ||
		candidate.reserved != [2]byte{} ||
		candidate.kdfProfile != kdfProfileForSuite(candidate.core.suite) ||
		(candidate.core.suite == SuiteStandard && candidate.wrapSerpentIV != [16]byte{}) {
		return Candidate{}, NewInvalidStructureError(StageCapsuleStructure)
	}
	return candidate, nil
}

func decodeCandidate(decoded []byte) Candidate {
	var candidate Candidate
	copy(candidate.core.magic[:], decoded[0:4])
	candidate.core.major = binary.BigEndian.Uint16(decoded[4:6])
	candidate.core.schema = binary.BigEndian.Uint16(decoded[6:8])
	candidate.core.suite = Suite(binary.BigEndian.Uint16(decoded[8:10]))
	candidate.core.featureFlags = binary.BigEndian.Uint16(decoded[10:12])
	candidate.core.frontHeaderLength = binary.BigEndian.Uint32(decoded[12:16])
	copy(candidate.core.volumeID[:], decoded[16:48])
	candidate.core.payloadKind = PayloadKind(decoded[48])
	candidate.core.recordProfile = decoded[49]
	candidate.core.metadataProfile = decoded[50]
	candidate.core.reserved = decoded[51]
	candidate.core.plaintextLength = binary.BigEndian.Uint64(decoded[52:60])
	candidate.core.recordCount = binary.BigEndian.Uint64(decoded[60:68])
	copy(candidate.core.xChaChaNoncePrefix[:], decoded[68:84])
	copy(candidate.core.serpentIVPrefix[:], decoded[84:92])
	candidate.core.commentLength = binary.BigEndian.Uint32(decoded[92:96])
	candidate.role = CapsuleRole(decoded[96])
	candidate.credentialMode = CredentialMode(decoded[97])
	candidate.keyfileMode = KeyfileMode(decoded[98])
	candidate.kdfProfile = KDFProfile(decoded[99])
	candidate.keyfileCount = binary.BigEndian.Uint16(decoded[100:102])
	copy(candidate.reserved[:], decoded[102:104])
	copy(candidate.argonSalt[:], decoded[104:120])
	copy(candidate.wrapNonce[:], decoded[120:144])
	copy(candidate.wrapSerpentIV[:], decoded[144:160])
	copy(candidate.wrappedVolumeKey[:], decoded[160:192])
	copy(candidate.replicaTag[:], decoded[192:256])
	copy(candidate.wrapTag[:], decoded[256:320])
	return candidate
}

func validLogicalCore(core logicalCore) bool {
	if string(core.magic[:]) != normalDiscriminator ||
		core.major != formatMajor || core.schema != formatSchema ||
		!isSupportedSuite(core.suite) || core.featureFlags&^supportedFeatureMask != 0 ||
		core.payloadKind < PayloadKindRaw || core.payloadKind > PayloadKindArchive ||
		core.recordProfile != 1 || core.metadataProfile != 1 || core.reserved != 0 ||
		core.commentLength > maximumCommentLength ||
		core.recordCount != canonicalRecordCount(core.plaintextLength) ||
		core.recordCount >= maximumRecordCount ||
		(core.suite == SuiteStandard && core.serpentIVPrefix != [8]byte{}) {
		return false
	}
	_, expectedFrontHeader, ok := canonicalMetadataGeometry(core.commentLength)
	return ok && uint64(core.frontHeaderLength) == expectedFrontHeader
}

func canonicalRecordCount(plaintextLength uint64) uint64 {
	if plaintextLength == 0 {
		return 0
	}
	return (plaintextLength-1)/recordPlaintextMax + 1
}

func validCredentialTuple(mode CredentialMode, keyfileMode KeyfileMode, count uint16) bool {
	switch mode {
	case CredentialModePassword:
		return keyfileMode == KeyfileModeNone && count == 0
	case CredentialModeKeyfiles, CredentialModeCombined:
		return (keyfileMode == KeyfileModeOrdered || keyfileMode == KeyfileModeUnordered) &&
			count >= 1 && count <= 64
	default:
		return false
	}
}

func isSupportedCapsuleRole(role CapsuleRole) bool {
	return role == CapsuleRolePrimary || role == CapsuleRoleBackup
}

func kdfProfileForSuite(suite Suite) KDFProfile {
	if suite == SuiteParanoid {
		return KDFProfileParanoid
	}
	return KDFProfileNormal
}
