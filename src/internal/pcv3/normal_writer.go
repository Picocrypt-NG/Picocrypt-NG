package pcv3

import (
	"Picocrypt-NG/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3governance"
	"Picocrypt-NG/internal/util"
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"unicode/utf8"

	pcv3crypto "Picocrypt-NG/internal/crypto"
	pcencoding "Picocrypt-NG/internal/encoding"
)

var (
	errInvalidNormalWriteRequest = errors.New("pcv3: invalid normal write request")
	errNormalWriteSourceLength   = errors.New("pcv3: normal write source length mismatch")
	errNormalWriteSourceProgress = errors.New("pcv3: invalid normal write source progress")
	errNormalWriteSinkProgress   = errors.New("pcv3: invalid normal write sink progress")
	errNormalWriteCrypto         = errors.New("pcv3: normal write cryptographic operation failed")
	errNormalWriteRS             = errors.New("pcv3: normal write recovery encoding failed")
	errNormalWriteGeometry       = errors.New("pcv3: normal write geometry mismatch")
)

// normalWriteRequest contains only the exact semantic inputs to the normal
// codec. Filesystem paths, staging, publication, archive construction, source
// deletion, and frontend state deliberately do not cross this boundary.
type normalWriteRequest struct {
	suite           Suite
	payloadKind     PayloadKind
	payloadBodyRS   bool
	plaintextLength uint64
	comment         []byte
}

// normalWritePlan is the pure, canonical normal-volume geometry consumed by
// both the normal serializer and the D1 wrapper. Its core contains no generated
// identity, nonce, IV, credential, or key material.
type normalWritePlan struct {
	core     logicalCore
	geometry Geometry
}

type normalWriteCredentialMetadata struct {
	suite          Suite
	credentialMode CredentialMode
	keyfileMode    KeyfileMode
	keyfileCount   uint16
	kdfProfile     KDFProfile
	argonSalt      [16]byte
	volumeID       [32]byte
}

// normalWriteMaterial separates the production Owner from literal TEST ONLY
// material without adding a public key API. copyKeys fills one serializer-owned
// bundle exactly once; the serializer clears that bundle on every exit.
type normalWriteMaterial interface {
	credentialMetadata() (normalWriteCredentialMetadata, error)
	copyKeys(context.Context, Suite, *normalWriteKeys) error
}

type normalWriteKeys struct {
	volumeKey        [32]byte
	capsuleWrap      [2]capsuleWrapKeys
	replicaMAC       [2][32]byte
	metadataMAC      [32]byte
	payloadXChaCha20 [32]byte
	payloadSerpent   [32]byte
	payloadMAC       [32]byte
}

func (keys *normalWriteKeys) close() {
	if keys == nil {
		return
	}
	pcv3crypto.SecureZero(keys.volumeKey[:])
	for role := range keys.capsuleWrap {
		keys.capsuleWrap[role].close()
		pcv3crypto.SecureZero(keys.replicaMAC[role][:])
	}
	pcv3crypto.SecureZero(keys.metadataMAC[:])
	pcv3crypto.SecureZero(keys.payloadXChaCha20[:])
	pcv3crypto.SecureZero(keys.payloadSerpent[:])
	pcv3crypto.SecureZero(keys.payloadMAC[:])
}

type normalWriteSeams struct {
	entropy io.Reader
	codecs  *pcencoding.RSCodecs
}

type normalWriteCompletion struct{}

type normalWriteFailure struct {
	stage Stage
	cause error
}

func (*normalWriteFailure) Error() string {
	return "pcv3: normal serialization failed"
}

func (failure *normalWriteFailure) String() string {
	return failure.Error()
}

func (failure *normalWriteFailure) GoString() string {
	return failure.Error()
}

func (failure *normalWriteFailure) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, failure.Error())
}

func (failure *normalWriteFailure) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

func (failure *normalWriteFailure) Stage() Stage {
	if failure == nil {
		return StageNone
	}
	return failure.stage
}

type ownerNormalWriteMaterial struct {
	owner *pcv3credential.Owner
}

func (material ownerNormalWriteMaterial) credentialMetadata() (
	normalWriteCredentialMetadata,
	error,
) {
	if material.owner == nil {
		return normalWriteCredentialMetadata{}, errInvalidNormalWriteRequest
	}
	metadata := material.owner.Metadata()
	suite, ok := normalSuiteFromOwner(metadata.Suite)
	if !ok {
		return normalWriteCredentialMetadata{}, errInvalidNormalWriteRequest
	}
	mode, ok := normalCredentialModeFromOwner(metadata.CredentialMode)
	if !ok {
		return normalWriteCredentialMetadata{}, errInvalidNormalWriteRequest
	}
	keyfileMode, ok := normalKeyfileModeFromOwner(metadata.KeyfileMode)
	if !ok {
		return normalWriteCredentialMetadata{}, errInvalidNormalWriteRequest
	}
	result := normalWriteCredentialMetadata{
		suite:          suite,
		credentialMode: mode,
		keyfileMode:    keyfileMode,
		keyfileCount:   metadata.KeyfileCount,
		kdfProfile:     kdfProfileForSuite(suite),
		argonSalt:      metadata.ArgonSalt,
		volumeID:       metadata.VolumeID,
	}
	if !validNormalWriteCredentialMetadata(result) {
		return normalWriteCredentialMetadata{}, errInvalidNormalWriteRequest
	}
	return result, nil
}

func (material ownerNormalWriteMaterial) copyKeys(
	ctx context.Context,
	suite Suite,
	destination *normalWriteKeys,
) error {
	if material.owner == nil || ctx == nil || destination == nil || !isSupportedSuite(suite) {
		return errInvalidNormalWriteRequest
	}
	return material.owner.WithKeys(ctx, func(borrowed *pcv3credential.BorrowedKeys) error {
		if borrowed == nil {
			return errInvalidNormalWriteRequest
		}
		if err := borrowed.CopyVolumeKey(destination.volumeKey[:]); err != nil {
			return err
		}
		for role := CapsuleRolePrimary; role <= CapsuleRoleBackup; role++ {
			credentialKeyRole, ok := credentialRole(role)
			if !ok {
				return errInvalidNormalWriteRequest
			}
			if err := copyNormalWriteKey(
				borrowed,
				pcv3credential.KeyLabelCredentialWrapXChaCha20,
				credentialKeyRole,
				destination.capsuleWrap[role].xChaCha20[:],
			); err != nil {
				return err
			}
			if suite == SuiteParanoid {
				if err := copyNormalWriteKey(
					borrowed,
					pcv3credential.KeyLabelCredentialWrapSerpent,
					credentialKeyRole,
					destination.capsuleWrap[role].serpent[:],
				); err != nil {
					return err
				}
			}
			if err := copyNormalWriteKey(
				borrowed,
				pcv3credential.KeyLabelCredentialWrapMAC,
				credentialKeyRole,
				destination.capsuleWrap[role].mac[:],
			); err != nil {
				return err
			}
			if err := copyNormalWriteKey(
				borrowed,
				pcv3credential.KeyLabelVolumeReplicaMAC,
				credentialKeyRole,
				destination.replicaMAC[role][:],
			); err != nil {
				return err
			}
		}
		for _, request := range [...]struct {
			label       pcv3credential.KeyLabel
			destination []byte
		}{
			{pcv3credential.KeyLabelVolumeMetadataMAC, destination.metadataMAC[:]},
			{pcv3credential.KeyLabelVolumePayloadXChaCha20, destination.payloadXChaCha20[:]},
			{pcv3credential.KeyLabelVolumePayloadMAC, destination.payloadMAC[:]},
		} {
			if err := copyNormalWriteKey(
				borrowed,
				request.label,
				pcv3credential.KeyRoleNotReplica,
				request.destination,
			); err != nil {
				return err
			}
		}
		if suite == SuiteParanoid {
			return copyNormalWriteKey(
				borrowed,
				pcv3credential.KeyLabelVolumePayloadSerpent,
				pcv3credential.KeyRoleNotReplica,
				destination.payloadSerpent[:],
			)
		}
		return nil
	})
}

func copyNormalWriteKey(
	borrowed *pcv3credential.BorrowedKeys,
	label pcv3credential.KeyLabel,
	role pcv3credential.KeyRole,
	destination []byte,
) error {
	return borrowed.CopyKey(
		pcv3credential.KeyRequest{Label: label, Role: role, OutputBytes: 32},
		destination,
	)
}

// writeNormalVolume is the only production-shaped normal writer seam. The
// current governance package cannot create a valid authorization capability.
// Authorization is checked before codec creation, entropy, keys, source, or
// destination can be observed.
func writeNormalVolume(
	ctx context.Context,
	authorization *pcv3governance.EmissionAuthorization,
	request normalWriteRequest,
	source io.Reader,
	destination io.Writer,
	owner *pcv3credential.Owner,
) (*normalWriteCompletion, error) {
	if err := pcv3governance.RequireEmissionAuthorization(authorization); err != nil {
		return nil, newNormalWriteFailure(StageOutputPublication, err)
	}
	codecs, err := pcencoding.NewRSCodecs()
	if err != nil {
		return nil, newNormalWriteFailure(StageKDFRuntime, errNormalWriteRS)
	}
	return serializeNormalVolume(
		ctx,
		request,
		source,
		destination,
		ownerNormalWriteMaterial{owner: owner},
		normalWriteSeams{entropy: cryptorand.Reader, codecs: codecs},
	)
}

// writeNormalVolumeWithSeams exists only to make the authorization side-effect
// barrier observable in package tests. It remains unexported and validates the
// same opaque capability before inspecting any supplied seam or input.
func writeNormalVolumeWithSeams(
	ctx context.Context,
	authorization *pcv3governance.EmissionAuthorization,
	request normalWriteRequest,
	source io.Reader,
	destination io.Writer,
	material normalWriteMaterial,
	seams normalWriteSeams,
) (*normalWriteCompletion, error) {
	if err := pcv3governance.RequireEmissionAuthorization(authorization); err != nil {
		return nil, newNormalWriteFailure(StageOutputPublication, err)
	}
	return serializeNormalVolume(ctx, request, source, destination, material, seams)
}

// serializeNormalVolume is the single path-free streaming format engine. Its
// explicit entropy seam is unexported and has no production caller except the
// authorized adapter above, which always supplies crypto/rand.Reader.
func serializeNormalVolume(
	ctx context.Context,
	request normalWriteRequest,
	source io.Reader,
	destination io.Writer,
	material normalWriteMaterial,
	seams normalWriteSeams,
) (*normalWriteCompletion, error) {
	if ctx == nil || source == nil || destination == nil || material == nil ||
		!validNormalWriteSeams(seams) {
		return nil, newNormalWriteFailure(StageCredentialPolicy, errInvalidNormalWriteRequest)
	}
	if err := ctx.Err(); err != nil {
		return nil, newNormalWriteFailure(StageCancellation, err)
	}
	if !validNormalWriteRequest(request) {
		return nil, newNormalWriteFailure(StageCredentialPolicy, errInvalidNormalWriteRequest)
	}
	plan, err := planNormalWrite(request)
	if err != nil {
		return nil, err
	}
	metadata, err := material.credentialMetadata()
	if err != nil || !validNormalWriteCredentialMetadata(metadata) || metadata.suite != request.suite {
		return nil, newNormalWriteFailure(StageCredentialPolicy, errInvalidNormalWriteRequest)
	}

	core, primary, backup, err := prepareNormalWriteStructure(
		ctx,
		request,
		plan,
		metadata,
		seams.entropy,
	)
	if err != nil {
		return nil, err
	}
	defer clearNormalWriteEntropy(&core, &primary, &backup)
	geometry := plan.geometry
	if !recordGeometryMatchesCore(core, geometry) {
		return nil, newNormalWriteFailure(StageTailGeometry, errNormalWriteGeometry)
	}

	keys := &normalWriteKeys{}
	defer keys.close()
	if err := material.copyKeys(ctx, request.suite, keys); err != nil {
		if ctx.Err() != nil {
			return nil, newNormalWriteFailure(StageCancellation, ctx.Err())
		}
		return nil, newNormalWriteFailure(StageCredentialPolicy, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, newNormalWriteFailure(StageCancellation, err)
	}

	if err := serializeNormalVolumeWithKeys(
		ctx,
		request,
		core,
		geometry,
		primary,
		backup,
		source,
		destination,
		keys,
		seams.codecs,
	); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, newNormalWriteFailure(StageCancellation, err)
	}
	return &normalWriteCompletion{}, nil
}

func validNormalWriteRequest(request normalWriteRequest) bool {
	if !isSupportedSuite(request.suite) ||
		(request.payloadKind != PayloadKindRaw && request.payloadKind != PayloadKindArchive) ||
		len(request.comment) > maximumCommentLength || !utf8.Valid(request.comment) {
		return false
	}
	recordCount := canonicalRecordCount(request.plaintextLength)
	if recordCount >= maximumRecordCount {
		return false
	}
	_, _, ok := canonicalMetadataGeometry(uint32(len(request.comment))) //nolint:gosec // Maximum is validated above.
	return ok
}

func planNormalWrite(request normalWriteRequest) (normalWritePlan, error) {
	if !validNormalWriteRequest(request) {
		return normalWritePlan{}, newNormalWriteFailure(
			StageCredentialPolicy,
			errInvalidNormalWriteRequest,
		)
	}
	_, frontHeaderLength, ok := canonicalMetadataGeometry(uint32(len(request.comment))) //nolint:gosec // Maximum is validated above.
	if !ok || frontHeaderLength > math.MaxUint32 {
		return normalWritePlan{}, newNormalWriteFailure(
			StageTailGeometry,
			errNormalWriteGeometry,
		)
	}

	var core logicalCore
	copy(core.magic[:], normalDiscriminator)
	core.major = formatMajor
	core.schema = formatSchema
	core.suite = request.suite
	if request.payloadBodyRS {
		core.featureFlags = payloadBodyRSFeatureMask
	}
	core.frontHeaderLength = uint32(frontHeaderLength) //nolint:gosec // Checked against MaxUint32 above.
	core.payloadKind = request.payloadKind
	core.recordProfile = 1
	core.metadataProfile = 1
	core.plaintextLength = request.plaintextLength
	core.recordCount = canonicalRecordCount(request.plaintextLength)
	core.commentLength = uint32(len(request.comment)) //nolint:gosec // Maximum is validated above.

	geometry, err := deriveCanonicalGeometry(Candidate{core: core})
	if err != nil || !recordGeometryMatchesCore(core, geometry) {
		return normalWritePlan{}, newNormalWriteFailure(
			StageTailGeometry,
			errNormalWriteGeometry,
		)
	}
	return normalWritePlan{core: core, geometry: geometry}, nil
}

func validNormalWriteCredentialMetadata(metadata normalWriteCredentialMetadata) bool {
	return isSupportedSuite(metadata.suite) &&
		metadata.kdfProfile == kdfProfileForSuite(metadata.suite) &&
		validCredentialTuple(metadata.credentialMode, metadata.keyfileMode, metadata.keyfileCount)
}

func validNormalWriteSeams(seams normalWriteSeams) bool {
	return seams.entropy != nil && seams.codecs != nil &&
		seams.codecs.RS16 != nil && seams.codecs.RS16.Required() == 16 && seams.codecs.RS16.Total() == 48 &&
		seams.codecs.RS64 != nil && seams.codecs.RS64.Required() == 64 && seams.codecs.RS64.Total() == 192 &&
		seams.codecs.RS128 != nil && seams.codecs.RS128.Required() == 128 && seams.codecs.RS128.Total() == 136
}

func prepareNormalWriteStructure(
	ctx context.Context,
	request normalWriteRequest,
	plan normalWritePlan,
	metadata normalWriteCredentialMetadata,
	entropy io.Reader,
) (logicalCore, Candidate, Candidate, error) {
	if plan.core.suite != request.suite ||
		plan.core.payloadKind != request.payloadKind ||
		plan.core.plaintextLength != request.plaintextLength ||
		plan.core.commentLength != uint32(len(request.comment)) || //nolint:gosec // Maximum is validated before this call.
		!recordGeometryMatchesCore(plan.core, plan.geometry) {
		return logicalCore{}, Candidate{}, Candidate{}, newNormalWriteFailure(StageTailGeometry, errNormalWriteGeometry)
	}
	core := plan.core
	defer clearNormalWriteEntropy(&core)
	core.volumeID = metadata.volumeID
	if err := readNormalWriteEntropy(ctx, entropy, core.xChaChaNoncePrefix[:]); err != nil {
		return logicalCore{}, Candidate{}, Candidate{}, err
	}
	if request.suite == SuiteParanoid {
		if err := readNormalWriteEntropy(ctx, entropy, core.serpentIVPrefix[:]); err != nil {
			return logicalCore{}, Candidate{}, Candidate{}, err
		}
	}
	if !validLogicalCore(core) {
		return logicalCore{}, Candidate{}, Candidate{}, newNormalWriteFailure(StageCapsuleStructure, errInvalidNormalWriteRequest)
	}

	newCandidate := func(role CapsuleRole) Candidate {
		return Candidate{
			core:           core,
			role:           role,
			credentialMode: metadata.credentialMode,
			keyfileMode:    metadata.keyfileMode,
			kdfProfile:     metadata.kdfProfile,
			keyfileCount:   metadata.keyfileCount,
			argonSalt:      metadata.argonSalt,
		}
	}
	primary := newCandidate(CapsuleRolePrimary)
	backup := newCandidate(CapsuleRoleBackup)
	defer clearNormalWriteEntropy(nil, &primary, &backup)
	for _, candidate := range []*Candidate{&primary, &backup} {
		if err := readNormalWriteEntropy(ctx, entropy, candidate.wrapNonce[:]); err != nil {
			return logicalCore{}, Candidate{}, Candidate{}, err
		}
		if request.suite == SuiteParanoid {
			if err := readNormalWriteEntropy(ctx, entropy, candidate.wrapSerpentIV[:]); err != nil {
				return logicalCore{}, Candidate{}, Candidate{}, err
			}
		}
		if !validAuthCandidate(*candidate) {
			return logicalCore{}, Candidate{}, Candidate{}, newNormalWriteFailure(StageCapsuleStructure, errInvalidNormalWriteRequest)
		}
	}
	return core, primary, backup, nil
}

func clearNormalWriteEntropy(core *logicalCore, candidates ...*Candidate) {
	if core != nil {
		pcv3crypto.SecureZero(core.xChaChaNoncePrefix[:])
		pcv3crypto.SecureZero(core.serpentIVPrefix[:])
	}
	for _, candidate := range candidates {
		if candidate == nil {
			continue
		}
		pcv3crypto.SecureZero(candidate.wrapNonce[:])
		pcv3crypto.SecureZero(candidate.wrapSerpentIV[:])
	}
}

func serializeNormalVolumeWithKeys(
	ctx context.Context,
	request normalWriteRequest,
	core logicalCore,
	geometry Geometry,
	primary Candidate,
	backup Candidate,
	source io.Reader,
	destination io.Writer,
	keys *normalWriteKeys,
	codecs *pcencoding.RSCodecs,
) error {
	primaryEncoded, err := encodeNormalWriteCapsule(&primary, keys, codecs)
	if err != nil {
		return err
	}
	defer pcv3crypto.SecureZero(primaryEncoded[:])
	backupEncoded, err := encodeNormalWriteCapsule(&backup, keys, codecs)
	if err != nil {
		return err
	}
	defer pcv3crypto.SecureZero(backupEncoded[:])
	metadataEncoded, err := encodeNormalWriteMetadata(request.comment, core, geometry, keys.metadataMAC[:], codecs)
	if err != nil {
		return err
	}
	defer pcv3crypto.SecureZero(metadataEncoded)
	trailerEncoded, err := encodeNormalWriteTrailer(codecs)
	if err != nil {
		return err
	}
	defer pcv3crypto.SecureZero(trailerEncoded[:])

	writer := normalExactWriter{ctx: ctx, destination: destination}
	coreBytes := logicalCoreBytes(core)
	defer pcv3crypto.SecureZero(coreBytes[:])
	if err := writer.write(coreBytes[:16]); err != nil {
		return err
	}
	if err := writer.write(primaryEncoded[:]); err != nil {
		return err
	}
	if err := writer.write(metadataEncoded); err != nil {
		return err
	}
	if !normalWriteOffsetMatches(writer.offset, geometry.frontHeaderLength) {
		return newNormalWriteFailure(StageTailGeometry, errNormalWriteGeometry)
	}
	if err := writeNormalRecords(ctx, source, &writer, core, geometry, keys, codecs); err != nil {
		return err
	}
	if !normalWriteOffsetMatches(writer.offset, geometry.backupCapsuleOffset) {
		return newNormalWriteFailure(StageTailGeometry, errNormalWriteGeometry)
	}
	if err := writer.write(backupEncoded[:]); err != nil {
		return err
	}
	if !normalWriteOffsetMatches(writer.offset, geometry.trailerOffset) {
		return newNormalWriteFailure(StageTailGeometry, errNormalWriteGeometry)
	}
	if err := writer.write(trailerEncoded[:]); err != nil {
		return err
	}
	if !normalWriteOffsetMatches(writer.offset, geometry.fileSize) {
		return newNormalWriteFailure(StageTailGeometry, errNormalWriteGeometry)
	}
	return nil
}

func encodeNormalWriteCapsule(
	candidate *Candidate,
	keys *normalWriteKeys,
	codecs *pcencoding.RSCodecs,
) ([backupCapsuleLength]byte, error) {
	var encoded [backupCapsuleLength]byte
	if candidate == nil || keys == nil || codecs == nil || !isSupportedCapsuleRole(candidate.role) {
		return encoded, newNormalWriteFailure(StageCapsuleStructure, errInvalidNormalWriteRequest)
	}
	role := candidate.role
	var err error
	switch candidate.core.suite {
	case SuiteStandard:
		err = pcv3crypto.PCV3WrapStandard1(
			candidate.wrappedVolumeKey[:],
			keys.volumeKey[:],
			keys.capsuleWrap[role].xChaCha20[:],
			candidate.wrapNonce[:],
		)
	case SuiteParanoid:
		err = pcv3crypto.PCV3WrapParanoid1(
			candidate.wrappedVolumeKey[:],
			keys.volumeKey[:],
			keys.capsuleWrap[role].xChaCha20[:],
			candidate.wrapNonce[:],
			keys.capsuleWrap[role].serpent[:],
			candidate.wrapSerpentIV[:],
		)
	default:
		err = errNormalWriteCrypto
	}
	if err != nil {
		return encoded, newNormalWriteFailure(StageUnwrap, errNormalWriteCrypto)
	}

	replicaMessage := replicaAuthMessage(*candidate)
	replicaTag, err := suiteMACTag(candidate.core.suite, keys.replicaMAC[role][:], replicaMessage)
	pcv3crypto.SecureZero(replicaMessage)
	if err != nil {
		return encoded, newNormalWriteFailure(StageReplicaAuth, errNormalWriteCrypto)
	}
	copy(candidate.replicaTag[:], replicaTag[:])
	pcv3crypto.SecureZero(replicaTag[:])
	wrapMessage := wrapAuthMessage(*candidate)
	wrapTag, err := suiteMACTag(candidate.core.suite, keys.capsuleWrap[role].mac[:], wrapMessage)
	pcv3crypto.SecureZero(wrapMessage)
	if err != nil {
		return encoded, newNormalWriteFailure(StageWrapAuth, errNormalWriteCrypto)
	}
	copy(candidate.wrapTag[:], wrapTag[:])
	pcv3crypto.SecureZero(wrapTag[:])

	var decoded [decodedCapsuleLength]byte
	defer pcv3crypto.SecureZero(decoded[:])
	coreBytes := logicalCoreBytes(candidate.core)
	prefix := capsulePrefixBytes(*candidate)
	defer pcv3crypto.SecureZero(coreBytes[:])
	defer pcv3crypto.SecureZero(prefix[:])
	copy(decoded[0:96], coreBytes[:])
	copy(decoded[96:192], prefix[:])
	copy(decoded[192:256], candidate.replicaTag[:])
	copy(decoded[256:320], candidate.wrapTag[:])
	for lane := range 5 {
		if err := pcencoding.EncodeInto(
			encoded[lane*192:(lane+1)*192],
			codecs.RS64,
			decoded[lane*64:(lane+1)*64],
		); err != nil {
			pcv3crypto.SecureZero(encoded[:])
			return encoded, newNormalWriteFailure(StageCapsuleRS, errNormalWriteRS)
		}
	}
	return encoded, nil
}

func encodeNormalWriteMetadata(
	comment []byte,
	core logicalCore,
	geometry Geometry,
	macKey []byte,
	codecs *pcencoding.RSCodecs,
) ([]byte, error) {
	if geometry.metadataBlocks < minimumMetadataBlocks || geometry.metadataBlocks > maximumMetadataBlocks ||
		geometry.metadataBlocks > uint64(math.MaxInt/128) || geometry.metadataBlocks > uint64(math.MaxInt/136) {
		return nil, newNormalWriteFailure(StageMetadata, errNormalWriteGeometry)
	}
	decoded := make([]byte, int(geometry.metadataBlocks)*128)
	defer pcv3crypto.SecureZero(decoded)
	copy(decoded[0:4], metadataMagic)
	binary.BigEndian.PutUint16(decoded[4:6], metadataSchema)
	binary.BigEndian.PutUint16(decoded[6:8], metadataUTF8Encoding)
	binary.BigEndian.PutUint32(decoded[8:12], uint32(len(comment))) //nolint:gosec // Maximum is validated before this call.
	copy(decoded[16:16+len(comment)], comment)
	var header [16]byte
	copy(header[:], decoded[:16])
	tag, err := metadataTag(core.suite, macKey, core, header, comment)
	pcv3crypto.SecureZero(header[:])
	if err != nil {
		return nil, newNormalWriteFailure(StageMetadata, errNormalWriteCrypto)
	}
	copy(decoded[16+len(comment):16+len(comment)+len(tag)], tag[:])
	pcv3crypto.SecureZero(tag[:])

	encoded := make([]byte, int(geometry.metadataBlocks)*136)
	for block := range int(geometry.metadataBlocks) {
		if err := pcencoding.EncodeInto(
			encoded[block*136:(block+1)*136],
			codecs.RS128,
			decoded[block*128:(block+1)*128],
		); err != nil {
			pcv3crypto.SecureZero(encoded)
			return nil, newNormalWriteFailure(StageMetadata, errNormalWriteRS)
		}
	}
	return encoded, nil
}

func writeNormalRecords(
	ctx context.Context,
	source io.Reader,
	writer *normalExactWriter,
	core logicalCore,
	geometry Geometry,
	keys *normalWriteKeys,
	codecs *pcencoding.RSCodecs,
) error {
	first, err := expectedRecord(core, geometry, 0)
	if err != nil {
		return newNormalWriteFailure(StageDescriptor, errNormalWriteGeometry)
	}
	final, err := expectedRecord(core, geometry, core.recordCount)
	if err != nil {
		return newNormalWriteFailure(StageFinalRecord, errNormalWriteGeometry)
	}
	maximum := first
	if final.encodedBodyLength > maximum.encodedBodyLength {
		maximum = final
	}
	decodedMaximum, ok := decodedRecordBodyLength(maximum, geometry.payloadBodyRS)
	maximumCiphertextLength, lengthOK := normalWriteLengthToInt(maximum.ciphertextLength)
	if !ok || !lengthOK {
		return newNormalWriteFailure(StageRecordBodyRS, errNormalWriteGeometry)
	}
	plaintext := make([]byte, maximumCiphertextLength)
	semantic := make([]byte, decodedMaximum)
	defer pcv3crypto.SecureZero(plaintext)
	defer pcv3crypto.SecureZero(semantic)
	commitment := coreCommitment(core)
	defer pcv3crypto.SecureZero(commitment[:])
	var descriptor [48]byte
	var encodedBlock [136]byte
	defer pcv3crypto.SecureZero(descriptor[:])
	defer pcv3crypto.SecureZero(encodedBlock[:])

	for index := uint64(0); ; index++ {
		if err := ctx.Err(); err != nil {
			return newNormalWriteFailure(StageCancellation, err)
		}
		expected, err := expectedRecord(core, geometry, index)
		if err != nil {
			return newNormalWriteFailure(StageDescriptor, errNormalWriteGeometry)
		}
		stage := StageRecordAuth
		if expected.final {
			stage = StageFinalRecord
			if err := requireNormalWriteSourceEOF(ctx, source); err != nil {
				return err
			}
		}
		if !normalWriteOffsetMatches(writer.offset, expected.descriptorOffset) {
			return newNormalWriteFailure(stage, errNormalWriteGeometry)
		}
		pcv3crypto.SecureZero(descriptor[:])
		if err := pcencoding.EncodeInto(descriptor[:], codecs.RS16, expected.descriptor[:]); err != nil {
			return newNormalWriteFailure(stage, errNormalWriteRS)
		}
		if err := writer.write(descriptor[:]); err != nil {
			return err
		}
		if !normalWriteOffsetMatches(writer.offset, expected.bodyOffset) {
			return newNormalWriteFailure(stage, errNormalWriteGeometry)
		}

		pcv3crypto.SecureZero(plaintext)
		pcv3crypto.SecureZero(semantic)
		ciphertextLength, ok := normalWriteLengthToInt(expected.ciphertextLength)
		if !ok || ciphertextLength > len(plaintext) {
			return newNormalWriteFailure(stage, errNormalWriteGeometry)
		}
		if !expected.final {
			if err := readNormalWriteSourceExact(ctx, source, plaintext[:ciphertextLength]); err != nil {
				return err
			}
			var cipherErr error
			switch core.suite {
			case SuiteStandard:
				cipherErr = pcv3crypto.PCV3WrapStandard1(
					semantic[:ciphertextLength],
					plaintext[:ciphertextLength],
					keys.payloadXChaCha20[:],
					expected.nonce[:],
				)
			case SuiteParanoid:
				cipherErr = pcv3crypto.PCV3WrapParanoid1(
					semantic[:ciphertextLength],
					plaintext[:ciphertextLength],
					keys.payloadXChaCha20[:],
					expected.nonce[:],
					keys.payloadSerpent[:],
					expected.serpentIV[:],
				)
			default:
				cipherErr = errNormalWriteCrypto
			}
			if cipherErr != nil {
				return newNormalWriteFailure(StageRecordAuth, errNormalWriteCrypto)
			}
		}
		tag, err := recordTag(
			core.suite,
			keys.payloadMAC[:],
			commitment,
			expected.descriptor,
			semantic[:ciphertextLength],
		)
		if err != nil {
			return newNormalWriteFailure(stage, errNormalWriteCrypto)
		}
		semanticLength := ciphertextLength + len(tag)
		copy(semantic[ciphertextLength:semanticLength], tag[:])
		pcv3crypto.SecureZero(tag[:])
		if geometry.payloadBodyRS {
			decodedLength, ok := decodedRecordBodyLength(expected, true)
			if !ok || decodedLength > len(semantic) || decodedLength%128 != 0 {
				return newNormalWriteFailure(stage, errNormalWriteGeometry)
			}
			for block := range decodedLength / 128 {
				pcv3crypto.SecureZero(encodedBlock[:])
				if err := pcencoding.EncodeInto(
					encodedBlock[:],
					codecs.RS128,
					semantic[block*128:(block+1)*128],
				); err != nil {
					return newNormalWriteFailure(stage, errNormalWriteRS)
				}
				if err := writer.write(encodedBlock[:]); err != nil {
					return err
				}
			}
		} else if err := writer.write(semantic[:semanticLength]); err != nil {
			return err
		}
		if expected.final {
			return nil
		}
	}
}

func encodeNormalWriteTrailer(codecs *pcencoding.RSCodecs) ([48]byte, error) {
	var encoded [48]byte
	decoded := canonicalTrailerBytes()
	defer pcv3crypto.SecureZero(decoded[:])
	if err := pcencoding.EncodeInto(encoded[:], codecs.RS16, decoded[:]); err != nil {
		return encoded, newNormalWriteFailure(StageTailGeometry, errNormalWriteRS)
	}
	return encoded, nil
}

type normalExactWriter struct {
	ctx         context.Context
	destination io.Writer
	offset      uint64
}

func (writer *normalExactWriter) write(source []byte) error {
	if writer == nil || writer.ctx == nil || writer.destination == nil {
		return newNormalWriteFailure(StageOutputWrite, errNormalWriteSinkProgress)
	}
	if err := writer.ctx.Err(); err != nil {
		return newNormalWriteFailure(StageCancellation, err)
	}
	count, err := writer.destination.Write(source)
	if count < 0 || count > len(source) {
		return newNormalWriteFailure(StageOutputWrite, errNormalWriteSinkProgress)
	}
	updated, ok := checkedAdd64(writer.offset, uint64(count))
	if !ok {
		return newNormalWriteFailure(StageOutputWrite, errNormalWriteSinkProgress)
	}
	writer.offset = updated
	if err != nil {
		return newNormalWriteFailure(StageOutputWrite, err)
	}
	if count != len(source) {
		return newNormalWriteFailure(StageOutputWrite, io.ErrShortWrite)
	}
	if err := writer.ctx.Err(); err != nil {
		return newNormalWriteFailure(StageCancellation, err)
	}
	return nil
}

func readNormalWriteEntropy(ctx context.Context, entropy io.Reader, destination []byte) error {
	if err := readNormalWriteExact(ctx, entropy, destination); err != nil {
		return newNormalWriteFailure(StageRNG, err)
	}
	return nil
}

func readNormalWriteSourceExact(ctx context.Context, source io.Reader, destination []byte) error {
	if err := readNormalWriteExact(ctx, source, destination); err != nil {
		if ctx != nil && ctx.Err() != nil {
			return newNormalWriteFailure(StageCancellation, ctx.Err())
		}
		return newNormalWriteFailure(StageInputIO, err)
	}
	return nil
}

func readNormalWriteExact(ctx context.Context, source io.Reader, destination []byte) error {
	if ctx == nil || source == nil {
		return errInvalidNormalWriteRequest
	}
	read := 0
	for read < len(destination) {
		if err := ctx.Err(); err != nil {
			return err
		}
		count, err := source.Read(destination[read:])
		if count < 0 || count > len(destination)-read {
			return errNormalWriteSourceProgress
		}
		read += count
		if read == len(destination) {
			if cancellation := ctx.Err(); cancellation != nil {
				return cancellation
			}
			return nil
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return errNormalWriteSourceLength
			}
			return err
		}
		if count == 0 {
			return errNormalWriteSourceProgress
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func requireNormalWriteSourceEOF(ctx context.Context, source io.Reader) error {
	if ctx == nil || source == nil {
		return newNormalWriteFailure(StageInputIO, errInvalidNormalWriteRequest)
	}
	if err := ctx.Err(); err != nil {
		return newNormalWriteFailure(StageCancellation, err)
	}
	var probe [1]byte
	count, err := source.Read(probe[:])
	pcv3crypto.SecureZero(probe[:])
	if count < 0 || count > 1 {
		return newNormalWriteFailure(StageInputIO, errNormalWriteSourceProgress)
	}
	if count != 0 {
		return newNormalWriteFailure(StageInputIO, errNormalWriteSourceLength)
	}
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return newNormalWriteFailure(StageInputIO, err)
	}
	return newNormalWriteFailure(StageInputIO, errNormalWriteSourceProgress)
}

func normalSuiteFromOwner(suite pcv3credential.Suite) (Suite, bool) {
	switch suite {
	case pcv3credential.SuiteStandard1:
		return SuiteStandard, true
	case pcv3credential.SuiteParanoid1:
		return SuiteParanoid, true
	default:
		return 0, false
	}
}

func normalCredentialModeFromOwner(mode pcv3credential.CredentialMode) (CredentialMode, bool) {
	switch mode {
	case pcv3credential.CredentialModePasswordOnly:
		return CredentialModePassword, true
	case pcv3credential.CredentialModeKeyfilesOnly:
		return CredentialModeKeyfiles, true
	case pcv3credential.CredentialModePasswordAndKeyfiles:
		return CredentialModeCombined, true
	default:
		return 0, false
	}
}

func normalKeyfileModeFromOwner(mode pcv3credential.KeyfileMode) (KeyfileMode, bool) {
	switch mode {
	case pcv3credential.KeyfileModeNone:
		return KeyfileModeNone, true
	case pcv3credential.KeyfileModeOrdered:
		return KeyfileModeOrdered, true
	case pcv3credential.KeyfileModeUnordered:
		return KeyfileModeUnordered, true
	default:
		return 0, false
	}
}

func normalWriteOffsetMatches(actual uint64, expected int64) bool {
	actualOffset, ok := util.SafeUint64ToInt64(actual)
	return ok && actualOffset == expected
}

func normalWriteLengthToInt(length uint64) (int, bool) {
	if length > uint64(math.MaxInt) {
		return 0, false
	}
	return int(length), true
}

func newNormalWriteFailure(stage Stage, cause error) error {
	return &normalWriteFailure{stage: stage, cause: cause}
}
