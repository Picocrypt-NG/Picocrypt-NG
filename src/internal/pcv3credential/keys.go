package pcv3credential

import (
	"Picocrypt-NG/internal/crypto"
	"crypto/hkdf"
	"crypto/sha3"
	"encoding/binary"
)

const (
	derivedKeyBytes       = 32
	scheduleVolumeIDBytes = 32
	scheduleDomain        = "Picocrypt-NG/PCV3/HKDF\x00"
)

// KeyRole identifies whether a requested key belongs to the front replica,
// tail replica, or neither replica.
type KeyRole uint8

const (
	KeyRolePrimary    KeyRole = 0x00
	KeyRoleBackup     KeyRole = 0x01
	KeyRoleNotReplica KeyRole = 0xff
)

// KeyLabel is one immutable PCV3 key purpose.
type KeyLabel string

const (
	KeyLabelCredentialWrapXChaCha20 KeyLabel = "credential/wrap/xchacha20" //nolint:gosec // Public protocol label, not a credential.
	KeyLabelCredentialWrapSerpent   KeyLabel = "credential/wrap/serpent"   //nolint:gosec // Public protocol label, not a credential.
	KeyLabelCredentialWrapMAC       KeyLabel = "credential/wrap/mac"       //nolint:gosec // Public protocol label, not a credential.
	KeyLabelVolumeReplicaMAC        KeyLabel = "volume/replica/mac"        //gitleaks:allow -- Public protocol label, not a secret.
	KeyLabelVolumeMetadataMAC       KeyLabel = "volume/metadata/mac"
	KeyLabelVolumePayloadXChaCha20  KeyLabel = "volume/payload/xchacha20"
	KeyLabelVolumePayloadSerpent    KeyLabel = "volume/payload/serpent"
	KeyLabelVolumePayloadMAC        KeyLabel = "volume/payload/mac"
)

// KeyRequest contains public schedule metadata only. Root selection is closed
// over the suite registry and callers cannot provide output storage.
type KeyRequest struct {
	Label       KeyLabel
	Role        KeyRole
	OutputBytes uint16
}

type scheduleRoot uint8

const (
	scheduleRootCredential scheduleRoot = iota + 1
	scheduleRootVolume
)

type scheduleRow struct {
	suite   Suite
	root    scheduleRoot
	request KeyRequest
}

type validatedSchedule struct {
	suite Suite
	rows  []scheduleRow
}

type volumeKey struct {
	secret *crypto.Secret
}

func (volumeKey) String() string {
	return "pcv3credential.volumeKey([REDACTED])"
}

func (volumeKey) GoString() string {
	return "pcv3credential.volumeKey([REDACTED])"
}

func (key *volumeKey) close() {
	if key == nil || key.secret == nil {
		return
	}
	key.secret.Close()
	key.secret = nil
}

type credentialPRK struct {
	secret *crypto.Secret
}

func (credentialPRK) String() string {
	return "pcv3credential.credentialPRK([REDACTED])"
}

func (credentialPRK) GoString() string {
	return "pcv3credential.credentialPRK([REDACTED])"
}

func (prk *credentialPRK) close() {
	if prk == nil || prk.secret == nil {
		return
	}
	prk.secret.Close()
	prk.secret = nil
}

type volumePRK struct {
	secret *crypto.Secret
}

func (volumePRK) String() string {
	return "pcv3credential.volumePRK([REDACTED])"
}

func (volumePRK) GoString() string {
	return "pcv3credential.volumePRK([REDACTED])"
}

func (prk *volumePRK) close() {
	if prk == nil || prk.secret == nil {
		return
	}
	prk.secret.Close()
	prk.secret = nil
}

type derivedKey struct {
	row    scheduleRow
	secret *crypto.Secret
}

func (derivedKey) String() string {
	return "pcv3credential.derivedKey([REDACTED])"
}

func (derivedKey) GoString() string {
	return "pcv3credential.derivedKey([REDACTED])"
}

type keyMaterial struct {
	credentialRoot *credentialRoot
	volumeKey      *volumeKey
	credentialPRK  *credentialPRK
	volumePRK      *volumePRK
	keys           []derivedKey
}

func (keyMaterial) String() string {
	return "pcv3credential.keyMaterial([REDACTED])"
}

func (keyMaterial) GoString() string {
	return "pcv3credential.keyMaterial([REDACTED])"
}

func (material *keyMaterial) close() {
	if material == nil {
		return
	}
	if material.credentialRoot != nil {
		material.credentialRoot.close()
		material.credentialRoot = nil
	}
	if material.volumeKey != nil {
		material.volumeKey.close()
		material.volumeKey = nil
	}
	if material.credentialPRK != nil {
		material.credentialPRK.close()
		material.credentialPRK = nil
	}
	if material.volumePRK != nil {
		material.volumePRK.close()
		material.volumePRK = nil
	}
	for i := range material.keys {
		if material.keys[i].secret != nil {
			material.keys[i].secret.Close()
			material.keys[i].secret = nil
		}
	}
	material.keys = nil
}

// hkdfExtractor receives read-only borrows valid only for the call. It
// transfers ownership of its returned slice even when it also returns an
// error.
type hkdfExtractor func(secret, salt []byte) ([]byte, error)

// hkdfExpander receives read-only borrows valid only for the call. It
// transfers ownership of its returned slice even when it also returns an
// error.
type hkdfExpander func(
	pseudorandomKey []byte,
	info string,
	keyLength int,
) ([]byte, error)

// ScheduleErrorCode identifies a public key-schedule failure reason.
type ScheduleErrorCode uint8

const (
	ScheduleErrorInvalidRequest ScheduleErrorCode = iota + 1
	ScheduleErrorInvalidSuite
	ScheduleErrorCardinality
	ScheduleErrorUnknownRequest
	ScheduleErrorDuplicateRequest
	ScheduleErrorCredentialRoot
	ScheduleErrorVolumeKey
	ScheduleErrorVolumeID
	ScheduleErrorExtract
	ScheduleErrorExpand
	ScheduleErrorOutput
)

// ScheduleError contains public identifiers only.
type ScheduleError struct {
	Code  ScheduleErrorCode
	Suite Suite
	Index int
}

func (err *ScheduleError) Error() string {
	if err == nil {
		return "pcv3credential: key schedule failure"
	}
	switch err.Code {
	case ScheduleErrorInvalidRequest:
		return "pcv3credential: invalid key schedule request"
	case ScheduleErrorInvalidSuite:
		return "pcv3credential: unsupported key schedule suite"
	case ScheduleErrorCardinality:
		return "pcv3credential: key schedule cardinality rejected"
	case ScheduleErrorUnknownRequest:
		return "pcv3credential: unknown key schedule request"
	case ScheduleErrorDuplicateRequest:
		return "pcv3credential: duplicate key schedule request"
	case ScheduleErrorCredentialRoot:
		return "pcv3credential: invalid CredentialRoot"
	case ScheduleErrorVolumeKey:
		return "pcv3credential: invalid VolumeKey"
	case ScheduleErrorVolumeID:
		return "pcv3credential: invalid volume ID"
	case ScheduleErrorExtract:
		return "pcv3credential: key root extraction failed"
	case ScheduleErrorExpand:
		return "pcv3credential: key expansion failed"
	case ScheduleErrorOutput:
		return "pcv3credential: invalid key derivation output"
	default:
		return "pcv3credential: key schedule failure"
	}
}

func fixedScheduleForSuite(suite Suite) ([]scheduleRow, error) {
	row := func(
		root scheduleRoot,
		label KeyLabel,
		role KeyRole,
	) scheduleRow {
		return scheduleRow{
			suite: suite,
			root:  root,
			request: KeyRequest{
				Label:       label,
				Role:        role,
				OutputBytes: derivedKeyBytes,
			},
		}
	}
	switch suite {
	case SuiteStandard1:
		rows := [...]scheduleRow{
			row(
				scheduleRootCredential,
				KeyLabelCredentialWrapXChaCha20,
				KeyRolePrimary,
			),
			row(
				scheduleRootCredential,
				KeyLabelCredentialWrapXChaCha20,
				KeyRoleBackup,
			),
			row(
				scheduleRootCredential,
				KeyLabelCredentialWrapMAC,
				KeyRolePrimary,
			),
			row(
				scheduleRootCredential,
				KeyLabelCredentialWrapMAC,
				KeyRoleBackup,
			),
			row(
				scheduleRootVolume,
				KeyLabelVolumeReplicaMAC,
				KeyRolePrimary,
			),
			row(
				scheduleRootVolume,
				KeyLabelVolumeReplicaMAC,
				KeyRoleBackup,
			),
			row(
				scheduleRootVolume,
				KeyLabelVolumeMetadataMAC,
				KeyRoleNotReplica,
			),
			row(
				scheduleRootVolume,
				KeyLabelVolumePayloadXChaCha20,
				KeyRoleNotReplica,
			),
			row(
				scheduleRootVolume,
				KeyLabelVolumePayloadMAC,
				KeyRoleNotReplica,
			),
		}
		return rows[:], nil
	case SuiteParanoid1:
		rows := [...]scheduleRow{
			row(
				scheduleRootCredential,
				KeyLabelCredentialWrapXChaCha20,
				KeyRolePrimary,
			),
			row(
				scheduleRootCredential,
				KeyLabelCredentialWrapXChaCha20,
				KeyRoleBackup,
			),
			row(
				scheduleRootCredential,
				KeyLabelCredentialWrapSerpent,
				KeyRolePrimary,
			),
			row(
				scheduleRootCredential,
				KeyLabelCredentialWrapSerpent,
				KeyRoleBackup,
			),
			row(
				scheduleRootCredential,
				KeyLabelCredentialWrapMAC,
				KeyRolePrimary,
			),
			row(
				scheduleRootCredential,
				KeyLabelCredentialWrapMAC,
				KeyRoleBackup,
			),
			row(
				scheduleRootVolume,
				KeyLabelVolumeReplicaMAC,
				KeyRolePrimary,
			),
			row(
				scheduleRootVolume,
				KeyLabelVolumeReplicaMAC,
				KeyRoleBackup,
			),
			row(
				scheduleRootVolume,
				KeyLabelVolumeMetadataMAC,
				KeyRoleNotReplica,
			),
			row(
				scheduleRootVolume,
				KeyLabelVolumePayloadXChaCha20,
				KeyRoleNotReplica,
			),
			row(
				scheduleRootVolume,
				KeyLabelVolumePayloadSerpent,
				KeyRoleNotReplica,
			),
			row(
				scheduleRootVolume,
				KeyLabelVolumePayloadMAC,
				KeyRoleNotReplica,
			),
		}
		return rows[:], nil
	default:
		return nil, newScheduleError(
			ScheduleErrorInvalidSuite,
			suite,
			-1,
		)
	}
}

func validateKeySchedule(
	suite Suite,
	requests []KeyRequest,
) (*validatedSchedule, error) {
	allowedRows, err := fixedScheduleForSuite(suite)
	if err != nil {
		return nil, err
	}
	if len(requests) == 0 || len(requests) > len(allowedRows) {
		return nil, newScheduleError(
			ScheduleErrorCardinality,
			suite,
			-1,
		)
	}

	allowed := make(map[KeyRequest]scheduleRow, len(allowedRows))
	for _, row := range allowedRows {
		allowed[row.request] = row
	}
	seen := make(map[KeyRequest]struct{}, len(requests))
	canonical := make([]scheduleRow, len(requests))
	for i, request := range requests {
		row, ok := allowed[request]
		if !ok {
			return nil, newScheduleError(
				ScheduleErrorUnknownRequest,
				suite,
				i,
			)
		}
		if _, duplicate := seen[request]; duplicate {
			return nil, newScheduleError(
				ScheduleErrorDuplicateRequest,
				suite,
				i,
			)
		}
		seen[request] = struct{}{}
		canonical[i] = row
	}
	return &validatedSchedule{
		suite: suite,
		rows:  canonical,
	}, nil
}

// deriveKeyMaterial consumes root and key on every success, error, and panic
// exit. Callers must transfer unique pointers and retain no copies.
func deriveKeyMaterial(
	schedule *validatedSchedule,
	root *credentialRoot,
	key *volumeKey,
	volumeID []byte,
) (*keyMaterial, error) {
	return deriveKeyMaterialWith(
		schedule,
		root,
		key,
		volumeID,
		func(secret, salt []byte) ([]byte, error) {
			return hkdf.Extract(sha3.New256, secret, salt)
		},
		func(
			pseudorandomKey []byte,
			info string,
			keyLength int,
		) ([]byte, error) {
			return hkdf.Expand(
				sha3.New256,
				pseudorandomKey,
				info,
				keyLength,
			)
		},
	)
}

// deriveKeyMaterialWith consumes root and key on every success, error, and
// panic exit. Callers must transfer unique pointers and retain no copies.
func deriveKeyMaterialWith(
	schedule *validatedSchedule,
	root *credentialRoot,
	key *volumeKey,
	volumeID []byte,
	extract hkdfExtractor,
	expand hkdfExpander,
) (_ *keyMaterial, returnErr error) {
	suite := Suite(0)
	if schedule != nil {
		suite = schedule.suite
	}
	material := &keyMaterial{
		credentialRoot: takeCredentialRoot(root),
		volumeKey:      takeVolumeKey(key),
	}
	success := false
	defer func() {
		if !success {
			material.close()
		}
	}()

	if schedule == nil || len(schedule.rows) == 0 ||
		extract == nil || expand == nil {
		return nil, newScheduleError(
			ScheduleErrorInvalidRequest,
			suite,
			-1,
		)
	}
	if material.credentialRoot == nil ||
		material.credentialRoot.secret == nil ||
		material.credentialRoot.secret.Len() != credentialRootBytes {
		return nil, newScheduleError(
			ScheduleErrorCredentialRoot,
			suite,
			-1,
		)
	}
	if material.volumeKey == nil ||
		material.volumeKey.secret == nil ||
		material.volumeKey.secret.Len() != derivedKeyBytes {
		return nil, newScheduleError(
			ScheduleErrorVolumeKey,
			suite,
			-1,
		)
	}
	if len(volumeID) != scheduleVolumeIDBytes {
		return nil, newScheduleError(
			ScheduleErrorVolumeID,
			suite,
			-1,
		)
	}

	var volumeIDSnapshot [scheduleVolumeIDBytes]byte
	copy(volumeIDSnapshot[:], volumeID)
	credentialSalt := volumeIDSnapshot
	volumeSalt := volumeIDSnapshot

	material.credentialPRK = &credentialPRK{}
	material.volumePRK = &volumePRK{}
	material.keys = make([]derivedKey, len(schedule.rows))
	for i, row := range schedule.rows {
		material.keys[i].row = row
	}

	returned, err := extract(
		material.credentialRoot.secret.Bytes(),
		credentialSalt[:],
	)
	credentialExtract, err := ownProviderResult(
		returned,
		err,
		suite,
		-1,
		ScheduleErrorExtract,
	)
	if err != nil {
		return nil, err
	}
	material.credentialPRK.secret = credentialExtract

	returned, err = extract(
		material.volumeKey.secret.Bytes(),
		volumeSalt[:],
	)
	volumeExtract, err := ownProviderResult(
		returned,
		err,
		suite,
		-1,
		ScheduleErrorExtract,
	)
	if err != nil {
		return nil, err
	}
	material.volumePRK.secret = volumeExtract

	for i, row := range schedule.rows {
		var prk []byte
		switch row.root {
		case scheduleRootCredential:
			prk = material.credentialPRK.secret.Bytes()
		case scheduleRootVolume:
			prk = material.volumePRK.secret.Bytes()
		default:
			return nil, newScheduleError(
				ScheduleErrorInvalidRequest,
				suite,
				i,
			)
		}
		returned, err = expand(
			prk,
			scheduleInfo(row),
			int(row.request.OutputBytes),
		)
		owned, ownErr := ownProviderResult(
			returned,
			err,
			suite,
			i,
			ScheduleErrorExpand,
		)
		if ownErr != nil {
			return nil, ownErr
		}
		material.keys[i].secret = owned
	}

	success = true
	return material, nil
}

func scheduleInfo(row scheduleRow) string {
	label := string(row.request.Label)
	info := make([]byte, 0, len(scheduleDomain)+9+len(label))
	info = append(info, []byte(scheduleDomain)...)
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], 0x0003)
	info = append(info, encoded[:]...)
	binary.BigEndian.PutUint16(encoded[:], 0x0001)
	info = append(info, encoded[:]...)
	binary.BigEndian.PutUint16(encoded[:], uint16(row.suite))
	info = append(info, encoded[:]...)
	info = append(info, byte(row.request.Role))
	labelBytes := uint16(len(label)) //nolint:gosec // Closed registry labels are all shorter than 2^16 bytes.
	binary.BigEndian.PutUint16(encoded[:], labelBytes)
	info = append(info, encoded[:]...)
	info = append(info, []byte(label)...)
	return string(info)
}

func takeCredentialRoot(root *credentialRoot) *credentialRoot {
	if root == nil {
		return nil
	}
	owned := &credentialRoot{secret: root.secret}
	root.secret = nil
	return owned
}

func takeVolumeKey(key *volumeKey) *volumeKey {
	if key == nil {
		return nil
	}
	owned := &volumeKey{secret: key.secret}
	key.secret = nil
	return owned
}

func ownProviderResult(
	returned []byte,
	providerErr error,
	suite Suite,
	index int,
	providerCode ScheduleErrorCode,
) (*crypto.Secret, error) {
	defer crypto.SecureZero(returned)
	if providerErr != nil {
		return nil, newScheduleError(providerCode, suite, index)
	}
	if len(returned) != derivedKeyBytes {
		return nil, newScheduleError(ScheduleErrorOutput, suite, index)
	}
	owned := make([]byte, derivedKeyBytes)
	copy(owned, returned)
	return crypto.SecretFrom(owned), nil
}

func newScheduleError(
	code ScheduleErrorCode,
	suite Suite,
	index int,
) *ScheduleError {
	return &ScheduleError{
		Code:  code,
		Suite: suite,
		Index: index,
	}
}
