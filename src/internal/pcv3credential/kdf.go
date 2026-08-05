package pcv3credential

import (
	"Picocrypt-NG/internal/crypto"
	"context"
	"errors"

	"golang.org/x/crypto/argon2"
)

const (
	kdfSaltBytes        = 16
	credentialRootBytes = 32
)

// Suite identifies one immutable PCV3 cryptographic suite.
type Suite uint16

const (
	SuiteStandard1 Suite = 0x0001
	SuiteParanoid1 Suite = 0x0002
)

// KDFProfile is a value snapshot of one suite-selected Argon2id profile.
// An Admitter may inspect or mutate its copy without affecting the runner and
// callers cannot supply a profile to the runner.
type KDFProfile struct {
	ID            uint8
	Argon2Version uint8
	Time          uint32
	MemoryKiB     uint32
	Parallelism   uint8
	SaltBytes     uint8
	OutputBytes   uint32
}

// KDFAdmission is one fail-closed resource-admission result.
type KDFAdmission uint8

const (
	KDFAdmissionUnknown KDFAdmission = iota
	KDFAdmissionGranted
	KDFAdmissionDenied
)

// Admitter decides whether the already-selected fixed profile may run.
type Admitter interface {
	AdmitKDF(context.Context, KDFProfile) (KDFAdmission, error)
}

// KDFErrorCode identifies a public, non-secret KDF failure reason.
type KDFErrorCode uint8

const (
	KDFErrorInvalidRequest KDFErrorCode = iota + 1
	KDFErrorInvalidSuite
	KDFErrorInvalidInput
	KDFErrorInvalidSalt
	KDFErrorAdmission
	KDFErrorCancelled
	KDFErrorDerivation
	KDFErrorOutput
)

// KDFError contains public identifiers only.
type KDFError struct {
	Code  KDFErrorCode
	Suite Suite
}

func (err *KDFError) Error() string {
	if err == nil {
		return "pcv3credential: KDF failure"
	}
	switch err.Code {
	case KDFErrorInvalidRequest:
		return "pcv3credential: invalid KDF request"
	case KDFErrorInvalidSuite:
		return "pcv3credential: unsupported KDF suite"
	case KDFErrorInvalidInput:
		return "pcv3credential: invalid KDF input"
	case KDFErrorInvalidSalt:
		return "pcv3credential: invalid KDF salt"
	case KDFErrorAdmission:
		return "pcv3credential: KDF runtime admission failed"
	case KDFErrorCancelled:
		return "pcv3credential: KDF cancelled"
	case KDFErrorDerivation:
		return "pcv3credential: KDF derivation failed"
	case KDFErrorOutput:
		return "pcv3credential: invalid KDF output"
	default:
		return "pcv3credential: KDF failure"
	}
}

type credentialRoot struct {
	secret *crypto.Secret
}

func (credentialRoot) String() string {
	return "pcv3credential.credentialRoot([REDACTED])"
}

func (credentialRoot) GoString() string {
	return "pcv3credential.credentialRoot([REDACTED])"
}

func (root *credentialRoot) close() {
	if root == nil || root.secret == nil {
		return
	}
	root.secret.Close()
	root.secret = nil
}

// kdfDeriver transfers ownership of its returned slice even when it also
// returns an error. The runner clears that exact slice on every exit.
type kdfDeriver func(
	input []byte,
	salt []byte,
	profile KDFProfile,
) ([]byte, error)

var errUnsupportedArgon2Version = errors.New(
	"pcv3credential: unsupported built-in Argon2 version",
)

func fixedProfileForSuite(suite Suite) (KDFProfile, error) {
	switch suite {
	case SuiteStandard1:
		return KDFProfile{
			ID:            0x01,
			Argon2Version: 0x13,
			Time:          4,
			MemoryKiB:     1048576,
			Parallelism:   4,
			SaltBytes:     16,
			OutputBytes:   32,
		}, nil
	case SuiteParanoid1:
		return KDFProfile{
			ID:            0x02,
			Argon2Version: 0x13,
			Time:          8,
			MemoryKiB:     1048576,
			Parallelism:   8,
			SaltBytes:     16,
			OutputBytes:   32,
		}, nil
	default:
		return KDFProfile{}, newKDFError(KDFErrorInvalidSuite, suite)
	}
}

func deriveCredentialRoot(
	ctx context.Context,
	input *CredentialInputNormal,
	salt []byte,
	suite Suite,
	admitter Admitter,
) (*credentialRoot, error) {
	return runCredentialKDF(
		ctx,
		input,
		salt,
		suite,
		admitter,
		deriveArgon2ID,
	)
}

func runCredentialKDF(
	ctx context.Context,
	input *CredentialInputNormal,
	salt []byte,
	suite Suite,
	admitter Admitter,
	derive kdfDeriver,
) (*credentialRoot, error) {
	var root *credentialRoot
	consumeErr := input.consume(func(normalInput []byte) error {
		var err error
		root, err = runCredentialKDFBorrowed(
			ctx,
			normalInput,
			salt,
			suite,
			admitter,
			derive,
		)
		return err
	})
	if consumeErr == nil {
		return root, nil
	}
	if root != nil {
		root.close()
	}
	var kdfErr *KDFError
	if errors.As(consumeErr, &kdfErr) {
		return nil, kdfErr
	}
	return nil, newKDFError(KDFErrorInvalidInput, suite)
}

func runCredentialKDFBorrowed(
	ctx context.Context,
	normalInput []byte,
	salt []byte,
	suite Suite,
	admitter Admitter,
	derive kdfDeriver,
) (*credentialRoot, error) {
	if ctx == nil || admitter == nil || derive == nil {
		return nil, newKDFError(KDFErrorInvalidRequest, suite)
	}
	if len(normalInput) != credentialInputNormalBytes {
		return nil, newKDFError(KDFErrorInvalidInput, suite)
	}

	profile, err := fixedProfileForSuite(suite)
	if err != nil {
		return nil, err
	}
	if uint64(len(salt)) != uint64(profile.SaltBytes) {
		return nil, newKDFError(KDFErrorInvalidSalt, suite)
	}
	var fixedSalt [kdfSaltBytes]byte
	copy(fixedSalt[:], salt)

	if ctx.Err() != nil {
		return nil, newKDFError(KDFErrorCancelled, suite)
	}
	admission, admissionErr := admitter.AdmitKDF(ctx, profile)
	if ctx.Err() != nil {
		return nil, newKDFError(KDFErrorCancelled, suite)
	}
	if admissionErr != nil || admission != KDFAdmissionGranted {
		return nil, newKDFError(KDFErrorAdmission, suite)
	}

	returned, deriveErr := derive(normalInput, fixedSalt[:], profile)
	defer crypto.SecureZero(returned)
	if ctx.Err() != nil {
		return nil, newKDFError(KDFErrorCancelled, suite)
	}
	if deriveErr != nil {
		return nil, newKDFError(KDFErrorDerivation, suite)
	}
	if uint64(len(returned)) != uint64(profile.OutputBytes) {
		return nil, newKDFError(KDFErrorOutput, suite)
	}

	owned := make([]byte, credentialRootBytes)
	copy(owned, returned)
	return &credentialRoot{secret: crypto.SecretFrom(owned)}, nil
}

func deriveArgon2ID(
	input []byte,
	salt []byte,
	profile KDFProfile,
) ([]byte, error) {
	if profile.Argon2Version != argon2.Version {
		return nil, errUnsupportedArgon2Version
	}
	return argon2.IDKey(
		input,
		salt,
		profile.Time,
		profile.MemoryKiB,
		profile.Parallelism,
		profile.OutputBytes,
	), nil
}

func newKDFError(code KDFErrorCode, suite Suite) *KDFError {
	return &KDFError{Code: code, Suite: suite}
}
