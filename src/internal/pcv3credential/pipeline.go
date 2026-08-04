package pcv3credential

import (
	"Picocrypt-NG/internal/crypto"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"sync"
)

// CredentialRequest transfers ownership of Factors to NewCredential.
type CredentialRequest struct {
	Suite       Suite
	Factors     *FactorRequest
	KeyRequests []KeyRequest
}

func (CredentialRequest) String() string {
	return "pcv3credential.CredentialRequest([REDACTED])"
}

func (CredentialRequest) GoString() string {
	return "pcv3credential.CredentialRequest([REDACTED])"
}

// PipelineErrorCode identifies a bounded public pipeline failure.
type PipelineErrorCode uint8

const (
	PipelineErrorInvalidRequest PipelineErrorCode = iota + 1
	PipelineErrorFactors
	PipelineErrorTranscript
	PipelineErrorSchedule
	PipelineErrorAdmission
	PipelineErrorEntropy
	PipelineErrorCancelled
	PipelineErrorKDF
	PipelineErrorKeyDerivation
	PipelineErrorOwner
	PipelineErrorCallback
)

// PipelineStage identifies the public pipeline boundary that failed.
type PipelineStage uint8

const (
	PipelineStageRequest PipelineStage = iota + 1
	PipelineStageFactors
	PipelineStageTranscript
	PipelineStageSchedule
	PipelineStageAdmission
	PipelineStageArgonSalt
	PipelineStageVolumeID
	PipelineStageVolumeKey
	PipelineStageKDF
	PipelineStageKeyDerivation
	PipelineStageOwner
	PipelineStageCallback
)

// PipelineError contains public identifiers only.
type PipelineError struct {
	Code  PipelineErrorCode
	Stage PipelineStage
	Suite Suite
}

func (err *PipelineError) Error() string {
	if err == nil {
		return "pcv3credential: credential pipeline failure"
	}
	switch err.Code {
	case PipelineErrorInvalidRequest:
		return "pcv3credential: invalid credential pipeline request"
	case PipelineErrorFactors:
		return "pcv3credential: credential factor processing failed"
	case PipelineErrorTranscript:
		return "pcv3credential: canonical credential transcript failed"
	case PipelineErrorSchedule:
		return "pcv3credential: credential key schedule rejected"
	case PipelineErrorAdmission:
		return "pcv3credential: credential runtime admission failed"
	case PipelineErrorEntropy:
		return "pcv3credential: credential entropy acquisition failed"
	case PipelineErrorCancelled:
		return "pcv3credential: credential pipeline cancelled"
	case PipelineErrorKDF:
		return "pcv3credential: credential KDF failed"
	case PipelineErrorKeyDerivation:
		return "pcv3credential: credential key derivation failed"
	case PipelineErrorOwner:
		return "pcv3credential: credential owner publication failed"
	case PipelineErrorCallback:
		return "pcv3credential: credential callback failed"
	default:
		return "pcv3credential: credential pipeline failure"
	}
}

type pipelineMaterialDeriver func(
	*validatedSchedule,
	*credentialRoot,
	*volumeKey,
	[]byte,
) (*keyMaterial, error)

type pipelineSeams struct {
	entropy            io.Reader
	derive             kdfDeriver
	deriveMaterial     pipelineMaterialDeriver
	beforeKDF          func()
	observeNormalInput func([]byte)
	observeOwner       func(*Owner)
}

// NewCredential consumes one complete request and returns its sole key owner.
func NewCredential(
	ctx context.Context,
	request *CredentialRequest,
	admitter Admitter,
) (*Owner, error) {
	return newCredential(ctx, request, admitter, pipelineSeams{
		entropy:        rand.Reader,
		derive:         deriveArgon2ID,
		deriveMaterial: deriveKeyMaterial,
	})
}

func newCredential(
	ctx context.Context,
	request *CredentialRequest,
	admitter Admitter,
	seams pipelineSeams,
) (*Owner, error) {
	if request == nil {
		return nil, newPipelineError(
			PipelineErrorInvalidRequest,
			PipelineStageRequest,
			0,
		)
	}

	suite := request.Suite
	factors := request.Factors
	request.Factors = nil
	keyRequests := append([]KeyRequest(nil), request.KeyRequests...)
	request.KeyRequests = nil

	if ctx == nil ||
		admitter == nil ||
		seams.entropy == nil ||
		seams.derive == nil ||
		seams.deriveMaterial == nil {
		releaseFactorRequest(factors)
		return nil, newPipelineError(
			PipelineErrorInvalidRequest,
			PipelineStageRequest,
			suite,
		)
	}

	expectedPolicy := FactorPolicy(0)
	if factors != nil {
		expectedPolicy = factors.ExpectedPolicy
	}
	var published *Owner
	factorErr := WithValidatedFactors(
		ctx,
		factors,
		func(validated *ValidatedFactors) error {
			schedule, err := validateKeySchedule(suite, keyRequests)
			if err != nil {
				return newPipelineError(
					PipelineErrorSchedule,
					PipelineStageSchedule,
					suite,
				)
			}

			transcript, err := NewCanonicalTranscript(validated)
			if err != nil {
				return newPipelineError(
					PipelineErrorTranscript,
					PipelineStageTranscript,
					suite,
				)
			}
			defer transcript.Close()

			input, err := NewCredentialInputNormal(transcript)
			if err != nil {
				return newPipelineError(
					PipelineErrorTranscript,
					PipelineStageTranscript,
					suite,
				)
			}
			defer input.Close()
			if seams.observeNormalInput != nil {
				seams.observeNormalInput(input.secret.Bytes())
			}

			admitted, err := admitFixedProfile(ctx, suite, admitter)
			if err != nil {
				return err
			}

			argonSalt := make([]byte, kdfSaltBytes)
			defer crypto.SecureZero(argonSalt)
			if err := readPipelineEntropy(
				ctx,
				seams.entropy,
				argonSalt,
				suite,
				PipelineStageArgonSalt,
			); err != nil {
				return err
			}

			volumeID := make([]byte, scheduleVolumeIDBytes)
			defer crypto.SecureZero(volumeID)
			if err := readPipelineEntropy(
				ctx,
				seams.entropy,
				volumeID,
				suite,
				PipelineStageVolumeID,
			); err != nil {
				return err
			}

			volumeKeyBytes := make([]byte, derivedKeyBytes)
			defer crypto.SecureZero(volumeKeyBytes)
			if err := readPipelineEntropy(
				ctx,
				seams.entropy,
				volumeKeyBytes,
				suite,
				PipelineStageVolumeKey,
			); err != nil {
				return err
			}

			if seams.beforeKDF != nil {
				seams.beforeKDF()
			}
			if ctx.Err() != nil {
				return newPipelineError(
					PipelineErrorCancelled,
					PipelineStageKDF,
					suite,
				)
			}

			root, err := runCredentialKDF(
				ctx,
				input,
				argonSalt,
				suite,
				admitted,
				seams.derive,
			)
			if err != nil {
				var kdfErr *KDFError
				if errors.As(err, &kdfErr) &&
					kdfErr.Code == KDFErrorCancelled {
					return newPipelineError(
						PipelineErrorCancelled,
						PipelineStageKDF,
						suite,
					)
				}
				return newPipelineError(
					PipelineErrorKDF,
					PipelineStageKDF,
					suite,
				)
			}
			defer root.close()
			if ctx.Err() != nil {
				return newPipelineError(
					PipelineErrorCancelled,
					PipelineStageKDF,
					suite,
				)
			}

			ownedVolumeKey := append([]byte(nil), volumeKeyBytes...)
			key := &volumeKey{secret: crypto.SecretFrom(ownedVolumeKey)}
			defer key.close()

			material, err := seams.deriveMaterial(
				schedule,
				root,
				key,
				volumeID,
			)
			if err != nil {
				return newPipelineError(
					PipelineErrorKeyDerivation,
					PipelineStageKeyDerivation,
					suite,
				)
			}
			defer func() {
				if material != nil {
					material.close()
				}
			}()
			if ctx.Err() != nil {
				return newPipelineError(
					PipelineErrorCancelled,
					PipelineStageOwner,
					suite,
				)
			}

			metadata := OwnerMetadata{
				Suite:          suite,
				ExpectedPolicy: expectedPolicy,
			}
			copy(metadata.ArgonSalt[:], argonSalt)
			copy(metadata.VolumeID[:], volumeID)
			owner, err := newOwner(metadata, material)
			if err != nil {
				return newPipelineError(
					PipelineErrorOwner,
					PipelineStageOwner,
					suite,
				)
			}
			material = nil
			success := false
			defer func() {
				if !success {
					owner.Close()
				}
			}()
			if seams.observeOwner != nil {
				seams.observeOwner(owner)
			}
			published = owner
			success = true
			return nil
		},
	)
	if factorErr == nil {
		return published, nil
	}
	var pipelineErr *PipelineError
	if errors.As(factorErr, &pipelineErr) {
		return nil, pipelineErr
	}
	var factorFailure *FactorError
	if errors.As(factorErr, &factorFailure) {
		if factorFailure.Code == FactorErrorCancelled {
			return nil, newPipelineError(
				PipelineErrorCancelled,
				PipelineStageFactors,
				suite,
			)
		}
		return nil, newPipelineError(
			PipelineErrorFactors,
			PipelineStageFactors,
			suite,
		)
	}
	return nil, newPipelineError(
		PipelineErrorFactors,
		PipelineStageFactors,
		suite,
	)
}

type fixedAdmission struct {
	mu        sync.Mutex
	profile   KDFProfile
	available bool
}

func (admission *fixedAdmission) AdmitKDF(
	ctx context.Context,
	profile KDFProfile,
) (KDFAdmission, error) {
	admission.mu.Lock()
	defer admission.mu.Unlock()
	if ctx == nil ||
		ctx.Err() != nil ||
		!admission.available ||
		profile != admission.profile {
		admission.available = false
		return KDFAdmissionDenied, nil
	}
	admission.available = false
	return KDFAdmissionGranted, nil
}

func admitFixedProfile(
	ctx context.Context,
	suite Suite,
	admitter Admitter,
) (Admitter, error) {
	profile, err := fixedProfileForSuite(suite)
	if err != nil {
		return nil, newPipelineError(
			PipelineErrorSchedule,
			PipelineStageSchedule,
			suite,
		)
	}
	if ctx.Err() != nil {
		return nil, newPipelineError(
			PipelineErrorCancelled,
			PipelineStageAdmission,
			suite,
		)
	}
	admission, admissionErr := admitter.AdmitKDF(ctx, profile)
	if ctx.Err() != nil {
		return nil, newPipelineError(
			PipelineErrorCancelled,
			PipelineStageAdmission,
			suite,
		)
	}
	if admissionErr != nil || admission != KDFAdmissionGranted {
		return nil, newPipelineError(
			PipelineErrorAdmission,
			PipelineStageAdmission,
			suite,
		)
	}
	return &fixedAdmission{
		profile:   profile,
		available: true,
	}, nil
}

func readPipelineEntropy(
	ctx context.Context,
	source io.Reader,
	destination []byte,
	suite Suite,
	stage PipelineStage,
) error {
	if ctx.Err() != nil {
		return newPipelineError(
			PipelineErrorCancelled,
			stage,
			suite,
		)
	}
	if _, err := io.ReadFull(source, destination); err != nil {
		return newPipelineError(
			PipelineErrorEntropy,
			stage,
			suite,
		)
	}
	if ctx.Err() != nil {
		return newPipelineError(
			PipelineErrorCancelled,
			stage,
			suite,
		)
	}
	return nil
}

func releaseFactorRequest(factors *FactorRequest) {
	if factors == nil {
		return
	}
	_ = factors.Close()
}

func newPipelineError(
	code PipelineErrorCode,
	stage PipelineStage,
	suite Suite,
) *PipelineError {
	return &PipelineError{
		Code:  code,
		Stage: stage,
		Suite: suite,
	}
}
