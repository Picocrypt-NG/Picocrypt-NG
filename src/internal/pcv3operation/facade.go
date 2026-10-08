package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3artifact"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3recovery"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3resource"
	"context"
	"io"
)

// Outcome and the other closed presentation metadata are the only codec result types
// exposed here. Credential derivation, key ownership, admission, randomness,
// serializers and recovery engines remain behind the nested internal boundary.
type (
	Outcome               = pcv3.Outcome
	Stage                 = pcv3.Stage
	Code                  = pcv3.Code
	Failure               = pcv3.Failure
	Route                 = pcv3.Route
	Suite                 = pcv3.Suite
	PayloadKind           = pcv3.PayloadKind
	ForceProvenance       = pcv3.ForceProvenance
	D1BootstrapProvenance = pcv3.D1BootstrapProvenance
)

const (
	CodeAmbiguousVolume                 = pcv3.CodeAmbiguousVolume
	CodeAuthenticatedDegraded           = pcv3.CodeAuthenticatedDegraded
	CodeAuthenticationFailed            = pcv3.CodeAuthenticationFailed
	CodeCredentialsOrDamage             = pcv3.CodeCredentialsOrDamage
	CodeForcePartial                    = pcv3.CodeForcePartial
	CodeForceUnverified                 = pcv3.CodeForceUnverified
	CodeInvalidStructure                = pcv3.CodeInvalidStructure
	CodeOperationFailed                 = pcv3.CodeOperationFailed
	CodeSuccess                         = pcv3.CodeSuccess
	CodeUnsupported                     = pcv3.CodeUnsupported
	D1BootstrapProvenanceFront          = pcv3.D1BootstrapProvenanceFront
	D1BootstrapProvenanceMatching       = pcv3.D1BootstrapProvenanceMatching
	D1BootstrapProvenanceNone           = pcv3.D1BootstrapProvenanceNone
	D1BootstrapProvenanceTail           = pcv3.D1BootstrapProvenanceTail
	ForceProvenanceNone                 = pcv3.ForceProvenanceNone
	ForceProvenancePartial              = pcv3.ForceProvenancePartial
	ForceProvenanceUnverified           = pcv3.ForceProvenanceUnverified
	ForceProvenanceVerified             = pcv3.ForceProvenanceVerified
	OutcomeAmbiguousVolume              = pcv3.OutcomeAmbiguousVolume
	OutcomeAuthenticatedDegraded        = pcv3.OutcomeAuthenticatedDegraded
	OutcomeAuthenticationFailed         = pcv3.OutcomeAuthenticationFailed
	OutcomeCommittedDurabilityUncertain = pcv3.OutcomeCommittedDurabilityUncertain
	OutcomeCredentialsOrDamage          = pcv3.OutcomeCredentialsOrDamage
	OutcomeForcePartial                 = pcv3.OutcomeForcePartial
	OutcomeForceUnverified              = pcv3.OutcomeForceUnverified
	OutcomeInvalidStructurePreKDF       = pcv3.OutcomeInvalidStructurePreKDF
	OutcomeOperationFailed              = pcv3.OutcomeOperationFailed
	OutcomePublicationIndeterminate     = pcv3.OutcomePublicationIndeterminate
	OutcomeSuccess                      = pcv3.OutcomeSuccess
	OutcomeUnsupportedRoutingPreKDF     = pcv3.OutcomeUnsupportedRoutingPreKDF
	PayloadKindArchive                  = pcv3.PayloadKindArchive
	PayloadKindRaw                      = pcv3.PayloadKindRaw
	RouteLegacyEligible                 = pcv3.RouteLegacyEligible
	RouteNormalPCV                      = pcv3.RouteNormalPCV
	StageCancellation                   = pcv3.StageCancellation
	StageCapsuleRS                      = pcv3.StageCapsuleRS
	StageCapsuleStructure               = pcv3.StageCapsuleStructure
	StageCredentialPolicy               = pcv3.StageCredentialPolicy
	StageD1Body                         = pcv3.StageD1Body
	StageD1Bootstrap                    = pcv3.StageD1Bootstrap
	StageDescriptor                     = pcv3.StageDescriptor
	StageDirectorySync                  = pcv3.StageDirectorySync
	StageFinalRecord                    = pcv3.StageFinalRecord
	StageInnerVolume                    = pcv3.StageInnerVolume
	StageInputIO                        = pcv3.StageInputIO
	StageKDFRuntime                     = pcv3.StageKDFRuntime
	StageMetadata                       = pcv3.StageMetadata
	StageNone                           = pcv3.StageNone
	StageOutputPublication              = pcv3.StageOutputPublication
	StageOutputWrite                    = pcv3.StageOutputWrite
	StagePreamble                       = pcv3.StagePreamble
	StageRNG                            = pcv3.StageRNG
	StageResourceBudget                 = pcv3.StageResourceBudget
	StageRecordAuth                     = pcv3.StageRecordAuth
	StageRecordBodyRS                   = pcv3.StageRecordBodyRS
	StageReplicaAuth                    = pcv3.StageReplicaAuth
	StageRouting                        = pcv3.StageRouting
	StageTailGeometry                   = pcv3.StageTailGeometry
	StageUnwrap                         = pcv3.StageUnwrap
	StageWrapAuth                       = pcv3.StageWrapAuth
	SuiteParanoid                       = pcv3.SuiteParanoid
	SuiteStandard                       = pcv3.SuiteStandard
)

type (
	FactorRequest  = pcv3credential.FactorRequest
	KeyfileReader  = pcv3credential.KeyfileReader
	CredentialMode = pcv3credential.CredentialMode
	FactorPolicy   = pcv3credential.FactorPolicy
	KeyfileMode    = pcv3credential.KeyfileMode
)

const (
	CredentialModeKeyfilesOnly        = pcv3credential.CredentialModeKeyfilesOnly
	CredentialModePasswordAndKeyfiles = pcv3credential.CredentialModePasswordAndKeyfiles
	CredentialModePasswordOnly        = pcv3credential.CredentialModePasswordOnly
	FactorPolicyKeyfilesOnly          = pcv3credential.FactorPolicyKeyfilesOnly
	FactorPolicyPasswordAndKeyfiles   = pcv3credential.FactorPolicyPasswordAndKeyfiles
	FactorPolicyPasswordOnly          = pcv3credential.FactorPolicyPasswordOnly
	KeyfileModeNone                   = pcv3credential.KeyfileModeNone
	KeyfileModeOrdered                = pcv3credential.KeyfileModeOrdered
	KeyfileModeUnordered              = pcv3credential.KeyfileModeUnordered
)

type (
	ArtifactInspection         = pcv3recovery.ArtifactInspection
	ArtifactInspectionMetadata = pcv3recovery.ArtifactInspectionMetadata
)

type (
	ArtifactState       = pcv3artifact.State
	ArtifactRole        = pcv3artifact.Role
	ArtifactFinalStatus = pcv3artifact.FinalStatus
	ArtifactRangeStatus = pcv3artifact.RangeStatus
	ArtifactRange       = pcv3artifact.Range
)

const (
	ArtifactFinalMissing            = pcv3artifact.FinalMissing
	ArtifactFinalVerified           = pcv3artifact.FinalVerified
	ArtifactFinalUnverified         = pcv3artifact.FinalUnverified
	ArtifactRangeMissing            = pcv3artifact.RangeMissing
	ArtifactRangeVerified           = pcv3artifact.RangeVerified
	ArtifactRangeUnverified         = pcv3artifact.RangeUnverified
	ArtifactRoleBackup              = pcv3artifact.RoleBackup
	ArtifactRoleD1Front             = pcv3artifact.RoleD1Front
	ArtifactRoleD1Tail              = pcv3artifact.RoleD1Tail
	ArtifactRoleNone                = pcv3artifact.RoleNone
	ArtifactRolePrimary             = pcv3artifact.RolePrimary
	ArtifactStatePartial            = pcv3artifact.StatePartial
	ArtifactStateUnverifiedForensic = pcv3artifact.StateUnverifiedForensic
)

// DetectPrefix classifies format ownership without invoking credentials.
func DetectPrefix(prefix []byte) Route { return pcv3.DetectPrefix(prefix) }

// Probe checks bounded public structure for routing. It never returns capsule,
// salt, KDF, or serializer state to the caller.
func Probe(source io.ReaderAt, size int64) (Route, error) {
	route, _, err := pcv3.Probe(source, size)
	return route, err
}

var ErrReaderUnavailable = pcv3.ErrReaderUnavailable

// OwnKeyfileReader transfers the already-opened reader into factor custody.
func OwnKeyfileReader(reader io.ReadCloser) *KeyfileReader {
	return pcv3credential.OwnKeyfileReader(reader)
}

// AndroidResourceSession exposes only the observation challenge lifecycle.
// Its private resource broker cannot be used as an admission or snapshot API.
type AndroidResourceSession struct {
	native *pcv3resource.AndroidResourceSession
}
type AndroidResourceChallenge struct {
	native *pcv3resource.AndroidResourceChallenge
}

func NewAndroidResourceSession() *AndroidResourceSession {
	return &AndroidResourceSession{native: pcv3resource.NewAndroidResourceSession()}
}

func WithAndroidResourceSession(ctx context.Context, session *AndroidResourceSession) context.Context {
	if session == nil {
		return ctx
	}
	return pcv3resource.WithAndroidResourceSession(ctx, session.native)
}

func (session *AndroidResourceSession) Challenge() *AndroidResourceChallenge {
	if session == nil || session.native == nil {
		return nil
	}
	challenge := session.native.Challenge()
	if challenge == nil {
		return nil
	}
	return &AndroidResourceChallenge{native: challenge}
}

func (challenge *AndroidResourceChallenge) Submit(totalRAMBytes, effectiveAvailable, platformThreshold, processFootprint int64, processIs64Bit, lowMemory bool) bool {
	if challenge == nil || challenge.native == nil {
		return false
	}
	return challenge.native.Submit(totalRAMBytes, effectiveAvailable, platformThreshold, processFootprint, processIs64Bit, lowMemory)
}

func AndroidReadPolicyConfigured() bool { return pcv3resource.AndroidReadPolicyConfigured() }
