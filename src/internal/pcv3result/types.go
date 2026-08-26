// Package pcv3result owns the dependency-leaf PCV3 outcome and stage
// registries shared by the format and publication packages.
package pcv3result

import (
	"fmt"
	"strconv"
)

// Outcome identifies one name in the closed PCV3 conformance registry.
type Outcome uint8

const (
	// OutcomeUnsupportedRoutingPreKDF rejects an unknown claimed PCV route.
	OutcomeUnsupportedRoutingPreKDF Outcome = iota + 1
	// OutcomeInvalidStructurePreKDF rejects malformed claimed PCV structure.
	OutcomeInvalidStructurePreKDF
	// OutcomeOperationFailed reports a non-structural input operation failure.
	OutcomeOperationFailed
	// OutcomeCredentialsOrDamage collapses wrong credentials and capsule damage.
	OutcomeCredentialsOrDamage
	// OutcomeAuthenticatedDegraded retains one authenticated recovery path.
	OutcomeAuthenticatedDegraded
	// OutcomeAmbiguousVolume rejects conflicting authenticated replicas.
	OutcomeAmbiguousVolume
	// OutcomeSuccess reports a fully authenticated, non-degraded result.
	OutcomeSuccess
	// OutcomeAuthenticationFailed rejects a confirmed volume with failed payload authentication.
	OutcomeAuthenticationFailed
	// OutcomeForcePartial reports verified anchors with missing or damaged payload records.
	OutcomeForcePartial
	// OutcomeForceUnverified reports explicit unverified recovery without a payload anchor.
	OutcomeForceUnverified
	// OutcomeCommittedDurabilityUncertain reports publication without confirmed directory durability.
	OutcomeCommittedDurabilityUncertain
	// OutcomePublicationIndeterminate reports an atomic publication whose commit cannot be proven.
	OutcomePublicationIndeterminate
)

// Stage identifies one boundary in the closed PCV3 conformance registry.
type Stage uint8

const StageNone Stage = 0

const (
	StageRouting Stage = iota + 1
	StagePreamble
	StageCapsuleRS
	StageCapsuleStructure
	StageTailGeometry
	StageInputIO
	StageCredentialPolicy
	StageWrapAuth
	StageUnwrap
	StageReplicaAuth
	StageKDFRuntime
	StageCancellation
	StageMetadata
	StageDescriptor
	StageRecordBodyRS
	StageRecordAuth
	StageFinalRecord
	StageOutputPublication
	StageD1Bootstrap
	StageD1Body
	StageInnerVolume
	StageRNG
	StageOutputWrite
	StageDirectorySync
)

// String returns the exact conformance outcome name.
func (outcome Outcome) String() string {
	switch outcome {
	case OutcomeUnsupportedRoutingPreKDF:
		return "unsupported-routing-pre-kdf"
	case OutcomeInvalidStructurePreKDF:
		return "invalid-structure-pre-kdf"
	case OutcomeOperationFailed:
		return "operation-failed"
	case OutcomeCredentialsOrDamage:
		return "credentials-or-damage"
	case OutcomeAuthenticatedDegraded:
		return "authenticated-degraded"
	case OutcomeAmbiguousVolume:
		return "ambiguous-volume"
	case OutcomeSuccess:
		return "success"
	case OutcomeAuthenticationFailed:
		return "authentication-failed"
	case OutcomeForcePartial:
		return "force-partial"
	case OutcomeForceUnverified:
		return "force-unverified"
	case OutcomeCommittedDurabilityUncertain:
		return "committed-durability-uncertain"
	case OutcomePublicationIndeterminate:
		return "publication-indeterminate"
	default:
		return "unknown-outcome"
	}
}

// GoString returns a fixed, non-numeric outcome name.
func (outcome Outcome) GoString() string {
	return outcome.String()
}

// Format keeps unknown outcomes from rendering their numeric value.
func (outcome Outcome) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, outcome.String())
}

// String returns the exact conformance stage name.
func (stage Stage) String() string {
	switch stage {
	case StageNone:
		return "none"
	case StageRouting:
		return "routing"
	case StagePreamble:
		return "preamble"
	case StageCapsuleRS:
		return "capsule-rs"
	case StageCapsuleStructure:
		return "capsule-structure"
	case StageTailGeometry:
		return "tail-geometry"
	case StageInputIO:
		return "input-io"
	case StageCredentialPolicy:
		return "credential-policy"
	case StageWrapAuth:
		return "wrap-auth"
	case StageUnwrap:
		return "unwrap"
	case StageReplicaAuth:
		return "replica-auth"
	case StageKDFRuntime:
		return "kdf-runtime"
	case StageCancellation:
		return "cancellation"
	case StageMetadata:
		return "metadata"
	case StageDescriptor:
		return "descriptor"
	case StageRecordBodyRS:
		return "record-body-rs"
	case StageRecordAuth:
		return "record-auth"
	case StageFinalRecord:
		return "final-record"
	case StageOutputPublication:
		return "output-publication"
	case StageD1Bootstrap:
		return "d1-bootstrap"
	case StageD1Body:
		return "d1-body"
	case StageInnerVolume:
		return "inner-volume"
	case StageRNG:
		return "rng"
	case StageOutputWrite:
		return "output-write"
	case StageDirectorySync:
		return "directory-sync"
	default:
		return "unknown-stage"
	}
}

// GoString returns a fixed, non-numeric stage name.
func (stage Stage) GoString() string {
	return stage.String()
}

// Format keeps unknown stages from rendering their numeric value.
func (stage Stage) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, stage.String())
}

func writeFixedFormat(state fmt.State, verb rune, value string) {
	if verb == 'q' {
		value = strconv.Quote(value)
	}
	_, _ = state.Write([]byte(value))
}
