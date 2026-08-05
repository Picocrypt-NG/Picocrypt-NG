package pcv3

import "errors"

var errInvalidForceAnalysis = errors.New("pcv3: invalid Force analysis")

// forceCandidateIdentity is a callback-scoped key identity. Implementations
// compare the candidate VolumeKey in constant time and never expose its bytes.
type forceCandidateIdentity interface {
	sameVolumeKey(forceCandidateIdentity) bool
}

type forceCandidateAnalysis struct {
	identity      forceCandidateIdentity
	candidate     Candidate
	geometry      Geometry
	damageStage   Stage
	wrapVerified  bool
	replicaValid  bool
	metadataValid bool
	ranges        []RecoveryRange
	final         RecoveryFinalState
}

type forceResolution struct {
	result   *RecoveryResult
	selected int
	role     CapsuleRole
}

func resolveForceCandidates(
	request recoveryRequest,
	analyses []forceCandidateAnalysis,
) (forceResolution, error) {
	resolution := forceResolution{selected: -1}
	if !request.valid() || len(analyses) == 0 || len(analyses) > 2 {
		return resolution, errInvalidForceAnalysis
	}
	for index := range analyses {
		if !validForceCandidateAnalysis(analyses[index]) {
			return resolution, errInvalidForceAnalysis
		}
	}

	anchored := make([]int, 0, len(analyses))
	for index := range analyses {
		if forceAnalysisAnchored(analyses[index]) {
			anchored = append(anchored, index)
		}
	}
	if len(anchored) > 1 {
		first := analyses[anchored[0]]
		for _, index := range anchored[1:] {
			other := analyses[index]
			if first.candidate.core != other.candidate.core ||
				!first.identity.sameVolumeKey(other.identity) {
				result, err := newRecoveryResult(
					OutcomeAmbiguousVolume,
					ForceProvenanceNone,
					StageCapsuleStructure,
					0,
					nil,
					0,
				)
				resolution.result = result
				return resolution, err
			}
		}
	}

	selected := -1
	if len(anchored) != 0 {
		selected = chooseForceReplica(request, analyses, anchored)
	} else if request.Mode() == RecoveryModeForceUnverified {
		for index := range analyses {
			if request.authorizesUnverified(analyses[index].candidate.Role()) &&
				forceAnalysisHasUnverified(analyses[index]) {
				if selected != -1 {
					return resolution, errInvalidForceAnalysis
				}
				selected = index
			}
		}
	}

	if selected == -1 {
		result, err := newRecoveryResult(
			OutcomeCredentialsOrDamage,
			ForceProvenanceNone,
			StageWrapAuth,
			0,
			nil,
			0,
		)
		resolution.result = result
		return resolution, err
	}

	analysis := analyses[selected]
	if forceAnalysisHasUnverified(analysis) &&
		!request.authorizesUnverified(analysis.candidate.Role()) {
		return resolution, errInvalidForceAnalysis
	}
	outcome := OutcomeForcePartial
	provenance := ForceProvenancePartial
	stage := forceDamageStage(analysis)
	if !forceAnalysisAnchored(analysis) {
		outcome = OutcomeForceUnverified
		provenance = ForceProvenanceUnverified
	} else if forceAnalysisFullyVerified(analysis) {
		outcome = OutcomeAuthenticatedDegraded
		provenance = ForceProvenanceVerified
	}
	result, err := newRecoveryResult(
		outcome,
		provenance,
		stage,
		analysis.candidate.PlaintextLength(),
		analysis.ranges,
		analysis.final,
	)
	if err != nil {
		return resolution, err
	}
	resolution.result = result
	resolution.selected = selected
	if forceAnalysisHasUnverified(analysis) {
		resolution.role = analysis.candidate.Role()
	}
	return resolution, nil
}

func validForceCandidateAnalysis(analysis forceCandidateAnalysis) bool {
	if analysis.identity == nil || !validAuthCandidate(analysis.candidate) ||
		!recordGeometryMatchesCore(analysis.candidate.core, analysis.geometry) ||
		!validCanonicalRecoveryRanges(analysis.candidate.PlaintextLength(), analysis.ranges) ||
		!validRecoveryFinalState(analysis.final) {
		return false
	}
	return analysis.damageStage == StageNone ||
		analysis.damageStage == StagePreamble ||
		analysis.damageStage == StageCapsuleRS ||
		analysis.damageStage == StageCapsuleStructure ||
		analysis.damageStage == StageWrapAuth ||
		analysis.damageStage == StageReplicaAuth ||
		analysis.damageStage == StageMetadata ||
		analysis.damageStage == StageDescriptor ||
		analysis.damageStage == StageRecordBodyRS ||
		analysis.damageStage == StageRecordAuth ||
		analysis.damageStage == StageFinalRecord ||
		analysis.damageStage == StageTailGeometry
}

func forceAnalysisAnchored(analysis forceCandidateAnalysis) bool {
	if analysis.final == RecoveryFinalVerified {
		return true
	}
	for _, recoveryRange := range analysis.ranges {
		if recoveryRange.state == RecoveryRangeVerified {
			return true
		}
	}
	return false
}

func forceAnalysisHasUnverified(analysis forceCandidateAnalysis) bool {
	if analysis.final == RecoveryFinalUnverified {
		return true
	}
	for _, recoveryRange := range analysis.ranges {
		if recoveryRange.state == RecoveryRangeUnverified {
			return true
		}
	}
	return false
}

func forceAnalysisFullyVerified(analysis forceCandidateAnalysis) bool {
	if analysis.final != RecoveryFinalVerified {
		return false
	}
	for _, recoveryRange := range analysis.ranges {
		if recoveryRange.state != RecoveryRangeVerified {
			return false
		}
	}
	return true
}

func chooseForceReplica(
	request recoveryRequest,
	analyses []forceCandidateAnalysis,
	anchored []int,
) int {
	if request.Mode() == RecoveryModeForceUnverified {
		for _, index := range anchored {
			if request.authorizesUnverified(analyses[index].candidate.Role()) {
				return index
			}
		}
	}
	for _, index := range anchored {
		if analyses[index].candidate.Role() == CapsuleRolePrimary {
			return index
		}
	}
	return anchored[0]
}

func forceDamageStage(analysis forceCandidateAnalysis) Stage {
	if analysis.damageStage != StageNone {
		return analysis.damageStage
	}
	if analysis.final != RecoveryFinalVerified {
		return StageFinalRecord
	}
	for _, recoveryRange := range analysis.ranges {
		if recoveryRange.state != RecoveryRangeVerified {
			return StageRecordAuth
		}
	}
	// A Force-verified result must retain the ordinary failure which caused
	// explicit Force routing. Raw capsule admission first diverges at wrap auth.
	return StageWrapAuth
}
