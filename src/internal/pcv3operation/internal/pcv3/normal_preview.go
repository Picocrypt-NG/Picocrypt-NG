package pcv3

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"context"
	"fmt"
	"io"

	pcencoding "Picocrypt-NG/internal/encoding"
)

// FactorRequirements contains public, unauthenticated factor claims only.
// Its zero value is unavailable and cannot select or authorize credentials.
type FactorRequirements struct {
	policy       pcv3credential.FactorPolicy
	keyfileMode  pcv3credential.KeyfileMode
	keyfileCount uint16
}

func (requirements FactorRequirements) Policy() pcv3credential.FactorPolicy {
	return requirements.policy
}

func (requirements FactorRequirements) KeyfileMode() pcv3credential.KeyfileMode {
	return requirements.keyfileMode
}
func (requirements FactorRequirements) KeyfileCount() uint16 { return requirements.keyfileCount }
func (FactorRequirements) String() string                    { return "pcv3: unauthenticated factor requirements" }
func (requirements FactorRequirements) GoString() string     { return requirements.String() }
func (requirements FactorRequirements) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, requirements.String())
}

func factorRequirements(mode CredentialMode, order KeyfileMode, count uint16) (FactorRequirements, bool) {
	_, keyfileMode, ok := credentialRecoveryModes(mode, order)
	policy, policyOK := credentialFactorPolicy(mode)
	if !ok || !policyOK || !validCredentialTuple(mode, order, count) {
		return FactorRequirements{}, false
	}
	return FactorRequirements{policy: policy, keyfileMode: keyfileMode, keyfileCount: count}, true
}

// NormalPreview is an optional public header hint. It carries no authentication,
// key ownership, recovery selection, output or deletion authority.
type NormalPreview struct {
	factors          FactorRequirements
	factorsAvailable bool
	comment          string
	commentAvailable bool
}

func (preview NormalPreview) Factors() (FactorRequirements, bool) {
	return preview.factors, preview.factorsAvailable
}

func (preview NormalPreview) Comment() (string, bool) {
	return preview.comment, preview.commentAvailable
}
func (NormalPreview) String() string           { return "pcv3: unauthenticated normal preview" }
func (preview NormalPreview) GoString() string { return preview.String() }
func (preview NormalPreview) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, preview.String())
}

// PreviewNormal reads only the preamble, primary capsule and bounded metadata
// from a borrowed source. Missing or structurally damaged hints are unavailable;
// source contract failures and cooperative cancellation remain errors. It never
// reads payload, backup or tail, including when the source is a first split part.
func PreviewNormal(ctx context.Context, source io.ReaderAt, sourceSize int64) (NormalPreview, error) {
	if ctx == nil || source == nil || sourceSize < 0 {
		return NormalPreview{}, NewInputError(errInvalidReader)
	}
	if err := ctx.Err(); err != nil {
		return NormalPreview{}, metadataOperationFailure(StageCancellation, err)
	}
	if sourceSize < primaryCapsuleOffset {
		return NormalPreview{}, nil
	}
	var preambleBytes [16]byte
	truncated, err := readMetadataExactAt(ctx, source, 0, preambleBytes[:])
	if err != nil || truncated {
		return NormalPreview{}, err
	}
	if string(preambleBytes[:4]) != normalDiscriminator {
		return NormalPreview{}, nil
	}
	preamble, err := ParsePreamble([4]byte(preambleBytes[:4]), preambleBytes[4:])
	if err != nil {
		return NormalPreview{}, nil
	}
	if sourceSize < int64(frontHeaderBase) {
		return NormalPreview{}, nil
	}
	var primary [backupCapsuleLength]byte
	truncated, err = readMetadataExactAt(ctx, source, primaryCapsuleOffset, primary[:])
	if err != nil || truncated {
		return NormalPreview{}, err
	}
	codecs, err := pcencoding.NewRSCodecs()
	if err != nil {
		return NormalPreview{}, NewInputError(err)
	}
	candidate, geometry, err := inspectPrimaryCapsule(codecs, primary[:])
	if err != nil || !authenticatedCoreMatchesPreamble(candidate.core, preamble) {
		return NormalPreview{}, nil
	}
	blocks, front, ok := canonicalMetadataGeometry(candidate.core.commentLength)
	if !ok || candidate.core.commentLength > maximumCommentLength || blocks < minimumMetadataBlocks || blocks > maximumMetadataBlocks ||
		front > maximumFrontHeader || geometry.metadataBlocks != blocks || geometry.frontHeaderLength < 0 || uint64(geometry.frontHeaderLength) != front {
		return NormalPreview{}, nil
	}
	requirements, ok := factorRequirements(candidate.credentialMode, candidate.keyfileMode, candidate.keyfileCount)
	if !ok {
		return NormalPreview{}, nil
	}
	preview := NormalPreview{factors: requirements, factorsAvailable: true}
	if uint64(sourceSize) < front {
		return preview, nil
	}
	decoded := make([]byte, int(blocks*rs128DataLength))
	defer clear(decoded)
	for block := range blocks {
		decodedBlock, damaged, err := readMetadataBlock(ctx, source, int64(frontHeaderBase+block*rs128CodewordLength), codecs)
		if err != nil {
			if ctx.Err() != nil {
				return NormalPreview{}, err
			}
			return preview, err
		}
		if damaged {
			return preview, nil
		}
		copy(decoded[int(block*rs128DataLength):], decodedBlock)
		clear(decodedBlock)
	}
	if err := ctx.Err(); err != nil {
		return NormalPreview{}, metadataOperationFailure(StageCancellation, err)
	}
	recovered := parseCanonicalMetadata(decoded, candidate.core.commentLength)
	defer recovered.close()
	if recovered.state == metadataRecoveryCanonical {
		preview.comment = string(recovered.comment)
		preview.commentAvailable = true
	}
	return preview, nil
}
