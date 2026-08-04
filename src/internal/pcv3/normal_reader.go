package pcv3

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	pcencoding "Picocrypt-NG/internal/encoding"
	"bytes"
	"context"
	"errors"
	"io"
)

// readNormalVolumeWithProvider is the package-local normal-volume session.
// Its source is borrowed; the session owns only its credential provider,
// authenticated result, suffix scratch, and nonpublishing sink lifecycle.
func readNormalVolumeWithProvider(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	cached Structure,
	provider capsuleCredentialProvider,
	sink normalVolumeSink,
) (*normalReadResult, *normalCompletion) {
	if closer, ok := provider.(capsuleCredentialProviderCloser); ok {
		defer closer.close()
	}
	completed := false
	defer func() {
		if !completed && sink != nil {
			sink.abortUncommitted()
		}
	}()
	if ctx == nil || sink == nil {
		return newNormalReadResult(OutcomeOperationFailed, StageCredentialPolicy, 0, nil), nil
	}
	if err := ctx.Err(); err != nil {
		return newNormalReadResult(OutcomeOperationFailed, StageCancellation, 0, nil), nil
	}

	route, fresh, err := Probe(source, sourceSize)
	if err != nil || route != RouteNormalPCV || fresh.observedSize != sourceSize || fresh != cached {
		return newNormalReadResult(OutcomeOperationFailed, StageInputIO, 0, nil), nil
	}

	auth := authenticateCapsulesBorrowingProvider(ctx, fresh, provider, defaultCapsuleAuthSeams())
	if auth == nil {
		return newNormalReadResult(OutcomeOperationFailed, StageCredentialPolicy, 0, nil), nil
	}
	defer auth.Close()
	if auth.outcome != OutcomeSuccess && auth.outcome != OutcomeAuthenticatedDegraded {
		return newNormalReadResult(auth.outcome, auth.stage, auth.AuthenticatedCapsules(), nil), nil
	}

	degradedStage := auth.stage
	if stage, ok := fresh.Issue(ComponentTrailer); ok {
		degradedStage = earlierAuthStage(degradedStage, stage)
	}

	var suffix [fixedSuffixLength]byte
	defer pcv3crypto.SecureZero(suffix[:])
	if _, err := readExactAt(source, auth.geometry.backupCapsuleOffset, suffix[:], StageTailGeometry); err != nil {
		return newNormalReadResult(OutcomeAuthenticationFailed, StageTailGeometry, auth.AuthenticatedCapsules(), nil), nil
	}

	codecs, err := pcencoding.NewRSCodecs()
	if err != nil {
		return newNormalReadResult(OutcomeOperationFailed, StageKDFRuntime, auth.AuthenticatedCapsules(), nil), nil
	}
	metadata, err := authenticateMetadata(ctx, source, auth, codecs)
	if err != nil {
		return normalResultForAuthenticatedError(err, auth.AuthenticatedCapsules()), nil
	}
	if metadata == nil {
		return newNormalReadResult(OutcomeOperationFailed, StageCredentialPolicy, auth.AuthenticatedCapsules(), nil), nil
	}
	defer metadata.close()
	if metadata.state == metadataDamaged {
		degradedStage = earlierAuthStage(degradedStage, StageMetadata)
	}

	if _, err := readNormalRecords(ctx, source, auth, codecs, sink); err != nil {
		return normalResultForAuthenticatedError(err, auth.AuthenticatedCapsules()), nil
	}

	var finalSuffix [fixedSuffixLength]byte
	defer pcv3crypto.SecureZero(finalSuffix[:])
	if _, err := readExactAt(source, auth.geometry.backupCapsuleOffset, finalSuffix[:], StageTailGeometry); err != nil ||
		!bytes.Equal(suffix[:], finalSuffix[:]) ||
		sourceSize != auth.geometry.fileSize ||
		!normalPhysicalEOF(source, sourceSize) {
		return newNormalReadResult(OutcomeAuthenticationFailed, StageTailGeometry, auth.AuthenticatedCapsules(), nil), nil
	}

	comment := metadata.commentBytes()
	defer pcv3crypto.SecureZero(comment)
	outcome := OutcomeSuccess
	stage := StageNone
	if degradedStage != StageNone {
		outcome = OutcomeAuthenticatedDegraded
		stage = degradedStage
	}
	completed = true
	return newNormalReadResult(outcome, stage, auth.AuthenticatedCapsules(), comment), &normalCompletion{}
}

func normalResultForAuthenticatedError(err error, authenticated int) *normalReadResult {
	var recordErr *recordFailure
	if errors.As(err, &recordErr) {
		switch recordErr.stage {
		case StageDescriptor, StageRecordBodyRS, StageRecordAuth, StageFinalRecord:
			return newNormalReadResult(OutcomeAuthenticationFailed, recordErr.stage, authenticated, nil)
		case StageInputIO, StageCancellation, StageOutputWrite, StageCredentialPolicy:
			return newNormalReadResult(OutcomeOperationFailed, recordErr.stage, authenticated, nil)
		default:
			return newNormalReadResult(OutcomeOperationFailed, StageCredentialPolicy, authenticated, nil)
		}
	}
	var failure Failure
	if errors.As(err, &failure) && failure.Outcome() == OutcomeOperationFailed {
		return newNormalReadResult(OutcomeOperationFailed, failure.Stage(), authenticated, nil)
	}
	return newNormalReadResult(OutcomeOperationFailed, StageCredentialPolicy, authenticated, nil)
}

func normalPhysicalEOF(source io.ReaderAt, offset int64) bool {
	if source == nil || offset < 0 {
		return false
	}
	var byteAtEOF [1]byte
	count, err := source.ReadAt(byteAtEOF[:], offset)
	pcv3crypto.SecureZero(byteAtEOF[:])
	return count == 0 && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF))
}
