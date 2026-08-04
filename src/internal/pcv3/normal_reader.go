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
	completed := false
	// This defer is registered before every later cleanup defer so it observes
	// their panics, discards uncommitted plaintext, and preserves the panic.
	defer func() {
		if recovered := recover(); recovered != nil {
			if sink != nil {
				sink.abortUncommitted()
			}
			panic(recovered)
		}
		if !completed && sink != nil {
			sink.abortUncommitted()
		}
	}()
	if closer, ok := provider.(capsuleCredentialProviderCloser); ok {
		defer closer.close()
	}
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
		return normalTailReadResult(err, auth.AuthenticatedCapsules()), nil
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
	_, tailErr := readExactAt(source, auth.geometry.backupCapsuleOffset, finalSuffix[:], StageTailGeometry)
	if err := ctx.Err(); err != nil {
		return newNormalReadResult(OutcomeOperationFailed, StageCancellation, auth.AuthenticatedCapsules(), nil), nil
	}
	if tailErr != nil {
		return normalTailReadResult(tailErr, auth.AuthenticatedCapsules()), nil
	}
	eofState := normalPhysicalEOF(source, sourceSize)
	if err := ctx.Err(); err != nil {
		return newNormalReadResult(OutcomeOperationFailed, StageCancellation, auth.AuthenticatedCapsules(), nil), nil
	}
	if !bytes.Equal(suffix[:], finalSuffix[:]) || sourceSize != auth.geometry.fileSize || eofState == normalEOFFailure {
		return newNormalReadResult(OutcomeAuthenticationFailed, StageTailGeometry, auth.AuthenticatedCapsules(), nil), nil
	}
	if eofState == normalEOFOperation {
		return newNormalReadResult(OutcomeOperationFailed, StageInputIO, auth.AuthenticatedCapsules(), nil), nil
	}

	comment := metadata.commentBytes()
	defer pcv3crypto.SecureZero(comment)
	outcome := OutcomeSuccess
	stage := StageNone
	if degradedStage != StageNone {
		outcome = OutcomeAuthenticatedDegraded
		stage = degradedStage
	}
	result := newNormalReadResult(outcome, stage, auth.AuthenticatedCapsules(), comment)
	completion := &normalCompletion{}
	completed = true
	return result, completion
}

func normalTailReadResult(err error, authenticated int) *normalReadResult {
	var failure Failure
	if errors.As(err, &failure) && failure.Outcome() == OutcomeOperationFailed {
		return newNormalReadResult(OutcomeOperationFailed, failure.Stage(), authenticated, nil)
	}
	return newNormalReadResult(OutcomeAuthenticationFailed, StageTailGeometry, authenticated, nil)
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

type normalEOFState uint8

const (
	normalEOFExact normalEOFState = iota + 1
	normalEOFFailure
	normalEOFOperation
)

func normalPhysicalEOF(source io.ReaderAt, offset int64) normalEOFState {
	if source == nil || offset < 0 {
		return normalEOFOperation
	}
	var byteAtEOF [1]byte
	defer pcv3crypto.SecureZero(byteAtEOF[:])
	for range 2 {
		count, err := source.ReadAt(byteAtEOF[:], offset)
		if count < 0 || count > len(byteAtEOF) {
			return normalEOFOperation
		}
		if count != 0 {
			return normalEOFFailure
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return normalEOFExact
		}
		if err != nil {
			return normalEOFOperation
		}
	}
	return normalEOFOperation
}
