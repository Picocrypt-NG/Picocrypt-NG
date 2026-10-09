package pcv3

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	pcencoding "Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3publication"
	"bufio"
	"context"
	cryptorand "crypto/rand"
	"errors"
	"io"
	"os"
)

type d1CreationRequest struct {
	sourcePath          string
	destinationPath     string
	protected           []string
	expectedSource      os.FileInfo
	source              *os.File
	plaintext           io.Reader
	retainedOutput      **pcv3publication.RetainedFile
	journalPrivateStage bool
	normal              normalWriteRequest
	factors             *pcv3credential.FactorRequest
	admitter            pcv3credential.Admitter
}

type d1CreationObserver func(d1CreationBoundary, *pcv3publication.Stage) error

type d1CreationSeams struct {
	entropy     io.Reader
	codecs      *pcencoding.RSCodecs
	credentials d1CreationCredentialSession
	observe     d1CreationObserver
	createStage func(string, []string, pcv3publication.Policy) (*pcv3publication.Stage, error)
	flush       func(*bufio.Writer) error
}

func defaultD1CreationSeams() d1CreationSeams {
	codecs, _ := pcencoding.NewRSCodecs()
	return d1CreationSeams{
		entropy:     cryptorand.Reader,
		codecs:      codecs,
		credentials: withD1ProductionCredentialSession,
		observe: func(d1CreationBoundary, *pcv3publication.Stage) error {
			return nil
		},
		createStage: pcv3publication.Create,
		flush:       (*bufio.Writer).Flush,
	}
}

func composeD1OuterStage(
	ctx context.Context,
	request *d1CreationRequest,
	seams d1CreationSeams,
) (result pcv3publication.Result, returnErr error) {
	if ctx == nil || request == nil || request.sourcePath == "" || request.destinationPath == "" ||
		request.source == nil || request.plaintext == nil ||
		request.normal.suite != SuiteParanoid || request.factors == nil ||
		request.admitter == nil {
		return nil, newD1OuterFailure(StageCredentialPolicy, errInvalidD1Creation)
	}
	plan, err := planD1Write(request.normal)
	if err != nil {
		return nil, err
	}
	sameFile, err := fileops.SamePathOrFile(
		request.sourcePath,
		request.destinationPath,
	)
	if err != nil || sameFile || !validD1CreationSeams(seams) {
		return nil, newD1OuterFailure(StageCredentialPolicy, errInvalidD1Creation)
	}
	if err := ctx.Err(); err != nil {
		return nil, newD1OuterFailure(StageCancellation, err)
	}

	protected := append([]string{request.sourcePath}, request.protected...)
	stage, err := seams.createStage(
		request.destinationPath,
		protected,
		pcv3publication.PolicyNoReplace,
	)
	if err != nil {
		var publicationResult pcv3publication.Result
		if errors.As(err, &publicationResult) {
			if errors.Is(err, pcv3publication.ErrCleanupIncomplete) {
				return publicationResult, newD1OuterFailure(
					StageOutputPublication,
					pcv3publication.ErrCleanupIncomplete,
				)
			}
			return publicationResult, nil
		}
		return nil, newD1OuterFailure(StageOutputPublication, err)
	}
	defer func() {
		if cleanupErr := stage.Cleanup(); cleanupErr != nil {
			returnErr = errors.Join(
				returnErr,
				newD1OuterFailure(StageOutputPublication, cleanupErr),
			)
		}
	}()
	if err := stage.CheckCapability(); err != nil {
		return nil, newD1OuterFailure(StageOutputPublication, err)
	}
	if request.journalPrivateStage {
		if err := stage.PersistCleanupJournal(); err != nil {
			return nil, newD1OuterFailure(StageOutputPublication, err)
		}
	}
	defer func() {
		if closeErr := request.factors.Close(); closeErr != nil {
			returnErr = errors.Join(
				returnErr,
				newD1OuterFailure(StageCredentialPolicy, closeErr),
			)
		}
	}()
	observe := func(boundary d1CreationBoundary) error {
		return seams.observe(boundary, stage)
	}
	if err := observe(d1BoundaryStageCreated); err != nil {
		return nil, err
	}

	sourceInfo, err := request.source.Stat()
	if err != nil || !sourceInfo.Mode().IsRegular() || sourceInfo.Size() < 0 ||
		(request.expectedSource != nil && (!os.SameFile(request.expectedSource, sourceInfo) || request.expectedSource.Size() != sourceInfo.Size())) {
		return nil, newD1OuterFailure(StageInputIO, errInvalidD1Creation)
	}
	if _, err := request.source.Seek(0, io.SeekStart); err != nil {
		return nil, newD1OuterFailure(StageInputIO, err)
	}

	secrets, err := newD1CreationSecrets(ctx, seams.entropy, observe)
	if err != nil {
		return nil, err
	}
	defer secrets.close()
	buffered := bufio.NewWriterSize(stage.File(), 64<<10)
	err = seams.credentials(
		ctx,
		request.factors,
		secrets,
		request.admitter,
		observe,
		func(
			front d1BootstrapCredentialAccess,
			tail d1BootstrapCredentialAccess,
			outer d1OuterKeyAccess,
			normal normalWriteMaterial,
		) error {
			if err := observe(d1BoundaryFrontBootstrap); err != nil {
				return err
			}
			frontBytes, err := encodeD1Bootstrap(
				ctx,
				D1BootstrapFront,
				plan.outer.bodyLength,
				secrets.front,
				front,
				outer,
			)
			if err != nil {
				return err
			}
			defer pcv3crypto.SecureZero(frontBytes[:])
			if err := writeD1CreationExact(ctx, buffered, frontBytes[:]); err != nil {
				return err
			}
			if err := observe(d1BoundaryBody); err != nil {
				return err
			}
			completion, err := writeD1NormalBody(
				ctx,
				request.normal,
				request.plaintext,
				buffered,
				normal,
				normalWriteSeams{
					entropy: &d1CreationEntropyReader{
						ctx:      ctx,
						reader:   seams.entropy,
						observe:  observe,
						boundary: d1BoundaryInnerEntropy,
					},
					codecs: seams.codecs,
				},
				outer,
			)
			if err != nil {
				return err
			}
			if completion == nil || completion.bodyLength != plan.outer.bodyLength {
				return newD1OuterFailure(StageD1Body, errD1WriterProgress)
			}
			if err := observe(d1BoundaryTailBootstrap); err != nil {
				return err
			}
			tailBytes, err := encodeD1Bootstrap(
				ctx,
				D1BootstrapTail,
				plan.outer.bodyLength,
				secrets.tail,
				tail,
				outer,
			)
			if err != nil {
				return err
			}
			defer pcv3crypto.SecureZero(tailBytes[:])
			return writeD1CreationExact(ctx, buffered, tailBytes[:])
		},
	)
	if err != nil {
		return nil, err
	}
	if err := observe(d1BoundaryFlush); err != nil {
		return nil, err
	}
	if err := seams.flush(buffered); err != nil {
		return nil, newD1OuterFailure(StageOutputWrite, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, newD1OuterFailure(StageCancellation, err)
	}
	if err := observe(d1BoundaryPublish); err != nil {
		return nil, err
	}
	if request.retainedOutput != nil {
		publication, retained := stage.PublishWriteRetained(ctx)
		*request.retainedOutput = retained
		return publication, nil
	}
	return stage.PublishWrite(ctx), nil
}

func validD1CreationSeams(seams d1CreationSeams) bool {
	return seams.credentials != nil && seams.observe != nil &&
		seams.createStage != nil && seams.flush != nil &&
		validNormalWriteSeams(normalWriteSeams{
			entropy: seams.entropy,
			codecs:  seams.codecs,
		})
}
