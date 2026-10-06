package pcv3

import (
	"Picocrypt-NG/internal/fileops"
	"context"
	"errors"
	"os"
)

var (
	errArchiveHandoffDenied        = errors.New("pcv3: archive extraction requires a fully authenticated archive payload")
	errArchivePlaintextUnavailable = errors.New("pcv3: authenticated archive plaintext unavailable")
)

func unpackAuthenticatedArchiveWithResult(
	ctx context.Context,
	completion *normalCompletion,
	archive *os.File,
	root *os.Root,
	expectedRoot os.FileInfo,
	review func(fileops.ZIPSummary) error,
) fileops.UnpackResult {
	if validateAuthenticatedArchive(completion, archive) != nil ||
		root == nil || expectedRoot == nil {
		return nil //nolint:nilerr // Invalid handoff inputs intentionally expose no extraction result.
	}
	return unpackAuthenticatedZIPWithResult(ctx, archive, root, expectedRoot, review)
}

// The caller owns a sealed archive handoff, either format-declared or explicitly
// prepared from fully authenticated raw ZIP bytes.
func unpackAuthenticatedZIPWithResult(ctx context.Context, archive *os.File, root *os.Root, expectedRoot os.FileInfo, review func(fileops.ZIPSummary) error) fileops.UnpackResult {
	if archive == nil || root == nil || expectedRoot == nil {
		return nil
	}
	return fileops.UnpackWithResult(fileops.UnpackOptions{
		ZipFile:             archive,
		ExtractDir:          root.Name(),
		ExtractRoot:         root,
		ExpectedExtractRoot: expectedRoot,
		Cancel:              func() bool { return ctx.Err() != nil },
		Review:              review,
	})
}

func validateAuthenticatedArchive(
	completion *normalCompletion,
	archive *os.File,
) error {
	payloadKind, authenticated := completion.authenticatedPayloadKind()
	if !authenticated || payloadKind != PayloadKindArchive {
		return errArchiveHandoffDenied
	}
	if archive == nil {
		return errArchivePlaintextUnavailable
	}
	return nil
}
