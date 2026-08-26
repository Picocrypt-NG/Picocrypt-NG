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

// unpackAuthenticatedArchive is the sole PCV3 archive admission boundary. It
// validates the reader-minted capability before fileops can inspect the archive
// or create an extraction destination, then delegates all containment, staging,
// no-clobber, and rollback behavior to the existing extractor.
func unpackAuthenticatedArchive(
	completion *normalCompletion,
	archive *os.File,
	options fileops.UnpackOptions,
) error {
	if err := validateAuthenticatedArchive(completion, archive); err != nil {
		return err
	}
	options.ZipPath = ""
	options.ZipFile = archive
	return fileops.Unpack(options)
}

func unpackAuthenticatedArchiveWithResult(
	ctx context.Context,
	completion *normalCompletion,
	archive *os.File,
	root *os.Root,
	expectedRoot os.FileInfo,
) fileops.UnpackResult {
	if validateAuthenticatedArchive(completion, archive) != nil ||
		root == nil || expectedRoot == nil {
		return nil //nolint:nilerr // Invalid handoff inputs intentionally expose no extraction result.
	}
	return fileops.UnpackWithResult(fileops.UnpackOptions{
		ZipFile:             archive,
		ExtractDir:          root.Name(),
		ExtractRoot:         root,
		ExpectedExtractRoot: expectedRoot,
		Cancel:              func() bool { return ctx.Err() != nil },
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
