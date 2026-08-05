package pcv3

import (
	"Picocrypt-NG/internal/fileops"
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
	payloadKind, authenticated := completion.authenticatedPayloadKind()
	if !authenticated || payloadKind != PayloadKindArchive {
		return errArchiveHandoffDenied
	}
	if archive == nil {
		return errArchivePlaintextUnavailable
	}
	options.ZipPath = ""
	options.ZipFile = archive
	return fileops.Unpack(options)
}
