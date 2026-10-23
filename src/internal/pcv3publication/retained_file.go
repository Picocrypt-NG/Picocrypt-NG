package pcv3publication

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/secret"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

const retainedCopyBufferSize = 128 << 10

type retainedReader struct{ io.Reader }

type retainedWriter struct{ io.Writer }

// CopyResult is the closed result of copying one retained file to a
// caller-owned descriptor. It carries no path or raw platform error.
type CopyResult struct {
	copied                     bool
	cleanupIncomplete          bool
	cleanupDurabilityUncertain bool
}

// Copied reports that the complete source was written under the copy method's
// destination contract.
func (result CopyResult) Copied() bool { return result.copied }

// CleanupIncomplete reports that cleanup of an operation-owned source or
// partial destination could not be proven.
func (result CopyResult) CleanupIncomplete() bool { return result.cleanupIncomplete }

// CleanupDurabilityUncertain reports confirmed live removal without a successful
// directory barrier. It does not imply that owned bytes remain accessible.
func (result CopyResult) CleanupDurabilityUncertain() bool { return result.cleanupDurabilityUncertain }

func copyCleanupResult(copied bool, cleanupErr error) CopyResult {
	return CopyResult{
		copied:                     copied,
		cleanupIncomplete:          errors.Is(cleanupErr, ErrCleanupIncomplete),
		cleanupDurabilityUncertain: errors.Is(cleanupErr, ErrCleanupDurabilityUncertain),
	}
}

// RetainedFile is an opaque, one-owner capability for one proven published
// file (durable or durability-uncertain). It retains pinned filesystem handles and exact identity, never a path
// accepted later from a caller.
type RetainedFile struct {
	mu sync.Mutex

	file        *os.File
	identityPin *os.File
	lease       *os.File
	root        *os.Root
	parent      *os.File
	identity    os.FileInfo
	sha256      [sha256.Size]byte
	digestReady bool
	targetName  string

	remove                     func(*os.Root, string) error
	syncDirectory              func(*os.File) error
	active                     bool
	cleanupIncomplete          bool
	cleanupDurabilityUncertain bool
}

// Live reports whether this exact capability can still copy or remove its
// retained file. It grants no filesystem information.
func (file *RetainedFile) Live() bool {
	if file == nil {
		return false
	}
	file.mu.Lock()
	defer file.mu.Unlock()
	return file.liveLocked()
}

func (file *RetainedFile) liveLocked() bool {
	return file.active && file.file != nil && file.root != nil && file.parent != nil &&
		file.identity != nil && file.digestReady && file.targetName != "" && file.remove != nil &&
		file.syncDirectory != nil
}

// CopyTo takes ownership of destination. A successful copy does not remove or
// consume the retained source; the owner must separately call RemoveExact.
// Failure attempts to truncate any bytes written to destination and leaves the
// retained source live.
func (file *RetainedFile) CopyTo(destination *os.File) CopyResult {
	if file == nil {
		closeUnusedDestination(destination)
		return CopyResult{}
	}
	file.mu.Lock()
	defer file.mu.Unlock()
	if !file.liveLocked() || destination == nil {
		closeUnusedDestination(destination)
		return CopyResult{}
	}

	sourceInfo, sourceErr := file.file.Stat()
	destinationInfo, destinationErr := destination.Stat()
	sameIdentity := sourceInfo != nil && destinationInfo != nil &&
		os.SameFile(sourceInfo, destinationInfo)
	if sourceErr != nil || destinationErr != nil || sourceInfo == nil || destinationInfo == nil ||
		!sourceInfo.Mode().IsRegular() || !destinationInfo.Mode().IsRegular() ||
		sourceInfo.Size() != file.identity.Size() || !os.SameFile(file.identity, sourceInfo) || sameIdentity {
		closeUnusedDestination(destination)
		return CopyResult{cleanupIncomplete: sameIdentity}
	}
	if _, err := file.file.Seek(0, io.SeekStart); err != nil {
		closeUnusedDestination(destination)
		return CopyResult{}
	}
	if err := destination.Truncate(0); err != nil {
		closeUnusedDestination(destination)
		return CopyResult{}
	}
	if _, err := destination.Seek(0, io.SeekStart); err != nil {
		return failedRetainedCopy(destination, false)
	}

	buffer := make([]byte, retainedCopyBufferSize)
	defer secret.SecureZero(buffer)
	digest := sha256.New()
	written, copyErr := io.CopyBuffer(
		io.MultiWriter(retainedWriter{Writer: destination}, digest),
		retainedReader{Reader: file.file},
		buffer,
	)
	plaintextWritten := written > 0
	if copyErr != nil || written != sourceInfo.Size() || !bytes.Equal(digest.Sum(nil), file.sha256[:]) {
		return failedRetainedCopy(destination, plaintextWritten)
	}
	after, err := file.file.Stat()
	if err != nil || after == nil || !after.Mode().IsRegular() ||
		!os.SameFile(file.identity, after) || after.Size() != sourceInfo.Size() {
		return failedRetainedCopy(destination, plaintextWritten)
	}
	if err := destination.Sync(); err != nil {
		return failedRetainedCopy(destination, plaintextWritten)
	}
	if err := destination.Close(); err != nil {
		return failedRetainedCopy(destination, plaintextWritten)
	}
	return CopyResult{copied: true}
}

// StreamTo consumes the retained source and writes its exact open descriptor
// to destination. On Unix the owned pathname is unlinked before the first
// write; cancellation closes destination to interrupt a blocked stream.
func (file *RetainedFile) StreamTo(ctx context.Context, destination *os.File) (result CopyResult) {
	if file == nil {
		return CopyResult{}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	file.mu.Lock()
	defer file.mu.Unlock()
	if !file.liveLocked() {
		return CopyResult{}
	}
	file.active = false
	if destination == nil {
		return copyCleanupResult(false, file.removeExactLocked())
	}

	sourceInfo, err := file.file.Stat()
	if err != nil || sourceInfo == nil || !sourceInfo.Mode().IsRegular() || sourceInfo.Size() < 0 ||
		sourceInfo.Size() != file.identity.Size() || !os.SameFile(file.identity, sourceInfo) {
		return copyCleanupResult(false, file.removeExactLocked())
	}
	var cleanupErr error
	removed := false
	if runtime.GOOS != "windows" {
		if !safePublishedRemoval(file.parent, file.identityPin) || probeIdentity(file.root, file.targetName, file.identity) != identityExpected ||
			removeOwnedFile(file.root, file.targetName, file.identityPin, file.remove) != nil {
			cleanupErr = ErrCleanupIncomplete
		} else {
			removed = true
		}
	}
	defer func() {
		if runtime.GOOS == "windows" {
			cleanupErr = errors.Join(cleanupErr, file.removeExactLocked())
		} else {
			cleanupErr = errors.Join(cleanupErr, file.finishRemovalLocked(removed))
		}
		result.cleanupIncomplete = errors.Is(cleanupErr, ErrCleanupIncomplete)
		result.cleanupDurabilityUncertain = errors.Is(cleanupErr, ErrCleanupDurabilityUncertain)
	}()
	if _, err := file.file.Seek(0, io.SeekStart); err != nil {
		return CopyResult{}
	}
	buffer := make([]byte, retainedCopyBufferSize)
	defer secret.SecureZero(buffer)
	preDigest := sha256.New()
	remaining := sourceInfo.Size()
	for {
		if err := ctx.Err(); err != nil {
			_ = destination.Close()
			return CopyResult{}
		}
		if remaining == 0 {
			break
		}
		want := int64(len(buffer))
		if remaining < want {
			want = remaining
		}
		count, readErr := io.ReadFull(file.file, buffer[:want])
		if readErr != nil {
			return CopyResult{}
		}
		_, _ = preDigest.Write(buffer[:count])
		remaining -= int64(count)
	}
	if !bytes.Equal(preDigest.Sum(nil), file.sha256[:]) {
		secret.SecureZero(buffer)
		return CopyResult{}
	}
	if _, err := file.file.Seek(0, io.SeekStart); err != nil {
		secret.SecureZero(buffer)
		return CopyResult{}
	}
	secret.SecureZero(buffer)

	type streamResult struct {
		written int64
		digest  []byte
		err     error
	}
	done := make(chan streamResult, 1)
	source := file.file
	go func() {
		streamed := func() streamResult {
			buffer := make([]byte, retainedCopyBufferSize)
			defer secret.SecureZero(buffer)
			digest := sha256.New()
			written, copyErr := io.CopyBuffer(
				io.MultiWriter(retainedWriter{Writer: destination}, digest),
				retainedReader{Reader: source},
				buffer,
			)
			return streamResult{written: written, digest: digest.Sum(nil), err: copyErr}
		}()
		// Finish owned scratch cleanup before publishing copy completion.
		done <- streamed
	}()
	var streamed streamResult
	cancelled := false
	select {
	case streamed = <-done:
	case <-ctx.Done():
		_ = destination.Close()
		streamed.err = ctx.Err()
		cancelled = true
	}
	copied := !cancelled && streamed.err == nil && streamed.written == sourceInfo.Size() &&
		bytes.Equal(streamed.digest, file.sha256[:])
	if !cancelled {
		after, statErr := file.file.Stat()
		if statErr != nil || after == nil || !after.Mode().IsRegular() ||
			after.Size() != sourceInfo.Size() || !os.SameFile(file.identity, after) {
			copied = false
		}
	}
	return CopyResult{copied: copied}
}

func failedRetainedCopy(destination *os.File, plaintextWritten bool) CopyResult {
	if destination == nil {
		return CopyResult{cleanupIncomplete: plaintextWritten}
	}
	cleanupIncomplete := false
	if plaintextWritten {
		if err := destination.Truncate(0); err != nil {
			cleanupIncomplete = true
		} else if err := destination.Sync(); err != nil {
			cleanupIncomplete = true
		}
	}
	if err := destination.Close(); err != nil && plaintextWritten {
		cleanupIncomplete = true
	}
	return CopyResult{cleanupIncomplete: cleanupIncomplete}
}

func closeUnusedDestination(destination *os.File) {
	if destination != nil {
		_ = destination.Close()
	}
}

// SplitRetainedWithResult consumes one retained capability and splits only its
// exact published file. It removes the full source only after durable chunks;
// an unconfirmed final directory barrier preserves both complete chunks and source.
func SplitRetainedWithResult(retained *RetainedFile, options fileops.SplitOptions) (fileops.SplitState, error) {
	if retained == nil {
		return fileops.SplitFailed, ErrCleanupIncomplete
	}
	retained.mu.Lock()
	defer retained.mu.Unlock()
	if !retained.liveLocked() {
		return fileops.SplitFailed, ErrCleanupIncomplete
	}
	retained.active = false

	options.InputPath = filepath.Join(retained.root.Name(), retained.targetName)
	sourceInfo, sourceErr := retained.file.Stat()
	parentInfo, parentErr := retained.parent.Stat()
	if sourceErr != nil || parentErr != nil || sourceInfo == nil || parentInfo == nil ||
		!sourceInfo.Mode().IsRegular() || !parentInfo.IsDir() ||
		retained.identity.Size() != sourceInfo.Size() || !os.SameFile(retained.identity, sourceInfo) {
		return fileops.SplitFailed, errors.Join(sourceErr, parentErr, ErrCleanupIncomplete, retained.closeHandlesLocked())
	}
	options.ExpectedInput = sourceInfo
	options.ExpectedDirectory = parentInfo
	options.ExpectedSHA256 = &retained.sha256
	options.RequireDirectorySync = true
	if options.MinimumChunkSize < 4 {
		options.MinimumChunkSize = 4
	}
	completion, splitErr := fileops.SplitPinnedWithResult(options, retained.file, retained.root, retained.parent, retained.syncDirectory)
	if splitErr == nil && len(completion.Chunks) == 0 {
		splitErr = errors.New("pcv3 publication: retained split produced no chunks")
	}
	if splitErr != nil {
		return fileops.SplitFailed, errors.Join(splitErr, retained.closeHandlesLocked())
	}
	if completion.State == fileops.SplitCompleteDurabilityUncertain {
		return completion.State, retained.closeHandlesLocked()
	}
	return completion.State, retained.removeExactLocked()
}

// RemoveExact consumes the capability before effects and removes only while
// the pinned target name still resolves to the exact retained regular file.
func (file *RetainedFile) RemoveExact() error {
	if file == nil {
		return ErrCleanupIncomplete
	}
	file.mu.Lock()
	defer file.mu.Unlock()
	if !file.liveLocked() {
		return ErrCleanupIncomplete
	}
	file.active = false
	return file.removeExactLocked()
}

func (file *RetainedFile) removeExactLocked() error {
	removed := false
	sourceInfo, err := file.file.Stat()
	if safePublishedRemoval(file.parent, file.identityPin) && err == nil && sourceInfo != nil && sourceInfo.Mode().IsRegular() &&
		os.SameFile(file.identity, sourceInfo) &&
		probeIdentity(file.root, file.targetName, file.identity) == identityExpected {
		if probeIdentity(file.root, file.targetName, file.identity) == identityExpected &&
			removeOwnedFile(file.root, file.targetName, file.identityPin, file.remove) == nil {
			removed = true
		}
	}
	var cleanupErr error
	if !removed {
		cleanupErr = ErrCleanupIncomplete
	}
	return errors.Join(cleanupErr, file.finishRemovalLocked(removed))
}

func (file *RetainedFile) finishRemovalLocked(removed bool) error {
	var cleanupErr error
	if file.closeFileHandlesLocked() {
		cleanupErr = ErrCleanupIncomplete
	}
	if removed {
		if _, err := file.root.Lstat(file.targetName); !errors.Is(err, os.ErrNotExist) {
			cleanupErr = errors.Join(cleanupErr, ErrCleanupIncomplete)
		} else if file.syncDirectory(file.parent) != nil {
			cleanupErr = errors.Join(cleanupErr, ErrCleanupDurabilityUncertain)
		}
	}
	return errors.Join(cleanupErr, file.closeHandlesLocked())
}

func (file *RetainedFile) closeFileHandlesLocked() (failed bool) {
	if file.file != nil {
		if err := file.file.Close(); err != nil {
			failed = true
		}
		file.file = nil
	}
	if file.identityPin != nil {
		if err := file.identityPin.Close(); err != nil {
			failed = true
		}
		file.identityPin = nil
	}
	return failed
}

func (file *RetainedFile) closeHandlesLocked() error {
	failed := file.closeFileHandlesLocked() || file.cleanupIncomplete
	if file.parent != nil {
		if err := file.parent.Close(); err != nil {
			failed = true
		}
		file.parent = nil
	}
	if file.root != nil {
		if err := file.root.Close(); err != nil {
			failed = true
		}
		file.root = nil
	}
	if file.lease != nil {
		if err := file.lease.Close(); err != nil {
			failed = true
		}
		file.lease = nil
	}
	file.identity = nil
	clear(file.sha256[:])
	file.digestReady = false
	file.targetName = ""
	file.remove = nil
	file.syncDirectory = nil
	var cleanupErr error
	if failed {
		cleanupErr = ErrCleanupIncomplete
	}
	if file.cleanupDurabilityUncertain {
		cleanupErr = errors.Join(cleanupErr, ErrCleanupDurabilityUncertain)
	}
	return cleanupErr
}

func (file *RetainedFile) String() string { return "pcv3 retained file" }

func (file *RetainedFile) GoString() string { return file.String() }

func (file *RetainedFile) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, file.String())
}

// Close releases custody without removing the published file.
func (file *RetainedFile) Close() error {
	if file == nil {
		return nil
	}
	file.mu.Lock()
	defer file.mu.Unlock()
	file.active = false
	return file.closeHandlesLocked()
}
