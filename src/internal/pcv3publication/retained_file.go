package pcv3publication

import (
	"fmt"
	"io"
	"os"
	"sync"
)

const retainedCopyBufferSize = 128 << 10

type retainedReader struct{ io.Reader }

type retainedWriter struct{ io.Writer }

// CopyResult is the closed result of copying one retained file to a
// caller-owned descriptor. It carries no path or raw platform error.
type CopyResult struct {
	copied            bool
	cleanupIncomplete bool
}

// Copied reports that the complete source was written, synchronized, and the
// transferred destination descriptor was closed successfully.
func (result CopyResult) Copied() bool { return result.copied }

// CleanupIncomplete reports that absence of partial plaintext at the
// destination could not be proven after a failed copy.
func (result CopyResult) CleanupIncomplete() bool { return result.cleanupIncomplete }

// RetainedFile is an opaque, one-owner capability for one durably published
// file. It retains pinned filesystem handles and exact identity, never a path
// accepted later from a caller.
type RetainedFile struct {
	mu sync.Mutex

	file       *os.File
	root       *os.Root
	parent     *os.File
	identity   os.FileInfo
	targetName string

	remove        func(*os.Root, string) error
	syncDirectory func(*os.File) error
	active        bool
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
		file.identity != nil && file.targetName != "" && file.remove != nil &&
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
		!os.SameFile(file.identity, sourceInfo) || sameIdentity {
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
	defer clear(buffer)
	written, copyErr := io.CopyBuffer(
		retainedWriter{Writer: destination},
		retainedReader{Reader: file.file},
		buffer,
	)
	plaintextWritten := written > 0
	if copyErr != nil || written != sourceInfo.Size() {
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

	cleanupIncomplete := false
	sourceInfo, err := file.file.Stat()
	if err != nil || sourceInfo == nil || !sourceInfo.Mode().IsRegular() ||
		!os.SameFile(file.identity, sourceInfo) ||
		probeIdentity(file.root, file.targetName, file.identity) != identityExpected {
		cleanupIncomplete = true
	} else if err := file.file.Close(); err != nil {
		file.file = nil
		cleanupIncomplete = true
	} else {
		file.file = nil
		if probeIdentity(file.root, file.targetName, file.identity) != identityExpected {
			cleanupIncomplete = true
		} else if err := file.remove(file.root, file.targetName); err != nil {
			cleanupIncomplete = true
		} else if err := file.syncDirectory(file.parent); err != nil {
			cleanupIncomplete = true
		}
	}
	if file.closeHandlesLocked() {
		cleanupIncomplete = true
	}
	if cleanupIncomplete {
		return ErrCleanupIncomplete
	}
	return nil
}

func (file *RetainedFile) closeHandlesLocked() (failed bool) {
	if file.file != nil {
		if err := file.file.Close(); err != nil {
			failed = true
		}
		file.file = nil
	}
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
	file.identity = nil
	file.targetName = ""
	file.remove = nil
	file.syncDirectory = nil
	return failed
}

func (file *RetainedFile) String() string { return "pcv3 retained file" }

func (file *RetainedFile) GoString() string { return file.String() }

func (file *RetainedFile) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, file.String())
}
