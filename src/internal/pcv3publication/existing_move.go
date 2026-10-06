package pcv3publication

import (
	"Picocrypt-NG/internal/fileops"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ExistingFileMoveState describes custody of a completed app-private input.
// Only ExistingFilePublished grants custody of the target's original inode.
type ExistingFileMoveState uint8

const (
	ExistingFileNotPublished ExistingFileMoveState = iota
	ExistingFilePublished
	ExistingFileMoveIndeterminate
)

// MoveExistingNoReplace moves an already completed regular file inside one
// pinned directory. It never copies bytes, replaces a target, or removes files.
// The caller retains cleanup ownership: a published state remains significant
// even with an error, including a descriptor-close error after the move.
// This input-copy operation does not promise crash durability.
func MoveExistingNoReplace(parentPath, sourceName, targetName string, device, inode uint64) (ExistingFileMoveState, error) {
	return moveExistingNoReplace(parentPath, sourceName, targetName, device, inode, nativeOperations())
}

func moveExistingNoReplace(parentPath, sourceName, targetName string, device, inode uint64, operations platformOperations) (state ExistingFileMoveState, retErr error) {
	validName := func(name string) bool {
		return name != "" && name != "." && name != ".." && filepath.Base(name) == name &&
			!strings.ContainsAny(name, "/\\\x00")
	}
	if !filepath.IsAbs(parentPath) || filepath.Clean(parentPath) != parentPath ||
		!validName(sourceName) || !validName(targetName) || sourceName == targetName || operations.atomicPublish == nil {
		return ExistingFileNotPublished, os.ErrInvalid
	}
	root, err := fileops.OpenRootNoSymlink(parentPath)
	if err != nil {
		return ExistingFileNotPublished, err
	}
	defer func() { retErr = errors.Join(retErr, root.Close()) }()
	parent, err := root.Open(".")
	if err != nil {
		return ExistingFileNotPublished, err
	}
	defer func() { retErr = errors.Join(retErr, parent.Close()) }()
	parentInfo, err := parent.Stat()
	if err != nil {
		return ExistingFileNotPublished, err
	}
	parentCurrent := func() bool {
		current, err := os.Lstat(parentPath)
		return err == nil && current.IsDir() && current.Mode()&os.ModeSymlink == 0 && os.SameFile(parentInfo, current)
	}
	info, err := root.Lstat(sourceName)
	if err != nil {
		return ExistingFileNotPublished, err
	}
	if !existingMoveIdentityMatches(info, device, inode) {
		return ExistingFileNotPublished, errors.New("input copy identity changed")
	}
	source, err := root.Open(sourceName)
	if err != nil {
		return ExistingFileNotPublished, err
	}
	closeSource := operations.closeStage
	if closeSource == nil {
		closeSource = (*os.File).Close
	}
	defer func() { retErr = errors.Join(retErr, closeSource(source)) }()
	opened, err := source.Stat()
	if err != nil {
		return ExistingFileNotPublished, err
	}
	if !os.SameFile(info, opened) || !parentCurrent() || probeIdentity(root, sourceName, info) != identityExpected {
		return ExistingFileNotPublished, errors.New("input copy binding changed")
	}
	if _, err := root.Lstat(targetName); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			err = os.ErrExist
		}
		return ExistingFileNotPublished, err
	}
	atomicErr := operations.atomicPublish(parent, sourceName, targetName, PolicyNoReplace)
	// A refused collision grants no target ownership, even if the target is an
	// alias of our source. Identity alone must not authorize deleting that name.
	if errors.Is(atomicErr, os.ErrExist) {
		return ExistingFileNotPublished, atomicErr
	}
	sourceProbe := probeIdentity(root, sourceName, info)
	targetProbe := probeIdentity(root, targetName, info)
	if parentCurrent() && (sourceProbe == identityMissing || sourceProbe == identityOther) && targetProbe == identityExpected {
		return ExistingFilePublished, atomicErr
	}
	if atomicErr != nil && sourceProbe == identityExpected && targetProbe != identityExpected && targetProbe != identityUnknown {
		return ExistingFileNotPublished, atomicErr
	}
	return ExistingFileMoveIndeterminate, errors.Join(atomicErr, errors.New("input copy publication indeterminate"))
}
