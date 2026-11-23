package fileops

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var (
	unpackPublishFn          = publishUnpackFile
	unpackCopyFn             = io.Copy
	unpackRemoveCopyTargetFn = removeUnpackCopyTarget
)

func (entry *stagedUnpackEntry) checkStage(root *os.Root) error {
	info, err := root.Lstat(entry.stageName)
	if err != nil {
		return fmt.Errorf("inspect stage for %s: %w", entry.outPath, err)
	}
	if !info.Mode().IsRegular() || !os.SameFile(entry.info, info) {
		return fmt.Errorf("stage path changed before publishing %s", entry.outPath)
	}
	return nil
}

func publishStagedUnpackEntry(
	stageRoot *os.Root, stageDirectory *os.File, dirs *unpackDirectories, entry *stagedUnpackEntry, cancel CancelFunc,
) (published bool, durabilityErr, retErr error) {
	parentName, targetName := filepath.Dir(entry.targetName), filepath.Base(entry.targetName)
	targetRoot, err := dirs.open(parentName, false)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		if err := dirs.close(targetRoot); err != nil {
			retErr = errors.Join(retErr, err, ErrUnpackCleanupIncomplete)
		}
	}()
	targetDirectory, err := targetRoot.Open(".")
	if err != nil {
		return false, nil, fmt.Errorf("open extraction destination parent %s: %w", entry.outPath, err)
	}
	defer func() {
		if err := targetDirectory.Close(); err != nil {
			retErr = errors.Join(retErr, err, ErrUnpackCleanupIncomplete)
		}
	}()
	if err := entry.checkStage(stageRoot); err != nil {
		return false, nil, err
	}
	if err := dirs.verify(parentName); err != nil {
		return false, nil, err
	}

	published, stageConsumed, nativeErr := unpackPublishFn(
		stageDirectory, targetDirectory, entry.stageName, targetName, entry.info,
	)
	if stageConsumed {
		entry.stageName = ""
	}
	outputInfo := entry.info
	switch {
	case published && nativeErr != nil:
		return true, nil, fmt.Errorf("publish extraction output %s: %w", entry.outPath, nativeErr)
	case !published && errors.Is(nativeErr, errors.ErrUnsupported) && !errors.Is(nativeErr, ErrUnpackCleanupIncomplete):
		outputInfo, published, durabilityErr, err = copyStagedUnpackEntry(
			stageRoot, targetRoot, targetDirectory, targetName, entry, cancel,
		)
		if err != nil {
			return published, durabilityErr, err
		}
	case !published:
		return false, nil, fmt.Errorf("publish extraction output %s: %w", entry.outPath, nativeErr)
	}

	current, err := targetRoot.Lstat(targetName)
	if err != nil {
		return true, durabilityErr, fmt.Errorf("inspect published extraction output %s: %w", entry.outPath, err)
	}
	if !current.Mode().IsRegular() || !os.SameFile(outputInfo, current) {
		return true, durabilityErr, fmt.Errorf("published extraction output changed: %s", entry.outPath)
	}
	if err := dirs.verify(parentName); err != nil {
		return true, durabilityErr, err
	}
	if proven, err := entry.cleanup(stageRoot); !proven || err != nil {
		return true, durabilityErr, errors.Join(err, ErrUnpackCleanupIncomplete)
	}
	return true, durabilityErr, nil
}

func copyStagedUnpackEntry(
	stageRoot, targetRoot *os.Root, targetDirectory *os.File, targetName string, entry *stagedUnpackEntry, cancel CancelFunc,
) (info os.FileInfo, published bool, durabilityErr, retErr error) {
	stage, err := stageRoot.Open(entry.stageName)
	if err != nil {
		return nil, false, nil, fmt.Errorf("open stage for %s: %w", entry.outPath, err)
	}
	defer func() {
		if err := stage.Close(); err != nil {
			retErr = errors.Join(retErr, err, ErrUnpackCleanupIncomplete)
		}
	}()
	stageInfo, err := stage.Stat()
	if err != nil || !stageInfo.Mode().IsRegular() || !os.SameFile(entry.info, stageInfo) {
		return nil, false, nil, errors.Join(fmt.Errorf("stage changed before copying %s", entry.outPath), err)
	}

	if cancel != nil && cancel() {
		return nil, false, nil, errZIPCancelled
	}
	target, err := createUnpackCopyTarget(targetRoot, targetDirectory, targetName)
	if err != nil {
		return nil, false, nil, fmt.Errorf("create extraction destination %s: %w", entry.outPath, err)
	}
	published = true
	defer func() {
		removed := false
		if retErr != nil {
			if err := unpackRemoveCopyTargetFn(target); err == nil {
				removed = true
			} else if !errors.Is(err, errors.ErrUnsupported) {
				retErr = errors.Join(retErr, fmt.Errorf("remove incomplete extraction output %s: %w", entry.outPath, err))
			}
		}
		if err := target.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close extraction destination %s: %w", entry.outPath, err), ErrUnpackCleanupIncomplete)
		} else if removed {
			published = false
		}
	}()
	info, err = target.Stat()
	if err != nil {
		return nil, true, nil, fmt.Errorf("inspect extraction destination %s: %w", entry.outPath, err)
	}
	var dst io.Writer = target
	if cancel != nil {
		dst = &zipCancelWriter{Writer: target, cancel: cancel}
	}
	if _, err := unpackCopyFn(dst, stage); err != nil {
		return nil, true, nil, fmt.Errorf("copy staged output %s: %w", entry.outPath, err)
	}
	if err := target.Sync(); err != nil {
		durabilityErr = fmt.Errorf("sync extraction destination %s: %w", entry.outPath, err)
	}
	return info, true, durabilityErr, nil
}
