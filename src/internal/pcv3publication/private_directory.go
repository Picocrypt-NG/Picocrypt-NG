package pcv3publication

import (
	"os"
	"runtime"
)

// retirePrivateDirectory never follows a replacement name in the public parent.
// A parent writable by another user cannot support an identity-conditional rmdir;
// preserve that namespace entry and report uncertainty even when it is empty.
func (stage *Stage) retirePrivateDirectory() bool {
	if stage.sourceRoot == nil && stage.sourceParent == nil {
		return true
	}
	clean := true
	if runtime.GOOS == "windows" {
		clean = removePrivateDirectoryHandle(stage.sourceParent) == nil
	} else if (stage.journaled && stage.cleanupDisposition == cleanupUncertain) || stage.sourceRoot == nil || stage.sourceParent == nil || stage.root == nil || !trustedCleanupParent(stage.parent) {
		clean = false
	} else {
		current, err := stage.root.Lstat(stage.sourceName)
		if err != nil || current == nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(stage.sourceInfo, current) {
			clean = false
		} else if err := stage.root.Remove(stage.sourceName); err != nil {
			clean = false
		} else if stage.operations.syncDirectory(stage.parent) != nil {
			clean = false
		}
	}
	if stage.sourceParent != nil {
		if stage.sourceParent.Close() != nil {
			clean = false
		}
		stage.sourceParent = nil
	}
	if stage.sourceRoot != nil {
		if stage.sourceRoot.Close() != nil {
			clean = false
		}
		stage.sourceRoot = nil
	}
	if runtime.GOOS == "windows" && stage.operations.syncDirectory(stage.parent) != nil {
		clean = false
	}
	return clean
}
