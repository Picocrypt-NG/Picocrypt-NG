//go:build linux && !android

package pcv3publication

import (
	"Picocrypt-NG/internal/fileops"
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// CleanupOrphanedStages inspects only the selected destination. It removes
// private stages proven orphaned by the v3 journal and an exclusive kernel
// lease. Live operations, legacy records, and uncertain identities grant no
// deletion authority. Already-published targets are always preserved.
// If both recorded names are missing after an uncertain partial recovery, the
// journal remains incomplete; absence does not prove where its owned object went.
// protectedFiles are borrowed, live regular-file or directory descriptors for
// every selected input and keyfile; callers must retain them throughout this call.
func CleanupOrphanedStages(parentPath string, protectedFiles []*os.File) (CleanupJournalState, error) {
	return cleanupOrphanedStagesWithOperations(parentPath, protectedFiles, nativeJournalCleanupOperations())
}

type orphanCleanup struct {
	root       *os.Root
	parent     *os.File
	identity   os.FileInfo
	path       string
	protected  []os.FileInfo
	operations journalCleanupOperations
}

func cleanupOrphanedStagesWithOperations(parentPath string, protectedFiles []*os.File, operations journalCleanupOperations) (CleanupJournalState, error) {
	if parentPath == "" || operations.remove == nil || operations.syncDirectory == nil {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	protected := make([]os.FileInfo, 0, len(protectedFiles))
	for _, file := range protectedFiles {
		if file == nil {
			return CleanupJournalIncomplete, ErrCleanupIncomplete
		}
		info, err := file.Stat()
		if err != nil || info == nil || (!info.Mode().IsRegular() && !info.IsDir()) {
			return CleanupJournalIncomplete, ErrCleanupIncomplete
		}
		protected = append(protected, info)
	}
	root, err := fileops.OpenRootNoSymlink(parentPath)
	if err != nil {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	defer root.Close()
	parent, err := root.Open(".")
	if err != nil {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	defer parent.Close()
	info, err := parent.Stat()
	rootInfo, rootErr := root.Stat(".")
	if err != nil || rootErr != nil || info == nil || !os.SameFile(info, rootInfo) {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	cleanup := orphanCleanup{root: root, parent: parent, identity: info, path: parentPath, protected: protected, operations: operations}
	if !cleanup.parentCurrent() {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	protectedParent, err := protectedDirectoryAncestor(parent, protected)
	if err != nil {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	state := CleanupJournalAbsent
	incomplete, active := false, false
	// Deletions can invalidate directory iteration. A second, read-only pass
	// refuses residual orphans before reporting that cleanup is complete.
	for pass := range 2 {
		if _, err := parent.Seek(0, io.SeekStart); err != nil {
			return CleanupJournalIncomplete, ErrCleanupIncomplete
		}
		for {
			entries, readErr := parent.ReadDir(128)
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return CleanupJournalIncomplete, ErrCleanupIncomplete
			}
			for _, entry := range entries {
				name := entry.Name()
				if !strings.HasPrefix(name, stageNamePrefix) {
					continue
				}
				if protectedParent || !strings.HasPrefix(name, stageNamePrefix+"private-") {
					incomplete = true
					continue
				}
				candidateState, err := cleanup.directory(name, pass == 0)
				if err != nil {
					incomplete = true
					continue
				}
				if candidateState == CleanupJournalActive {
					active = true
				} else if candidateState == CleanupJournalCleaned {
					state = CleanupJournalCleaned
				}
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
		}
	}
	if incomplete || !cleanup.parentCurrent() {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	if active {
		return CleanupJournalActive, nil
	}
	return state, nil
}

func (cleanup *orphanCleanup) parentCurrent() bool {
	if !trustedCleanupParent(cleanup.parent) {
		return false
	}
	info, err := os.Lstat(cleanup.path) //nolint:gosec // G703: metadata-only identity check of the selected destination; all effects use its pinned root.
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && os.SameFile(cleanup.identity, info)
}

func protectedIdentity(info os.FileInfo, protected []os.FileInfo) bool {
	for _, selected := range protected {
		if os.SameFile(info, selected) {
			return true
		}
	}
	return false
}

// Walk only pinned parent metadata, never directory contents. A selected source
// directory protects its complete subtree even when the destination is nested.
func protectedDirectoryAncestor(parent *os.File, protected []os.FileInfo) (bool, error) {
	current, err := duplicateIdentityFile(parent)
	if err != nil {
		return false, err
	}
	defer func() { _ = current.Close() }()
	for {
		info, err := current.Stat()
		if err != nil {
			return false, err
		}
		if protectedIdentity(info, protected) {
			return true, nil
		}
		fd, err := unix.Openat(int(current.Fd()), "..", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return false, err
		}
		next := os.NewFile(uintptr(fd), "pcv3 cleanup ancestor")
		nextInfo, err := next.Stat()
		if err != nil {
			_ = next.Close()
			return false, err
		}
		if os.SameFile(info, nextInfo) {
			return false, next.Close()
		}
		if err := current.Close(); err != nil {
			_ = next.Close()
			return false, err
		}
		current = next
	}
}

func (cleanup *orphanCleanup) directory(name string, allowDelete bool) (CleanupJournalState, error) {
	info, err := cleanup.root.Lstat(name)
	if err != nil || !privateDirectoryInfo(info) || protectedIdentity(info, cleanup.protected) {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	root, err := cleanup.root.OpenRoot(name)
	if err != nil {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	defer root.Close()
	parent, err := root.Open(".")
	if err != nil {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	defer parent.Close()
	pinned, err := parent.Stat()
	if err != nil || !privateDirectoryInfo(pinned) || !os.SameFile(info, pinned) {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	current := func() bool {
		named, err := cleanup.root.Lstat(name)
		opened, openedErr := parent.Stat()
		return cleanup.parentCurrent() && err == nil && openedErr == nil &&
			privateDirectoryInfo(named) && privateDirectoryInfo(opened) &&
			os.SameFile(info, named) && os.SameFile(info, opened)
	}
	if !current() {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	lease, err := acquireStageLease(parent)
	active := errors.Is(err, unix.EWOULDBLOCK)
	if !active && (err != nil || lease == nil) {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	if lease != nil {
		defer lease.Close()
	}
	journalInfo, err := root.Lstat(cleanupJournalName)
	if err != nil || journalInfo == nil || journalInfo.Size() < 0 || journalInfo.Size() > cleanupJournalMaxBytes ||
		protectedIdentity(journalInfo, cleanup.protected) {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	journalIdentity, err := makeJournalFileIdentity(journalInfo)
	if err != nil {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	journal, err := root.Open(cleanupJournalName)
	if err != nil {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	defer journal.Close()
	opened, err := journal.Stat()
	if err != nil || !journalIdentity.matches(opened) {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	data, err := io.ReadAll(io.LimitReader(journal, cleanupJournalMaxBytes+1))
	if err != nil || len(data) > cleanupJournalMaxBytes {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	record, err := decodeCleanupJournal(data)
	if err != nil || record.Version != cleanupLeasedVersion || !validCleanupStageName(record.Stage) ||
		!record.Parent.matches(pinned) || record.Destination == nil || !record.Destination.matches(cleanup.identity) || !validTargetName(record.Target) {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	if _, err := parent.Seek(0, io.SeekStart); err != nil {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	seen := 0
	for {
		entries, readErr := parent.ReadDir(3 - seen)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return CleanupJournalIncomplete, ErrCleanupIncomplete
		}
		seen += len(entries)
		if seen > 2 {
			return CleanupJournalIncomplete, ErrCleanupIncomplete
		}
		for _, entry := range entries {
			if entry.Name() != cleanupJournalName && entry.Name() != record.Stage {
				return CleanupJournalIncomplete, ErrCleanupIncomplete
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}
	stageInfo, stageErr := root.Lstat(record.Stage)
	privateStage := stageErr == nil
	stageRoot, stageName := root, record.Stage
	if errors.Is(stageErr, os.ErrNotExist) {
		stageRoot, stageName = cleanup.root, record.Target
		stageInfo, stageErr = stageRoot.Lstat(stageName)
	}
	if stageErr != nil || stageInfo == nil || !record.File.matches(stageInfo) ||
		(privateStage && protectedIdentity(stageInfo, cleanup.protected)) {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	stage, err := stageRoot.Open(stageName)
	if err != nil {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	defer stage.Close()
	openedStage, err := stage.Stat()
	if err != nil || !record.File.matches(openedStage) {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	journalCurrent := func() bool {
		info, err := root.Lstat(cleanupJournalName)
		parentInfo, parentErr := parent.Stat()
		return current() && parentErr == nil && record.Parent.matches(parentInfo) && err == nil && journalIdentity.matches(info)
	}
	if !journalCurrent() || probeIdentity(stageRoot, stageName, openedStage) != identityExpected {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	if active {
		return CleanupJournalActive, nil
	}
	if !allowDelete {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	if privateStage {
		if !removeExactJournalEntry(root, record.Stage, openedStage, cleanup.operations.remove) || cleanup.operations.syncDirectory(parent) != nil {
			return CleanupJournalIncomplete, ErrCleanupIncomplete
		}
	} else if probeIdentity(root, record.Stage, openedStage) != identityMissing {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	if !journalCurrent() || !removeExactJournalEntry(root, cleanupJournalName, journalInfo, cleanup.operations.remove) || cleanup.operations.syncDirectory(parent) != nil {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	if !current() || cleanup.root.Remove(name) != nil || cleanup.operations.syncDirectory(cleanup.parent) != nil {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	return CleanupJournalCleaned, nil
}
