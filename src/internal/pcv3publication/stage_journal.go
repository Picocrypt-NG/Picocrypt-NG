package pcv3publication

import (
	"Picocrypt-NG/internal/fileops"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	cleanupJournalName       = ".picocrypt-pcv3-stage.journal"
	cleanupJournalTempPrefix = ".picocrypt-pcv3-journal-tmp-"
	cleanupJournalVersion    = 1
	cleanupJournalMaxBytes   = 2048
	cleanupJournalMaxName    = 128
)

var (
	errCleanupJournalPersist = errors.New("pcv3 publication: cleanup journal persistence failed")
	errCleanupJournalExists  = errors.New("pcv3 publication: cleanup journal already exists")
)

type cleanupJournal struct {
	Version int                   `json:"version"`
	Stage   string                `json:"stage"`
	Parent  journalParentIdentity `json:"parent"`
	File    journalFileIdentity   `json:"file"`
}

// CleanupJournalState is the closed startup-cleanup outcome. Callers must not
// collapse an absent journal into proof that a stage was cleaned.
type CleanupJournalState uint8

const (
	CleanupJournalIncomplete CleanupJournalState = iota
	CleanupJournalAbsent
	CleanupJournalCleaned
)

// PersistCleanupJournal durably records the exact existing stage object so a
// later process can remove it without granting pathname-based authority. It is
// safe to call before the first plaintext write because only immutable identity
// metadata is recorded.
func (stage *Stage) PersistCleanupJournal() error {
	if stage == nil || stage.journaled || stage.cleanupDone ||
		stage.cleanupDisposition != cleanupOwned || stage.file == nil ||
		stage.root == nil || stage.parent == nil || stage.stageInfo == nil ||
		stage.stageName == "" || stage.operations.syncStage == nil ||
		stage.operations.closeStage == nil || stage.operations.removeStage == nil ||
		stage.operations.syncDirectory == nil {
		if stage != nil && stage.journaled && !stage.cleanupDone {
			return nil
		}
		return errCleanupJournalPersist
	}
	if !stage.parentIdentityCurrent() || !stage.stageIdentityCurrent() {
		return errCleanupJournalPersist
	}
	if err := stage.operations.syncStage(stage.file); err != nil {
		return errCleanupJournalPersist
	}
	if !stage.parentIdentityCurrent() || !stage.stageIdentityCurrent() {
		return errCleanupJournalPersist
	}

	parentInfo, err := stage.parent.Stat()
	if err != nil {
		return errCleanupJournalPersist
	}
	parentIdentity, err := makeJournalParentIdentity(parentInfo)
	if err != nil {
		return errCleanupJournalPersist
	}
	stageInfo, err := stage.file.Stat()
	if err != nil || stageInfo == nil || !stageInfo.Mode().IsRegular() ||
		!os.SameFile(stage.stageInfo, stageInfo) {
		return errCleanupJournalPersist
	}
	fileIdentity, err := makeJournalFileIdentity(stageInfo)
	if err != nil {
		return errCleanupJournalPersist
	}

	record := cleanupJournal{
		Version: cleanupJournalVersion,
		Stage:   stage.stageName,
		Parent:  parentIdentity,
		File:    fileIdentity,
	}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded)+1 > cleanupJournalMaxBytes {
		return errCleanupJournalPersist
	}
	encoded = append(encoded, '\n')

	if _, err := stage.root.Lstat(cleanupJournalName); err == nil {
		return errors.Join(errCleanupJournalExists, ErrCleanupIncomplete)
	} else if !errors.Is(err, os.ErrNotExist) {
		return errCleanupJournalPersist
	}

	tempName, tempFile, tempInfo, err := createCleanupJournalTemp(stage.root)
	if err != nil {
		return errCleanupJournalPersist
	}
	tempClosed := false
	cleanupTemp := func() bool {
		if !tempClosed {
			_ = tempFile.Close()
			tempClosed = true
		}
		removed := removeExactJournalEntry(stage.root, tempName, tempInfo, stage.operations.removeStage)
		return removed && stage.operations.syncDirectory(stage.parent) == nil
	}

	if err := writeFull(tempFile, encoded); err != nil {
		if cleanupTemp() {
			return errCleanupJournalPersist
		}
		return errors.Join(errCleanupJournalPersist, ErrCleanupIncomplete)
	}
	if err := stage.operations.syncStage(tempFile); err != nil {
		if cleanupTemp() {
			return errCleanupJournalPersist
		}
		return errors.Join(errCleanupJournalPersist, ErrCleanupIncomplete)
	}
	if err := stage.operations.closeStage(tempFile); err != nil {
		tempClosed = true
		if cleanupTemp() {
			return errCleanupJournalPersist
		}
		return errors.Join(errCleanupJournalPersist, ErrCleanupIncomplete)
	}
	tempClosed = true

	installErr := installCleanupJournalNoReplace(stage.parent, tempName, cleanupJournalName)
	tempProbe := probeIdentity(stage.root, tempName, tempInfo)
	journalProbe := probeIdentity(stage.root, cleanupJournalName, tempInfo)
	installed := journalProbe == identityExpected && tempProbe == identityMissing
	if !installed {
		cleanupProven := true
		removed := false
		if tempProbe == identityExpected {
			removed = true
			cleanupProven = removeExactJournalEntry(stage.root, tempName, tempInfo, stage.operations.removeStage)
		} else if tempProbe != identityMissing {
			cleanupProven = false
		}
		if journalProbe == identityExpected {
			removed = true
			cleanupProven = removeExactJournalEntry(stage.root, cleanupJournalName, tempInfo, stage.operations.removeStage) && cleanupProven
		} else if journalProbe == identityUnknown {
			cleanupProven = false
		}
		if removed && stage.operations.syncDirectory(stage.parent) != nil {
			cleanupProven = false
		}
		failure := errCleanupJournalPersist
		if installErr != nil && journalProbe == identityOther {
			failure = errCleanupJournalExists
		}
		if cleanupProven {
			if errors.Is(failure, errCleanupJournalExists) {
				return errors.Join(failure, ErrCleanupIncomplete)
			}
			return failure
		}
		return errors.Join(failure, ErrCleanupIncomplete)
	}

	journalInfo, err := stage.root.Lstat(cleanupJournalName)
	if err != nil || journalInfo == nil || !journalInfo.Mode().IsRegular() ||
		!os.SameFile(tempInfo, journalInfo) || !stage.parentIdentityCurrent() {
		return stage.rollbackInstalledJournal(tempInfo)
	}
	if err := stage.operations.syncDirectory(stage.parent); err != nil {
		return stage.rollbackInstalledJournal(tempInfo)
	}
	stage.journalInfo = journalInfo
	stage.journalStageIdentity = fileIdentity
	stage.journaled = true
	return nil
}

func (stage *Stage) rollbackInstalledJournal(expected os.FileInfo) error {
	cleanupProven := removeExactJournalEntry(
		stage.root,
		cleanupJournalName,
		expected,
		stage.operations.removeStage,
	)
	if cleanupProven && stage.operations.syncDirectory(stage.parent) == nil {
		return errCleanupJournalPersist
	}
	return errors.Join(errCleanupJournalPersist, ErrCleanupIncomplete)
}

func createCleanupJournalTemp(root *os.Root) (string, *os.File, os.FileInfo, error) {
	for range 4 {
		name := cleanupJournalTempPrefix + rand.Text()
		file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", nil, nil, err
		}
		info, statErr := file.Stat()
		if statErr != nil || info == nil || !info.Mode().IsRegular() {
			_ = file.Close()
			return name, nil, nil, errors.Join(statErr, ErrCleanupIncomplete)
		}
		return name, file, info, nil
	}
	return "", nil, nil, errCleanupJournalPersist
}

func writeFull(file *os.File, data []byte) error {
	for len(data) > 0 {
		written, err := file.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func removeExactJournalEntry(
	root *os.Root,
	name string,
	expected os.FileInfo,
	remove func(*os.Root, string) error,
) bool {
	if root == nil || name == "" || expected == nil || remove == nil ||
		probeIdentity(root, name, expected) != identityExpected {
		return false
	}
	removeErr := remove(root, name)
	return removeErr == nil && probeIdentity(root, name, expected) == identityMissing
}

func (stage *Stage) cleanupJournaledOwned(cleanupFailed *bool) {
	if stage.root == nil || stage.parent == nil || stage.stageName == "" ||
		stage.stageInfo == nil || stage.journalInfo == nil ||
		stage.operations.removeStage == nil || stage.operations.syncDirectory == nil {
		*cleanupFailed = true
		return
	}
	currentStage, stageErr := stage.root.Lstat(stage.stageName)
	if stageErr != nil || currentStage == nil || !currentStage.Mode().IsRegular() ||
		!os.SameFile(stage.stageInfo, currentStage) || !stage.journalStageIdentity.matches(currentStage) ||
		probeIdentity(stage.root, cleanupJournalName, stage.journalInfo) != identityExpected {
		*cleanupFailed = true
		return
	}

	stageRemoved := removeExactJournalEntry(
		stage.root,
		stage.stageName,
		stage.stageInfo,
		stage.operations.removeStage,
	)
	if !stageRemoved {
		*cleanupFailed = true
		return
	}
	if stage.operations.syncDirectory(stage.parent) != nil {
		*cleanupFailed = true
		return
	}
	journalRemoved := removeExactJournalEntry(
		stage.root,
		cleanupJournalName,
		stage.journalInfo,
		stage.operations.removeStage,
	)
	if !journalRemoved {
		*cleanupFailed = true
		return
	}
	if stage.operations.syncDirectory(stage.parent) != nil {
		*cleanupFailed = true
	}
}

func (stage *Stage) retireCleanupJournal() bool {
	if stage == nil || !stage.journaled || stage.journalInfo == nil ||
		stage.root == nil || stage.parent == nil || stage.operations.removeStage == nil ||
		stage.operations.syncDirectory == nil ||
		!removeExactJournalEntry(stage.root, cleanupJournalName, stage.journalInfo, stage.operations.removeStage) {
		return false
	}
	stage.journalRemoved = true
	if stage.operations.syncDirectory(stage.parent) != nil {
		return false
	}
	stage.journaled = false
	stage.journalRemoved = false
	stage.journalInfo = nil
	stage.journalStageIdentity = journalFileIdentity{}
	return true
}

func (stage *Stage) cleanupPublishedJournaledOwned(cleanupFailed *bool) {
	if stage.root == nil || stage.parent == nil || stage.targetName == "" ||
		stage.stageInfo == nil || stage.operations.removeStage == nil ||
		stage.operations.syncDirectory == nil {
		*cleanupFailed = true
		return
	}

	currentTarget, targetErr := stage.root.Lstat(stage.targetName)
	if stage.targetRemoved {
		if probeIdentity(stage.root, stage.targetName, stage.stageInfo) != identityMissing {
			*cleanupFailed = true
		}
	} else if targetErr == nil && currentTarget != nil && stage.journalStageIdentity.matches(currentTarget) && removeExactJournalEntry(
		stage.root,
		stage.targetName,
		stage.stageInfo,
		stage.operations.removeStage,
	) {
		stage.targetRemoved = true
	} else {
		*cleanupFailed = true
	}
	if !stage.targetRemoved {
		return
	}
	if !stage.targetRemovalSynced {
		if stage.operations.syncDirectory(stage.parent) != nil {
			*cleanupFailed = true
			return
		}
		stage.targetRemovalSynced = true
	}

	// Preserve the recovery journal until the committed target is durably proven gone.
	// Otherwise a transient target-removal failure followed by process death
	// would strand plaintext without startup cleanup authority.
	if stage.targetRemoved {
		if stage.journalRemoved {
			if probeIdentity(stage.root, cleanupJournalName, stage.journalInfo) != identityMissing {
				*cleanupFailed = true
			}
		} else if stage.journalInfo != nil && removeExactJournalEntry(
			stage.root,
			cleanupJournalName,
			stage.journalInfo,
			stage.operations.removeStage,
		) {
			stage.journalRemoved = true
		} else {
			*cleanupFailed = true
		}
	}
	if !stage.journalRemoved {
		return
	}
	if stage.operations.syncDirectory(stage.parent) != nil {
		*cleanupFailed = true
	}
	if !*cleanupFailed {
		stage.journaled = false
		stage.journalRemoved = false
		stage.targetRemoved = false
		stage.targetRemovalSynced = false
		stage.journalInfo = nil
		stage.journalStageIdentity = journalFileIdentity{}
	}
}

// CleanupJournaledStage removes only the exact stage recorded in the fixed
// journal beneath parentPath. Invalid or uncertain records grant no deletion
// authority.
func CleanupJournaledStage(parentPath string) (CleanupJournalState, error) {
	return cleanupJournaledStageWithOperations(parentPath, nativeJournalCleanupOperations())
}

type journalCleanupOperations struct {
	remove        func(*os.Root, string) error
	syncDirectory func(*os.File) error
}

func nativeJournalCleanupOperations() journalCleanupOperations {
	return journalCleanupOperations{
		remove:        (*os.Root).Remove,
		syncDirectory: (*os.File).Sync,
	}
}

func cleanupJournaledStageWithOperations(parentPath string, operations journalCleanupOperations) (CleanupJournalState, error) {
	if parentPath == "" || operations.remove == nil || operations.syncDirectory == nil {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	root, err := fileops.OpenRootNoSymlink(parentPath)
	if err != nil {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	defer root.Close()
	rootInfo, err := root.Stat(".")
	if err != nil {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	parent, err := root.Open(".")
	if err != nil {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	defer parent.Close()
	parentInfo, err := parent.Stat()
	if err != nil || parentInfo == nil || !os.SameFile(rootInfo, parentInfo) {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}

	journalInfo, err := root.Lstat(cleanupJournalName)
	if errors.Is(err, os.ErrNotExist) {
		entries, readErr := readPinnedDirectory(parent)
		if readErr != nil {
			return CleanupJournalIncomplete, ErrCleanupIncomplete
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), stageNamePrefix) {
				return CleanupJournalIncomplete, ErrCleanupIncomplete
			}
		}
		return CleanupJournalAbsent, nil
	}
	if err != nil || journalInfo == nil || !journalInfo.Mode().IsRegular() ||
		journalInfo.Size() < 0 || journalInfo.Size() > cleanupJournalMaxBytes {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	journalFile, err := root.Open(cleanupJournalName)
	if err != nil {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	openedInfo, statErr := journalFile.Stat()
	if statErr != nil || openedInfo == nil || !openedInfo.Mode().IsRegular() ||
		!os.SameFile(journalInfo, openedInfo) {
		_ = journalFile.Close()
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	data, readErr := io.ReadAll(io.LimitReader(journalFile, cleanupJournalMaxBytes+1))
	closeErr := journalFile.Close()
	if readErr != nil || closeErr != nil || len(data) > cleanupJournalMaxBytes {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	record, err := decodeCleanupJournal(data)
	if err != nil || !validCleanupStageName(record.Stage) ||
		!record.Parent.matches(rootInfo) {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	currentParent, err := os.Lstat(parentPath)
	if err != nil || currentParent == nil || !currentParent.IsDir() ||
		currentParent.Mode()&os.ModeSymlink != 0 || !os.SameFile(rootInfo, currentParent) ||
		!record.Parent.matches(currentParent) {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	stageName := record.Stage
	stageInfo, err := root.Lstat(stageName)
	if errors.Is(err, os.ErrNotExist) {
		stageName, stageInfo, err = findRenamedJournaledStage(parent, root, record.File)
	}
	if err != nil || stageInfo == nil || !stageInfo.Mode().IsRegular() || !record.File.matches(stageInfo) {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	if probeIdentity(root, cleanupJournalName, journalInfo) != identityExpected {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	currentParent, err = os.Lstat(parentPath)
	if err != nil || currentParent == nil || !currentParent.IsDir() ||
		currentParent.Mode()&os.ModeSymlink != 0 || !os.SameFile(rootInfo, currentParent) ||
		!record.Parent.matches(currentParent) {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}

	stageRemoved := removeExactJournalEntry(root, stageName, stageInfo, operations.remove)
	if !stageRemoved {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	if operations.syncDirectory(parent) != nil {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	journalRemoved := removeExactJournalEntry(root, cleanupJournalName, journalInfo, operations.remove)
	if !journalRemoved || operations.syncDirectory(parent) != nil {
		return CleanupJournalIncomplete, ErrCleanupIncomplete
	}
	return CleanupJournalCleaned, nil
}

func findRenamedJournaledStage(
	parent *os.File,
	root *os.Root,
	expected journalFileIdentity,
) (string, os.FileInfo, error) {
	entries, err := readPinnedDirectory(parent)
	if err != nil {
		return "", nil, err
	}
	var matchName string
	var matchInfo os.FileInfo
	for _, entry := range entries {
		name := entry.Name()
		if name == cleanupJournalName {
			continue
		}
		info, statErr := root.Lstat(name)
		if statErr != nil {
			return "", nil, statErr
		}
		if !info.Mode().IsRegular() || !expected.matches(info) {
			continue
		}
		if matchInfo != nil {
			return "", nil, errors.New("multiple stage identity matches")
		}
		matchName = name
		matchInfo = info
	}
	if matchInfo == nil {
		return "", nil, os.ErrNotExist
	}
	return matchName, matchInfo, nil
}

func readPinnedDirectory(parent *os.File) ([]os.DirEntry, error) {
	if parent == nil {
		return nil, os.ErrInvalid
	}
	if _, err := parent.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return parent.ReadDir(-1)
}

func decodeCleanupJournal(data []byte) (cleanupJournal, error) {
	var record cleanupJournal
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return cleanupJournal{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return cleanupJournal{}, errors.New("cleanup journal has trailing data")
	}
	if record.Version != cleanupJournalVersion {
		return cleanupJournal{}, fmt.Errorf("unsupported cleanup journal version")
	}
	canonical, err := json.Marshal(record)
	if err != nil {
		return cleanupJournal{}, err
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(data, canonical) {
		return cleanupJournal{}, errors.New("cleanup journal is not canonical")
	}
	return record, nil
}

func validCleanupStageName(name string) bool {
	if len(name) < len(stageNamePrefix)+26 || len(name) > cleanupJournalMaxName ||
		!strings.HasPrefix(name, stageNamePrefix) || filepath.Base(name) != name ||
		strings.ContainsAny(name, `/\\`) {
		return false
	}
	for _, character := range name[len(stageNamePrefix):] {
		if (character < 'A' || character > 'Z') && (character < '2' || character > '7') {
			return false
		}
	}
	return true
}
