package fileops

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var stagedFileRenameFn = (*os.Root).Rename

// StagedFile is a temporary file owned by the current operation. It is created
// with a random name beside its eventual destination so publication stays on
// the same filesystem. Call Cleanup on every exit path; after Commit it is a
// no-op.
type StagedFile struct {
	file        *os.File
	root        *os.Root
	rootInfo    os.FileInfo
	stageInfo   os.FileInfo
	stageName   string
	targetName  string
	path        string
	targetPath  string
	cleanupDone bool
	cleanupErr  error
}

// CreateSiblingTemp creates an exclusively owned, mode-0600 temporary file in
// the target's directory and keeps its original handle open.
func CreateSiblingTemp(targetPath string) (*StagedFile, error) {
	absoluteTarget, err := filepath.Abs(filepath.Clean(targetPath))
	if err != nil {
		return nil, fmt.Errorf("resolve output path: %w", err)
	}

	targetDir := filepath.Dir(absoluteTarget)
	root, err := os.OpenRoot(targetDir)
	if err != nil {
		return nil, fmt.Errorf("open output directory: %w", err)
	}
	rootInfo, err := root.Stat(".")
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("inspect output directory: %w", err)
	}
	return createSiblingTempWithRoot(root, rootInfo, filepath.Base(absoluteTarget), absoluteTarget)
}

func createSiblingTempInRoot(
	root *os.Root,
	rootInfo os.FileInfo,
	targetName string,
	targetPath string,
) (*StagedFile, error) {
	if root == nil || rootInfo == nil || !rootInfo.IsDir() {
		return nil, os.ErrInvalid
	}
	ownedRoot, err := root.OpenRoot(".")
	if err != nil {
		return nil, fmt.Errorf("retain output directory: %w", err)
	}
	openedInfo, err := ownedRoot.Stat(".")
	if err != nil || openedInfo == nil || !os.SameFile(rootInfo, openedInfo) {
		return nil, errors.Join(
			errors.New("output directory identity changed while retaining it"),
			err,
			ownedRoot.Close(),
		)
	}
	return createSiblingTempWithRoot(ownedRoot, openedInfo, targetName, targetPath)
}

func createSiblingTempWithRoot(
	root *os.Root,
	rootInfo os.FileInfo,
	targetName string,
	targetPath string,
) (*StagedFile, error) {
	if root == nil || rootInfo == nil || targetName == "" || targetName == "." {
		if root != nil {
			_ = root.Close()
		}
		return nil, os.ErrInvalid
	}

	stageName := ".picocrypt-" + rand.Text()
	file, err := root.OpenFile(stageName, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("create staged output: %w", err)
	}
	stageInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		_ = root.Close()
		return nil, fmt.Errorf("inspect staged output: %w", err)
	}

	return &StagedFile{
		file:       file,
		root:       root,
		rootInfo:   rootInfo,
		stageInfo:  stageInfo,
		stageName:  stageName,
		targetName: targetName,
		path:       filepath.Join(filepath.Dir(targetPath), stageName),
		targetPath: targetPath,
	}, nil
}

// File returns the original open handle for the staged file.
func (s *StagedFile) File() *os.File {
	if s == nil {
		return nil
	}
	return s.file
}

// Detach transfers the open staged descriptor to the caller while retaining
// the pinned pathname identity for exact Cleanup after the caller closes it.
func (s *StagedFile) Detach() (*os.File, error) {
	if s == nil || s.file == nil {
		return nil, os.ErrInvalid
	}
	file := s.file
	s.file = nil
	return file, nil
}

// Path returns the random path owned by this staged file.
func (s *StagedFile) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// TargetParentInfo returns the identity of the output directory retained when
// the stage was created. Callers may capture it before Commit and use it to
// verify a newly opened parent handle.
func (s *StagedFile) TargetParentInfo() os.FileInfo {
	if s == nil {
		return nil
	}
	return s.rootInfo
}

// Reset truncates the owned file and rewinds it without reopening its path.
func (s *StagedFile) Reset() error {
	if s == nil || s.file == nil {
		return os.ErrInvalid
	}
	if err := s.file.Truncate(0); err != nil {
		return fmt.Errorf("truncate staged output: %w", err)
	}
	if _, err := s.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind staged output: %w", err)
	}
	return nil
}

// ReserveTargetDirectory creates the target directory through the parent
// directory handle retained when the stage was created. The lexical parent and
// resulting directory must still resolve to those pinned identities.
func (s *StagedFile) ReserveTargetDirectory() (os.FileInfo, error) {
	if s == nil {
		return nil, os.ErrInvalid
	}
	return s.ReserveSiblingDirectory(s.targetPath)
}

// ReserveSiblingDirectory creates a directory beside the eventual output
// through the parent handle retained when the stage was created.
func (s *StagedFile) ReserveSiblingDirectory(targetPath string) (os.FileInfo, error) {
	targetName, absoluteTarget, err := s.resolveSiblingTarget(targetPath)
	if err != nil {
		return nil, err
	}
	currentDir, err := os.Stat(filepath.Dir(absoluteTarget))
	if err != nil {
		return nil, fmt.Errorf("inspect output directory before reservation: %w", err)
	}
	if !os.SameFile(s.rootInfo, currentDir) {
		return nil, errors.New("output directory changed before reservation")
	}
	if err := s.root.Mkdir(targetName, 0o700); err != nil {
		return nil, fmt.Errorf("reserve output directory: %w", err)
	}
	info, err := s.root.Lstat(targetName)
	if err != nil {
		return nil, fmt.Errorf(
			"inspect reserved output directory (manual cleanup may be required at %s): %w",
			absoluteTarget,
			err,
		)
	}
	if !info.IsDir() {
		return nil, errors.Join(
			errors.New("reserved output path is not a directory"),
			s.RemoveSiblingDirectory(absoluteTarget, info),
		)
	}

	currentDir, err = os.Stat(filepath.Dir(absoluteTarget))
	if err != nil || !os.SameFile(s.rootInfo, currentDir) {
		if err == nil {
			err = errors.New("output directory changed during reservation")
		} else {
			err = fmt.Errorf("inspect output directory after reservation: %w", err)
		}
		return nil, errors.Join(err, s.RemoveSiblingDirectory(absoluteTarget, info))
	}
	pathInfo, err := os.Lstat(absoluteTarget)
	if err != nil || !pathInfo.IsDir() || !os.SameFile(info, pathInfo) {
		if err == nil {
			err = errors.New("reserved output directory path changed")
		} else {
			err = fmt.Errorf("inspect reserved output directory path: %w", err)
		}
		return nil, errors.Join(err, s.RemoveSiblingDirectory(absoluteTarget, info))
	}
	return info, nil
}

// RemoveTargetDirectory removes a reserved target only while it still names the
// exact empty directory created through this stage's pinned parent.
func (s *StagedFile) RemoveTargetDirectory(expected os.FileInfo) error {
	if s == nil {
		return os.ErrInvalid
	}
	return s.RemoveSiblingDirectory(s.targetPath, expected)
}

// RemoveSiblingDirectory removes a reserved sibling only while it still names
// the exact empty directory created through this stage's pinned parent.
func (s *StagedFile) RemoveSiblingDirectory(targetPath string, expected os.FileInfo) error {
	targetName, _, err := s.resolveSiblingTarget(targetPath)
	if err != nil {
		return err
	}
	if expected == nil {
		return os.ErrInvalid
	}
	current, err := s.root.Lstat(targetName)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect reserved output directory during cleanup: %w", err)
	}
	if !current.IsDir() || !os.SameFile(expected, current) {
		return errors.New("reserved output directory changed; refusing to remove it")
	}
	if err := s.root.Remove(targetName); err != nil {
		return fmt.Errorf("remove reserved output directory: %w", err)
	}
	return nil
}

func (s *StagedFile) resolveSiblingTarget(targetPath string) (string, string, error) {
	if s == nil || s.root == nil || s.rootInfo == nil || s.targetPath == "" || targetPath == "" {
		return "", "", os.ErrInvalid
	}
	absoluteTarget, err := filepath.Abs(filepath.Clean(targetPath))
	if err != nil {
		return "", "", fmt.Errorf("resolve sibling output path: %w", err)
	}
	if filepath.Dir(absoluteTarget) != filepath.Dir(s.targetPath) {
		return "", "", errors.New("reserved directory is not beside the staged output")
	}
	targetName := filepath.Base(absoluteTarget)
	if targetName == "" || targetName == "." || targetName == string(filepath.Separator) {
		return "", "", errors.New("reserved directory name is invalid")
	}
	return targetName, absoluteTarget, nil
}

// Commit flushes and closes the staged file, then replaces the target path.
// The target remains untouched until the staged contents are complete.
func (s *StagedFile) Commit() error {
	if s == nil || s.file == nil || s.root == nil || s.stageName == "" {
		return os.ErrInvalid
	}

	if err := s.file.Sync(); err != nil {
		return fmt.Errorf("sync staged output: %w", err)
	}
	if err := s.file.Close(); err != nil {
		s.file = nil
		return fmt.Errorf("close staged output: %w", err)
	}
	s.file = nil

	currentDir, err := os.Stat(filepath.Dir(s.targetPath))
	if err != nil {
		return fmt.Errorf("inspect output directory before publish: %w", err)
	}
	if !os.SameFile(s.rootInfo, currentDir) {
		return errors.New("output directory changed before publish")
	}
	currentStage, err := s.root.Lstat(s.stageName)
	if err != nil {
		return fmt.Errorf("inspect staged output before publish: %w", err)
	}
	if !currentStage.Mode().IsRegular() || !os.SameFile(s.stageInfo, currentStage) {
		return errors.New("staged output path changed before publish")
	}

	if err := stagedFileRenameFn(s.root, s.stageName, s.targetName); err != nil {
		return fmt.Errorf("publish staged output: %w", err)
	}
	s.stageName = ""
	s.path = ""
	if err := s.root.Close(); err != nil {
		s.root = nil
		return fmt.Errorf("close output directory: %w", err)
	}
	s.root = nil
	// Legacy staging permits a stable symlink-selected parent. Follow it as
	// the pre-publication check does, and preserve the committed output on a
	// mismatch rather than granting callers ordinary success.
	currentDir, err = os.Stat(filepath.Dir(s.targetPath))
	if err != nil || !os.SameFile(s.rootInfo, currentDir) {
		return errors.Join(errors.New("output directory changed after publish; committed output preserved"), err)
	}
	s.rootInfo = nil
	s.stageInfo = nil
	return nil
}

// Cleanup closes and removes only the random file created by this instance.
// It returns an error containing the retained path if an operation-owned stage
// could not be removed, so callers can report possible sensitive residue.
func (s *StagedFile) Cleanup() error {
	if s == nil {
		return nil
	}
	if s.cleanupDone {
		return s.cleanupErr
	}
	s.cleanupDone = true
	var cleanupErrs []error
	if s.file != nil {
		if err := s.file.Close(); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("close staged output %s: %w", s.path, err))
		}
		s.file = nil
	}
	stageRemoved := s.stageName == ""
	if s.root != nil && s.stageName != "" {
		current, err := s.root.Lstat(s.stageName)
		switch {
		case errors.Is(err, os.ErrNotExist):
			cleanupErrs = append(cleanupErrs, fmt.Errorf("staged output %s missing during cleanup; owned data absence unproven", s.path))
		case err != nil:
			cleanupErrs = append(cleanupErrs, fmt.Errorf("inspect staged output %s during cleanup: %w", s.path, err))
		case !current.Mode().IsRegular() || !os.SameFile(s.stageInfo, current):
			cleanupErrs = append(cleanupErrs, fmt.Errorf("staged output %s changed during cleanup; refusing to remove replacement", s.path))
		default:
			if err := s.root.Remove(s.stageName); err != nil {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("remove staged output %s: %w", s.path, err))
			} else {
				stageRemoved = true
			}
		}
	}
	if s.root != nil {
		if err := s.root.Close(); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("close staged output directory for %s: %w", s.path, err))
		}
		s.root = nil
	}
	if stageRemoved {
		s.rootInfo = nil
		s.stageInfo = nil
		s.stageName = ""
		s.path = ""
		s.targetName = ""
		s.targetPath = ""
	}
	s.cleanupErr = errors.Join(cleanupErrs...)
	return s.cleanupErr
}
