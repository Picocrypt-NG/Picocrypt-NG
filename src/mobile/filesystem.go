package mobile

import (
	"Picocrypt-NG/internal/pcv3publication"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

func openPCV3Regular(path string) (*os.File, error) {
	file, err := openPCV3Existing(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || info == nil || !info.Mode().IsRegular() || info.Size() < 0 {
		_ = file.Close()
		return nil, errors.New("PCV3 input is not a regular file")
	}
	return file, nil
}

// RemoveTreeNoFollow removes targetPath without following any directory
// symlink between rootPath and the target. The empty string means success.
//
// Android calls this through gomobile because android.system.Os does not expose
// the descriptor-relative openat/unlinkat operations needed for a race-safe
// recursive deletion. os.Root provides those semantics on Android.
func RemoveTreeNoFollow(rootPath, targetPath string) string {
	if err := removeTreeNoFollow(rootPath, targetPath); err != nil {
		return err.Error()
	}
	return ""
}

// CleanupPCV3Journal performs deny-by-default startup cleanup for one local
// parent directory. It exposes only the closed cleanup state, never a path or
// raw filesystem error.
func CleanupPCV3Journal(parentPath string) string {
	if parentPath == "" || len(parentPath) > maxPCV3PathBytes ||
		!utf8.ValidString(parentPath) || strings.ContainsRune(parentPath, '\x00') ||
		strings.Contains(parentPath, "://") || !filepath.IsAbs(parentPath) ||
		filepath.Clean(parentPath) != parentPath {
		return "incomplete"
	}
	state, err := pcv3publication.CleanupJournaledStage(parentPath)
	if err != nil {
		return "incomplete"
	}
	switch state {
	case pcv3publication.CleanupJournalAbsent:
		return "absent"
	case pcv3publication.CleanupJournalCleaned:
		return "cleaned"
	default:
		return "incomplete"
	}
}

// PublishInputCopy atomically moves a complete Android input copy without
// replacing another owner. Published codes grant target cleanup custody even
// if a post-move error prevents handoff; all other codes grant none.
func PublishInputCopy(parentPath, sourceName, targetName string, device, inode int64) string {
	if device < 0 || inode <= 0 || len(parentPath) > maxPCV3PathBytes || len(sourceName) > 255 || len(targetName) > 255 ||
		!utf8.ValidString(parentPath) || !utf8.ValidString(sourceName) || !utf8.ValidString(targetName) {
		return "not-published"
	}
	state, err := pcv3publication.MoveExistingNoReplace(parentPath, sourceName, targetName, uint64(device), uint64(inode))
	switch state {
	case pcv3publication.ExistingFilePublished:
		if err != nil {
			return "published-error"
		}
		return "published"
	case pcv3publication.ExistingFileNotPublished:
		return "not-published"
	default:
		return "indeterminate"
	}
}

func removeTreeNoFollow(rootPath, targetPath string) (retErr error) {
	rootPath, err := filepath.Abs(filepath.Clean(rootPath))
	if err != nil {
		return fmt.Errorf("resolve cleanup root: %w", err)
	}
	targetPath, err = filepath.Abs(filepath.Clean(targetPath))
	if err != nil {
		return fmt.Errorf("resolve cleanup target: %w", err)
	}
	relative, err := filepath.Rel(rootPath, targetPath)
	if err != nil {
		return fmt.Errorf("resolve cleanup target relative to root: %w", err)
	}
	if relative == "." || !filepath.IsLocal(relative) {
		return errors.New("cleanup target is outside its root")
	}

	components := strings.Split(relative, string(filepath.Separator))
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return fmt.Errorf("open cleanup root: %w", err)
	}
	roots := []*os.Root{root}
	defer func() {
		for i := len(roots) - 1; i >= 0; i-- {
			retErr = errors.Join(retErr, roots[i].Close())
		}
	}()

	current := root
	for _, component := range components[:len(components)-1] {
		expected, err := current.Lstat(component)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect cleanup directory %q: %w", component, err)
		}
		if !expected.IsDir() || expected.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("cleanup directory %q is not an owned directory", component)
		}

		next, err := current.OpenRoot(component)
		if err != nil {
			return fmt.Errorf("open cleanup directory %q: %w", component, err)
		}
		roots = append(roots, next)
		opened, err := next.Stat(".")
		if err != nil {
			return fmt.Errorf("inspect opened cleanup directory %q: %w", component, err)
		}
		if !os.SameFile(expected, opened) {
			return fmt.Errorf("cleanup directory %q changed while it was opened", component)
		}
		current = next
	}

	if err := current.RemoveAll(components[len(components)-1]); err != nil {
		return fmt.Errorf("remove cleanup target: %w", err)
	}
	return nil
}
