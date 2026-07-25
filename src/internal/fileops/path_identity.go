package fileops

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// SamePathOrFile reports whether two paths name the same filesystem object.
// Lexical absolute equality covers paths that do not exist yet; SameFile also
// catches symlinks, hardlinks, and filesystem-specific aliases.
func SamePathOrFile(first, second string) (bool, error) {
	firstAbs, err := filepath.Abs(filepath.Clean(first))
	if err != nil {
		return false, fmt.Errorf("resolve path %q: %w", first, err)
	}
	secondAbs, err := filepath.Abs(filepath.Clean(second))
	if err != nil {
		return false, fmt.Errorf("resolve path %q: %w", second, err)
	}
	if firstAbs == secondAbs {
		return true, nil
	}

	firstInfo, firstErr := os.Stat(firstAbs)
	if firstErr != nil {
		if errors.Is(firstErr, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("inspect path %q: %w", first, firstErr)
	}
	secondInfo, secondErr := os.Stat(secondAbs)
	if secondErr != nil {
		if errors.Is(secondErr, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("inspect path %q: %w", second, secondErr)
	}
	return os.SameFile(firstInfo, secondInfo), nil
}

// RemoveIfSameFile removes path only while it still names the regular file
// represented by expected. It returns false without removing anything if the
// path disappeared or was replaced.
func RemoveIfSameFile(path string, expected os.FileInfo) (bool, error) {
	if expected == nil {
		return false, nil
	}
	current, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("inspect path %q before removal: %w", path, err)
	}
	if !current.Mode().IsRegular() || !os.SameFile(expected, current) {
		return false, nil
	}
	if err := os.Remove(path); err != nil {
		return false, fmt.Errorf("remove path %q: %w", path, err)
	}
	return true, nil
}
