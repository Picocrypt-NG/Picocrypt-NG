package mobile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
