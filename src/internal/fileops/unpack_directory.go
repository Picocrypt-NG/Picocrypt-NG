package fileops

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type unpackDirectories struct {
	root    *os.Root
	path    string
	info    os.FileInfo
	first   map[string]*zipDirectoryIdentity
	missing []string
}

func (dirs *unpackDirectories) close(root *os.Root) error {
	if root != nil && root != dirs.root {
		return root.Close()
	}
	return nil
}

// open walks the first observed ancestry with at most two child handles.
// During preflight a nil root means the path was observed absent.
func (dirs *unpackDirectories) open(path string, observe bool) (root *os.Root, retErr error) {
	if err := verifyExtractionRootPath(dirs.path, dirs.info); err != nil {
		return nil, err
	}
	if path == "." {
		return dirs.root, nil
	}
	current := dirs.root
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, dirs.close(current))
		}
	}()
	prefix := ""
	for part := range strings.SplitSeq(path, string(filepath.Separator)) {
		prefix = filepath.Join(prefix, part)
		expected := dirs.first[prefix]
		var next *os.Root
		if observe {
			var info os.FileInfo
			if current != nil {
				var err error
				info, err = current.Lstat(part)
				if err != nil && !errors.Is(err, os.ErrNotExist) {
					return nil, err
				}
				if info != nil && !info.IsDir() {
					if info.Mode()&os.ModeSymlink != 0 {
						return nil, fmt.Errorf("refusing to follow symlink during extraction: %s", filepath.Join(dirs.path, prefix))
					}
					return nil, fmt.Errorf("path exists as file: %s", filepath.Join(dirs.path, prefix))
				}
			}
			if expected == nil {
				expected = &zipDirectoryIdentity{name: part, info: info}
				dirs.first[prefix] = expected
				if info == nil {
					dirs.missing = append(dirs.missing, prefix)
				}
			} else if expected.info == nil && info != nil {
				return nil, fmt.Errorf("extraction directory appeared after preflight: %s: %w", filepath.Join(dirs.path, prefix), os.ErrExist)
			}
		}
		if expected == nil || expected.info == nil && !observe {
			return nil, fmt.Errorf("extraction directory identity unavailable: %s", filepath.Join(dirs.path, prefix))
		}
		if expected.info != nil {
			if current == nil {
				return nil, fmt.Errorf("extraction directory ancestor changed: %s", filepath.Join(dirs.path, prefix))
			}
			var err error
			next, err = expected.openChild(current)
			if err != nil {
				return nil, fmt.Errorf("verify extraction directory %s: %w", filepath.Join(dirs.path, prefix), err)
			}
		}
		err := dirs.close(current)
		current = next
		if err != nil {
			return nil, err
		}
	}
	return current, nil
}

func (dirs *unpackDirectories) verify(path string) error {
	root, err := dirs.open(path, false)
	return errors.Join(err, dirs.close(root))
}

func (dirs *unpackDirectories) verifyExisting() error {
	if err := dirs.verify("."); err != nil {
		return err
	}
	for path, expected := range dirs.first {
		if expected.info != nil {
			if err := dirs.verify(path); err != nil {
				return err
			}
		}
	}
	return nil
}

func (dirs *unpackDirectories) preflight(path string, isDir bool) (retErr error) {
	parent := path
	if !isDir {
		parent = filepath.Dir(path)
	}
	root, err := dirs.open(parent, true)
	if err != nil || root == nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, dirs.close(root)) }()
	if isDir {
		return nil
	}
	outPath := filepath.Join(dirs.path, path)
	info, err := root.Lstat(filepath.Base(path))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("inspect extraction destination %s: %w", outPath, err)
	case info.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("refusing to follow symlink during extraction: %s", outPath)
	case info.IsDir():
		return fmt.Errorf("path exists as directory: %s", outPath)
	default:
		return fmt.Errorf("extraction destination already exists: %s: %w", outPath, os.ErrExist)
	}
}

func (dirs *unpackDirectories) create(path string) (created bool, retErr error) {
	parentName, leaf := filepath.Dir(path), filepath.Base(path)
	parent, err := dirs.open(parentName, false)
	if err != nil {
		return false, err
	}
	defer func() { retErr = errors.Join(retErr, dirs.close(parent)) }()
	if err := parent.Mkdir(leaf, 0o700); err != nil {
		return false, fmt.Errorf("create directory %s: %w", filepath.Join(dirs.path, path), err)
	}
	info, err := unpackCreatedDirLstatFn(parent, leaf)
	if err != nil {
		return true, fmt.Errorf("inspect created directory %s: %w", filepath.Join(dirs.path, path), err)
	}
	if info == nil || !info.IsDir() || !os.SameFile(info, info) {
		return true, fmt.Errorf("created extraction directory identity unavailable: %s", filepath.Join(dirs.path, path))
	}
	dirs.first[path].info = info
	return true, dirs.verify(path)
}

func (dirs *unpackDirectories) sync(stagedEntries []stagedUnpackEntry) (bindingErr, durabilityErr, cleanupErr error) {
	modified := map[string]struct{}{".": {}}
	for _, entry := range stagedEntries {
		modified[filepath.Dir(entry.targetName)] = struct{}{}
	}
	for _, path := range dirs.missing {
		modified[filepath.Dir(path)] = struct{}{}
	}

	ordered := make([]string, 0, len(modified))
	for path := range modified {
		ordered = append(ordered, path)
	}
	slices.SortFunc(ordered, func(left, right string) int {
		if left == right {
			return 0
		}
		if left == "." {
			return 1
		}
		if right == "." {
			return -1
		}
		if depth := strings.Count(right, string(filepath.Separator)) - strings.Count(left, string(filepath.Separator)); depth != 0 {
			return depth
		}
		return strings.Compare(left, right)
	})

	var durabilityErrs, cleanupErrs zipCleanupErrors
	defer func() {
		durabilityErr = durabilityErrs.err()
		cleanupErr = cleanupErrs.err()
	}()
	for _, path := range ordered {
		root, err := dirs.open(path, false)
		if err != nil {
			return err, nil, nil
		}
		handle, err := root.Open(".")
		if err != nil {
			durabilityErrs.add(fmt.Errorf("open modified extraction directory: %w", err))
		} else {
			if err := unpackDirectorySyncFn(handle); err != nil {
				durabilityErrs.add(fmt.Errorf("sync modified extraction directory: %w", err))
			}
			if err := unpackDirectoryCloseFn(handle); err != nil {
				cleanupErrs.add(fmt.Errorf("close modified extraction directory: %w", err))
			}
		}
		if err := dirs.close(root); err != nil {
			cleanupErrs.add(fmt.Errorf("close pinned extraction directory: %w", err))
		}
	}
	return nil, nil, nil
}
