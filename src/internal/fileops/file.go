package fileops

import (
	"errors"
	"fmt"
	"os"
)

// CreateSecureNoSymlink creates or truncates a file unless the leaf is a symlink.
// It is the only sanctioned write-creation primitive (SEC-02): the plain CreateSecure was retired
// so an unguarded O_CREATE that follows a pre-planted symlink cannot be reintroduced.
func CreateSecureNoSymlink(path string) (*os.File, error) {
	f, err := openFileNoFollow(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err == nil {
		return f, nil
	}

	if info, lerr := os.Lstat(path); lerr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing to open symlink: %s", path)
		}
		if info.IsDir() {
			return nil, fmt.Errorf("path exists as directory: %s", path)
		}
	}
	return nil, err
}

// CreateExclusiveNoSymlink creates a new file only if no leaf entry already
// exists. A successful return gives the caller exclusive ownership of the path,
// so cleanup may safely remove it.
func CreateExclusiveNoSymlink(path string) (*os.File, error) {
	f, err := openFileNoFollow(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err == nil {
		return f, nil
	}
	return nil, err
}

// OpenExistingNoSymlink opens an existing file for writes without following a
// symlink planted at the leaf path. Callers must pass only non-creating flags.
func OpenExistingNoSymlink(path string, flag int) (*os.File, error) {
	if flag&os.O_CREATE != 0 {
		return nil, fmt.Errorf("OpenExistingNoSymlink called with O_CREATE: %s", path)
	}
	f, err := openFileNoFollow(path, flag, 0)
	if err == nil {
		return f, nil
	}

	if info, lerr := os.Lstat(path); lerr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing to open symlink: %s", path)
		}
		if info.IsDir() {
			return nil, fmt.Errorf("path exists as directory: %s", path)
		}
	}
	return nil, err
}

// OpenRegularReadNoSymlink opens an existing regular file read-only without
// following a leaf symlink. On Unix it opens nonblocking so a substituted FIFO
// cannot wait for a peer before the descriptor type is checked. The caller owns
// the returned descriptor; rejected descriptors are closed here.
func OpenRegularReadNoSymlink(path string) (*os.File, error) {
	file, err := OpenExistingNoSymlink(path, regularReadFlags)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || info == nil || !info.Mode().IsRegular() || info.Size() < 0 {
		return nil, errors.Join(errors.New("input is not a regular file"), err, file.Close())
	}
	return file, nil
}

// OpenRootNoSymlink opens one pre-existing directory without accepting a
// symlink as the selected root and proves that the opened handle has the same
// identity observed before the open. Callers own the returned root.
func OpenRootNoSymlink(path string) (*os.Root, error) {
	expected, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if expected.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to open directory symlink: %s", path)
	}
	if !expected.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", path)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	opened, statErr := root.Stat(".")
	if statErr != nil || opened == nil || !os.SameFile(expected, opened) {
		return nil, errors.Join(errors.New("directory identity changed while opening"), statErr, root.Close())
	}
	return root, nil
}
