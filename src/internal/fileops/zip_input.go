package fileops

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ZIPInputIdentity is an immutable discovery snapshot. The selected path names
// the archive entry; an explicitly followed link pins its resolved target once.
// It retains metadata, never an open descriptor or a copy of source bytes.
type ZIPInputIdentity struct {
	selectedPath string
	readPath     string
	info         os.FileInfo
}

// ReadPath is the fixed source path, which can differ from the archive name
// after explicit symlink following. It is also protected from output writes.
func (input ZIPInputIdentity) ReadPath() string { return input.readPath }

// ZIPInputFromFileInfo retains the regular-file identity observed by discovery.
// It must receive Lstat metadata, unless the caller already owns the descriptor.
func ZIPInputFromFileInfo(path string, info os.FileInfo) (ZIPInputIdentity, error) {
	if info == nil || !info.Mode().IsRegular() || info.Size() < 0 {
		return ZIPInputIdentity{}, fmt.Errorf("archive input %q is not a regular file", path)
	}
	// Windows pathname metadata resolves its file identity lazily. Resolve it
	// while discovery still owns this name, before a later replacement can bind it.
	if !os.SameFile(info, info) {
		return ZIPInputIdentity{}, fmt.Errorf("archive input %q identity is unavailable", path)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return ZIPInputIdentity{}, err
	}
	return ZIPInputIdentity{selectedPath: path, readPath: absolute, info: info}, nil
}

// CaptureZIPInput records a selected input before any archive work. Following
// links is opt-in; the original path remains the archive-name authority.
func CaptureZIPInput(path string, followSymlinks bool) (ZIPInputIdentity, error) {
	readPath := path
	if followSymlinks {
		var err error
		readPath, err = filepath.EvalSymlinks(path)
		if err != nil {
			return ZIPInputIdentity{}, err
		}
	}
	info, err := os.Lstat(readPath)
	if err != nil {
		return ZIPInputIdentity{}, err
	}
	identity, err := ZIPInputFromFileInfo(readPath, info)
	identity.selectedPath = path
	return identity, err
}

// Open reopens one selected regular file without following a substituted leaf,
// and compares the descriptor identity before the caller can read any bytes.
func (input ZIPInputIdentity) Open() (*os.File, error) {
	if input.info == nil {
		return nil, errors.New("archive input identity is unavailable")
	}
	file, err := OpenRegularReadNoSymlink(input.readPath)
	if err != nil {
		return nil, err
	}
	if err := input.CheckFile(file); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

// CheckFile checks a borrowed descriptor against the discovery snapshot.
func (input ZIPInputIdentity) CheckFile(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	return input.CheckInfo(info)
}

// CheckInfo binds a descriptor's metadata to the original discovery identity.
func (input ZIPInputIdentity) CheckInfo(info os.FileInfo) error {
	if input.info == nil || info == nil || !info.Mode().IsRegular() || !os.SameFile(input.info, info) {
		return fmt.Errorf("archive input %q changed after selection", input.selectedPath)
	}
	return nil
}

// CaptureZIPInputs captures missing snapshots for direct callers, or validates
// an existing selection without replacing its discovery identities.
// The caller must admit retained metadata before invoking this function.
func CaptureZIPInputs(paths []string, identities []ZIPInputIdentity) ([]ZIPInputIdentity, error) {
	if identities != nil {
		if len(paths) != len(identities) {
			return nil, errors.New("archive input identities do not match selection")
		}
		for index, identity := range identities {
			if identity.info == nil || identity.selectedPath != paths[index] {
				return nil, errors.New("archive input identities do not match selection")
			}
		}
		return identities, nil
	}
	identities = make([]ZIPInputIdentity, 0, len(paths))
	for _, path := range paths {
		identity, err := CaptureZIPInput(path, false)
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	return identities, nil
}
