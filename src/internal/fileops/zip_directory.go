package fileops

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ZIPInputCandidate carries discovery's original containing-directory authority.
// It is immutable metadata, with no descriptor ownership. Capture is required
// before retaining a regular input; Path continues to name the archive entry.
type ZIPInputCandidate struct {
	Path         string
	Info         os.FileInfo
	parent       *zipDirectoryIdentity
	name         string
	explicitLeaf bool
}

// A root stores one absolute path; descendants store one component and share
// their immutable ancestors. No node retains a descriptor or full ancestor list.
type zipDirectoryIdentity struct {
	parent *zipDirectoryIdentity
	name   string
	info   os.FileInfo
}

func captureZIPDirectory(path string) (*zipDirectoryIdentity, error) {
	return captureZIPDirectoryWithMetadata(path, nil)
}

func captureZIPDirectoryWithMetadata(path string, metadata *ZIPInputMetadataReservation) (*zipDirectoryIdentity, error) {
	path = zipNativeLookupPath(path)
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(resolved)
	if err != nil {
		return nil, err
	}
	// Keep the literal terminal dot: it makes the selected object an
	// intermediate directory lookup, so FIFO/device replacement cannot block a
	// read-only open before os.Root checks the descriptor's type.
	root, err := os.OpenRoot(absolute + string(filepath.Separator) + ".")
	if err != nil {
		return nil, err
	}
	info, statErr := root.Stat(".")
	if err := errors.Join(statErr, root.Close()); err != nil {
		return nil, err
	}
	if info == nil || !info.IsDir() || !os.SameFile(info, info) {
		return nil, errors.New("archive directory identity is unavailable")
	}
	if metadata != nil {
		return metadata.directory(nil, absolute, info)
	}
	return &zipDirectoryIdentity{name: absolute, info: info}, nil
}

func (directory *zipDirectoryIdentity) open() (*os.Root, error) {
	var root *os.Root
	var err error
	if directory.parent == nil {
		// The anchor is canonical at capture. Do not accept a later leaf link.
		info, statErr := os.Lstat(directory.name) //nolint:gosec // G703: inspect the user-selected anchor; descriptor identity is checked before reading source bytes.
		if statErr != nil {
			return nil, statErr
		}
		if !info.IsDir() || !os.SameFile(directory.info, info) {
			return nil, errors.New("archive directory changed after selection")
		}
		root, err = os.OpenRoot(directory.name + string(filepath.Separator) + ".")
	} else {
		parent, openErr := directory.parent.open()
		if openErr != nil {
			return nil, openErr
		}
		info, statErr := parent.Lstat(directory.name)
		if statErr != nil || info == nil || !info.IsDir() || !os.SameFile(directory.info, info) {
			return nil, errors.Join(errors.New("archive directory changed after selection"), statErr, parent.Close())
		}
		root, err = parent.OpenRoot(directory.name + string(filepath.Separator) + ".")
		err = errors.Join(err, parent.Close())
	}
	if err != nil {
		if root != nil {
			err = errors.Join(err, root.Close())
		}
		return nil, err
	}
	info, statErr := root.Stat(".")
	if statErr != nil || info == nil || !info.IsDir() || !os.SameFile(directory.info, info) {
		return nil, errors.Join(errors.New("archive directory changed while opening"), statErr, root.Close())
	}
	return root, nil
}

func (directory *zipDirectoryIdentity) path() string {
	if directory.parent == nil {
		return directory.name
	}
	return filepath.Join(directory.parent.path(), directory.name)
}

// pathBytes bounds the joined source path without constructing ancestor copies.
func (directory *zipDirectoryIdentity) pathBytes(name string) (uint64, error) {
	length := uint64(len(name))
	for directory != nil {
		var ok bool
		length, ok = zipResourceAdd(length, uint64(len(directory.name)))
		if !ok {
			return 0, ErrZIPMetadataLimit
		}
		length, ok = zipResourceAdd(length, 1)
		if !ok {
			return 0, ErrZIPMetadataLimit
		}
		directory = directory.parent
	}
	return length, nil
}

func (directory *zipDirectoryIdentity) candidate(path, name string) (ZIPInputCandidate, error) {
	root, err := directory.open()
	if err != nil {
		return ZIPInputCandidate{}, err
	}
	info, statErr := root.Lstat(name)
	if err := errors.Join(statErr, root.Close()); err != nil {
		return ZIPInputCandidate{}, err
	}
	return ZIPInputCandidate{Path: path, Info: info, parent: directory, name: name}, nil
}

// InspectZIPInput captures the original parent and leaf metadata without
// following the selected leaf. It retains no descriptor. Reserve the selection
// metadata before calling, and use Capture or Walk without recapturing its path.
func InspectZIPInput(path string) (ZIPInputCandidate, error) {
	return inspectExplicitZIPInput(path, nil)
}

func inspectExplicitZIPInput(path string, metadata *ZIPInputMetadataReservation) (ZIPInputCandidate, error) {
	candidate, err := inspectZIPInput(path, metadata)
	if err == nil || !errors.Is(err, os.ErrPermission) {
		return candidate, err
	}
	// A known named file needs search access, not listing access to its parent.
	// This initial explicit-selection exception is never used for discovered
	// members or by a later failed reopen of an already anchored identity.
	info, err := os.Lstat(path) //nolint:gosec // G703: explicit inputs may name any path; this reads metadata and subsequent source opens check the captured identity.
	if err != nil {
		return ZIPInputCandidate{}, err
	}
	if !os.SameFile(info, info) {
		return ZIPInputCandidate{}, errors.New("archive input identity is unavailable")
	}
	if !info.IsDir() {
		return ZIPInputCandidate{Path: path, Info: info, explicitLeaf: true}, nil
	}
	resolved, err := filepath.EvalSymlinks(zipNativeLookupPath(path))
	if err != nil {
		return ZIPInputCandidate{}, err
	}
	absolute, err := filepath.Abs(resolved)
	if err != nil {
		return ZIPInputCandidate{}, err
	}
	var directory *zipDirectoryIdentity
	if metadata != nil {
		directory, err = metadata.directory(nil, absolute, info)
	} else {
		directory = &zipDirectoryIdentity{name: absolute, info: info}
	}
	if err != nil {
		return ZIPInputCandidate{}, err
	}
	return ZIPInputCandidate{Path: path, Info: info, parent: directory, name: "."}, nil
}

func inspectZIPInput(path string, metadata *ZIPInputMetadataReservation) (ZIPInputCandidate, error) {
	selectedPath := path
	path = zipNativeLookupPath(path)
	parentPath, name := filepath.Split(path)
	if name == "." || name == ".." || name == "" {
		parent, err := captureZIPDirectoryWithMetadata(path, metadata)
		if err != nil {
			return ZIPInputCandidate{}, err
		}
		return parent.candidate(selectedPath, ".")
	}
	if parentPath == "" {
		parentPath = "."
	}
	parent, err := captureZIPDirectoryWithMetadata(parentPath, metadata)
	if err != nil {
		return ZIPInputCandidate{}, err
	}
	return parent.candidate(selectedPath, name)
}

func (candidate ZIPInputCandidate) directory() (*zipDirectoryIdentity, error) {
	return candidate.directoryWithMetadata(nil)
}

func (candidate ZIPInputCandidate) directoryWithMetadata(metadata *ZIPInputMetadataReservation) (*zipDirectoryIdentity, error) {
	if candidate.Info == nil || !candidate.Info.IsDir() || candidate.parent == nil {
		return nil, errors.New("archive input is not a directory")
	}
	if candidate.name == "." {
		if !os.SameFile(candidate.Info, candidate.parent.info) {
			return nil, errors.New("archive directory identity changed")
		}
		if metadata != nil {
			if err := metadata.retain(candidate.parent); err != nil {
				return nil, err
			}
		}
		return candidate.parent, nil
	}
	if metadata != nil {
		return metadata.directory(candidate.parent, candidate.name, candidate.Info)
	}
	return &zipDirectoryIdentity{parent: candidate.parent, name: strings.Clone(candidate.name), info: candidate.Info}, nil
}

// resolve follows only explicitly authorized links. Relative targets traverse
// the captured parents; an absolute or escaping target is a separate selection.
func (candidate ZIPInputCandidate) resolveWithMetadata(remaining int, metadata *ZIPInputMetadataReservation) (ZIPInputCandidate, error) {
	if candidate.Info == nil || (candidate.parent == nil && !candidate.explicitLeaf) {
		return ZIPInputCandidate{}, errors.New("archive input identity is unavailable")
	}
	if candidate.Info.Mode()&os.ModeSymlink == 0 {
		return candidate, nil
	}
	if remaining == 0 {
		return ZIPInputCandidate{}, errors.New("too many archive input symlinks")
	}
	if candidate.parent == nil {
		resolved, err := filepath.EvalSymlinks(zipNativeLookupPath(candidate.Path))
		if err != nil {
			return ZIPInputCandidate{}, err
		}
		next, err := inspectExplicitZIPInput(resolved, metadata)
		if err != nil {
			return ZIPInputCandidate{}, err
		}
		return next.resolveWithMetadata(remaining-1, metadata)
	}
	root, err := candidate.parent.open()
	if err != nil {
		return ZIPInputCandidate{}, err
	}
	name := candidate.name
	info, statErr := root.Lstat(name)
	if statErr != nil || info == nil || !os.SameFile(candidate.Info, info) {
		return ZIPInputCandidate{}, errors.Join(errors.New("archive input link changed after selection"), statErr, root.Close())
	}
	target, readErr := root.Readlink(name)
	if err := errors.Join(readErr, root.Close()); err != nil {
		return ZIPInputCandidate{}, err
	}
	if filepath.IsAbs(target) {
		next, err := inspectExplicitZIPInput(target, metadata)
		if err != nil {
			return ZIPInputCandidate{}, err
		}
		return next.resolveWithMetadata(remaining-1, metadata)
	}
	parent := candidate.parent
	components := strings.Split(filepath.FromSlash(target), string(filepath.Separator))
	var next ZIPInputCandidate
	for index, component := range components {
		switch component {
		case "", ".":
			continue
		case "..":
			if parent.parent == nil {
				// Keep lookup components: cleaning would bypass missing paths or
				// change the meaning of symlink/.. traversal.
				next, err := inspectExplicitZIPInput(parent.name+string(filepath.Separator)+strings.Join(components[index:], string(filepath.Separator)), metadata)
				if err != nil {
					return ZIPInputCandidate{}, err
				}
				return next.resolveWithMetadata(remaining-1, metadata)
			}
			parent = parent.parent
			continue
		}
		next, err = parent.candidate(filepath.Join(parent.path(), component), component)
		if err != nil {
			return ZIPInputCandidate{}, err
		}
		next, err = next.resolveWithMetadata(remaining-1, metadata)
		if err != nil {
			return ZIPInputCandidate{}, err
		}
		if index == len(components)-1 {
			return next, nil
		}
		parent, err = next.directoryWithMetadata(metadata)
		if err != nil {
			return ZIPInputCandidate{}, err
		}
	}
	return ZIPInputCandidate{Path: parent.path(), Info: parent.info, parent: parent, name: "."}, nil
}

// Capture binds a candidate to a regular source, preserving lexical entry names.
// Following links is opt-in and pins the resolved target independently of later
// changes to the selected link. Directory and broken links remain non-inputs.
func (candidate ZIPInputCandidate) Capture(followSymlinks bool) (ZIPInputIdentity, error) {
	return candidate.capture(followSymlinks, nil)
}

func (candidate ZIPInputCandidate) capture(followSymlinks bool, metadata *ZIPInputMetadataReservation) (ZIPInputIdentity, error) {
	selectedPath := candidate.Path
	var err error
	if followSymlinks {
		candidate, err = candidate.resolveWithMetadata(255, metadata)
	}
	if err != nil {
		return ZIPInputIdentity{}, err
	}
	if candidate.Info == nil || !candidate.Info.Mode().IsRegular() || candidate.Info.Size() < 0 || !os.SameFile(candidate.Info, candidate.Info) {
		return ZIPInputIdentity{}, fmt.Errorf("archive input %q is not a regular file", selectedPath)
	}
	if candidate.parent == nil {
		if !candidate.explicitLeaf {
			return ZIPInputIdentity{}, errors.New("archive input directory authority is unavailable")
		}
		readPath := candidate.Path
		if followSymlinks {
			readPath, err = filepath.EvalSymlinks(zipNativeLookupPath(readPath))
		}
		if err != nil {
			return ZIPInputIdentity{}, err
		}
		absolute, err := filepath.Abs(readPath)
		if err != nil {
			return ZIPInputIdentity{}, err
		}
		if metadata != nil {
			if err := metadata.admitReadPath(selectedPath, uint64(len(absolute))); err != nil {
				return ZIPInputIdentity{}, err
			}
		}
		identity := ZIPInputIdentity{selectedPath: selectedPath, readPath: absolute, info: candidate.Info, explicitLeaf: true}
		file, err := identity.Open()
		if err != nil {
			return ZIPInputIdentity{}, err
		}
		if err := file.Close(); err != nil {
			return ZIPInputIdentity{}, err
		}
		return identity, nil
	}
	if metadata != nil {
		if err := metadata.retain(candidate.parent); err != nil {
			return ZIPInputIdentity{}, err
		}
		length, err := candidate.parent.pathBytes(candidate.name)
		if err != nil {
			return ZIPInputIdentity{}, err
		}
		if err := metadata.admitReadPath(selectedPath, length); err != nil {
			return ZIPInputIdentity{}, err
		}
	}
	return ZIPInputIdentity{selectedPath: selectedPath, readPath: filepath.Join(candidate.parent.path(), candidate.name), info: candidate.Info, parent: candidate.parent}, nil
}
