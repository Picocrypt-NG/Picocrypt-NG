//go:build linux && !android

package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3publication"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func linuxDesktopCleanupSupported() bool { return true }

// PrepareLinuxDesktopCleanup recovers only the selected destination parent.
// Every descriptor is borrowed and must remain open until recovery returns.
// Callers preparing an archive must pin its original selection before calling.
func PrepareLinuxDesktopCleanup(target string, protectedFiles []*os.File) error {
	if target == "" {
		return pcv3publication.ErrCleanupIncomplete
	}
	_, err := pcv3publication.CleanupOrphanedStages(filepath.Dir(target), protectedFiles)
	return err
}

// PinDesktopCleanupInputs opens only protection handles, never payload readers.
// A held original also protects a renamed input or an explicitly followed link.
// The returned descriptors are owned by the caller; originals remain borrowed.
func PinDesktopCleanupInputs(paths []string, originals []*os.File) (owned []*os.File, err error) {
	defer func() {
		if err != nil {
			for _, file := range owned {
				err = errors.Join(err, file.Close())
			}
			owned = nil
		}
	}()
	infos := make([]os.FileInfo, len(originals))
	for index, file := range originals {
		if file == nil {
			return owned, pcv3publication.ErrCleanupIncomplete
		}
		info, statErr := file.Stat()
		if statErr != nil || info == nil || (!info.Mode().IsRegular() && !info.IsDir()) {
			return owned, pcv3publication.ErrCleanupIncomplete
		}
		infos[index] = info
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		current, statErr := os.Stat(path)
		covered := false
		for index, original := range originals {
			if (statErr == nil && os.SameFile(infos[index], current)) ||
				(errors.Is(statErr, os.ErrNotExist) && filepath.Clean(original.Name()) == filepath.Clean(path)) {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		fd, openErr := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return owned, pcv3publication.ErrCleanupIncomplete
		}
		file := os.NewFile(uintptr(fd), path)
		owned = append(owned, file)
		info, statErr := file.Stat()
		if statErr != nil || info == nil || (!info.Mode().IsRegular() && !info.IsDir()) {
			return owned, pcv3publication.ErrCleanupIncomplete
		}
	}
	return owned, nil
}

func prepareDesktopOperationCleanup(target string, source *os.File, factors *pcv3credential.FactorRequest, protected []string, borrowed []*os.File) ([]*os.File, error) {
	files := append([]*os.File(nil), borrowed...)
	if source != nil {
		files = append(files, source)
	}
	if factors != nil {
		for _, keyfile := range factors.Keyfiles {
			if keyfile == nil || keyfile.BorrowFile() == nil {
				return nil, pcv3publication.ErrCleanupIncomplete
			}
			files = append(files, keyfile.BorrowFile())
		}
	}
	owned := make([]*os.File, 0, len(files))
	for _, file := range files {
		if file == nil {
			return owned, pcv3publication.ErrCleanupIncomplete
		}
		fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return owned, pcv3publication.ErrCleanupIncomplete
		}
		owned = append(owned, os.NewFile(uintptr(fd), file.Name()))
	}
	additional, err := PinDesktopCleanupInputs(protected, files)
	owned = append(owned, additional...)
	if err != nil {
		return owned, err
	}
	if err := PrepareLinuxDesktopCleanup(target, append(files, owned...)); err != nil {
		return owned, err
	}
	return owned, nil
}
