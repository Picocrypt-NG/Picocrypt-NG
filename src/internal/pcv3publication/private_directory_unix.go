//go:build linux || darwin

package pcv3publication

import (
	"errors"
	"os"
	"syscall"
)

func privateDirectoryInfo(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o700 && int64(stat.Uid) == int64(os.Geteuid())
}

func trustedCleanupParent(parent *os.File) bool {
	if parent == nil {
		return false
	}
	info, err := parent.Stat()
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	// Ownership/BSD mode and platform ACL checks must both exclude namespace
	// mutation by another user; Darwin ACL allow entries can override mode bits.
	return ok && stat != nil && info.IsDir() && (int64(stat.Uid) == int64(os.Geteuid()) || stat.Uid == 0) && (info.Mode().Perm()&0o022 == 0 || info.Mode()&os.ModeSticky != 0) && directoryACLAllowsTrustedCleanup(parent)
}

func createPrivateDirectory(root *os.Root, parent *os.File, name string) (*os.Root, *os.File, os.FileInfo, error) {
	if err := root.Mkdir(name, 0o700); err != nil {
		return nil, nil, nil, err
	}
	named, err := root.Lstat(name)
	if err != nil || named == nil || !privateDirectoryInfo(named) {
		return nil, nil, nil, errors.New("private directory ownership unavailable")
	}
	child, err := root.OpenRoot(name)
	if err != nil {
		return nil, nil, nil, err
	}
	handle, err := child.Open(".")
	if err != nil {
		_ = child.Close()
		return nil, nil, nil, err
	}
	info, err := handle.Stat()
	if err != nil || info == nil || !privateDirectoryInfo(info) || !os.SameFile(named, info) {
		_ = handle.Close()
		_ = child.Close()
		return nil, nil, nil, errors.New("private directory binding unavailable")
	}
	parentInfo, err := parent.Stat()
	if err != nil || parentInfo == nil {
		_ = handle.Close()
		_ = child.Close()
		return nil, nil, nil, errors.New("private directory parent unavailable")
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	childStat := info.Sys().(*syscall.Stat_t)
	if err != nil || !ok || parentStat.Dev != childStat.Dev {
		_ = handle.Close()
		_ = child.Close()
		return nil, nil, nil, errors.New("private directory filesystem mismatch")
	}
	if err := establishPrivateDirectoryACL(handle); err != nil {
		_ = handle.Close()
		_ = child.Close()
		return nil, nil, nil, err
	}
	verified, err := handle.Stat()
	if err != nil || verified == nil || !privateDirectoryInfo(verified) || !os.SameFile(info, verified) {
		_ = handle.Close()
		_ = child.Close()
		return nil, nil, nil, errors.New("private directory changed while restricting access")
	}
	entries, err := readPinnedDirectory(handle)
	if err != nil || len(entries) != 0 {
		_ = handle.Close()
		_ = child.Close()
		return nil, nil, nil, errors.New("private directory contains unexpected entries")
	}
	return child, handle, verified, nil
}

func createPrivateStage(root *os.Root, _ *os.File, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
}

// Legacy journals are authoritative only in a parent whose names other users
// cannot create or replace. Sticky public directories do not authenticate the
// owner of a supplied legacy journal.
func trustedLegacyJournalParent(parent *os.File) bool {
	if !trustedCleanupParent(parent) {
		return false
	}
	info, err := parent.Stat()
	return err == nil && info.Mode().Perm()&0o022 == 0
}
