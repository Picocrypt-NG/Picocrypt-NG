//go:build linux || android

package pcv3publication

import (
	"errors"
	"os"
	"syscall"
)

type journalParentIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Mode   uint32 `json:"mode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
}

type journalFileIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Mode   uint32 `json:"mode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Links  uint64 `json:"links"`
}

func makeJournalParentIdentity(info os.FileInfo) (journalParentIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil || !info.IsDir() {
		return journalParentIdentity{}, errors.ErrUnsupported
	}
	return journalParentIdentity{
		Device: stat.Dev,
		Inode:  stat.Ino,
		Mode:   uint32(info.Mode()),
		UID:    stat.Uid,
		GID:    stat.Gid,
	}, nil
}

func makeJournalFileIdentity(info os.FileInfo) (journalFileIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil || !info.Mode().IsRegular() || stat.Nlink != 1 {
		return journalFileIdentity{}, errors.ErrUnsupported
	}
	return journalFileIdentity{
		Device: stat.Dev,
		Inode:  stat.Ino,
		Mode:   uint32(info.Mode()),
		UID:    stat.Uid,
		GID:    stat.Gid,
		Links:  journalLinkCount(stat.Nlink),
	}, nil
}

func journalLinkCount[T ~uint32 | ~uint64](links T) uint64 {
	return uint64(links)
}

func (identity journalParentIdentity) matches(info os.FileInfo) bool {
	current, err := makeJournalParentIdentity(info)
	return err == nil && identity == current
}

func (identity journalFileIdentity) matches(info os.FileInfo) bool {
	current, err := makeJournalFileIdentity(info)
	return err == nil && identity == current
}

func installCleanupJournalNoReplace(parent *os.File, oldName, newName string) error {
	if parent == nil {
		return errors.ErrUnsupported
	}
	return renameNoReplace(int(parent.Fd()), oldName, newName)
}
