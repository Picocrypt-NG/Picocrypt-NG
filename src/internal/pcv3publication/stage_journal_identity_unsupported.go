//go:build !linux && !android

package pcv3publication

import (
	"errors"
	"os"
)

type journalParentIdentity struct{}

type journalFileIdentity struct{}

func makeJournalParentIdentity(os.FileInfo) (journalParentIdentity, error) {
	return journalParentIdentity{}, errors.ErrUnsupported
}

func makeJournalFileIdentity(os.FileInfo) (journalFileIdentity, error) {
	return journalFileIdentity{}, errors.ErrUnsupported
}

func (journalParentIdentity) matches(os.FileInfo) bool { return false }

func (journalFileIdentity) matches(os.FileInfo) bool { return false }

func installCleanupJournalNoReplace(*os.File, string, string) error {
	return errors.ErrUnsupported
}
