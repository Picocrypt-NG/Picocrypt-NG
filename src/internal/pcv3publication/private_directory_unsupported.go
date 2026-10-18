//go:build !linux && !darwin && !windows

package pcv3publication

import (
	"errors"
	"os"
)

func privateDirectoryInfo(os.FileInfo) bool { return false }
func trustedCleanupParent(*os.File) bool    { return false }
func createPrivateDirectory(*os.Root, *os.File, string) (*os.Root, *os.File, os.FileInfo, error) {
	return nil, nil, nil, errors.ErrUnsupported
}

func createPrivateStage(*os.Root, *os.File, string) (*os.File, error) {
	return nil, errors.ErrUnsupported
}

func trustedLegacyJournalParent(*os.File) bool { return false }

func privateDirectoryBackendAvailable() bool { return false }

func privateDirectoryParentTrusted(*os.File) bool { return false }
