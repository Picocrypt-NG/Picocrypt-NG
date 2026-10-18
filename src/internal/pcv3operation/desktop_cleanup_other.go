//go:build !linux || android

package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"os"
)

func linuxDesktopCleanupSupported() bool { return false }

// PrepareLinuxDesktopCleanup leaves the existing non-Linux cleanup contract unchanged.
func PrepareLinuxDesktopCleanup(string, []*os.File) error { return nil }

// PinDesktopCleanupInputs is unused outside the Linux desktop backend.
func PinDesktopCleanupInputs([]string, []*os.File) ([]*os.File, error) { return nil, nil }

func prepareDesktopOperationCleanup(string, *os.File, *pcv3credential.FactorRequest, []string, []*os.File) ([]*os.File, error) {
	return nil, nil
}
