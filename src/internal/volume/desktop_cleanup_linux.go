//go:build linux && !android

package volume

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3publication"
	"errors"
	"os"
)

// Pin the original selection before preprocessing can close its ZIP readers.
// The caller owns held and factors, including when preparation fails.
func prepareDesktopEncryptCleanup(req *EncryptRequest, options pcv3operation.ExecutionOptions) (factors *pcv3operation.FactorRequest, held []*os.File, err error) {
	if !options.LinuxDesktopCleanup {
		return nil, nil, nil
	}
	identities, err := fileops.CaptureZIPInputs(preprocessInputFiles(req), req.InputIdentities)
	if err != nil {
		return nil, held, errors.Join(pcv3publication.ErrCleanupIncomplete, err)
	}
	for _, identity := range identities {
		file, openErr := identity.Open()
		if openErr != nil {
			return nil, held, errors.Join(pcv3publication.ErrCleanupIncomplete, openErr)
		}
		held = append(held, file)
	}
	directories, err := pcv3operation.PinDesktopCleanupInputs(req.OnlyFolders, append(append([]*os.File(nil), held...), options.DesktopProtectedFiles...))
	held = append(held, directories...)
	if err != nil {
		return nil, held, err
	}
	factors, err = pcv3WriteFactors(req)
	if err != nil {
		return factors, held, err
	}
	protected := append(append([]*os.File(nil), held...), options.DesktopProtectedFiles...)
	for _, keyfile := range factors.Keyfiles {
		if keyfile == nil || keyfile.BorrowFile() == nil {
			return factors, held, pcv3publication.ErrCleanupIncomplete
		}
		protected = append(protected, keyfile.BorrowFile())
	}
	return factors, held, pcv3operation.PrepareLinuxDesktopCleanup(req.OutputFile, protected)
}
