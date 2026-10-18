//go:build !linux || android

package volume

import (
	"Picocrypt-NG/internal/pcv3operation"
	"os"
)

func prepareDesktopEncryptCleanup(*EncryptRequest, pcv3operation.ExecutionOptions) (*pcv3operation.FactorRequest, []*os.File, error) {
	return nil, nil, nil
}
