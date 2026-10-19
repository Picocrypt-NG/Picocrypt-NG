//go:build !linux && !darwin

package pcv3operation

import (
	"context"
	"os"
)

func encryptedStreamDestination(_ context.Context, destination *os.File, _ os.FileInfo) (encryptedStreamTransport, error) {
	return newFileEncryptedStreamTransport(destination, destination), nil
}
