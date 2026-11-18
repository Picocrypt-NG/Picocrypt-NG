package pcv3operation

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3resource"
	"context"
	"errors"
)

var ErrLegacyKDFResource = errors.New("available memory could not be confirmed for legacy Argon2id")

// AdmitLegacyKDF checks the native resource envelope for the fixed legacy
// allocation. The caller holds the shared KDF lease during this check and
// derivation.
func AdmitLegacyKDF(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	admitter := pcv3resource.NewPlatformAdmitter()
	decision, err := admitter.AdmitKDF(ctx, pcv3credential.KDFProfile{MemoryKiB: crypto.Argon2NormalMemory})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || decision != pcv3credential.KDFAdmissionGranted {
		return ErrLegacyKDFResource
	}
	return nil
}
