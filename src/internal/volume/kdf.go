package volume

import (
	"Picocrypt-NG/internal/argon2"
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/kdfgate"
	"Picocrypt-NG/internal/pcv3operation"
	"context"
	"runtime/debug"
)

var deriveVolumeKey = crypto.DeriveKey

var admitLegacyKDF = pcv3operation.AdmitLegacyKDF

func runLegacyKDF(ctx context.Context, derive func() ([]byte, error)) ([]byte, error) {
	release, err := kdfgate.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if err := admitLegacyKDF(ctx); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key, err := derive()
	if cancelled := ctx.Err(); cancelled != nil {
		crypto.SecureZero(key)
		return nil, cancelled
	}
	if err != nil {
		crypto.SecureZero(key)
		return nil, err
	}
	return key, nil
}

func admittedVolumeKey(ctx context.Context, password, salt []byte, paranoid bool) ([]byte, error) {
	return runLegacyKDF(ctx, func() ([]byte, error) {
		return deriveVolumeKey(password, salt, paranoid)
	})
}

func admittedDeniabilityKey(ctx context.Context, password, salt []byte) ([]byte, error) {
	return runLegacyKDF(ctx, func() ([]byte, error) {
		return deriveDeniabilityKey(password, salt), nil
	})
}

func productionDeniabilityKey(password, salt []byte) []byte {
	key := argon2.IDKey(
		password,
		salt,
		crypto.Argon2NormalPasses,
		crypto.Argon2NormalMemory,
		crypto.Argon2NormalThreads,
		crypto.Argon2KeySize,
	)
	debug.FreeOSMemory()
	return key
}

var deriveDeniabilityKey = productionDeniabilityKey
