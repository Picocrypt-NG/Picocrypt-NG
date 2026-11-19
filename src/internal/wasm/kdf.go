package wasm

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/kdfgate"
	"Picocrypt-NG/internal/pcv3operation"
	"context"
)

var (
	deriveWASMKey           = crypto.DeriveKey
	legacyBrowserHasKDFRoom = kdfgate.BrowserHasKDFRoom
)

func admittedWASMKey(pending uint64, password, salt []byte, paranoid bool) ([]byte, error) {
	release, err := kdfgate.Acquire(context.Background())
	if err != nil {
		return nil, err
	}
	defer release()
	if !legacyBrowserHasKDFRoom(pending) {
		return nil, pcv3operation.ErrLegacyKDFResource
	}
	return deriveWASMKey(password, salt, paranoid)
}
