package volume

import (
	"Picocrypt-NG/internal/argon2"
	"Picocrypt-NG/internal/crypto"
)

var deriveVolumeKey = crypto.DeriveKey

func productionDeniabilityKey(password, salt []byte) []byte {
	return argon2.IDKey(
		password,
		salt,
		crypto.Argon2NormalPasses,
		crypto.Argon2NormalMemory,
		crypto.Argon2NormalThreads,
		crypto.Argon2KeySize,
	)
}

var deriveDeniabilityKey = productionDeniabilityKey
