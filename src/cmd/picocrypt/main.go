// Picocrypt NG v3.0
// Copyright (c) Picocrypt NG developers
// Released under GPL-3.0-only
// https://github.com/Picocrypt-NG/Picocrypt-NG
//
// Picocrypt NG is a secure file encryption tool that uses:
//   - Argon2id for password-based key derivation (memory-hard, GPU-resistant)
//   - XChaCha20 for symmetric encryption (256-bit security, extended nonce)
//   - BLAKE2b-512 for message authentication (or HMAC-SHA3 in paranoid mode)
//   - Optional Serpent-CTR as second cipher layer (paranoid mode)
//   - Reed-Solomon error correction for data recovery
//   - Plausible deniability through nested encryption
//
// The upstream Picocrypt revision 7e403a2 was audited in 2024.
//
// Build modes:
//   - Default build: GUI + CLI (requires graphics libraries)
//   - CLI-only build: go build -tags cli (no graphics dependencies)

package main

// version is the application version displayed in About and CLI version output.
// Format: "vMAJOR.MINOR" (e.g., "v3.0")
const version = "v3.0"

func main() {
	run()
}
