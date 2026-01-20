// Picocrypt NG v2.04
// Copyright (c) Picocrypt NG developers
// Released under GPL-3.0-only
// https://github.com/Picocrypt-NG/Picocrypt-NG
//
// Picocrypt NG is a secure, audited file encryption tool that uses:
//   - Argon2id for password-based key derivation (memory-hard, GPU-resistant)
//   - XChaCha20 for symmetric encryption (256-bit security, extended nonce)
//   - BLAKE2b-512 for message authentication (or HMAC-SHA3 in paranoid mode)
//   - Optional Serpent-CTR as second cipher layer (paranoid mode)
//   - Reed-Solomon error correction for data recovery
//   - Plausible deniability through nested encryption
//
// The cryptographic implementation was audited in August 2024.
//
// Build modes:
//   - Default build: GUI + CLI (requires graphics libraries)
//   - CLI-only build: go build -tags cli (no graphics dependencies)

package main

// version is the application version displayed in the window title.
// Format: "vMAJOR.MINOR" (e.g., "v2.02")
const version = "v2.04"

func main() {
	run()
}
