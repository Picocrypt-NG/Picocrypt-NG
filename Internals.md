# Internals
If you're wondering about how Picocrypt NG handles cryptography, you've come to the right place! This page contains the technical details about the cryptographic algorithms and parameters used, as well as how cryptographic values are stored in the header format.

# Core Cryptography
Picocrypt NG uses the following cryptographic primitives:
- XChaCha20 (cascaded with Serpent in counter mode for paranoid mode)
- Keyed-BLAKE2b for normal mode, HMAC-SHA3 for paranoid mode (256-bit key, 512-bit digest)
- HKDF-SHA3-256 for deriving subkeys from a single stream:
    - 64-byte subkey for header HMAC (v2)
    - 32-byte subkey for payload MAC (BLAKE2b or HMAC-SHA3)
    - 32-byte subkey for Serpent
    - Additional nonces/IVs during rekeying
- Argon2id:
    - Normal mode: 4 passes, 1 GiB memory, 4 threads
    - Paranoid mode: 8 passes, 1 GiB memory, 8 threads

All primitives used are from the well-known [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) module.

# Counter Overflow
Since XChaCha20 has a max message size of 256 GiB, Picocrypt NG will use the HKDF-SHA3 mentioned above to generate a new nonce for XChaCha20 and a new IV for Serpent if the total encrypted data is more than 60 GiB. While this threshold can be increased up to 256 GiB, Picocrypt NG uses 60 GiB to prevent any edge cases with blocks or the counter used by Serpent.

# Header Format
A Picocrypt NG volume's header is encoded with Reed-Solomon by default since it is, after all, the most important part of the entire file. An encoded value will take up three times the size of the unencoded value.

**All offsets and sizes below are in bytes.**
| Offset | Encoded size | Decoded size | Description
| ------ | ------------ | ------------ | -----------
| 0      | 15           | 5            | Version number (ex. "v2.00")
| 15     | 15           | 5            | Length of comments, zero-padded to 5 bytes
| 30     | 3C           | C            | Comments with a length of C characters
| 30+3C  | 15           | 5            | Flags (paranoid mode, use keyfiles, etc.)
| 45+3C  | 48           | 16           | Salt for Argon2
| 93+3C  | 96           | 32           | Salt for HKDF-SHA3
| 189+3C | 48           | 16           | IV for Serpent
| 237+3C | 72           | 24           | Nonce for XChaCha20
| 309+3C | 192          | 64           | HMAC-SHA3-512 of header (v2) or SHA3-512 of key (v1.x)
| 501+3C | 96           | 32           | SHA3-256 of keyfile key
| 597+3C | 192          | 64           | Authentication tag (BLAKE2b/HMAC-SHA3)
| 789+3C |              |              | Encrypted contents of input data

## Header Authentication (v2)
In v2.00+, the "key hash" field contains an HMAC-SHA3-512 computed over the following header fields (in order):
1. Version string
2. Comments length (5-char zero-padded string)
3. Comments content
4. Flags
5. Argon2 salt
6. HKDF salt
7. Serpent IV
8. XChaCha20 nonce
9. Keyfile hash

This provides integrity protection for the entire header, unlike v1.x which only stored SHA3-512(key). Picocrypt NG v2.00 maintains backward compatibility with v1.x volumes.

## Verify First Mode (Two-Pass Decryption)

Picocrypt NG offers an optional "Verify first" mode that addresses security audit recommendation PCC-004: authenticate ciphertext before decryption.

In standard streaming decryption, the MAC is computed incrementally alongside decryption, meaning the MAC can only be verified after the entire file has been decrypted. While Picocrypt uses encrypt-then-MAC (the correct order), this means the decryption algorithm is applied to potentially attacker-controlled data before authenticity is confirmed.

When "Verify first" is enabled, decryption proceeds in two passes:
1. **Pass 1 (Verification)**: Read entire file, compute MAC over ciphertext without decrypting
2. **MAC Check**: Verify computed MAC matches stored authentication tag
3. **Pass 2 (Decryption)**: Only if MAC is valid, perform actual decryption

**Trade-offs:**
- **Security**: Keys are never applied to unverified data
- **Performance**: File is read twice, roughly doubling I/O time
- **Recommended for**: High-security scenarios, untrusted file sources

This feature is available in the decrypt advanced options as "Verify first" checkbox.

# Keyfile Design
Picocrypt NG allows the use of keyfiles as an additional form of authentication. Picocrypt NG's unique "Require correct order" feature enforces the user to drop keyfiles into the window in the same order as they did when encrypting in order to decrypt the volume successfully. Here's how it works:

If correct order is not required, Picocrypt NG will take the SHA3-256 of each keyfile individually and XOR the hashes together. Finally, the result is XORed with the master key. Because the XOR operation is both commutative and associative, the order in which the keyfile hashes are XORed with each other doesn't matter - the end result is the same.

If correct order is required, Picocrypt NG will concatenate the keyfiles together in the order they were dropped into the window and take the SHA3-256 of the combined keyfiles. If the order is not correct, the keyfiles, when appended to each other, will result in a different file, and thus a different hash. So, the correct order of keyfiles is required to decrypt the volume successfully.

# Reed-Solomon
By default, all Picocrypt NG volume headers are encoded with Reed-Solomon to improve resiliency against bit rot. The header uses N+2N encoding, where N is the size of a particular header field such as the version number, and 2N is the number of parity bytes added. Using the Berlekamp-Welch algorithm, Picocrypt NG is able to automatically detect and correct up to 2N/2=N broken bytes.

If Reed-Solomon is to be used with the input data itself, the data will be encoded using 128+8 encoding, with the data being read in 1 MiB chunks and encoded in 128-byte blocks, and the final block padded to 128 bytes using PKCS#7.

To address the edge case where the final 128-byte block happens to be padded so that it completes a full 1 MiB chunk, a flag is used to distinguish whether the last 128-byte block was padded originally or if it is just a full 128-byte block of data.

# Deniability
Plausible deniability in Picocrypt NG is achieved by simply re-encrypting the volume but without storing any identifiable header data. A new Argon2 salt and XChaCha20 nonce will be generated and stored in the deniable volume, but since both values are random, they don't reveal anything. A deniable volume will look something like this:
```
[argon2 salt][xchacha20 nonce][encrypted stream of bytes]
```

**Security Note:** The deniability layer intentionally uses unauthenticated encryption (XChaCha20 without a MAC). Adding authentication would defeat the purpose of deniability, as the MAC would be identifiable metadata. The inner volume remains fully authenticated, so data integrity is still protected.

# Security Considerations

## CLI Password Input

The CLI provides three methods for password input:

1. **Interactive (recommended)**: Omit `-p` and `-P` flags. The password is entered without echo and won't appear in shell history.
2. **Stdin (`-P`)**: For scripted use. Pipe password via stdin: `echo "pw" | picocrypt -P ...`
3. **Command-line (`-p`)**: **Warning**: The password will be visible in shell history, process listings (`ps`), and potentially system logs. Only use in environments where shell history is disabled or for testing.

For maximum security, prefer interactive prompts or stdin piping.

## Memory Handling

Picocrypt NG zeros sensitive key material after use via `crypto.SecureZero()`. This uses constant-time operations to prevent compiler optimization from removing the zeroing. However, Go's garbage collector may create copies of sensitive data that cannot be zeroed. This is an inherent limitation of garbage-collected languages. For most threat models, the implemented zeroing significantly reduces the attack window.

# Code Structure

Picocrypt NG v2.00+ has been refactored into a modular architecture. The codebase is organized as follows:

## Core Cryptographic Packages (AUDIT-CRITICAL)

These packages implement the cryptographic operations and must be modified with extreme care:

### `internal/crypto/`
- **cipher.go**: XChaCha20 and Serpent-CTR cipher suite with proper encrypt-then-MAC ordering
- **kdf.go**: Argon2id key derivation and HKDF-SHA3-256 subkey derivation
- **mac.go**: BLAKE2b-512 (normal mode) and HMAC-SHA3-512 (paranoid mode)
- **rekey.go**: Cipher rekeying every 60 GiB to prevent nonce overflow
- **zeroing.go**: Secure memory zeroing using constant-time operations

### `internal/header/`
- **format.go**: Volume header structure and field size constants
- **reader.go**: Header deserialization with Reed-Solomon decoding
- **writer.go**: Header serialization with Reed-Solomon encoding
- **auth.go**: Header authentication (v2: HMAC-SHA3-512; v1: SHA3-512 of key)

### `internal/keyfile/`
- **processor.go**: Keyfile hashing with ordered/unordered modes
  - Ordered: `SHA3-256(file1 || file2 || ...)`
  - Unordered: `SHA3-256(file1) XOR SHA3-256(file2) XOR ...`

### `internal/volume/`
- **encrypt.go**: 8-phase encryption pipeline orchestration
- **decrypt.go**: 7-phase decryption pipeline with v1/v2 compatibility (optional two-pass verify-first mode)
- **context.go**: Operation context with automatic key material cleanup
- **deniability.go**: Plausible deniability wrapper (random-looking header)

## Supporting Packages

### `internal/encoding/`
- **rs.go**: Reed-Solomon error correction with 7 codec configurations
- **padding.go**: PKCS#7 padding for Reed-Solomon block alignment

### `internal/fileops/`
- **zip.go**: Multi-file compression with optional Deflate
- **unpack.go**: Zip extraction with automatic folder creation
- **split.go**: Volume splitting into chunks (for cloud storage limits)
- **recombine.go**: Chunk recombination before decryption

### `internal/app/`
- **state.go**: Centralized application state (replaces global variables)
- **reporter.go**: Progress reporting interface for UI updates
- **runner.go**: Operation orchestration with goroutine management

### `internal/ui/`
- **app.go**: Main window and Dear ImGui integration
- **drop.go**: Drag-and-drop file handling
- **modals.go**: Modal dialogs (password generator, keyfile selection)
- **state.go**: UI-specific state helpers

### `internal/util/`
- **constants.go**: Size units (KiB, MiB, GiB, TiB)
- **format.go**: Progress, speed, and time formatting
- **passgen.go**: Cryptographically secure password generation

## Entry Point

**`cmd/picocrypt/main.go`**: Application entry point (~40 lines)
- Initializes UI
- Minimal logic (all business logic in `internal/`)

## Reading the Code

For understanding specific operations:
1. **Encryption flow**: Start at `volume.Encrypt()` in `internal/volume/encrypt.go`
2. **Decryption flow**: Start at `volume.Decrypt()` in `internal/volume/decrypt.go`
3. **Crypto primitives**: Read `internal/crypto/*.go` (well-commented, ~1000 lines total)
4. **Header format**: See `internal/header/format.go` for field layout

The refactored code is thoroughly commented and much easier to understand than the original monolithic implementation.
