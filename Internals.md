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

# Key Schedule & Subkey Stream
This section documents the exact key-derivation order so an independent decryptor can be written. Source: `internal/crypto/kdf.go` (`SubkeyReader`) and `internal/volume/decrypt.go` (`decryptVerifyAuth`).

## Master key
1. `key = Argon2id(password, salt)` — salt is the 16-byte Argon2 salt from the header; parameters per mode (normal: 4 passes, 1 GiB, 4 threads; paranoid: 8 passes, 1 GiB, 8 threads), output 32 bytes.
2. Keyfile key (if keyfiles are used) is XORed into the master key. The **timing** of this XOR differs between v1 and v2 (see below).

## HKDF subkey stream
A single `HKDF-SHA3-256(key, hkdfSalt)` stream produces all subkeys, read **sequentially** in a fixed order. `hkdfSalt` is the 32-byte HKDF salt from the header. The `SubkeyReader` enforces the read order via a state machine — reading out of order, or skipping a subkey, shifts every later subkey and makes the volume undecryptable.

**v2.00+ subkey order (`Picocrypt-NG`):**

| Stream offset | Size | Subkey |
| ------------- | ---- | ------ |
| 0   | 64 | Header subkey — keys the HMAC-SHA3-512 over the header fields (v2 only) |
| 64  | 32 | MAC subkey — keys the payload MAC (BLAKE2b-512 normal / HMAC-SHA3-512 paranoid) |
| 96  | 32 | Serpent key (paranoid mode cascade) |
| 128+ | 24 + 16 | Per rekey cycle: XChaCha20 nonce (24) then Serpent IV (16) |

**v1.x subkey order (original Picocrypt — no header subkey):**

| Stream offset | Size | Subkey |
| ------------- | ---- | ------ |
| 0   | 32 | MAC subkey |
| 32  | 32 | Serpent key |
| 64+ | 24 + 16 | Per rekey cycle: XChaCha20 nonce (24) then Serpent IV (16) |

## Keyfile-XOR timing: v1 vs v2
The two formats differ in **when** the keyfile key is XORed relative to HKDF initialization:

- **v1.x — XOR before HKDF.** `key = Argon2(password, salt)`, then `key = key XOR keyfileKey`, then `hkdf = HKDF-SHA3-256(key, hkdfSalt)`. The keyfile contribution flows into the entire subkey stream (MAC subkey, Serpent key, rekey values).
- **v2.00+ — HKDF before XOR.** `key = Argon2(password, salt)`, then `hkdf = HKDF-SHA3-256(key, hkdfSalt)` (using the password-only key), then `key = key XOR keyfileKey`. The XOR affects **only the XChaCha20 key**; the HKDF stream (header/MAC/Serpent subkeys) is derived from the password-only key.

Getting either the subkey order or the XOR timing wrong yields the wrong subkeys and authentication fails. The `SubkeyReader.HeaderSubkey()` call is the v2-only first read; v1 starts directly at `MACSubkey()`.

# Password Normalization
A visually identical password can be encoded as different UTF-8 bytes depending on the platform's keyboard/input method (e.g. composed `é` U+00E9 vs decomposed `e` + U+0301). Because the password bytes feed Argon2id directly, two such forms would derive different keys, so a volume encrypted on one platform could not be decrypted on another.

To fix this, the password is normalized to **Unicode NFC** (`golang.org/x/text/unicode/norm`) before key derivation, as mandated for passwords by [RFC 8265](https://www.rfc-editor.org/rfc/rfc8265) (PRECIS `OpaqueString`) and recommended by NIST SP 800-63B-4 §3.1.1.2. Only canonical composition is applied — never compatibility normalization (NFKC/NFKD, which would collapse distinct characters and reduce entropy), case folding, or whitespace trimming.

- **Encrypt** normalizes the password to NFC (including the deniability wrapper key), so new volumes are cross-platform-stable.
- **Decrypt** tries each form in order — NFC, then NFD, then the raw bytes as typed — and keeps the first that authenticates against the volume MAC. This opens new volumes, pre-existing volumes whose password was already NFC/ASCII, and legacy volumes encrypted from decomposed or non-canonical bytes. Trying several canonical forms of the same password never bypasses authentication; each form is verified independently.
- **ASCII passwords are invariant** under every normalization form, so they collapse to a single candidate with no extra key derivations — the overwhelming majority of volumes are unaffected.
- **Force-decrypt** bypasses authentication, so it has no signal to choose a form and uses the password exactly as typed.

This is implemented in `internal/password` and applied at every key-derivation chokepoint (desktop/CLI/mobile via `internal/volume`, and the web build in `internal/wasm`). Note one consequence: a *new* volume whose password contains non-ASCII characters may not decrypt in an *older* Picocrypt build that does not normalize, unless the user happens to type the exact stored bytes — the desktop and CLI therefore show an advisory when encrypting with a non-ASCII password.

# Counter Overflow
Since XChaCha20 has a max message size of 256 GiB, Picocrypt NG will use the HKDF-SHA3 mentioned above to generate a new nonce for XChaCha20 and a new IV for Serpent if the total encrypted data is more than 60 GiB. While this threshold can be increased up to 256 GiB, Picocrypt NG uses 60 GiB to prevent any edge cases with blocks or the counter used by Serpent.

Each rekey cycle reads the next **24-byte XChaCha20 nonce** followed by the next **16-byte Serpent IV** from the HKDF subkey stream described above (starting at stream offset 128 for v2, offset 64 for v1). The MAC subkey is never re-read, so the payload MAC spans the entire stream across all rekey boundaries. Note this is distinct from the deniability layer's rekeying (see [Deniability](#deniability)), which derives its new nonce from `SHA3-256(old_nonce)` rather than from an HKDF stream.

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

The HMAC message covers the entire listed header, unlike v1.x which only stored
`SHA3-512(key)`. In a password-only v2 volume the HMAC is keyed by a
password-derived subkey. In a legacy v2 keyfile volume, however, that subkey is
derived before keyfile XOR. Including the public keyfile hash in the message
does not make the HMAC key depend on the keyfile. Picocrypt NG retains v1/v2
read compatibility, but Picocrypt-NG 2.19 does not create new v2 keyfile
volumes.

## Version Routing

`MatchVersion` recognizes the syntax `vN.NN`; syntax recognition is not
cryptographic-version authorization. Picocrypt-NG 2.19 supports v1 and v2.
Immediately after decoding the version field, the header reader rejects every
other well-formed major with `ErrUnsupportedVersion`, before reading flags or
KDF inputs. Force decrypt cannot bypass this gate. Deniability detection keeps
a syntactically valid unknown-major header on the normal header path so it is
rejected rather than accidentally treated as an outer wrapper.

## Verify First Mode (Two-Pass Decryption)

Picocrypt NG offers an optional "Verify first" mode that addresses security audit recommendation PCC-004: authenticate ciphertext before decryption.

In standard streaming decryption, the MAC is computed incrementally alongside decryption, meaning the MAC can only be verified after the entire file has been decrypted. While Picocrypt uses encrypt-then-MAC (the correct order), this means the decryption algorithm is applied to potentially attacker-controlled data before authenticity is confirmed.

When "Verify first" is enabled, decryption proceeds in two passes:
1. **Pass 1 (Verification)**: Read entire file, compute MAC over ciphertext without decrypting
2. **MAC Check**: Verify computed MAC matches stored authentication tag
3. **Pass 2 (Decryption)**: Only if MAC is valid, perform actual decryption

**Trade-offs:**
- **Security**: Payload decryption is not performed before the stored MAC is checked
- **Performance**: File is read twice, roughly doubling I/O time
- **Recommended for**: High-security scenarios, untrusted file sources

This feature is available in the decrypt advanced options as "Verify first" checkbox.

# Keyfile Design

The following algorithm describes the legacy v1/v2 read format. Picocrypt-NG
2.19 preserves decryption of supported keyfile volumes but rejects every new
encryption request containing keyfiles, whether keyfile-only or
password-plus-keyfile. New 2.19 volumes are password-only.

If correct order is not required, Picocrypt NG will take the SHA3-256 of each keyfile individually and XOR the hashes together. Finally, the result is XORed with the master key. Because the XOR operation is both commutative and associative, the order in which the keyfile hashes are XORed with each other doesn't matter - the end result is the same.

If correct order is required, Picocrypt NG will concatenate the keyfiles together in the order they were dropped into the window and take the SHA3-256 of the combined keyfiles. If the order is not correct, the keyfiles, when appended to each other, will result in a different file, and thus a different hash. So, the correct order of keyfiles is required to decrypt the volume successfully.

For v1, keyfile XOR precedes HKDF and contributes to the derived operational
keys. For legacy v2, HKDF is initialized first: the keyfile changes the
XChaCha20 key and remains necessary for confidentiality, but it does not bind
the header MAC, payload MAC, Serpent key, or the HKDF rekey nonce/IV schedule.
After recovery, create a new password-only 2.19 volume. If a keyfile factor is
mandatory, wait for a reviewed v3 format rather than treating another v2 volume
as factor-bound; v3 is not implemented or scheduled here.

# Reed-Solomon
By default, all Picocrypt NG volume headers are encoded with Reed-Solomon to improve resiliency against bit rot. The header uses N+2N encoding, where N is the size of a particular header field such as the version number, and 2N is the number of parity bytes added. Using the Berlekamp-Welch algorithm, Picocrypt NG is able to automatically detect and correct up to 2N/2=N broken bytes.

If Reed-Solomon is to be used with the input data itself, the data will be encoded using 128+8 encoding, with the data being read in 1 MiB chunks and encoded in 128-byte blocks, and the final block padded to 128 bytes using PKCS#7.

To address the edge case where the final 128-byte block happens to be padded so that it completes a full 1 MiB chunk, a flag is used to distinguish whether the last 128-byte block was padded originally or if it is just a full 128-byte block of data.

# Deniability
Picocrypt NG's deniability option re-encrypts the regular volume without retaining its recognizable Picocrypt NG header. The resulting salt, nonce, and ciphertext are intended to look random to an observer who does not know the password. This limited random-looking-container property is not anonymity and does not guarantee protection against forensic analysis, traffic or storage metadata, endpoint compromise, or coercion. A deniable volume has this layout:
```
[argon2 salt][xchacha20 nonce][encrypted stream of bytes]
```

**Layout (`internal/volume/deniability.go`).** The wrapper prepends exactly two raw, unencoded fields before the encrypted inner volume:

| Offset | Size | Field |
| ------ | ---- | ----- |
| 0  | 16 | Argon2 salt (random) |
| 16 | 24 | XChaCha20 nonce (random) |
| 40 | …  | XChaCha20-encrypted inner volume (the complete regular `.pcv`) |

Neither field is Reed-Solomon encoded. The raw random salt and nonce avoid adding a recognizable Picocrypt NG header, supporting the wrapper's limited random-looking-container goal.

**Key derivation.** The deniability key is `Argon2id(NFC(password), salt)` using **normal-mode** parameters regardless of the inner volume's mode: 4 passes, 1 GiB memory, 4 threads, 32-byte output. (The inner volume keeps its own independent salt/key in its header.)

**Credential boundary (Picocrypt-NG 2.19 writers).** Every new volume requires a non-empty password, and every encryption request containing keyfiles is rejected before encryption begins. This applies with or without deniability. Direct `AddDeniability` also rejects an empty password before deriving the outer key or replacing its input. Keyfile material is never an input to the outer Argon2id derivation.

**Legacy read compatibility.** Readers continue to accept supported v1/v2 keyfile volumes, including keyfile-only deniable v2 volumes historically created with an empty outer password. Decrypt such a volume with its original credentials, then create a new password-only volume. Merely rewrapping the affected inner v2 volume with a non-empty outer password fixes the empty-wrapper problem but does not add keyfile binding to the inner header MAC, payload MAC, Serpent key, or rekey schedule.

**Rekeying.** The deniability layer rekeys every 60 GiB, but unlike the inner volume it does **not** use an HKDF stream. The new nonce is `nonce = SHA3-256(old_nonce)[:24]` (`crypto.DeniabilityRekey`); the Argon2 key is unchanged.

**Detection.** A regular volume begins with an RS5-encoded, syntactically valid version field; a deniable wrapper normally begins with random salt/nonce bytes that do not decode to that syntax. A well-formed but unsupported major stays on the regular-header path and fails closed. To unwrap a deniable volume, read salt(16) + nonce(24), derive the key, and XChaCha20-decrypt the remainder; the result is a normal Picocrypt volume parsed as described above.

**Security note.** The outer layer uses XChaCha20 without its own authentication tag. A wrong outer password or wrapper modification is recognized only when the recovered inner volume can be parsed and authenticated. The inner volume supplies its format-specific authentication, subject to the legacy limitations above; force decrypt can deliberately bypass the payload-MAC failure.

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

### `internal/ui/`
- **app.go**: Main window and Fyne GUI integration
- **drop.go**: Drag-and-drop file handling
- **dialogs.go**: Modal dialogs (password generator, keyfile selection)
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
