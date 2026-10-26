# Internals
The algorithms, key schedule, header layout, rekeying and Reed-Solomon details
below describe legacy v1/v2 compatibility. PCV3-specific notes are labelled.
New native encryption uses PCV3 with a separate format and credential schedule;
see the [PCV3 security contract](docs/SECURITY_CONTRACT.md) and
[native architecture](ARCHITECTURE.md).

# PCV3 cryptography

PCV3 uses independent purpose-labelled HKDF-SHA3-256 keys rather than the
legacy sequential subkey stream below. Each volume has a fresh random 32-byte
VolumeKey. Standalone Normal uses XChaCha20/keyed BLAKE2b-512 or, with Paranoid,
Serpent-256-CTR followed by XChaCha20/HMAC-SHA3-512. Records and the final record
are authenticated before ordinary plaintext is released. Reed-Solomon repairs
semantic bytes before their MAC check; authentication does not cover every
physical parity byte, and ordinary reads are not full-RS scrubs.

## PCV3 password profile

PCV3 freezes **bounded Unicode 18.0.0 NFC** under
[UAX #15 revision 58](https://www.unicode.org/reports/tr15/tr15-58.html) in the
isolated `internal/pcv3operation/internal/pcv3unicode` package. Accepted passwords
receive NFC without implicit U+034F CGJ insertion; explicitly entered CGJ is
preserved. Excessive normalization runs are rejected before KDF instead of
being mapped to different credentials. This resource admission constraint
excludes some valid Unicode strings; it is separate from Unicode NFC itself.

The bound uses the frozen normalizer's leading/trailing non-starter counts:
expanded NFKD properties, CCC or backward-combining behavior, zero-CCC Jamo V/T,
and Hangul trailing-count overrides. A leading-count sum above 30 is refused;
counting only nonzero CCC is incompatible. The credential boundary retains the
pinned engine but rejects its output if the CGJ count increases, after checking
the 1 MiB output limit. It clears the rejected owned output. This does not
compatibility-normalize the password or require a second Unicode engine.
Exact generator/runtime sources and hashes are pinned in
[Unicode provenance](src/internal/pcv3operation/internal/pcv3unicode/provenance.json);
[UAX #15 section 13](https://www.unicode.org/reports/tr15/tr15-58.html#Stream_Safe_Text_Format)
explains the underlying Stream-Safe mechanism.

Passwords must be valid UTF-8 using the UnicodeData-derived assigned repertoire,
with at most 1 MiB before and after canonicalization. Spaces and U+0000 are
significant; no trimming, case folding, compatibility normalization or NFD/raw
retry is applied. An empty password is valid only when the password factor is
absent in keyfile-only mode.

The pre-release implementation fixes NFC composition defects tracked as
upstream x/text issues 81001 and 81021. Earlier experimental PCV3 credential
bytes produced by those defects are intentionally unsupported, with no
automatic fallback to the defective transformations. Experimental credential
bytes that depended on implicit CGJ insertion likewise have no compatibility
guarantee or automatic fallback before this format's first publication. Newly
assigned Unicode-18 scalars are admissible within the same resource bounds.
Existing volume and Unicode-17 fixture bytes remain unchanged. Legacy v1/v2
continue to use `internal/password` and the normalization/retry behavior
documented below; their runtime dependency was
not upgraded for this PCV3 change.

## PCV3 D1C

D1 is the explicit frontend mode; D1C is its current construction. Both hidden
profiles protect the complete password/keyfile transcript. Standard profile
`0x0101` uses XChaCha20/keyed BLAKE2b-512; Paranoid profile `0x0102` adds
Serpent-CTR and uses HMAC-SHA3-512. Both use fixed Argon2id version 1.3,
1 GiB memory, eight passes and eight lanes (profile `0x03`), independently of
the cipher choice. No resource shortage lowers these parameters.

Two 320-byte bootstraps separately wrap independent random outer key `O` and
inner root input `I`; the inner VolumeKey `V` is independent of both. A
bootstrap's prefix is 128 bytes, followed by 64-byte replica, outer-wrap and
inner-wrap tags at offsets 128, 192 and 256. Both credential tags bind the
complete wrapped pair. Creation performs two sequential KDFs; a healthy
ordinary read performs one, tail fallback at most two. The inner root uses
purpose-separated HKDF, feature mask `0x0002` and root marker `0x03`; its salt
is authenticated metadata, with no inner Argon2id call. Strict verification
requires both bootstraps and two KDFs; see the
[`VerifyD1` API contract](API.md#pcv3-operation-boundary).

The complete inner header, metadata and trailer are encrypted. D1C streams
creation through the outer encoder and reads through a bounded virtual reader;
it creates no separate clear inner-volume staging file. It has no outer RS;
inner structural RS and optional payload RS remain inside the encrypted stream.
The frozen independent encoder and composition vectors are documented in the
[D1 fixture README](src/internal/pcv3operation/internal/pcv3/testdata/d1/README.md).

D1C hides the recognizable header. File name, size and filesystem traces remain
visible; it promises no complete deniability. Ordinary opening may authenticate
only front and payload, leaving tail unchecked. Strict verification is separate
and does not claim authentication of every physical RS parity byte. Recovery
trust, including permanent raw-selected provenance, follows the
[security contract](docs/SECURITY_CONTRACT.md#recovery-trust).

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

Implementations use the Go standard library and dependencies pinned in
[src/go.mod](src/go.mod), including `golang.org/x/crypto` and the separate
`github.com/Picocrypt-NG/serpent` module.

# Key Schedule & Subkey Stream
This section documents the exact key-derivation order so an independent decryptor can be written. Source: `internal/crypto/kdf.go` (`SubkeyReader`) and `internal/volume/decrypt.go` (`decryptVerifyAuth`).

## Master key
1. `key = Argon2id(password, salt)`: salt is the 16-byte Argon2 salt from the header; parameters per mode (normal: 4 passes, 1 GiB, 4 threads; paranoid: 8 passes, 1 GiB, 8 threads), output 32 bytes.
2. Keyfile key (if keyfiles are used) is XORed into the master key. The **timing** of this XOR differs between v1 and v2 (see below).

## HKDF subkey stream
A single `HKDF-SHA3-256(key, hkdfSalt)` stream produces all subkeys in a fixed
sequential order. `hkdfSalt` is the 32-byte HKDF salt from the header. Callers
must preserve the version-specific order below. `SubkeyReader` rejects duplicate
named reads and Serpent-before-MAC reads, but does not enforce every ordering
constraint; its raw `Reader` also advances the stream. Skipping or reordering
bytes changes the later subkeys.

**v2.00+ subkey order (`Picocrypt-NG`):**

| Stream offset | Size | Subkey |
| ------------- | ---- | ------ |
| 0   | 64 | Header subkey for HMAC-SHA3-512 over the header fields (v2 only) |
| 64  | 32 | MAC subkey for the payload MAC (BLAKE2b-512 normal / HMAC-SHA3-512 paranoid) |
| 96  | 32 | Serpent key (paranoid mode cascade) |
| 128+ | 24; 40 in Paranoid | Per rekey cycle: XChaCha20 nonce (24), then Serpent IV (16) only in Paranoid mode |

**v1.x subkey order (original Picocrypt, no header subkey):**

| Stream offset | Size | Subkey |
| ------------- | ---- | ------ |
| 0   | 32 | MAC subkey |
| 32  | 32 | Serpent key |
| 64+ | 24; 40 in Paranoid | Per rekey cycle: XChaCha20 nonce (24), then Serpent IV (16) only in Paranoid mode |

## Keyfile-XOR timing: v1 vs v2
The two formats differ in **when** the keyfile key is XORed relative to HKDF initialization:

- **v1.x: XOR before HKDF.** `key = Argon2(password, salt)`, then `key = key XOR keyfileKey`, then `hkdf = HKDF-SHA3-256(key, hkdfSalt)`. The keyfile contribution flows into the entire subkey stream (MAC subkey, Serpent key, rekey values).
- **v2.00+: HKDF before XOR.** `key = Argon2(password, salt)`, then `hkdf = HKDF-SHA3-256(key, hkdfSalt)` (using the password-only key), then `key = key XOR keyfileKey`. The XOR affects **only the XChaCha20 key**; the HKDF stream (header/MAC/Serpent subkeys) is derived from the password-only key.

Getting either the subkey order or the XOR timing wrong yields the wrong subkeys and authentication fails. The `SubkeyReader.HeaderSubkey()` call is the v2-only first read; v1 starts directly at `MACSubkey()`.

# Password Normalization
This section describes the legacy v1/v2 path; PCV3 uses the frozen profile above.

A visually identical password can have different UTF-8 encodings, such as
composed `é` (U+00E9) and decomposed `e` + U+0301. Those bytes derive different
Argon2id keys unless the reader applies the matching normalization.

`internal/password` retains the legacy use of
`golang.org/x/text/unicode/norm`. Its NFC and NFD operations include Stream-Safe
processing, which can insert U+034F CGJ into excessive normalization runs.
This differs from PCV3's bounded profile, which refuses implicit insertion.
Legacy processing applies no NFKC/NFKD normalization, case folding or whitespace
trimming.

- The internal legacy compatibility writer uses current NFC for the inner
  password and the deniability wrapper. Native and browser frontends create
  PCV3 rather than exposing this writer.
- Ordinary legacy readers try current NFC, current NFD, raw bytes, historical
  Unicode-15 NFC, then historical Unicode-15 NFD, removing duplicate candidates.
  The v1 password-key hash or v2 header MAC selects the candidate; final payload
  authentication remains separate. The historical forms preserve credentials
  produced by earlier normalization tables and defects.
- ASCII input produces one candidate and needs no additional normalization
  attempts.
- Native legacy Force uses the raw password as typed because its authentication
  bypass cannot select a candidate. Browser legacy Force still tries the
  candidates and requires header authentication before retaining damaged payload.

The unauthenticated legacy deniability wrapper selects an outer candidate by a
recognizable inner version field. The inner reader must then perform its own
format-specific authentication. These compatibility retries do not apply to
PCV3. Older implementations without matching normalization may still require
the exact historical password bytes.

# Counter Overflow
Legacy payload processing reinitializes its XChaCha20 and optional Serpent
ciphers every 60 GiB, below XChaCha20's per-nonce 256 GiB limit.

Each rekey cycle reads a 24-byte XChaCha20 nonce from the HKDF stream. Paranoid
mode then reads a 16-byte Serpent IV; Normal mode consumes no IV bytes. The first
cycle starts at offset 128 for v2 or 64 for v1, and subsequent cycles consume 24
bytes in Normal mode or 40 in Paranoid mode. The MAC subkey is not re-read, so
the payload MAC spans every rekey boundary. The legacy deniability layer uses
`SHA3-256(old_nonce)` instead; see [Deniability](#deniability).

# Header Format
Legacy v1/v2 headers use Reed-Solomon encoding. Each encoded header field uses
three times its decoded byte length.

**All offsets and sizes below are in bytes.**
| Offset | Encoded size | Decoded size | Description
| ------ | ------------ | ------------ | -----------
| 0      | 15           | 5            | Version number (ex. "v2.00")
| 15     | 15           | 5            | Length of comments, zero-padded to 5 bytes
| 30     | 3C           | C            | Comments with a length of C UTF-8 bytes
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
read compatibility, but the legacy compatibility writer does not create new v2 keyfile
volumes.

## Version Routing

`MatchVersion` recognizes the syntax `vN.NN`; syntax recognition is not
cryptographic-version authorization. The legacy header reader supports v1 and v2;
PCV3 routes separately.
Immediately after decoding the version field, the header reader rejects every
other well-formed major with `ErrUnsupportedVersion`, before reading flags or
KDF inputs. Force decrypt cannot bypass this gate. Deniability detection keeps
a syntactically valid unknown-major header on the normal header path so it is
rejected rather than accidentally treated as an outer wrapper.

## Verify First Mode (Two-Pass Decryption)

Legacy decryption offers an optional "Verify first" mode for audit recommendation
PCC-004: authenticate the payload ciphertext before payload decryption.

Ordinary legacy streaming decryption computes the payload MAC alongside
decryption and checks it at the end, before publication. The cipher therefore
processes potentially unauthenticated ciphertext into private staging.

With "Verify first" and without Force, payload processing uses two passes:

1. **Pass 1 (Verification)**: Read entire file, compute MAC over ciphertext without decrypting
2. **MAC Check**: Verify computed MAC matches stored authentication tag
3. **Pass 2 (Decryption)**: Only if MAC is valid, perform actual decryption

The extra pass reads the payload again and re-derives the keys. Force can
explicitly bypass a failed MAC check even with this option enabled. The
desktop exposes the "Verify first" checkbox for legacy decryption; PCV3 has
its own authentication and publication contract.

# Keyfile Design

The following algorithm describes the legacy v1/v2 read format. The compatibility
reader preserves supported keyfile volumes, but the writer rejects every new
legacy v2 encryption request containing keyfiles. New legacy v2 volumes are
password-only. Native applications now create PCV3 by default with password,
keyfile, or combined credential policies; every selected keyfile must be non-empty.

If correct order is not required, Picocrypt NG will take the SHA3-256 of each keyfile individually and XOR the hashes together. Finally, the result is XORed with the master key. Because the XOR operation is both commutative and associative, the order in which the keyfile hashes are XORed with each other doesn't matter - the end result is the same.

If correct order is required, Picocrypt NG will concatenate the keyfiles together in the order they were dropped into the window and take the SHA3-256 of the combined keyfiles. If the order is not correct, the keyfiles, when appended to each other, will result in a different file, and thus a different hash. So, the correct order of keyfiles is required to decrypt the volume successfully.

For v1, keyfile XOR precedes HKDF and contributes to the derived operational
keys. For legacy v2, HKDF is initialized first: the keyfile changes the
XChaCha20 key and remains necessary for confidentiality, but it does not bind
the header MAC, payload MAC, Serpent key, or the HKDF rekey nonce/IV schedule.
After recovery, create a new PCV3 volume. PCV3 binds its declared
password/keyfile policy through the PCV3
credential transcript; this does not repair an existing legacy v2 volume.

# Reed-Solomon
By default, all Picocrypt NG volume headers are encoded with Reed-Solomon to improve resiliency against bit rot. The header uses N+2N encoding, where N is the size of a particular header field such as the version number, and 2N is the number of parity bytes added. Using the Berlekamp-Welch algorithm, Picocrypt NG is able to automatically detect and correct up to 2N/2=N broken bytes.

If Reed-Solomon is to be used with the input data itself, the data will be encoded using 128+8 encoding, with the data being read in 1 MiB chunks and encoded in 128-byte blocks, and the final block padded to 128 bytes using PKCS#7.

To address the edge case where the final 128-byte block happens to be padded so that it completes a full 1 MiB chunk, a flag is used to distinguish whether the last 128-byte block was padded originally or if it is just a full 128-byte block of data.

# Deniability
The wrapper layout and rekeying in this section describe legacy v1/v2.
Current PCV3 uses [D1C](#pcv3-d1c).

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

**Legacy credential boundary.** Every new legacy v2 volume requires a non-empty password, and every legacy encryption request containing keyfiles is rejected before encryption begins. Direct legacy `AddDeniability` also rejects an empty password before deriving the outer key or replacing its input. Keyfile material is never an input to this legacy outer Argon2id derivation.

**PCV3 D1 credential boundary.** See [PCV3 D1C](#pcv3-d1c) for the current
construction. It accepts password-only, keyfile-only or combined factors;
keyfiles protect both layers. A known or predictable keyfile still permits
offline candidate testing.

**Legacy read compatibility.** Readers continue to accept supported v1/v2 keyfile volumes, including keyfile-only deniable v2 volumes historically created with an empty outer password. Decrypt such a volume with its original credentials, then create a native PCV3 volume with the required password and keyfile factors. Merely rewrapping the affected inner v2 volume with a non-empty outer password fixes the empty-wrapper problem but does not add keyfile binding to the inner header MAC, payload MAC, Serpent key, or rekey schedule.

**Rekeying.** The deniability layer rekeys every 60 GiB, but unlike the inner volume it does **not** use an HKDF stream. The new nonce is `nonce = SHA3-256(old_nonce)[:24]` (`crypto.DeniabilityRekey`); the Argon2 key is unchanged.

**Detection.** A regular volume begins with an RS5-encoded, syntactically valid version field; a deniable wrapper normally begins with random salt/nonce bytes that do not decode to that syntax. A well-formed but unsupported major stays on the regular-header path and fails closed. To unwrap a deniable volume, read salt(16) + nonce(24), derive the key, and XChaCha20-decrypt the remainder; the result is a normal Picocrypt volume parsed as described above.

**Security note.** The outer layer uses XChaCha20 without its own authentication tag. A wrong outer password or wrapper modification is recognized only when the recovered inner volume can be parsed and authenticated. The inner volume supplies its format-specific authentication, subject to the legacy limitations above; force decrypt can deliberately bypass the payload-MAC failure.

# Security Considerations

## CLI Password Input

The CLI provides four methods for password input:

1. **Interactive (recommended)**: Omit `-p`, `-P`, and `--password-fd`; the terminal prompt disables echo.
2. **Stdin (`-P`)**: Read one password line from a secret provider or an owner-only password file when stdin is free.
3. **Inherited descriptor (`--password-fd`)**: On Unix, use descriptor 3 or higher to keep credentials separate from payload stdin; open it afresh for each invocation.
4. **Command-line (`-p`)**: Real passwords can appear in process listings, shell history, and logs. Disabling shell history does not remove the process-list risk; reserve this option for non-secret test values or deliberate empty-password keyfile-only use.

## Memory Handling

Picocrypt NG overwrites owned sensitive byte buffers after use via `crypto.SecureZero()`, backed by `internal/secret`. The helper uses a non-inlined `clear` followed by `runtime.KeepAlive`, without allocating another buffer. Optimized compiler output must be checked when changing this helper or the toolchain. This is best-effort cleanup: other copies held by the runtime, compiler or dependencies may remain, and complete memory erasure is not guaranteed.

Production Argon2 calls use `internal/argon2`, maintained from `golang.org/x/crypto` v0.58.0 with explicit cleanup of its workspace and selected intermediate buffers. Cleanup follows worker completion and extraction of the independent output key; algorithm parameters and derived bytes are unchanged. The existing `FreeOSMemory` calls reclaim memory but do not provide a secure-erasure contract. Internal hash state, assembly/register copies, and earlier swap or dump contents remain outside this cleanup guarantee.

ARM and x86 32-bit builds allocate the workspace in separate typed chunks of at most 4 MiB; other architectures retain contiguous storage. Android builds set the pinned Go runtime's `madvdontneed=1` default at link time so completed workspaces release resident pages before the next memory observation. Android shared-library startup does not import process `GODEBUG` settings.

# Code Structure

The codebase is organized as follows:

## Core Cryptographic Packages (AUDIT-CRITICAL)

These packages implement the cryptographic operations and must be modified with extreme care:

### `internal/crypto/`
- **cipher.go**: XChaCha20 and Serpent-CTR cipher suite with encrypt-then-MAC ordering
- **kdf.go**: Argon2id key derivation and HKDF-SHA3-256 subkey derivation
- **mac.go**: BLAKE2b-512 (normal mode) and HMAC-SHA3-512 (paranoid mode)
- **rekey.go**: Cipher rekeying every 60 GiB to prevent nonce overflow
- **zeroing.go**: Compatibility facade for shared sensitive-buffer cleanup

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
- **encrypt.go**: encryption pipeline orchestration
- **decrypt.go**: decryption pipeline with v1/v2 compatibility (optional two-pass verify-first mode)
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

`cmd/picocrypt/main.go` applies startup process protection and dispatches to the
GUI/CLI build-specific entry point. Operation logic lives under `internal/`.

## Reading the Code

For understanding specific operations:

- Native encryption enters `volume.EncryptWithResult` in
  `internal/volume/encrypt.go` and dispatches PCV3 to `internal/pcv3operation/`.
- Legacy decryption starts at `volume.Decrypt` in `internal/volume/decrypt.go`;
  PCV3 reads use the separate operation facade.
- Legacy primitives live in `internal/crypto/`; their header layout lives in
  `internal/header/format.go`.
