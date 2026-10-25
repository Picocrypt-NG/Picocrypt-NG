# Picocrypt NG Architecture

## Package Structure

```
src/
├── cmd/
│   ├── picocrypt/         # CLI + GUI entry point
│   └── wasm/              # WASM entry point
│
├── internal/
│   ├── app/               # Application state and progress reporting
│   │   ├── state.go       # Centralized UI state
│   │   └── reporter.go    # Progress callbacks
│   │
│   ├── cli/               # Cobra CLI commands (encrypt/decrypt)
│   │
│   ├── argon2/            # Pinned Argon2 implementation with workspace cleanup (AUDIT-CRITICAL)
│   │
│   ├── crypto/            # Cryptographic primitives (AUDIT-CRITICAL)
│   │   ├── cipher.go      # XChaCha20, Serpent
│   │   ├── kdf.go         # Argon2id, HKDF
│   │   ├── mac.go         # BLAKE2b, HMAC-SHA3
│   │   ├── rekey.go       # Cipher rekeying for >60 GiB
│   │   └── zeroing.go     # Sensitive-buffer cleanup
│   │
│   ├── diskspace/         # Available disk space checks
│   ├── distmeta/          # Distribution metadata (version strings)
│   │
│   ├── encoding/          # Reed-Solomon and padding
│   │   ├── rs.go          # Error correction
│   │   └── padding.go     # PKCS#7
│   │
│   ├── errors/            # Typed sentinel errors
│   │
│   ├── fileops/           # File operations
│   │   ├── zip.go         # Zip creation
│   │   ├── unpack.go      # Zip extraction
│   │   ├── split.go       # File splitting
│   │   └── recombine.go   # Chunk recombination
│   │
│   ├── header/            # Volume header format (AUDIT-CRITICAL)
│   │   ├── format.go      # Header structure
│   │   ├── reader.go      # Deserialization + RS decoding
│   │   ├── writer.go      # Serialization + RS encoding
│   │   └── auth.go        # Header authentication (v2 HMAC)
│   │
│   ├── keyfile/           # Keyfile processing (AUDIT-CRITICAL)
│   │   └── processor.go   # Ordered/unordered hashing
│   │
│   ├── log/               # Logging seam (null logger by default)
│   ├── password/          # Legacy password normalization and compatibility retries
│   │
│   ├── pcv3operation/     # Closed native PCV3 application API
│   │   └── internal/     # Go compiler-enforced private implementation
│   │       ├── pcv3/          # Streaming format engines and native adapters
│   │       ├── pcv3artifact/  # Recovery artifact parser/serializer
│   │       ├── pcv3credential/# Credential transcript and key ownership
│   │       ├── pcv3crypto/    # PCV3-only stream primitives
│   │       ├── pcv3recovery/  # Recovery and unverified Force execution
│   │       ├── pcv3resource/  # Resource admission and platform observations
│   │       └── pcv3unicode/   # Frozen Unicode credential normalization
│   ├── pcv3publication/   # Separate staging and atomic publication infrastructure
│   ├── pcv3result/        # Shared outcome/stage leaf types
│   │
│   ├── processsecurity/   # Executable-only Linux dump policy and portal-package scope
│   │
│   ├── ui/                # Fyne GUI
│   │   ├── app.go         # Main window
│   │   ├── drop.go        # Drag-and-drop
│   │   └── ...
│   │
│   ├── util/              # Utilities
│   │   ├── constants.go   # Size constants
│   │   ├── format.go      # Progress/speed formatting
│   │   └── passgen.go     # Password generation
│   │
│   ├── volume/            # High-level encrypt/decrypt (AUDIT-CRITICAL)
│   │   ├── encrypt.go     # Encryption pipeline
│   │   ├── decrypt.go     # Decryption pipeline
│   │   ├── context.go     # Operation context with cleanup
│   │   └── deniability.go # Plausible deniability
│   │
│   ├── wasm/              # WASM bindings
│   └── workflowpolicy/    # CI/release workflow policy checks
│
├── mobile/                # gomobile bindings and typed Android progress/error boundary
│
└── testdata/
    ├── golden/            # v1/v2 compatibility test vectors
    └── legacy/            # Archived original implementation
```

## Data Flow

### Native PCV3 encryption

```
Desktop/CLI: volume.EncryptWithResult -> pcv3operation.RunWriteWithOptions
Android: StartPCV3 -> pcv3operation.RunWriteWithOptions
  1. Prepare a single input or an encrypted temporary ZIP for folders/multiple files
  2. Validate declared factors and admit the fixed KDF resource profile
  3. Derive credentials and serialize Normal PCV3 or D1
  4. Publish through the identity-bound no-replace publisher
  5. Complete optional splitting and cleanup, then return the shared Result
```

Native desktop, CLI and Android creation use PCV3 by default, with a password,
keyfiles, or both. Source deletion requires the shared result's explicit authority.
The internal legacy writer remains for compatibility tests; native and browser
frontends provide no legacy-creation fallback.

### Decryption

Normal PCV3 is routed by content; random-looking D1 requires explicit selection.
The shared operation boundary authenticates, publishes and returns the common
result, including archive and retained-output follow-ups where supported.

Legacy v1/v2 reads remain available through `volume.Decrypt`: recombine chunks,
remove the legacy deniability wrapper when selected, read the header, derive keys,
check the version-specific password/header verifier and payload MAC, then complete requested unpacking.
Unknown major versions fail closed even under force decrypt.

### Android mobile status and error boundary

```text
volume/fileops reporter text
         ↓
src/mobile classifier -> typed ProgressResult codes and arguments
         ↓
gomobile getters -> GoBridge
         ↓
OperationStatus resource renderer
         ↓
Compose ProgressCard + foreground notification
```

`Status`, `Info`, and `Error` remain raw compatibility/diagnostic fields. Android user-facing text
comes from `StatusCode`, speed/ETA, `InfoCode`, item counts/progress, and the stable error `Code`.
Unknown status falls back to localized **Working**; unknown or malformed detail is hidden rather
than exposing backend text. Status and detail code families are tested independently, and operation
state keeps the first terminal result so a later poll cannot replace cancellation, success, or error.

The error boundary maps `AUTH_FAILED`, `DATA_CORRUPTED`, `CORRUPT_HEADER`, `FILE_NOT_FOUND`,
`CANCELLED`, and `GENERIC` to resource-backed `AppError` values. Raw Go/JVM messages are retained
only as technical detail. The recovery matrix remains fail-closed: only authentication errors offer
password retry, and only payload-corruption errors offer force decrypt.

Android's release locale configuration is generated by AGP from the eight filtered app catalogs
(`en`, `ru`, `de`, `fr`, `es`, `zh-Hans`, `hi`, and `ko`) with English declared as the unqualified default;
debug pseudolocales are not release locales.

### Key Derivation (legacy v2 keyfile read semantics)

```
Password
    ↓
Argon2id(password, salt) -> master_key [32 bytes]
    ↓
HKDF-SHA3-256(master_key, hkdf_salt):
    ├─ Bytes 0-63:   header_subkey (header HMAC)
    ├─ Bytes 64-95:  mac_subkey (payload MAC)
    ├─ Bytes 96-127: serpent_key
    └─ Bytes 128+:   rekey values (every 60 GiB)
    ↓
master_key XOR keyfile_key -> encryption_key
    ↓
XChaCha20(encryption_key, nonce) -> cipher stream
```

Because the v2 HKDF stream is initialized before keyfile XOR, the keyfile
changes the XChaCha20 key but does not bind the header MAC, payload MAC, Serpent
key, or rekey values. The legacy v2 compatibility writer therefore rejects
keyfiles, while legacy reads remain available.

`EncryptRequest.PCV3` selects the canonical PCV3 serializer and is enabled by
native frontends. Its zero value preserves the internal legacy compatibility
writer. Android supports files, folders, multiple inputs and compression through
the shared writer. Browser creation uses the same PCV3 engines through a
`js && wasm`-only memory facade; it exposes no legacy writer. Normal PCV3 and PCV3 D1
support password, keyfile, and combined credentials. D1 is the
random-looking path with optional Paranoid ciphers and a fixed D1 KDF.
Its complete credential transcript protects separate outer and inner key wraps;
creation performs two KDFs, and a healthy front-bootstrap read performs one.

## Security

### Audit-Critical Code

The legacy paths in `crypto/`, `header/`, `keyfile/`, and `volume/` descend from audited code. PCV3 has not received an independent audit. Changes require:

1. Running the complete golden corpus: `go test -count=1 -run '^TestGolden' ./internal/volume`
2. Verifying v1.x backward compatibility
3. Assigning owned key buffers explicit cleanup with `crypto.SecureZero` or the existing secret owners
4. Using `subtle.ConstantTimeCompare()` for MAC verification

### Memory Security

Legacy volume operations use `NewEncryptContext(ctx, req)` or
`NewDecryptContext(ctx, req)` and preserve cleanup errors returned by `Close`.
PCV3 has separate credential and output owners behind `pcv3operation`.
These owners clear controllable sensitive buffers; runtime and dependency copies
remain outside the cleanup guarantee. See [memory handling](Internals.md#memory-handling).

### Thread Safety

- `app.State` uses `sync.RWMutex`
- `atomic.Bool` for cancellation flags
- Progress reporters must be thread-safe

## Testing

Run the [source verification lanes](src/README.md#test) from `src/`.
The default suite uses the `migrated_fynedo` tag and serializes packages that
run the fixed 1 GiB KDF. Run the additional production-KDF and uncached golden
commands separately.
For race-sensitive changes, use the documented serialized race lane rather
than running multiple KDF-heavy packages concurrently.

### Test Types

- **Unit tests**: `*_test.go` in each package
- **Golden tests**: `volume/golden_test.go` - verifies v1/v2 decryption
- **Roundtrip tests**: `volume/roundtrip_test.go` - encrypt->decrypt identity
- **Fuzz tests**: `encoding/fuzz_test.go`, `header/fuzz_test.go`

## Refactoring from v1.49

The archived upstream v1.49 source keeps UI, cryptography and global state in
one file. The maintained implementation separates those responsibilities into
packages under `src/internal/`.

The reference is preserved at `src/testdata/legacy/original_audited_picocrypt.go`.
Its filename is historical: the 2024 audit covered upstream commit `7e403a2`,
which declares v1.40, and does not establish that the archived v1.49 source was
audited. See the [legacy reference notes](src/testdata/legacy/README.md).

### Backward Compatibility

v2 decrypts v1.x volumes. Key differences handled:
- v1: SHA3-512(key) for auth, v2: HMAC-SHA3-512(header)
- v1: XORs keyfile before HKDF, v2: XORs after
- v1: Different HKDF stream offsets (no header subkey)

### PCV3 dependency boundary

Native CLI, desktop, mobile, and volume dispatch use `pcv3operation`. The Go
`internal` rule prevents those packages from importing its private codecs,
credential/key owners, recovery engines, resource admission, or frozen Unicode
implementation. Production frontend depguard rules additionally reject direct
cryptographic dependencies. These are compilation and architecture-policy gates,
not substitutes for behavioral compatibility and security tests.

The operation facade accepts owned factors and explicit modes, returns closed
presentation metadata and Go-minted follow-up capabilities, and offers bounded
artifact inspection. Android can submit fresh observations only through the
operation-scoped resource challenge; it cannot choose admission policy. Routing
probes return ownership and coarse errors without exposing parsed capsule state.

Normal and D1 stream serializers accept readers/writers and contain no filesystem
publication steps. D1 filesystem staging lives in `d1_native_writer.go`; stream
encoding lives in `d1_writer.go`. Native adapters remain in the same private codec
package to preserve unexported authenticated capabilities. This source-layer
separation is deliberate; it is not a compiler-enforced codec/native package split.

The browser facade retains verified output in bounded Go memory without OS
staging. It routes ordinary Normal reads separately from explicit recovery;
random-looking D1 requires explicit selection. Legacy v1/v2 reads remain in
`internal/wasm`. The public JavaScript exports validate size, typed-array storage,
closed modes and physical-role consent before copying whole inputs. Shared
storage is rejected. Only authenticated completion or explicit Force outcomes
can carry output.

Browser KDF admission is a separate address-space policy available only to
js/wasm builds; it neither fabricates native OS observations nor changes fixed
KDF profiles or native admission. Collected Go heap, pending output, workspace
and reserves must fit the bounded Go budget, with separate JavaScript buffer
accounting. Physical RAM remains unobservable: a fresh single-operation worker
and worker-error UI recovery are required because runtime OOM remains possible.
Publication remains separate infrastructure, including startup stage-journal
cleanup. The original v1/v2 format and compatibility writer remain unchanged.
