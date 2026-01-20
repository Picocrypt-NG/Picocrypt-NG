# Picocrypt NG Architecture

## Package Structure

```
src/
├── cmd/picocrypt/          # Entry point
│   └── main.go
│
├── internal/
│   ├── app/               # Application state and progress reporting
│   │   ├── state.go       # Centralized UI state
│   │   ├── reporter.go    # Progress callbacks
│   │   └── runner.go      # Operation orchestration
│   │
│   ├── ui/                # Fyne GUI
│   │   ├── app.go         # Main window
│   │   ├── drop.go        # Drag-and-drop
│   │   └── ...
│   │
│   ├── volume/            # High-level encrypt/decrypt (AUDIT-CRITICAL)
│   │   ├── encrypt.go     # Encryption pipeline
│   │   ├── decrypt.go     # Decryption pipeline
│   │   ├── context.go     # Operation context with cleanup
│   │   └── deniability.go # Plausible deniability
│   │
│   ├── crypto/            # Cryptographic primitives (AUDIT-CRITICAL)
│   │   ├── cipher.go      # XChaCha20, Serpent
│   │   ├── kdf.go         # Argon2id, HKDF
│   │   ├── mac.go         # BLAKE2b, HMAC-SHA3
│   │   ├── rekey.go       # Cipher rekeying for >60 GiB
│   │   └── zeroing.go     # Secure memory zeroing
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
│   ├── encoding/          # Reed-Solomon and padding
│   │   ├── rs.go          # Error correction
│   │   └── padding.go     # PKCS#7
│   │
│   ├── fileops/           # File operations
│   │   ├── zip.go         # Zip creation
│   │   ├── unpack.go      # Zip extraction
│   │   ├── split.go       # File splitting
│   │   └── recombine.go   # Chunk recombination
│   │
│   └── util/              # Utilities
│       ├── constants.go   # Size constants
│       ├── format.go      # Progress/speed formatting
│       └── passgen.go     # Password generation
│
└── testdata/
    ├── golden/            # v1/v2 compatibility test vectors
    └── legacy/            # Archived original implementation
```

## Data Flow

### Encryption

```
User drops files -> ui/drop.go
         ↓
Password/options -> app/state.go
         ↓
Click "Encrypt" -> volume.Encrypt():
  1. Zip multiple files (fileops/zip.go)
  2. Generate salts, nonces, IVs (crypto/kdf.go)
  3. Write RS-encoded header (header/writer.go)
  4. Argon2id key derivation (crypto/kdf.go)
  5. Process keyfiles (keyfile/processor.go)
  6. Compute header HMAC (header/auth.go)
  7. Encrypt: [Serpent] -> XChaCha20 -> MAC (crypto/cipher.go)
  8. Write auth tag, split chunks (fileops/split.go)
```

### Decryption

```
User drops .pcv -> detect decrypt mode
         ↓
volume.Decrypt():
  1. Recombine chunks, strip deniability
  2. RS-decode header (header/reader.go)
  3. Argon2id with params from header
  4. Validate keyfile hash
  5. Verify header MAC (v2) or key hash (v1)
  6. Decrypt: MAC -> XChaCha20 -> [Serpent]
  7. Verify final MAC, auto-unzip
```

### Key Derivation (v2)

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

## Security

### Audit-Critical Code

Packages `crypto/`, `header/`, `keyfile/`, `volume/` contain audited code. Changes require:

1. Running golden tests: `go test -v ./internal/volume -run TestGoldenVectors`
2. Verifying v1.x backward compatibility
3. Using `defer crypto.SecureZero(key)` for all key material
4. Using `subtle.ConstantTimeCompare()` for MAC verification

### Memory Security

```go
// Pattern used throughout
ctx := NewOperationContext(req)
defer ctx.Close()  // Zeros all sensitive data

// Explicit zeroing
crypto.SecureZero(key)
```

### Thread Safety

- `app.State` uses `sync.RWMutex`
- `atomic.Bool` for cancellation flags
- Progress reporters must be thread-safe

## Testing

```bash
go test ./...                                        # All tests
go test -v ./internal/volume -run TestGoldenVectors  # Backward compatibility
go test -race ./...                                  # Race detector
go test -bench=. ./...                               # Benchmarks
go test -fuzz=Fuzz ./internal/encoding               # Fuzz tests
```

### Test Types

- **Unit tests**: `*_test.go` in each package
- **Golden tests**: `volume/golden_test.go` - verifies v1/v2 decryption
- **Roundtrip tests**: `volume/roundtrip_test.go` - encrypt->decrypt identity
- **Fuzz tests**: `encoding/fuzz_test.go`, `header/fuzz_test.go`

## Refactoring from v1.49

Original: single `original_audited_picocrypt.go` file (~3000 lines), global variables, UI and crypto interleaved.

Refactored: 10+ packages, testable crypto code, <500 lines per file.

Original preserved at: `testdata/legacy/original_audited_picocrypt.go`

### Backward Compatibility

v2 decrypts v1.x volumes. Key differences handled:
- v1: SHA3-512(key) for auth, v2: HMAC-SHA3-512(header)
- v1: XORs keyfile before HKDF, v2: XORs after
- v1: Different HKDF stream offsets (no header subkey)
