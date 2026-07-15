# Picocrypt NG API Reference

Internal package APIs for developers working on or integrating with Picocrypt NG.

> **Audit-critical code:** packages marked *(AUDIT-CRITICAL)* affect
> encryption/decryption directly.  Changes require extra review.

---

## crypto *(AUDIT-CRITICAL)*

### Key Derivation

```go
// DeriveKey derives a 32-byte key using Argon2id.
// paranoid=true: 8 passes, 8 threads; false: 4 passes, 4 threads.
// Both use 1 GiB memory.
func DeriveKey(password, salt []byte, paranoid bool) ([]byte, error)

// NewHKDFStream returns an HKDF-SHA3-256 reader for subkey derivation.
func NewHKDFStream(key, salt []byte) io.Reader

// RandomBytes generates n cryptographically secure random bytes.
func RandomBytes(n int) ([]byte, error)
```

Argon2 parameters exposed as named constants:

```go
const (
    Argon2NormalPasses   = 4
    Argon2NormalMemory   = 1 << 20 // 1 GiB
    Argon2NormalThreads  = 4
    Argon2ParanoidPasses  = 8
    Argon2ParanoidMemory  = 1 << 20 // 1 GiB
    Argon2ParanoidThreads = 8
    Argon2KeySize        = 32 // output bytes
)
```

### Subkey Reader

`SubkeyReader` consumes an HKDF stream in the order required by the v2 wire
format:

```
Byte  0– 63: Header subkey (64 bytes) — v2 header MAC only
Byte 64– 95: MAC subkey (32 bytes)
Byte 96–127: Serpent key (32 bytes)
Byte 128+:   Per-cycle rekey values (nonce 24 + IV 16)
```

```go
type SubkeyReader struct{ /* unexported */ }

func NewSubkeyReader(hkdfStream io.Reader) *SubkeyReader
func (r *SubkeyReader) HeaderSubkey() ([]byte, error) // 64 bytes; v2 only
func (r *SubkeyReader) MACSubkey() ([]byte, error)    // 32 bytes
func (r *SubkeyReader) SerpentKey() ([]byte, error)   // 32 bytes
func (r *SubkeyReader) Reader() io.Reader              // raw HKDF for rekey reads
```

Subkey size constants:

```go
const (
    SubkeyHeaderSize  = 64
    SubkeyMACSize     = 32
    SubkeySerpentSize = 32
    RekeyNonceSize    = 24
    RekeyIVSize       = 16
)
```

### Cipher Suite

```go
type CipherSuite struct{ /* unexported */ }

// NewCipherSuite initialises XChaCha20 (+ Serpent-CTR if paranoid).
// mac and hkdf should come from NewMAC and NewHKDFStream respectively.
func NewCipherSuite(key, nonce, serpentKey, serpentIV []byte,
    mac hash.Hash, hkdf io.Reader, paranoid bool) (*CipherSuite, error)

// Encrypt: [Serpent-CTR if paranoid] → XChaCha20 → MAC(ciphertext).
// dst and src MUST NOT alias in paranoid mode; in-place (dst==src) is
// permitted only in non-paranoid mode (used by WASM).
func (cs *CipherSuite) Encrypt(dst, src []byte)

// Decrypt: MAC(ciphertext) → XChaCha20 → [Serpent-CTR if paranoid].
// Same aliasing constraint as Encrypt.
func (cs *CipherSuite) Decrypt(dst, src []byte)

// Rekey reinitialises ciphers from the HKDF stream. Call every 60 GiB.
func (cs *CipherSuite) Rekey() error

// IsParanoid reports whether paranoid mode is active.
func (cs *CipherSuite) IsParanoid() bool

// MAC returns the live MAC accumulator.
func (cs *CipherSuite) MAC() hash.Hash

// Sum returns the current MAC tag without finalising the hash state.
func (cs *CipherSuite) Sum() []byte

// Close zeros all key material.
func (cs *CipherSuite) Close()

// RekeyThreshold is the byte count after which Rekey must be called (60 GiB).
// It is a var (not const) to serve as a test seam only; never reassign in production.
var RekeyThreshold int64
```

### MAC

```go
// NewMAC creates a keyed MAC.
// paranoid=true → HMAC-SHA3-512; false → keyed BLAKE2b-512.
// subkey should be 32 bytes from the HKDF stream (SubkeyReader.MACSubkey).
func NewMAC(subkey []byte, paranoid bool) (hash.Hash, error)

const MACSize = 64 // output bytes (both modes)
```

### Deniability Rekeying

```go
// DeniabilityRekey derives a new nonce for the deniability layer.
// Unlike regular rekeying (HKDF), deniability uses SHA3-256(oldNonce)[:24].
func DeniabilityRekey(key, oldNonce []byte) (*chacha20.Cipher, []byte, error)
```

### Memory Hygiene

```go
// SecureZero overwrites b with zeros (compiler-fence protected).
func SecureZero(b []byte)

// SecureZeroMultiple zeros several slices in one call.
func SecureZeroMultiple(slices ...[]byte)

// SecureZeroHash resets a hash.Hash to clear partial state.
func SecureZeroHash(h hash.Hash)
```

---

## volume *(AUDIT-CRITICAL)*

### Encrypt

```go
type EncryptRequest struct {
    // Input — use InputFile for single file, InputFiles for multiple (auto-zipped)
    InputFile   string
    InputFiles  []string
    OnlyFolders []string // folders dropped directly (affects zip paths)
    OnlyFiles   []string // files dropped directly (affects zip paths)
    OutputFile  string

    // Credentials — at least one of Password/Keyfiles required
    Password       string   // NOTE: Go strings are immutable; zeroing is out of scope
    Keyfiles       []string
    KeyfileOrdered bool

    // Options
    Comments    string // Plaintext header comment (max 99999 chars, NOT encrypted)
    Paranoid    bool   // 8 Argon2 passes, Serpent-CTR + XChaCha20, HMAC-SHA3
    ReedSolomon bool   // Reed-Solomon on payload (~6% size overhead)
    Deniability bool   // Wrap volume in deniability layer
    Compress    bool   // Deflate compression in temp zip

    // Splitting
    Split     bool
    ChunkSize int
    ChunkUnit fileops.SplitUnit

    Reporter ProgressReporter      // may be nil
    RSCodecs *encoding.RSCodecs    // pre-initialised by caller
}

func (req *EncryptRequest) Validate() error

// Encrypt encrypts files into a .pcv volume.  ctx may be nil (uses Background).
func Encrypt(ctx context.Context, req *EncryptRequest) error
```

### Decrypt

```go
type DecryptRequest struct {
    InputFile  string
    OutputFile string

    Password string   // NOTE: immutable Go string; zeroing out of scope
    Keyfiles []string

    ForceDecrypt bool // continue despite MAC failure (may produce corrupt output)
    VerifyFirst  bool // two-pass: verify MAC before writing (slower)
    AutoUnzip    bool // extract if output is a .zip
    SameLevel    bool // extract to same dir as volume

    Recombine   bool // volume is split into chunks
    Deniability bool // volume has a deniability wrapper

    Reporter ProgressReporter
    RSCodecs *encoding.RSCodecs

    // Output — set by Decrypt after completion
    Kept *bool // non-nil + true if ForceDecrypt kept file despite MAC failure
}

func (req *DecryptRequest) Validate() error
func (req *DecryptRequest) ValidateCredentials(keyfilesRequired bool) error

// Decrypt decrypts a .pcv volume.  ctx may be nil (uses Background).
func Decrypt(ctx context.Context, req *DecryptRequest) error
```

### Progress

```go
// ProgressReporter provides UI callbacks during long-running operations.
// Implementations must be thread-safe.
type ProgressReporter interface {
    SetStatus(text string)
    SetProgress(fraction float32, info string) // fraction in [0, 1]
    SetCanCancel(can bool)
    Update()
    IsCancelled() bool
}
```

### Operation Context

```go
// OperationContext holds mutable state during encrypt/decrypt.
// Always call Close() to zero key material.
type OperationContext struct {
    Ctx        context.Context
    InputFile  string
    OutputFile string
    TempFile   string

    Header      *header.VolumeHeader
    Key         []byte              // Argon2-derived (possibly XORed with keyfile key)
    KeyfileKey  []byte
    KeyfileHash []byte
    SubkeyReader *crypto.SubkeyReader
    CipherSuite  *crypto.CipherSuite

    IsLegacyV1   bool
    UseKeyfiles  bool
    Padded       bool
    TempZipInUse bool
    TempCiphers  *fileops.TempZipCiphers
    TriedFullRSDecode bool
    Kept              bool
    RecombinedFile    string

    Total    int64
    Done     int64
    Reporter ProgressReporter
}

func NewEncryptContext(ctx context.Context, req *EncryptRequest) *OperationContext
func NewDecryptContext(ctx context.Context, req *DecryptRequest) *OperationContext
func (ctx *OperationContext) Close()
func (ctx *OperationContext) IsCancelled() bool
func (ctx *OperationContext) CancellationError() error
func (ctx *OperationContext) SetCanCancel(can bool)
func (ctx *OperationContext) SetStatus(status string)
func (ctx *OperationContext) UpdateProgress(fraction float32, info string)
func (ctx *OperationContext) TempZipReader(r io.Reader) io.Reader
```

### Deniability

```go
// AddDeniability wraps a volume with an XChaCha20 deniability layer.
// Uses its own Argon2 derivation (4 passes, 1 GiB, 4 threads).
// Writes salt(16) + nonce(24) at the start of the file.
func AddDeniability(volumePath, password string, reporter ProgressReporter) error

// RemoveDeniability decrypts a deniability-wrapped volume.
// Returns the path to a .tmp file containing the inner volume.
func RemoveDeniability(volumePath, password string, reporter ProgressReporter,
    rs *encoding.RSCodecs) (string, error)

// IsDeniable reports whether a volume appears to have a deniability wrapper.
func IsDeniable(volumePath string, rs *encoding.RSCodecs) bool
```

---

## header *(AUDIT-CRITICAL)*

### Version Constants

```go
const (
    CurrentVersion = "v2.19"
    MaxCommentLen  = 99999
)
```

### VolumeHeader

```go
type VolumeHeader struct {
    Version  string // "v2.19" or "v1.xx"
    Comments string // plaintext; NOT encrypted
    Flags    Flags

    Salt      []byte // 16 bytes — Argon2 salt
    HKDFSalt  []byte // 32 bytes — HKDF-SHA3 salt
    SerpentIV []byte // 16 bytes — Serpent IV
    Nonce     []byte // 24 bytes — XChaCha20 nonce

    KeyHash     []byte // 64 bytes — v2: HMAC-SHA3-512(header); v1: SHA3-512(key)
    KeyfileHash []byte // 32 bytes — SHA3-256(keyfileKey) or zeros
    AuthTag     []byte // 64 bytes — payload MAC (BLAKE2b or HMAC-SHA3)
}

func NewVolumeHeader(salt, hkdfSalt, serpentIV, nonce []byte) *VolumeHeader
func (h *VolumeHeader) IsLegacyV1() bool
```

### Flags

```go
type Flags struct {
    Paranoid       bool // flags[0]
    UseKeyfiles    bool // flags[1]
    KeyfileOrdered bool // flags[2]
    ReedSolomon    bool // flags[3]
    Padded         bool // flags[4]
}

func FlagsFromBytes(b []byte) Flags
func (f *Flags) ToBytes() []byte
```

### Reader

```go
type Reader struct{ /* unexported */ }

func NewReader(r io.Reader, rs *encoding.RSCodecs) *Reader

// ReadHeader reads and RS-decodes the volume header from the stream.
func (r *Reader) ReadHeader() (*ReadResult, error)

type ReadResult struct {
    Header                *VolumeHeader
    DecodeError           error // non-nil if any RS decode errors occurred
    CommentDecodeError    bool
    NonCommentDecodeError bool
    BytesRead             int
}
```

### Writer

```go
type Writer struct{ /* unexported */ }

func NewWriter(w io.Writer, rs *encoding.RSCodecs) *Writer

// WriteHeader RS-encodes and writes the volume header.
// Returns the number of bytes written.
func (w *Writer) WriteHeader(h *VolumeHeader) (int, error)
```

### Authentication

```go
// ComputeV2HeaderMAC computes HMAC-SHA3-512 over header fields for v2 volumes.
func ComputeV2HeaderMAC(subkeyHeader []byte, h *VolumeHeader, keyfileHash []byte) []byte

// ComputeV1KeyHash computes SHA3-512(key) for v1 volume key verification.
func ComputeV1KeyHash(key []byte) []byte

// VerifyV2Header validates key/keyfile credentials against a v2 header.
func VerifyV2Header(subkeyHeader []byte, h *VolumeHeader, keyfileHash []byte) *AuthResult

// VerifyV1Header validates key credentials against a v1 header.
func VerifyV1Header(key []byte, h *VolumeHeader) *AuthResult

// WriteAuthValues writes keyHash, keyfileHash, and authTag at offset in the output.
func WriteAuthValues(w io.WriterAt, offset int64, keyHash, keyfileHash, authTag []byte,
    rs *encoding.RSCodecs) error

// VerifyKeyfileHash compares computed vs stored keyfile hashes (constant-time).
func VerifyKeyfileHash(computed, stored []byte) bool

// IsPasswordError reports whether err is a password/auth failure.
func IsPasswordError(err error) bool

type AuthResult struct {
    Valid           bool
    KeyHashComputed []byte
}

type AuthError struct {
    PasswordIncorrect bool
    KeyfileIncorrect  bool
    KeyfileOrdered    bool
    Message           string
}

func NewPasswordError() *AuthError
func NewKeyfileError(ordered bool) *AuthError
func NewV2PasswordOrTamperError() *AuthError
func (e *AuthError) Error() string
```

### Utility

```go
const (
    SaltSize       = 16
    VersionEncSize = 15
    BaseHeaderSize = /* sum of all fixed fields */ ...
)

var (
    ErrCorruptedHeader      = errors.New("volume header is damaged")
    ErrInvalidCommentLength = errors.New("unable to read comments length")
    ErrInvalidVersion       = errors.New("invalid version format")
)

func AuthValuesOffset(commentsLen int) int64
func HeaderSize(commentsLen int) int
func MatchVersion(b []byte) bool
func PeekVersion(r io.Reader, rs *encoding.RSCodecs) (string, error)
```

---

## keyfile *(AUDIT-CRITICAL)*

```go
type ProgressFunc func(progress float32)

type Result struct {
    Key  []byte // 32 bytes — derived key for XOR with password key
    Hash []byte // 32 bytes — SHA3-256(Key) stored in header
}

// Process hashes keyfiles into a 32-byte key.
//   ordered=true:  SHA3-256(file1 || file2 || ...)
//   ordered=false: SHA3-256(file1) XOR SHA3-256(file2) XOR ...
func Process(paths []string, ordered bool, progress ProgressFunc) (*Result, error)

// Close zeros key material.
func (r *Result) Close()

// XORWithKey XORs the keyfile key with the Argon2-derived password key.
// Both slices must be exactly 32 bytes.
func XORWithKey(passwordKey, keyfileKey []byte) []byte

// IsDuplicateKeyfileKey returns true if the key is all zeros (XOR cancellation
// from an even number of identical keyfiles).
func IsDuplicateKeyfileKey(key []byte) bool
```

---

## encoding

### Reed-Solomon

```go
type RSCodecs struct {
    RS1   *infectious.FEC // 1 data  → 3 total   (comment bytes)
    RS5   *infectious.FEC // 5 data  → 15 total  (version, flags)
    RS16  *infectious.FEC // 16 data → 48 total  (salts, IVs)
    RS24  *infectious.FEC // 24 data → 72 total  (nonce)
    RS32  *infectious.FEC // 32 data → 96 total  (HKDF salt, keyfile hash)
    RS64  *infectious.FEC // 64 data → 192 total (key hash, auth tag)
    RS128 *infectious.FEC // 128 data → 136 total (payload chunks, ~6% overhead)
}

func NewRSCodecs() (*RSCodecs, error)

// Encode RS-encodes data using the given codec.  Returns (encoded, nil).
func Encode(rs *infectious.FEC, data []byte) ([]byte, error)

// EncodeInto RS-encodes data into a pre-allocated dst slice.
func EncodeInto(dst []byte, rs *infectious.FEC, data []byte) error

// Decode RS-decodes data.  fastDecode=true uses the fast path for uncorrupted data.
func Decode(rs *infectious.FEC, data []byte, fastDecode bool) ([]byte, error)

const (
    RS128DataSize = 128
    BlockSize     = 128
)
```

### Padding (PKCS#7-style, block size 128)

```go
// Pad appends a full extra block of 0x80 bytes when len(data) % BlockSize == 0,
// or a partial block otherwise.
func Pad(data []byte) []byte

// Unpad removes the trailing padding block.
func Unpad(data []byte) []byte
```

---

## fileops

### Zip

```go
type ZipOptions struct {
    Files      []string
    RootDir    string
    EntryNames map[string]string
    OutputPath string
    Compress   bool
    Cipher     *TempZipCiphers // optional encryption for temp file
    Progress   ProgressFunc
    Status     StatusFunc
    Cancel     CancelFunc
}

func CreateZip(opts ZipOptions) error
```

### Unpack (extract zip)

```go
type UnpackOptions struct {
    ZipPath        string
    ExtractDir     string       // empty = same as zip minus .zip
    SameLevel      bool         // extract to same dir as zip (not a subdirectory)
    Progress       ProgressFunc
    Status         StatusFunc
    Cancel         CancelFunc
    AvailableSpace func(string) (int64, error) // optional override for tests
}

func Unpack(opts UnpackOptions) error
```

### Split / Recombine

```go
type SplitUnit int

const (
    SplitUnitKiB   SplitUnit = iota // kibibytes
    SplitUnitMiB                    // mebibytes
    SplitUnitGiB                    // gibibytes
    SplitUnitTiB                    // tebibytes
    SplitUnitTotal                  // divide into N equal parts
)

type SplitOptions struct {
    InputPath string
    ChunkSize int
    Unit      SplitUnit
    Progress  ProgressFunc
    Status    StatusFunc
    Cancel    CancelFunc
}

// Split splits a file into chunks.  Returns the list of chunk paths.
func Split(opts SplitOptions) ([]string, error)

type RecombineOptions struct {
    InputBase  string // base path without the .N chunk suffix
    OutputPath string
    Progress   ProgressFunc
    Status     StatusFunc
    Cancel     CancelFunc
}

func Recombine(opts RecombineOptions) error

// ChunkSizeToBytes converts (chunkSize, unit) to bytes.
func ChunkSizeToBytes(chunkSize int, unit SplitUnit) (int64, error)

// CountChunks counts how many chunks exist for a base path.
func CountChunks(basePath string) (int, int64, error)

// IsSplitChunkPath reports whether path looks like a chunk path (ends in .N).
func IsSplitChunkPath(path string) bool

// SplitChunkBase returns the base path and true if path is a chunk path.
func SplitChunkBase(path string) (string, bool)
```

### Encrypted Temp-Zip Ciphers

```go
// TempZipCiphers holds paired ChaCha20 ciphers for encrypting the temporary
// zip file written during multi-file encryption.  Call Close() to zero the key.
type TempZipCiphers struct {
    Writer *chacha20.Cipher
    Reader *chacha20.Cipher
}

func NewTempZipCiphers() (*TempZipCiphers, error)
func (t *TempZipCiphers) Close()

// WrapReaderWithCipher wraps r with the cipher's XOR stream (in-place decryption).
func WrapReaderWithCipher(r io.Reader, cipher *TempZipCiphers) io.Reader
```

### Secure File Helpers

```go
// CreateSecureNoSymlink creates a file, refusing to follow symlinks.
func CreateSecureNoSymlink(path string) (*os.File, error)

// OpenExistingNoSymlink opens an existing file, refusing to follow symlinks.
func OpenExistingNoSymlink(path string, flag int) (*os.File, error)
```

### Callback Types

```go
type ProgressFunc func(progress float32, info string)
type StatusFunc   func(status string)
type CancelFunc   func() bool
```

---

## util

### Size Constants

```go
const (
    KiB = 1 << 10
    MiB = 1 << 20
    GiB = 1 << 30
    TiB = 1 << 40
)
```

### Formatting

```go
// Statify converts (done, total, start) to (progress 0–1, speed MiB/s, ETA "HH:MM:SS").
func Statify(done, total int64, start time.Time) (float32, float64, string)

// Sizeify converts bytes to a human-readable string ("1.50 GiB", etc.).
func Sizeify(size int64) string

// Timeify converts seconds to "HH:MM:SS".
func Timeify(seconds int) string
```

### Password Generation

```go
type PassgenOptions struct {
    Length  int
    Upper   bool // A–Z
    Lower   bool // a–z
    Numbers bool // 0–9
    Symbols bool // -=_+!@#$^&()?<>
}

// GenPassword generates a cryptographically secure password.
// Returns ("", nil) if no charset is enabled or Length <= 0.
func GenPassword(opts PassgenOptions) (string, error)
```

### Buffer Pool

```go
// BufferPool provides reusable MiB-sized buffers to reduce GC pressure.
// Buffers are zeroed on Put because they may carry plaintext.
type BufferPool struct{ /* unexported */ }

func NewBufferPool(size int) *BufferPool
func (p *BufferPool) Get() []byte
func (p *BufferPool) Put(b []byte)

// Pre-allocated global pools:
var MiBPool = NewBufferPool(MiB)

// Convenience wrappers for MiBPool and a small-buffer pool:
func GetMiBBuffer() []byte
func PutMiBBuffer(b []byte)
func GetSmallBuffer() []byte
func PutSmallBuffer(b []byte)
```

### Misc

```go
// RandomBytes generates n cryptographically secure random bytes.
func RandomBytes(n int) ([]byte, error)

// SafeUint64ToInt64 returns (value, true) if the value fits in int64,
// or (0, false) on overflow.
func SafeUint64ToInt64(v uint64) (int64, bool)

const MaxDecompressRatio = 1000
```
