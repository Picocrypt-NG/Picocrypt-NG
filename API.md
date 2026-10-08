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
// SecureZero overwrites caller-owned bytes without allocating a zero buffer.
// This is best-effort cleanup, not a guarantee of complete memory erasure.
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
    InputIdentities []fileops.ZIPInputIdentity // optional immutable discovery snapshots
    OnlyFolders []string // folders dropped directly (affects zip paths)
    OnlyFiles   []string // files dropped directly (affects zip paths)
    OutputFile  string

    // Credentials — legacy v2 requires Password; PCV3 accepts password,
    // keyfile, or combined policies
    Password       []byte   // Owned by caller; caller zeros it after the operation
    Keyfiles       []string // PCV3 keyfile paths; legacy v2 rejects non-empty values
    KeyfileOrdered bool     // Preserve keyfile order for PCV3
    PCV3           bool     // Select PCV3 instead of legacy v2

    // Options
    Comments    string // Plaintext header comment (max 99999 chars, NOT encrypted)
    Paranoid    bool   // 8 Argon2 passes, Serpent-CTR + XChaCha20, HMAC-SHA3
    ReedSolomon bool   // Reed-Solomon on payload (~6% size overhead)
    Deniability bool   // Legacy wrapper or, with PCV3+Paranoid, D1
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

    Password []byte   // Owned by caller; caller zeros it after the operation
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

// PreparedDecryptInput owns the exact descriptor routed before credential
// collection and records the selected split-chunk identities. Close is
// idempotent; ReadLegacyHeader does not transfer ownership.
type PreparedDecryptInput struct { /* unexported */ }

func PrepareDecryptInput(path string, recombine bool) (*PreparedDecryptInput, error)
func PrepareDecryptInputContext(ctx context.Context, path string, recombine bool) (*PreparedDecryptInput, error)
func (input *PreparedDecryptInput) ReadLegacyHeader(rs *encoding.RSCodecs) (*header.VolumeHeader, error)
func (input *PreparedDecryptInput) ValidateOutputAlias(output string) error
func (input *PreparedDecryptInput) Close() error

// DecryptPrepared borrows input; the caller keeps it open through the call and
// remains responsible for closing it afterward.
func DecryptPrepared(ctx context.Context, req *DecryptRequest, input *PreparedDecryptInput) error
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
    TriedFullRSDecode bool
    Kept              bool
    RecombinedFile    string

    Total    int64
    Done     int64
    Reporter ProgressReporter
}

func NewEncryptContext(ctx context.Context, req *EncryptRequest) *OperationContext
func NewDecryptContext(ctx context.Context, req *DecryptRequest) *OperationContext
func (ctx *OperationContext) Close() error
func (ctx *OperationContext) IsCancelled() bool
func (ctx *OperationContext) CancellationError() error
func (ctx *OperationContext) SetCanCancel(can bool)
func (ctx *OperationContext) SetStatus(status string)
func (ctx *OperationContext) UpdateProgress(fraction float32, info string)
func (ctx *OperationContext) TempZipReader(r io.Reader) (io.Reader, error)
```

### Deniability

```go
// AddDeniability wraps a volume with an XChaCha20 deniability layer.
// Uses its own Argon2 derivation (4 passes, 1 GiB, 4 threads).
// Writes salt(16) + nonce(24) at the start of the file.
func AddDeniability(volumePath string, password []byte, reporter ProgressReporter) error

// RemoveDeniability decrypts a deniability-wrapped volume.
// Returns an owned, random sibling stage containing the inner volume.
// The caller must call Cleanup when the stage is no longer needed.
func RemoveDeniability(volumePath string, password []byte, reporter ProgressReporter,
    rs *encoding.RSCodecs) (*fileops.StagedFile, error)

// IsDeniable reports whether a volume appears to have a deniability wrapper.
func IsDeniable(volumePath string, rs *encoding.RSCodecs) bool
```

**Writer contract.** Native frontends select PCV3 by default and expose no legacy-write
fallback. The internal compatibility writer (`EncryptRequest.PCV3 == false`) remains
available for legacy compatibility tests and rejects encryption-side keyfiles.
`EncryptRequest.PCV3 == true` selects PCV3 and accepts password-only,
keyfile-only, or combined factors. Normal PCV3 uses the canonical streaming serializer; PCV3 with
`Deniability` requires `Paranoid` and creates D1. ZIP preprocessing is supported. The desktop
GUI can save the authenticated ZIP or extract it for either Normal or D1 using `Auto unzip`.
`Same level` extracts into the output directory; otherwise a new subdirectory is created.
Existing files are not replaced. The selected credential
policy applies to both Normal PCV3 and D1.
Desktop recursive batches route each standalone Normal PCV3 input through
`ModeReadNormal` with its held source descriptor and a fresh owned factor request.
Legacy items retain their existing reader. The separate, explicit
`All selected files are PCV3 D1` option captures D1 intent for the complete batch:
each standalone input goes directly to `ModeReadD1` without format probing or
fallback to Normal/legacy. Failed probes and authenticated read failures count as
individual failures; cancellation ends the batch. PCV3 outputs use no-replace
publication and PCV3 batch reads retain encrypted originals because the read
facade does not grant source-deletion authority. Recovery and PCV3 split input
remain single-file operations. Batch state transfers require an active recursive
session and permit D1 only with the captured explicit D1 selection; they never
grant recovery authority. The D1 batch selector resets with the selection or when
recursive processing is disabled.
`ExecutionOptions.ArchiveAction` keeps the existing caller behavior at `ArchiveDefault`.
Ordinary reads can select `ArchiveSave`, `ArchivePrepare`, `ArchiveExtract`, or
`ArchiveExtractSameLevel`; these actions cannot be combined with retained-output delivery.
Extraction uses the authenticated private stage and a destination pinned before credential work.
`ArchiveReview` optionally approves the declared file count and expanded size before
extraction. Approval replaces the compression-ratio heuristic with per-file and total
byte limits derived from that archive; structural, CRC, path and no-overwrite checks
still apply. ZIP work uses one checked memory ledger: at most 256 MiB on 64-bit
desktop, 192 MiB combined Go/Kotlin on Android, and 64 MiB on 32-bit native builds.
Fresh platform headroom is checked separately; these are accounting ceilings,
not process RSS guarantees. Reader snapshots, metadata, path/overlap indexes,
writer selections and extraction custody are included. Archive review cannot
override this policy. Ordinary payload decryption can still save a ZIP without
parsing it. `BeginSAFWithContext` supports preparation cancellation; mobile
`PCV3Archive.CancelPreparation` reaches a pending begin before a session exists.
`HostMemoryBudgetBytes` exposes only the remaining host allowance, not policy authority.
SAF archive extraction requires the Normal native archive handoff. D1 archives
can use the existing ZIP save or native extraction actions; `BeginSAF` consumes
and closes their custody with a terminal invalid-request result.
PCV3 creation publishes through the identity-bound no-replace publisher.
`EncryptWithResult(ctx, request, options)` returns the common operation result
after input and preprocessing cleanup. A committed output with uncertain directory
durability remains available with a warning; it does not authorize source deletion.
When splitting finishes with verified complete chunks but uncertain final directory
durability, PCV3 retains both the chunks and the complete ciphertext.
`Result.SplitOutputUncertain()` identifies this result; its overall publication state is
`StatePublishedDurabilityUncertain`, and source deletion is forbidden.
`Result.SourceDeletionAllowed()` accounts for complete durable publication, follow-ups
and cleanup. A nil Go error or a presentation snapshot does not grant that permission.
Stdout and Android provider handoff use the operation's retained output capability,
which holds the original descriptor. Plaintext `SaveTo` consumes that capability
even on failure and removes its exact internal owner. Ciphertext `SaveTo` failure
retains the capability for a deliberate retry to another destination; only a live
`Result.OutputFollowUp()` establishes that authority. `StreamTo` consumes both
plaintext and ciphertext capabilities, including on failure. A durability-uncertain
write follow-up never grants source deletion. Successful handoff does not assert
provider storage durability.

This does not rewrite or upgrade existing volumes. Existing v1/v2 keyfile volumes remain readable
through their legacy branches. Recover plaintext before creating PCV3; merely wrapping an affected
legacy v2 volume does not make its old authentication schedule keyfile-bound. WASM does not expose
PCV3 creation. The Android gomobile bridge accepts `write-normal` and `write-d1` creation envelopes
alongside the read, recovery, and force modes; `write-d1` always runs the paranoid suite, and
creation uses the same runtime resource admission as reads.

---

## header *(AUDIT-CRITICAL)*

### Version Constants

`CurrentVersion` is the frozen legacy v2 on-disk marker, independent of the
application version in `VERSION`. Application version 3.0 does not change this
five-byte field or the legacy reader's v1/v2 routing.

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

// VerifyV2Header verifies the legacy v2 header HMAC, covering the supplied keyfileHash.
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

For legacy v2 keyfile volumes, `subkeyHeader` is derived from the password before keyfile XOR.
Including the public `keyfileHash` in the HMAC message therefore checks consistency but does not
make the HMAC key depend on the keyfile.

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
    ErrUnsupportedVersion   = errors.New("unsupported volume version")
)

func AuthValuesOffset(commentsLen int) int64
func HeaderSize(commentsLen int) int
func MatchVersion(b []byte) bool
func IsSupportedVersion(b []byte) bool
func PeekVersion(r io.Reader, rs *encoding.RSCodecs) (string, error)
```

`MatchVersion` recognizes only the syntax `vN.NN`; it does not authorize a cryptographic
generation. Picocrypt-NG 2.19 supports v1 and v2. `Reader.ReadHeader` returns
`ErrUnsupportedVersion` for every other well-formed major immediately after decoding the version,
before flags or KDF inputs are read. Force decrypt does not bypass this gate, and deniability
detection keeps a well-formed unknown-major header on the header path so it fails closed rather
than being treated as an outer wrapper.

---

## keyfile *(AUDIT-CRITICAL)*

```go
type ProgressFunc func(progress float32)

// The caller owns the result and clears Key after use.
type Result struct {
    Key  []byte // 32 bytes — derived key for XOR with password key
    Hash []byte // 32 bytes — SHA3-256(Key) stored in header
}

// Process hashes keyfiles into a 32-byte key.
//   ordered=true:  SHA3-256(file1 || file2 || ...)
//   ordered=false: SHA3-256(file1) XOR SHA3-256(file2) XOR ...
func Process(paths []string, ordered bool, progress ProgressFunc) (*Result, error)

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

Discovery snapshots bind each selected regular file to its read identity before
archive work. Explicit symlink following resolves the target once and preserves
the original entry name. Writers reopen without following a substituted leaf and
check the descriptor before reading; snapshots do not freeze same-inode writes.
GUI source-deletion manifests use the same identities as encryption and reject
a replaced input before work, rather than capturing a separate deletion target.

```go
type ZipOptions struct {
    Files      []string
    InputIdentities []ZIPInputIdentity // optional snapshots in Files order
    RootDir    string
    EntryNames map[string]string
    OutputPath string
    OutputFile *os.File // optional caller-owned, exclusively created output
    Compress   bool
    Progress   ProgressFunc
    Status     StatusFunc
    Cancel     CancelFunc
    Budget     *ZIPResourceBudget
}

func CreateZip(opts ZipOptions) error
```

### Unpack (extract zip)

```go
type UnpackOptions struct {
    ZipPath        string
    ZipFile        *os.File     // optional already-open archive
    ExtractDir     string       // empty = same as zip minus .zip
    ExtractRoot    *os.Root     // optional caller-owned already-open root
    ExpectedExtractRoot os.FileInfo // optional exact identity of extraction root
    SameLevel      bool         // extract to same dir as zip (not a subdirectory)
    Progress       ProgressFunc
    Status         StatusFunc
    Cancel         CancelFunc
    AvailableSpace func(string) (int64, error) // optional override for tests
    Budget         *ZIPResourceBudget
    Prepared       *PreparedZIPUnpack // optional one-shot pre-publication metadata owner
}

func Unpack(opts UnpackOptions) error
```

`PrepareZIPUnpack` retains admitted metadata and working charges for extraction
after publication. It borrows the file; any replacement descriptor must match
its original identity and extent. The caller closes the prepared owner after use.
Legacy auto-unzip keeps its recoverable malformed-ZIP fallback; resource refusal
does not authorize that fallback.

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
    InputPath            string
    ExpectedInput        os.FileInfo // optional identity InputPath must still name
    ExpectedDirectory    os.FileInfo // optional pinned split-directory identity
    ExpectedSHA256       *[32]byte   // optional digest frozen before splitting
    ChunkSize            int
    Unit                 SplitUnit
    MinimumChunkSize     int64
    RequireDirectorySync bool
    Progress             ProgressFunc
    Status               StatusFunc
    Cancel               CancelFunc
}

// Split splits a file into chunks.  Returns the list of chunk paths.
func Split(opts SplitOptions) ([]string, error)

// SplitPinned uses caller-owned input and directory handles for every chunk.
func SplitPinned(opts SplitOptions, input *os.File, root *os.Root, directory *os.File) ([]string, error)

type SplitState uint8

const (
    SplitFailed SplitState = iota
    SplitCompleteDurable
    SplitCompleteDurabilityUncertain
)

type SplitResult struct {
    State           SplitState
    Chunks          []string
    DurabilityError error
}

// SplitPinnedWithResult retains verified complete chunks if only the final directory barrier fails.
func SplitPinnedWithResult(opts SplitOptions, input *os.File, root *os.Root, directory *os.File,
    barrier func(*os.File) error) (SplitResult, error)

type RecombineOptions struct {
    InputBase          string // base path without the .N chunk suffix
    OutputPath         string
    Output             *os.File // optional borrowed output descriptor
    OutputInfo         *os.FileInfo // optional exact identity of completed output
    InputInfos         *[]os.FileInfo // optional identities of consumed chunks
    ExpectedInputs     []os.FileInfo // optional pinned identity and size for every chunk
    FirstChunk         *os.File     // optional borrowed chunk-zero descriptor
    ValidateFirstChunk func(*os.File) error
    Progress           ProgressFunc
    Status             StatusFunc
    Cancel             CancelFunc
}

func Recombine(opts RecombineOptions) error

// ChunkSizeToBytes converts (chunkSize, unit) to bytes.
func ChunkSizeToBytes(chunkSize int, unit SplitUnit) (int64, error)

// CountChunks counts how many chunks exist for a base path.
func CountChunks(basePath string) (int, int64, error)
func CountChunksWithCancel(basePath string, cancel CancelFunc) (int, int64, error)

// IsSplitChunkPath reports whether path looks like a chunk path (ends in .N).
func IsSplitChunkPath(path string) bool

// SplitChunkBase returns the base path and true if path is a chunk path.
func SplitChunkBase(path string) (string, bool)
```

`SplitPinnedWithResult` returns `SplitCompleteDurabilityUncertain` with a nil error only
after chunk completion, content verification, and directory identity checks succeed but
the final directory barrier fails. The PCV3 caller must retain the complete ciphertext as
well as the chunks and must not delete source files. A non-nil error remains a split
failure with operation-owned rollback and cleanup-error reporting; it is not a
durability-only result. The legacy `Split` and `SplitPinned` error contracts remain
unchanged.

### Authenticated Temporary ZIP

```go
type TempZipOptions struct {
    Files []string
    RootDir string
    EntryNames map[string]string
    NearPath string
    Compress bool
    MaxPhysicalBytes uint64 // trusted admitted physical extent, including tags
    Progress ProgressFunc
    Status StatusFunc
    Cancel CancelFunc
    Budget *ZIPResourceBudget
}
func CreateTempZip(ctx context.Context, opts TempZipOptions) (*TempZip, error)
func (t *TempZip) OpenReader() (io.Reader, error) // once, after finalization and Sync
func (t *TempZip) Length() uint64                // logical ZIP bytes, excluding tags
func (t *TempZip) File() *os.File                // borrowed pinned ciphertext descriptor
func (t *TempZip) Path() string
func (t *TempZip) Close() error                  // revoke reader, wipe, close and remove
func PanicCleanupIncomplete(value any) bool      // safe outer-boundary warning predicate
func RepanicWithCleanup(value any, cleanupErr error) // never returns; no raw-value accessor
```

The private spool uses age v1.1 STREAM payload framing with 64 KiB
ChaCha20-Poly1305 records and an explicit final-record flag. Each object owns a
fresh random 256-bit key, never serialized or reused. This is a local
implementation of published framing, not a full age container or an independently
audited implementation. A record is authenticated before its plaintext is
released; missing completion, changed extents, trailing bytes, corruption and
I/O failures are terminal non-EOF errors. The owner is sequential and cannot
resume or reopen after process restart.

Preparation admits both its encrypted physical extent and the simultaneous final
volume/chunk storage from observed filesystem space. This observation is not a
reservation; actual write and Sync failures still abort. Size remains subject to
public-volume geometry, ZIP memory budgets, filesystem capacity and signed file
offsets. Temporary authentication tags never enter legacy padding or PCV3 logical
payload length. Public encrypted-volume formats are unchanged.

Close wipes controllable key/plaintext buffers and releases primitive references.
Go, compression and the AEAD's private state do not provide complete-erasure
guarantees. Cleanup uses retained stage identity and never removes a foreign
replacement at its former pathname. Callback panics clean owned preparation
resources before propagating to the established operation boundary. Successful
cleanup preserves the exact original panic value. Failed cleanup propagates a
private carrier with fixed redacted formatting and no unwrapping access; outer
boundaries use `PanicCleanupIncomplete` to retain cleanup-warning truth without
rendering the original panic or cleanup path.

### Secure File Helpers

```go
// CreateSecureNoSymlink creates a file, refusing to follow symlinks.
func CreateSecureNoSymlink(path string) (*os.File, error)

// OpenExistingNoSymlink opens an existing file, refusing to follow symlinks.
func OpenExistingNoSymlink(path string, flag int) (*os.File, error)

// OpenRegularReadNoSymlink returns an owned read-only regular-file descriptor.
// It rejects leaf symlinks and closes descriptors rejected by its type check.
func OpenRegularReadNoSymlink(path string) (*os.File, error)
```

### Callback Types

```go
type ProgressFunc func(progress float32, info string)
type StatusFunc   func(status string)
type CancelFunc   func() bool
```

---

## mobile

The `mobile` package is the gomobile bridge used by the native Android app. Any change to an
exported method, type, or field requires rebuilding `android/app/libs/picocrypt-mobile.aar`; stale
bindings do not contain the generated Kotlin/Java getters.

### ProgressResult

```go
type ProgressResult struct {
    Status                  string
    StatusCode              string
    StatusSpeedMiBPerSecond float64
    StatusETA               string
    Progress                float32
    Info                    string
    InfoCode                string
    InfoCurrent             int64
    InfoTotal               int64
    Done                    bool
    Error                   string
    Code                    string
}

func GetProgress(operationID string) (*ProgressResult, error)
func CancelOperation(operationID string) (*ProgressResult, error)
```

`Status`, `Info`, and `Error` are compatibility/diagnostic fields. Android display boundaries use
the stable codes and typed arguments; they must not show raw backend text as localized UI copy.

`StatusCode` is one of:

```text
NONE, UNKNOWN, STARTING, COMPLETED, CANCELLED, ERROR,
COMPRESSING_FILES, GENERATING_VALUES, DERIVING_KEY, READING_KEYFILES,
CALCULATING_VALUES, WRITING_VALUES, SPLITTING, RECOMBINING_CHUNKS,
READING_VALUES, DUPLICATE_KEYFILES_WARNING, VERIFYING_INTEGRITY,
MAC_VERIFICATION_FAILED_CONTINUING, REPAIRING_VERIFYING,
INTEGRITY_VERIFIED_DECRYPTING, COMPARING_VALUES, UNZIPPING,
ADDING_PLAUSIBLE_DENIABILITY, REMOVING_DENIABILITY_PROTECTION,
COMPRESSING_RATE, ENCRYPTING_RATE, SPLITTING_RATE, RECOMBINING_RATE,
VERIFYING_RATE, DECRYPTING_RATE, REPAIRING_RATE, UNPACKING_RATE,
ADDING_DENIABILITY_RATE, REMOVING_DENIABILITY_RATE
```

Rate codes carry `StatusSpeedMiBPerSecond` and `StatusETA`. Unknown or malformed reporter text maps
to `UNKNOWN`; Android falls back to localized **Working** rather than exposing the raw status.

`InfoCode` is `NONE`, `PERCENT`, `ITEM_COUNT`, or `UNKNOWN`. `PERCENT` uses `Progress`;
`ITEM_COUNT` uses `InfoCurrent` and `InfoTotal`. Malformed or unknown detail is hidden.

`Code` is empty when there is no error, otherwise one of `AUTH_FAILED`, `DATA_CORRUPTED`,
`CORRUPT_HEADER`, `FILE_NOT_FOUND`, `CANCELLED`, or `GENERIC`. Android maps these to resource-backed
errors. The recovery contract is fail-closed: only `AUTH_FAILED` permits password retry, only
`DATA_CORRUPTED` permits force decrypt, and corrupt headers are never force-decryptable.

The operation state preserves the first terminal result. `CancelOperation` atomically returns that
canonical terminal snapshot, so cancellation cannot replace an already-recorded success or failure;
later polling likewise cannot replace an already-recorded cancellation, success, or failure.

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

## PCV3 operation boundary

`internal/pcv3operation` is the native PCV3 application API. Its nested `internal`
packages are compiler-inaccessible to CLI, desktop, mobile, WASM routing, and
volume dispatch. Callers transfer `FactorRequest`, password bytes, and owned
`KeyfileReader` handles to `Run` or `RunWrite`; unused factors must be closed.
Modes, suites, payload kinds, outcomes, stages, and codes are closed metadata.
No public facade exposes raw keys, digests, credential/KDF sessions, admission
grants, random generators, or serializer entry points.

`DetectPrefix` classifies format ownership. `Probe(io.ReaderAt, int64)` returns
`(Route, error)` after bounded structural inspection; it intentionally omits
capsules and KDF parameters. Claimed PCV3 input never falls back to legacy reads.
WASM retains its existing PCV3 refusal behavior.

`Result` is operation-minted. `Presentation` is display-only and cannot authorize
publication or deletion. Output and archive follow-ups preserve their one-shot
Go capability semantics. `ArtifactInspection.Metadata` and `Page` expose only
summary/range metadata; pages contain at most 128 defensive-copy descriptors.
Inspection shares immutable evidence and remains readable after operation release.
Raw-selected D1 recovery stays an unverified forensic artifact even when its inner
records authenticate. Its range/final statuses retain those authentication facts;
the physical D1 role records the untrusted selection. The artifact layout stays
unchanged, but older readers may reject this new combination of trust and evidence.
Recovery uses an 8 MiB allocation budget across candidates; an absent tail is
represented without allocating or scanning one entry per missing record. Artifact
parsing and serialization remain private and preserve the existing
`80 + 40*recordCount + recoveredBytes` layout. Output admission checks exact size,
disk headroom and unverified-table amplification before writing.

A resource refusal uses `StageResourceBudget` and `DiagnosticResourceLimit`.
Before publication, all publication fields remain zero; cleanup warnings are
independent and must survive frontend projection. A presentation is never an
authority to retry credentials, publish output or delete sources.

`NewAndroidResourceSession`, `WithAndroidResourceSession`, and `Challenge` bind
fresh platform observations to one live Go operation. A challenge's `Submit`
consumes bounded facts once; it does not return or select an admission decision.
The facade has no snapshot provider or platform-admitter constructor.
