# Picocrypt NG API Reference

Internal package APIs for developers working on or integrating with Picocrypt NG.

## crypto

### Key Derivation

```go
// DeriveKey derives a 32-byte key using Argon2id.
// paranoid=true: 8 passes, 8 threads; false: 4 passes, 4 threads
// Both use 1 GiB memory.
func DeriveKey(password, salt []byte, paranoid bool) ([]byte, error)

// NewHKDFStream creates an HKDF-SHA3-256 stream for subkey derivation.
func NewHKDFStream(key, salt []byte) io.Reader

// RandomBytes generates n cryptographically secure random bytes.
func RandomBytes(n int) ([]byte, error)
```

### Cipher Suite

```go
// NewCipherSuite creates a cipher for encryption/decryption.
func NewCipherSuite(key, nonce, serpentKey, serpentIV []byte,
    mac hash.Hash, hkdf io.Reader, paranoid bool) (*CipherSuite, error)

// Encrypt: [Serpent-CTR if paranoid] -> XChaCha20 -> MAC(ciphertext)
func (cs *CipherSuite) Encrypt(dst, src []byte)

// Decrypt: MAC(ciphertext) -> XChaCha20 -> [Serpent-CTR if paranoid]
func (cs *CipherSuite) Decrypt(dst, src []byte)

// Rekey reinitializes ciphers. Call every 60 GiB.
func (cs *CipherSuite) Rekey() error

// Close zeros all key material.
func (cs *CipherSuite) Close()
```

### MAC

```go
// NewBLAKE2b512 creates keyed BLAKE2b-512 (normal mode).
func NewBLAKE2b512(key []byte) (hash.Hash, error)

// NewHMACSHA3 creates HMAC-SHA3-512 (paranoid mode).
func NewHMACSHA3(key []byte) hash.Hash
```

### Memory

```go
// SecureZero overwrites slice with zeros (constant-time).
func SecureZero(b []byte)
```

## volume

### Encrypt

```go
type EncryptRequest struct {
    InputFile      string
    InputFiles     []string
    OnlyFiles      []string
    OnlyFolders    []string
    OutputFile     string
    Password       []byte
    Keyfiles       []string
    KeyfileOrdered bool
    Comments       string      // Plaintext, max 99999 chars
    Paranoid       bool
    ReedSolomon    bool
    Deniability    bool
    Compress       bool
    Split          int64       // Chunk size, 0 = no split
    Reporter       ProgressReporter
}

func Encrypt(req *EncryptRequest) error
```

### Decrypt

```go
type DecryptRequest struct {
    InputFile      string
    OutputFile     string
    Password       []byte
    Keyfiles       []string
    KeyfileOrdered bool
    Keep           bool   // Keep output despite MAC failure
    AutoUnzip      bool
    SameLevel      bool   // Extract to current dir
    Reporter       ProgressReporter
}

func Decrypt(req *DecryptRequest) error
```

### Progress

```go
type ProgressReporter interface {
    SetStatus(text string)
    UpdateProgress(progress float32, info string)
    SetCanCancel(canCancel bool)
    IsCancelled() bool
}
```

## header

```go
type VolumeHeader struct {
    Version     string    // "v2.02" or "v1.xx"
    Comments    string
    Flags       Flags
    Salt        []byte    // 16 bytes - Argon2
    HKDFSalt    []byte    // 32 bytes
    SerpentIV   []byte    // 16 bytes
    Nonce       []byte    // 24 bytes - XChaCha20
    KeyHash     []byte    // 64 bytes - HMAC (v2) or SHA3(key) (v1)
    KeyfileHash []byte    // 32 bytes
    AuthTag     []byte    // 64 bytes - payload MAC
}

type Flags struct {
    Paranoid       bool
    UseKeyfiles    bool
    KeyfileOrdered bool
    ReedSolomon    bool
    Padded         bool
}

func (r *Reader) ReadHeader(file io.ReadSeeker, rsCodecs *RSCodecs) (*VolumeHeader, error)
func (w *Writer) WriteHeader(file io.Writer, hdr *VolumeHeader, rsCodecs *RSCodecs) error
func ComputeHeaderHMAC(subkey []byte, hdr *VolumeHeader) ([]byte, error)
```

## keyfile

```go
type Result struct {
    Key  []byte  // 32 bytes
    Hash []byte  // 32 bytes
}

// Process hashes keyfiles into a 32-byte key.
// ordered=true: SHA3-256(file1 || file2 || ...)
// ordered=false: SHA3-256(file1) XOR SHA3-256(file2) XOR ...
func Process(paths []string, ordered bool, progress ProgressFunc) (*Result, error)

// Close zeros key material.
func (r *Result) Close()
```

## encoding

### Reed-Solomon

```go
// NewRSCodecs initializes all RS codecs.
func NewRSCodecs() (*RSCodecs, error)

// Codec configurations:
// RS1:   1->3 bytes   (comments)
// RS5:   5->15 bytes  (version, flags)
// RS16:  16->48 bytes (salts, IVs)
// RS24:  24->72 bytes (nonces)
// RS32:  32->96 bytes (HKDF salt, keyfile hash)
// RS64:  64->192 bytes (key hash, auth tag)
// RS128: 128->136 bytes (payload data)

func Encode(rs *infectious.FEC, data []byte) []byte
func Decode(rs *infectious.FEC, data []byte, fastDecode bool) ([]byte, error)
```

### Padding

```go
func Pad(data []byte, blockSize int) []byte
func Unpad(data []byte) ([]byte, error)
```

## fileops

```go
// Zip
func CreateZip(opts ZipOptions) error
func ExtractZip(zipPath, outputDir string, sameLevel bool, progress func(float32)) error

// Split/Recombine
func SplitFile(inputPath, outputBase string, chunkSize int64, progress func(float32)) error
func RecombineChunks(firstChunk, outputPath string, progress func(float32)) error
```

## util

```go
const (
    KiB = 1024
    MiB = 1024 * KiB
    GiB = 1024 * MiB
    TiB = 1024 * GiB
)

// Statify returns progress (0-1), speed (MiB/s), and ETA ("HH:MM:SS").
func Statify(done, total int64, start time.Time) (float32, float64, string)

// Sizeify returns human-readable size (e.g., "1.50 GiB").
func Sizeify(size int64) string

// GeneratePassword creates a secure random password.
func GeneratePassword(length int, upper, lower, nums, symbols bool) (string, error)
```
