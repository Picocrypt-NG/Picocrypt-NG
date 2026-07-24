// Package volume provides high-level encryption and decryption operations for Picocrypt volumes.
//
// This is AUDIT-CRITICAL code - changes here directly affect the cryptographic pipeline.
// The package orchestrates the complete encryption/decryption workflow:
//
// Encryption pipeline:
//  1. Preprocess: Create zip archive if multiple files or compression requested
//  2. Generate: Create random salts, nonces, IVs
//  3. Write header: RS-encode and write header fields
//  4. Derive keys: Argon2id password derivation
//  5. Process keyfiles: Hash and XOR with password key
//  6. Compute auth: Calculate header HMAC (v2) or key hash (v1)
//  7. Encrypt payload: Serpent-CTR -> XChaCha20 -> MAC
//  8. Finalize: Write auth tag, add deniability wrapper, split chunks
//
// Decryption pipeline:
//  1. Preprocess: Recombine chunks, remove deniability wrapper
//  2. Read header: RS-decode header fields
//  3. Derive keys: Argon2id password derivation
//  4. Process keyfiles: Validate against stored hash
//  5. Verify auth: Check header MAC (v2) or key hash (v1)
//  6. Decrypt payload: MAC -> XChaCha20 -> Serpent-CTR
//  7. Finalize: Verify MAC, auto-unzip if requested
//
// SECURITY: Always call OperationContext.Close() when done to zero key material.
package volume

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/header"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	perrors "Picocrypt-NG/internal/errors"
)

// ProgressReporter provides callbacks for UI updates during long-running operations.
// Implementations must be thread-safe as methods may be called from goroutines.
type ProgressReporter interface {
	SetStatus(text string)                     // Update status message (e.g., "Encrypting...")
	SetProgress(fraction float32, info string) // Update progress bar (0.0-1.0) and info text
	SetCanCancel(can bool)                     // Enable/disable cancel button
	Update()                                   // Trigger UI refresh
	IsCancelled() bool                         // Check if user requested cancellation
}

// EncryptRequest contains all parameters needed to encrypt files into a .pcv volume.
// Picocrypt-NG 2.19 requires Password and rejects new v2 writes with Keyfiles.
type EncryptRequest struct {
	// Input files - use InputFile for single file, InputFiles for multiple (zipped automatically)
	InputFile   string   // Single file path to encrypt
	InputFiles  []string // Multiple file paths (will be combined into encrypted zip)
	OnlyFolders []string // Folders that were dropped directly (for correct zip path calculation)
	OnlyFiles   []string // Files that were dropped directly (not from folders)
	OutputFile  string   // Output path for the .pcv volume

	// Credentials
	//
	// SECURITY (SEC-05): Password is an owned []byte, so the caller controls its
	// lifetime and zeros it (crypto.SecureZero) after the operation. The KDF
	// carrier is []byte end-to-end (CLI/wasm/mobile boundaries) — there is no
	// intermediate immutable string copy on those paths. Residual: the Fyne GUI's
	// widget.Entry yields a Go string in app.State.Password; ui/operations.go
	// converts it to an owned []byte here and zeros that copy, but the original
	// string still lingers until GC (intentionally out of scope — CONCERNS 3.1;
	// ROADMAP "Out of Scope: Guaranteed password zeroing").
	Password       []byte   // User password (processed through Argon2id) — see SECURITY note above
	Keyfiles       []string // Legacy API field; non-empty is rejected by the v2 writer
	KeyfileOrdered bool     // Legacy keyfile-order option; only relevant to legacy volume reads

	// Security options
	Comments    string // Plaintext comments stored in header (NOT encrypted!)
	Paranoid    bool   // Enable paranoid mode: 8 Argon2 passes, Serpent-CTR + XChaCha20, HMAC-SHA3
	ReedSolomon bool   // Enable Reed-Solomon error correction on payload (6% size overhead)
	Deniability bool   // Wrap volume in additional encryption layer for plausible deniability
	Compress    bool   // Use Deflate compression when creating zip archive

	// Output splitting - useful for storage on FAT32 or cloud services with file size limits
	Split     bool              // Enable splitting output into chunks
	ChunkSize int               // Size of each chunk
	ChunkUnit fileops.SplitUnit // Unit for ChunkSize: KiB, MiB, GiB, TiB, or Total (divide into N parts)

	// Progress reporting
	Reporter ProgressReporter // UI callback interface (can be nil for headless operation)

	// Internal - initialized by caller
	RSCodecs *encoding.RSCodecs // Pre-initialized Reed-Solomon codecs
}

// DecryptRequest contains all parameters needed to decrypt a .pcv volume.
// The Password and/or Keyfiles must match those used during encryption.
type DecryptRequest struct {
	// Input/Output paths
	InputFile  string // Path to .pcv volume (or first chunk if split)
	OutputFile string // Destination path for decrypted output

	// Credentials - must match encryption parameters
	//
	// SECURITY (SEC-05): owned []byte zeroed by the caller after use — same
	// ownership model and GUI residual as EncryptRequest.Password above (CONCERNS
	// 3.1; ROADMAP "Out of Scope: Guaranteed password zeroing").
	Password []byte   // User password — see SECURITY note above
	Keyfiles []string // Keyfile paths (validated against hash stored in header)

	// Decryption options
	ForceDecrypt bool // Continue despite MAC verification failure (may produce corrupted output)
	VerifyFirst  bool // Two-pass mode: verify MAC before decryption (slower but more secure, PCC-004)
	AutoUnzip    bool // Automatically extract if output is a .zip file
	SameLevel    bool // Extract zip contents to same directory as volume (not subdirectory)

	// Volume state (typically detected automatically)
	Recombine   bool // Volume is split into chunks that need recombining first
	Deniability bool // Volume has deniability wrapper that needs removing first

	// Progress reporting
	Reporter ProgressReporter // UI callback interface (can be nil for headless operation)

	// Internal - initialized by caller
	RSCodecs *encoding.RSCodecs // Pre-initialized Reed-Solomon codecs

	// Output - set by Decrypt() after completion
	Kept *bool // If non-nil and ForceDecrypt was used, set to true if file was kept despite MAC failure
}

// OperationContext holds mutable state during encryption/decryption operations.
// This is created at the start of Encrypt()/Decrypt() and passed through all phases.
type OperationContext struct {
	// Context for cancellation and timeouts
	Ctx context.Context

	// File paths
	InputFile  string // Current input file (may change during preprocessing)
	OutputFile string // Final output destination
	TempFile   string // Intermediate file path (zip archive or recombined chunks)

	// Volume header - populated during encryption or read during decryption
	Header *header.VolumeHeader

	// Cryptographic state
	Key           *crypto.Secret       // Argon2-derived key (possibly XORed with keyfile key)
	KeyfileKey    *crypto.Secret       // 32-byte key derived from keyfile(s)
	KeyfileHash   []byte               // SHA3-256(KeyfileKey) for verification (NON-SECRET: stored in header)
	passwordBytes *crypto.Secret       // KDF input for the current password form being tried (#19)
	secrets       []*crypto.Secret     // every Secret this context owns; Close() iterates this
	SubkeyReader  *crypto.SubkeyReader // HKDF stream for deriving MAC/Serpent subkeys
	CipherSuite   *crypto.CipherSuite  // Initialized cipher suite (XChaCha20 + optional Serpent)

	// Operation flags
	IsLegacyV1   bool                    // True if decrypting a v1.x volume (different HKDF timing)
	UseKeyfiles  bool                    // True if keyfiles were used/required
	Padded       bool                    // True if final chunk needs unpadding (RS mode)
	TempZipInUse bool                    // True if reading from encrypted temp zip
	TempCiphers  *fileops.TempZipCiphers // Ciphers for encrypted temp zip

	// Reed-Solomon retry state (for corrupt file recovery)
	TriedFullRSDecode bool // Prevents infinite retry loop when MAC fails
	Kept              bool // True if ForceDecrypt was used and MAC failed

	// Recombine state - for proper cleanup
	RecombinedFile string // Path to recombined file (separate from TempFile for when deniability changes it)
	recombinedInfo os.FileInfo

	stagedOutput *fileops.StagedFile
	ownedTemps   []*fileops.StagedFile
	tempInput    *fileops.StagedFile

	publishedOutputInfo os.FileInfo

	// Progress tracking
	Total    int64            // Total bytes to process
	Done     int64            // Bytes processed so far
	Reporter ProgressReporter // UI callback (may be nil)
}

// NewEncryptContext creates a context for encryption operations.
// If ctx is nil, context.Background() is used.
func NewEncryptContext(ctx context.Context, req *EncryptRequest) *OperationContext {
	if ctx == nil {
		ctx = context.Background()
	}
	return &OperationContext{
		Ctx:        ctx,
		OutputFile: req.OutputFile,
		Reporter:   req.Reporter,
	}
}

// NewDecryptContext creates a context for decryption operations.
// If ctx is nil, context.Background() is used.
func NewDecryptContext(ctx context.Context, req *DecryptRequest) *OperationContext {
	if ctx == nil {
		ctx = context.Background()
	}
	return &OperationContext{
		Ctx:        ctx,
		InputFile:  req.InputFile,
		OutputFile: req.OutputFile,
		Reporter:   req.Reporter,
	}
}

// UpdateProgress updates the progress reporter if available
func (ctx *OperationContext) UpdateProgress(fraction float32, info string) {
	if ctx.Reporter != nil {
		ctx.Reporter.SetProgress(fraction, info)
		ctx.Reporter.Update()
	}
}

// SetStatus updates the status reporter if available
func (ctx *OperationContext) SetStatus(status string) {
	if ctx.Reporter != nil {
		ctx.Reporter.SetStatus(status)
		ctx.Reporter.Update()
	}
}

// SetCanCancel updates cancel availability on the reporter if available.
func (ctx *OperationContext) SetCanCancel(can bool) {
	if ctx.Reporter != nil {
		ctx.Reporter.SetCanCancel(can)
		ctx.Reporter.Update()
	}
}

// IsCancelled checks if the operation has been cancelled.
// Returns true if either the context is done or the reporter indicates cancellation.
func (ctx *OperationContext) IsCancelled() bool {
	// Check context cancellation first (standard Go pattern)
	if ctx.Ctx != nil {
		select {
		case <-ctx.Ctx.Done():
			return true
		default:
		}
	}

	// Also check reporter-based cancellation (for UI cancel button)
	if ctx.Reporter != nil {
		return ctx.Reporter.IsCancelled()
	}
	return false
}

// CancellationError returns the appropriate error when cancelled.
// Returns context error if context is done, otherwise returns ErrCancelled.
func (ctx *OperationContext) CancellationError() error {
	if ctx.Ctx != nil {
		select {
		case <-ctx.Ctx.Done():
			return ctx.Ctx.Err()
		default:
		}
	}
	return perrors.ErrCancelled
}

// TempZipReader wraps the input file with decryption if temp zip was used
func (ctx *OperationContext) TempZipReader(r io.Reader) io.Reader {
	if ctx.TempZipInUse && ctx.TempCiphers != nil {
		return fileops.WrapReaderWithCipher(r, ctx.TempCiphers)
	}
	return r
}

func (ctx *OperationContext) beginStagedOutput() error {
	if ctx.stagedOutput != nil {
		return errors.New("staged output already exists")
	}
	stage, err := fileops.CreateSiblingTemp(ctx.OutputFile)
	if err != nil {
		return err
	}
	ctx.stagedOutput = stage
	return nil
}

func (ctx *OperationContext) stagedOutputFile() (*os.File, error) {
	if ctx.stagedOutput == nil || ctx.stagedOutput.File() == nil {
		return nil, errors.New("staged output is not open")
	}
	return ctx.stagedOutput.File(), nil
}

func (ctx *OperationContext) resetStagedOutput() error {
	if ctx.stagedOutput == nil {
		return errors.New("staged output does not exist")
	}
	return ctx.stagedOutput.Reset()
}

func (ctx *OperationContext) publishStagedOutput() error {
	if ctx.stagedOutput == nil {
		return errors.New("staged output does not exist")
	}
	file, err := ctx.stagedOutputFile()
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect staged output before publish: %w", err)
	}
	if err := ctx.stagedOutput.Commit(); err != nil {
		return err
	}
	ctx.publishedOutputInfo = info
	ctx.stagedOutput = nil
	return nil
}

func (ctx *OperationContext) adoptTempInput(stage *fileops.StagedFile) {
	ctx.ownedTemps = append(ctx.ownedTemps, stage)
	ctx.tempInput = stage
	ctx.TempFile = stage.Path()
}

func (ctx *OperationContext) rememberRecombinedFile(path string, info os.FileInfo) error {
	if info == nil {
		return errors.New("recombined file identity is unavailable")
	}
	ctx.RecombinedFile = path
	ctx.recombinedInfo = info
	return nil
}

func (ctx *OperationContext) cleanupRecombinedFile() error {
	if ctx.RecombinedFile == "" || ctx.recombinedInfo == nil {
		return nil
	}
	removed, err := fileops.RemoveIfSameFile(ctx.RecombinedFile, ctx.recombinedInfo)
	if err != nil {
		return err
	}
	if !removed {
		if _, err := os.Lstat(ctx.RecombinedFile); err == nil {
			return fmt.Errorf("recombined temporary path %q changed; refusing to remove it", ctx.RecombinedFile)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect recombined temporary path %q: %w", ctx.RecombinedFile, err)
		}
	}
	ctx.RecombinedFile = ""
	ctx.recombinedInfo = nil
	return nil
}

func (ctx *OperationContext) openInput() (*os.File, bool, error) {
	if ctx.tempInput != nil && ctx.InputFile == ctx.tempInput.Path() {
		file := ctx.tempInput.File()
		if file == nil {
			return nil, false, errors.New("temporary input is not open")
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return nil, false, fmt.Errorf("rewind temporary input: %w", err)
		}
		return file, false, nil
	}

	file, err := os.Open(ctx.InputFile)
	if err != nil {
		return nil, false, err
	}
	if ctx.RecombinedFile == ctx.InputFile && ctx.recombinedInfo != nil {
		info, statErr := file.Stat()
		if statErr != nil {
			_ = file.Close()
			return nil, false, fmt.Errorf("inspect recombined input: %w", statErr)
		}
		if !os.SameFile(ctx.recombinedInfo, info) {
			_ = file.Close()
			return nil, false, errors.New("recombined input path changed before use")
		}
	}
	return file, true, nil
}

// adopt registers s so Close() will zero it, and returns s.
func (ctx *OperationContext) adopt(s *crypto.Secret) *crypto.Secret {
	ctx.secrets = append(ctx.secrets, s)
	return s
}

// setKey replaces the derived key, zeroing the orphaned predecessor.
//
// SEC-05 / WR-01: mid-operation reassignments of ctx.Key (the v1/v2 keyfile XOR at
// decrypt.go and the full-RS retry re-derive at decryptDeriveKeys) produce a NEW
// slice (keyfile.XORWithKey allocates; Argon2 re-derive allocates), orphaning the
// old backing array. Routing every replacement through Secret.Set zeros that
// predecessor immediately instead of waiting for Close().
//
// The aliasing/self-assign guard now lives in crypto.Secret.Set: the no-keyfile v1
// path does `ctx.setKey(key)` where key IS ctx.Key's backing array, and Set's
// pointer-identity guard skips zeroing so the LIVE key survives.
func (ctx *OperationContext) setKey(k []byte) {
	if ctx.Key == nil {
		ctx.Key = ctx.adopt(crypto.SecretFrom(k))
		return
	}
	ctx.Key.Set(k)
}

// setKeyfileKey replaces the keyfile-derived key, zeroing the orphaned predecessor.
// Analogous to setKey: the full-RS retry re-processes keyfiles (decryptProcessKeyfiles),
// orphaning the prior keyfile-key buffer. Secret.Set zeros it before reassignment.
func (ctx *OperationContext) setKeyfileKey(k []byte) {
	if ctx.KeyfileKey == nil {
		ctx.KeyfileKey = ctx.adopt(crypto.SecretFrom(k))
		return
	}
	ctx.KeyfileKey.Set(k)
}

// setPasswordBytes replaces the current password byte form, zeroing the previous
// one. The decrypt path sets this per candidate normalization form (#19); the
// winning form is reused by the RS / verify-first re-derivation paths and is zeroed
// by Close. Secret.Set carries the same pointer-identity self-assign guard.
// (The password also lives in req.Password as an owned []byte zeroed by the
// caller after the operation — see Close's SECURITY note.)
func (ctx *OperationContext) setPasswordBytes(b []byte) {
	if ctx.passwordBytes == nil {
		ctx.passwordBytes = ctx.adopt(crypto.SecretFrom(b))
		return
	}
	ctx.passwordBytes.Set(b)
}

// Close securely zeros all sensitive cryptographic material in the context.
// This should be called via defer immediately after creating the context.
//
// SECURITY: Always call Close() when done with an operation to minimize
// the window during which key material is recoverable from memory.
//
// SECURITY (password limitation): Close() zeros only []byte key material it
// owns. EncryptRequest.Password / DecryptRequest.Password are now owned []byte
// zeroed by the caller (CLI/wasm/mobile pass []byte end-to-end with no
// intermediate string). The remaining residual is the Fyne GUI: widget.Entry
// stores the typed password as a Go string in app.State.Password, which is
// immutable and freely copied/relocated by the GC, so that one copy cannot be
// zeroed in place — ui/operations.go converts it to an owned []byte for the
// request and zeros that, but the string lingers until GC. This is intentionally
// out of scope (CONCERNS 3.1; ROADMAP "Out of Scope: Guaranteed password
// zeroing"), mirroring crypto.SecureZero's own GC/optimization caveat.
func (ctx *OperationContext) Close() error {
	if ctx == nil {
		return nil
	}

	var cleanupErrs []error
	if ctx.stagedOutput != nil {
		if err := ctx.stagedOutput.Cleanup(); err != nil {
			cleanupErrs = append(cleanupErrs, err)
		}
		ctx.stagedOutput = nil
	}
	for _, stage := range ctx.ownedTemps {
		if err := stage.Cleanup(); err != nil {
			cleanupErrs = append(cleanupErrs, err)
		}
	}
	ctx.ownedTemps = nil
	ctx.tempInput = nil
	ctx.publishedOutputInfo = nil

	// Zero every owned secret via the registry (Key/KeyfileKey/passwordBytes).
	for _, s := range ctx.secrets {
		s.Close()
	}
	ctx.secrets = nil
	ctx.Key = nil
	ctx.KeyfileKey = nil
	ctx.passwordBytes = nil

	// KeyfileHash is NON-SECRET (written to the header) but cleared defensively.
	crypto.SecureZero(ctx.KeyfileHash)
	ctx.KeyfileHash = nil

	// Close cipher suite (zeros internal key)
	if ctx.CipherSuite != nil {
		ctx.CipherSuite.Close()
		ctx.CipherSuite = nil
	}

	// Clear header auth values
	if ctx.Header != nil {
		crypto.SecureZeroMultiple(ctx.Header.KeyHash, ctx.Header.AuthTag)
		ctx.Header.KeyHash = nil
		ctx.Header.AuthTag = nil
	}

	// Clear SubkeyReader reference (HKDF state)
	ctx.SubkeyReader = nil

	// Close temp zip ciphers (zeros ephemeral key material)
	if ctx.TempCiphers != nil {
		ctx.TempCiphers.Close()
		ctx.TempCiphers = nil
	}
	return errors.Join(cleanupErrs...)
}
