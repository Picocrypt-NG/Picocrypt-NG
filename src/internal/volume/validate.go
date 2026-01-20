package volume

import (
	"os"

	"Picocrypt-NG/internal/errors"
)

// Validate checks that the EncryptRequest has all required fields and valid configuration.
// Returns nil if valid, or an error describing the validation failure.
func (req *EncryptRequest) Validate() error {
	// Check for input files
	if req.InputFile == "" && len(req.InputFiles) == 0 {
		return errors.ErrNoInputFiles
	}

	// Check for credentials
	if req.Password == "" && len(req.Keyfiles) == 0 {
		return errors.ErrNoCredentials
	}

	// Check output file is specified
	if req.OutputFile == "" {
		return errors.NewValidationError("OutputFile", "output file path is required")
	}

	// Validate split options
	if req.Split {
		if req.ChunkSize <= 0 {
			return errors.ErrInvalidChunkSize
		}
	}

	// Validate input files exist
	if req.InputFile != "" {
		if _, err := os.Stat(req.InputFile); err != nil {
			return errors.NewFileError("stat", req.InputFile, err)
		}
	}

	for _, f := range req.InputFiles {
		if _, err := os.Stat(f); err != nil {
			return errors.NewFileError("stat", f, err)
		}
	}

	// Validate keyfiles exist
	for _, kf := range req.Keyfiles {
		if _, err := os.Stat(kf); err != nil {
			return errors.NewFileError("stat", kf, err)
		}
	}

	return nil
}

// Validate checks that the DecryptRequest has all required fields and valid configuration.
// Returns nil if valid, or an error describing the validation failure.
func (req *DecryptRequest) Validate() error {
	// Check for input file
	if req.InputFile == "" {
		return errors.NewValidationError("InputFile", "input file path is required")
	}

	// Check input file exists
	if _, err := os.Stat(req.InputFile); err != nil {
		return errors.NewFileError("stat", req.InputFile, err)
	}

	// Note: We don't require password/keyfiles here because they may be
	// provided separately based on header information (keyfiles required flag)

	// Check output file is specified
	if req.OutputFile == "" {
		return errors.NewValidationError("OutputFile", "output file path is required")
	}

	// Validate keyfiles exist if provided
	for _, kf := range req.Keyfiles {
		if _, err := os.Stat(kf); err != nil {
			return errors.NewFileError("stat", kf, err)
		}
	}

	return nil
}

// ValidateCredentials checks that credentials are provided for decryption.
// This should be called after reading the header to know if keyfiles are required.
func (req *DecryptRequest) ValidateCredentials(keyfilesRequired bool) error {
	hasPassword := req.Password != ""
	hasKeyfiles := len(req.Keyfiles) > 0

	// Must have at least one credential type
	if !hasPassword && !hasKeyfiles {
		return errors.ErrNoCredentials
	}

	// If keyfiles are required by the volume, they must be provided
	if keyfilesRequired && !hasKeyfiles {
		return errors.NewValidationError("Keyfiles", "this volume requires keyfiles for decryption")
	}

	return nil
}

// EncryptRequestBuilder provides a fluent interface for building EncryptRequest.
type EncryptRequestBuilder struct {
	req EncryptRequest
}

// NewEncryptRequestBuilder creates a new builder for EncryptRequest.
func NewEncryptRequestBuilder() *EncryptRequestBuilder {
	return &EncryptRequestBuilder{}
}

// WithInputFile sets the single input file.
func (b *EncryptRequestBuilder) WithInputFile(path string) *EncryptRequestBuilder {
	b.req.InputFile = path
	return b
}

// WithInputFiles sets multiple input files.
func (b *EncryptRequestBuilder) WithInputFiles(paths []string) *EncryptRequestBuilder {
	b.req.InputFiles = paths
	return b
}

// WithOutputFile sets the output file path.
func (b *EncryptRequestBuilder) WithOutputFile(path string) *EncryptRequestBuilder {
	b.req.OutputFile = path
	return b
}

// WithPassword sets the encryption password.
func (b *EncryptRequestBuilder) WithPassword(password string) *EncryptRequestBuilder {
	b.req.Password = password
	return b
}

// WithKeyfiles sets the keyfile paths.
func (b *EncryptRequestBuilder) WithKeyfiles(paths []string, ordered bool) *EncryptRequestBuilder {
	b.req.Keyfiles = paths
	b.req.KeyfileOrdered = ordered
	return b
}

// WithComments sets the plaintext comments.
func (b *EncryptRequestBuilder) WithComments(comments string) *EncryptRequestBuilder {
	b.req.Comments = comments
	return b
}

// WithParanoidMode enables paranoid mode.
func (b *EncryptRequestBuilder) WithParanoidMode(enabled bool) *EncryptRequestBuilder {
	b.req.Paranoid = enabled
	return b
}

// WithReedSolomon enables Reed-Solomon error correction.
func (b *EncryptRequestBuilder) WithReedSolomon(enabled bool) *EncryptRequestBuilder {
	b.req.ReedSolomon = enabled
	return b
}

// WithDeniability enables deniability wrapper.
func (b *EncryptRequestBuilder) WithDeniability(enabled bool) *EncryptRequestBuilder {
	b.req.Deniability = enabled
	return b
}

// WithCompression enables compression.
func (b *EncryptRequestBuilder) WithCompression(enabled bool) *EncryptRequestBuilder {
	b.req.Compress = enabled
	return b
}

// WithSplit enables output splitting.
func (b *EncryptRequestBuilder) WithSplit(chunkSize int, unit string) *EncryptRequestBuilder {
	b.req.Split = true
	b.req.ChunkSize = chunkSize
	// Convert string unit to fileops.SplitUnit (handled by caller)
	return b
}

// WithReporter sets the progress reporter.
func (b *EncryptRequestBuilder) WithReporter(reporter ProgressReporter) *EncryptRequestBuilder {
	b.req.Reporter = reporter
	return b
}

// Build validates and returns the EncryptRequest.
func (b *EncryptRequestBuilder) Build() (*EncryptRequest, error) {
	if err := b.req.Validate(); err != nil {
		return nil, err
	}
	return &b.req, nil
}

// BuildUnchecked returns the EncryptRequest without validation.
// Use this when validation will be done later or externally.
func (b *EncryptRequestBuilder) BuildUnchecked() *EncryptRequest {
	return &b.req
}
