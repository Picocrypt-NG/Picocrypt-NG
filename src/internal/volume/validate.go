package volume

import (
	"Picocrypt-NG/internal/errors"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/header"
	"fmt"
	"os"
)

// Validate checks that the EncryptRequest has all required fields and valid configuration.
// Returns nil if valid, or an error describing the validation failure.
func (req *EncryptRequest) Validate() error {
	// Check for input files
	if req.InputFile == "" && len(req.InputFiles) == 0 {
		return errors.ErrNoInputFiles
	}

	// Check for credentials
	if len(req.Password) == 0 && len(req.Keyfiles) == 0 {
		return errors.ErrNoCredentials
	}

	// QUAL-05: reject an over-long comment here, before the expensive Argon2id
	// key derivation, instead of only at write time (header/writer.go). This
	// only moves *when* the existing bound is enforced — no on-disk format change.
	if len(req.Comments) > header.MaxCommentLen {
		return errors.ErrCommentTooLong
	}

	// Check output file is specified
	if req.OutputFile == "" {
		return errors.NewValidationError("OutputFile", "output file path is required")
	}

	// Validate split options
	if err := req.validateSplit(); err != nil {
		return err
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

	return req.ValidateOutputSafety()
}

// ValidateOutputSafety rejects destinations that alias an input or keyfile.
// Overwrite confirmation never authorizes replacing a protected source.
func (req *EncryptRequest) ValidateOutputSafety() error {
	protected := make([]string, 0, 1+len(req.InputFiles)+len(req.OnlyFiles)+len(req.OnlyFolders)+len(req.Keyfiles))
	if req.InputFile != "" {
		protected = append(protected, req.InputFile)
	}
	protected = append(protected, req.InputFiles...)
	protected = append(protected, req.OnlyFiles...)
	protected = append(protected, req.OnlyFolders...)
	protected = append(protected, req.Keyfiles...)
	return validateOutputSafety(req.OutputFile, protected)
}

// validateSplit checks the split configuration. It is shared by Validate and by
// the Encrypt pipeline entry so an unusable chunk size is rejected once, on every
// path. An over-large size must be caught here: scaled to bytes it overflows
// int64 and silently wraps, turning fileops.Split into a no-op the pipeline
// would mistake for success and then delete the just-written volume.
func (req *EncryptRequest) validateSplit() error {
	if !req.Split {
		return nil
	}
	if req.ChunkSize <= 0 {
		return errors.ErrInvalidChunkSize
	}
	if _, err := fileops.ChunkSizeToBytes(req.ChunkSize, req.ChunkUnit); err != nil {
		return errors.ErrChunkSizeTooLarge
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

	// A recombine request may name the base path before that file exists. In
	// that mode the numbered chunks are the real protected inputs.
	if req.Recombine {
		inputBase := recombineInputBase(req.InputFile)
		if _, _, err := fileops.CountChunks(inputBase); err != nil {
			return errors.NewFileError("stat chunks", inputBase, err)
		}
	} else if _, err := os.Stat(req.InputFile); err != nil {
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

	return req.ValidateOutputSafety()
}

// ValidateOutputSafety rejects destinations that alias the encrypted volume or
// a keyfile, regardless of any overwrite or force option.
func (req *DecryptRequest) ValidateOutputSafety() error {
	protected := make([]string, 0, 1+len(req.Keyfiles))
	if req.InputFile != "" {
		protected = append(protected, req.InputFile)
	}
	if req.Recombine {
		inputBase := recombineInputBase(req.InputFile)
		// Recombine creates a temporary encrypted volume at the base path.
		// Treat it as a protected input even when it does not exist yet, so the
		// plaintext destination cannot replace it before cleanup.
		protected = append(protected, inputBase)
		numChunks, _, err := fileops.CountChunks(inputBase)
		if err != nil {
			return errors.NewFileError("stat chunks", inputBase, err)
		}
		for i := range numChunks {
			protected = append(protected, fmt.Sprintf("%s.%d", inputBase, i))
		}
	}
	protected = append(protected, req.Keyfiles...)
	return validateOutputSafety(req.OutputFile, protected)
}

func recombineInputBase(input string) string {
	if base, ok := fileops.SplitChunkBase(input); ok {
		return base
	}
	return input
}

func validateOutputSafety(output string, protected []string) error {
	if output == "" {
		return nil
	}
	for _, source := range protected {
		if source == "" {
			continue
		}
		same, err := fileops.SamePathOrFile(source, output)
		if err != nil {
			return err
		}
		if same {
			return errors.NewValidationError(
				"OutputFile",
				fmt.Sprintf("output %q conflicts with protected source %q", output, source),
			)
		}
	}
	return nil
}

// ValidateCredentials checks that credentials are provided for decryption.
// This should be called after reading the header to know if keyfiles are required.
func (req *DecryptRequest) ValidateCredentials(keyfilesRequired bool) error {
	hasPassword := len(req.Password) > 0
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
