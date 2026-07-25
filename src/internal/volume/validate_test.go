package volume

import (
	"Picocrypt-NG/internal/errors"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/header"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptRequestValidate(t *testing.T) {
	// Create temp dir for test files
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0o644); err != nil {
		t.Fatal(err)
	}
	keyfile := filepath.Join(tmpDir, "test.key")
	if err := os.WriteFile(keyfile, []byte("keyfile content"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name              string
		req               *EncryptRequest
		wantSentinel      error  // non-nil => assert errors.Is(err, wantSentinel)
		wantValidationFld string // non-empty => assert *ValidationError with this Field
		wantFileNotFound  bool   // true => assert *FileError unwrapping to os.ErrNotExist
		wantNil           bool   // true => assert err == nil
	}{
		{
			name:         "no input files",
			req:          &EncryptRequest{},
			wantSentinel: errors.ErrNoInputFiles,
		},
		{
			name: "encryption requires a password",
			req: &EncryptRequest{
				InputFile:  testFile,
				OutputFile: filepath.Join(tmpDir, "out.pcv"),
			},
			wantValidationFld: "Password",
		},
		{
			name: "no output file",
			req: &EncryptRequest{
				InputFile: testFile,
				Password:  []byte("test"),
			},
			wantValidationFld: "OutputFile",
		},
		{
			name: "invalid split size",
			req: &EncryptRequest{
				InputFile:  testFile,
				OutputFile: filepath.Join(tmpDir, "out.pcv"),
				Password:   []byte("test"),
				Split:      true,
				ChunkSize:  0,
			},
			wantSentinel: errors.ErrInvalidChunkSize,
		},
		{
			name: "input file not found",
			req: &EncryptRequest{
				InputFile:  "/nonexistent/file.txt",
				OutputFile: filepath.Join(tmpDir, "out.pcv"),
				Password:   []byte("test"),
			},
			wantFileNotFound: true,
		},
		{
			name: "valid request",
			req: &EncryptRequest{
				InputFile:  testFile,
				OutputFile: filepath.Join(tmpDir, "out.pcv"),
				Password:   []byte("test"),
			},
			wantNil: true,
		},
		{
			name: "keyfile-only writer is disabled",
			req: &EncryptRequest{
				InputFile:  testFile,
				OutputFile: filepath.Join(tmpDir, "keyfile-only.pcv"),
				Keyfiles:   []string{keyfile},
			},
			wantValidationFld: "Keyfiles",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			switch {
			case tt.wantSentinel != nil:
				if !errors.Is(err, tt.wantSentinel) {
					t.Errorf("Validate() error = %v, want %v", err, tt.wantSentinel)
				}
			case tt.wantValidationFld != "":
				var ve *errors.ValidationError
				if !errors.As(err, &ve) {
					t.Fatalf("Validate() error = %v, want *ValidationError on field %q", err, tt.wantValidationFld)
				}
				if ve.Field != tt.wantValidationFld {
					t.Errorf("ValidationError.Field = %q, want %q", ve.Field, tt.wantValidationFld)
				}
			case tt.wantFileNotFound:
				var fe *errors.FileError
				if !errors.As(err, &fe) {
					t.Fatalf("Validate() error = %v, want *FileError", err)
				}
				if !errors.Is(err, os.ErrNotExist) {
					t.Errorf("Validate() error = %v, want it to wrap os.ErrNotExist", err)
				}
			case tt.wantNil:
				if err != nil {
					t.Errorf("Validate() error = %v, want nil", err)
				}
			}
		})
	}
}

// TestValidateRejectsOverflowingChunkSize proves the split upper bound: a chunk
// size whose byte product overflows int64 is rejected by Validate with
// errors.ErrChunkSizeTooLarge instead of silently wrapping. Mirrors the QUAL-05
// early-rejection pattern (the wrap would otherwise surface only at the final
// split step, after the volume is already written).
func TestValidateRejectsOverflowingChunkSize(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0o644); err != nil {
		t.Fatal(err)
	}

	req := &EncryptRequest{
		InputFile:  testFile,
		OutputFile: filepath.Join(tmpDir, "out.pcv"),
		Password:   []byte("test"),
		Split:      true,
		ChunkSize:  1 << 23, // 2^23 TiB * 2^40 = 2^63, overflows int64
		ChunkUnit:  fileops.SplitUnitTiB,
	}
	if err := req.Validate(); !errors.Is(err, errors.ErrChunkSizeTooLarge) {
		t.Fatalf("Validate() error = %v, want errors.ErrChunkSizeTooLarge", err)
	}
}

// TestValidateRejectsLongCommentEarly proves QUAL-05: an over-long comment is
// rejected by EncryptRequest.Validate() with errors.ErrCommentTooLong BEFORE any
// Argon2id key derivation runs. A counting spy wraps the deriveVolumeKey seam
// (the Argon2id entry the encrypt pipeline routes through at encrypt.go:220,
// AFTER Validate); the counter must stay 0 because Validate rejects first.
func TestValidateRejectsLongCommentEarly(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Install a counting spy over the deriveVolumeKey seam (override+restore).
	// TestMain already swaps deriveVolumeKey to the fast stub; we wrap that so the
	// counter proves no key derivation happens when Validate rejects early.
	var deriveCalls int
	prevVolumeKey := deriveVolumeKey
	deriveVolumeKey = func(password, salt []byte, paranoid bool) ([]byte, error) {
		deriveCalls++
		return prevVolumeKey(password, salt, paranoid)
	}
	defer func() { deriveVolumeKey = prevVolumeKey }()

	req := &EncryptRequest{
		InputFile:  testFile,
		OutputFile: filepath.Join(tmpDir, "out.pcv"),
		Password:   []byte("test"),
		Comments:   string(make([]byte, header.MaxCommentLen+1)), // 1 over the bound
	}

	err := req.Validate()
	if !errors.Is(err, errors.ErrCommentTooLong) {
		t.Fatalf("Validate() error = %v, want errors.ErrCommentTooLong", err)
	}
	if deriveCalls != 0 {
		t.Errorf("deriveVolumeKey called %d times during Validate; want 0 (no Argon2id before rejection)", deriveCalls)
	}
}

func TestDecryptRequestValidate(t *testing.T) {
	// Create temp dir for test files
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.pcv")
	if err := os.WriteFile(testFile, []byte("test content"), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name              string
		req               *DecryptRequest
		wantValidationFld string // non-empty => assert *ValidationError with this Field
		wantFileNotFound  bool   // true => assert *FileError unwrapping to os.ErrNotExist
		wantNil           bool   // true => assert err == nil
	}{
		{
			name:              "no input file",
			req:               &DecryptRequest{},
			wantValidationFld: "InputFile",
		},
		{
			name: "input file not found",
			req: &DecryptRequest{
				InputFile: "/nonexistent/file.pcv",
			},
			wantFileNotFound: true,
		},
		{
			name: "no output file",
			req: &DecryptRequest{
				InputFile: testFile,
			},
			wantValidationFld: "OutputFile",
		},
		{
			name: "valid request",
			req: &DecryptRequest{
				InputFile:  testFile,
				OutputFile: filepath.Join(tmpDir, "out.txt"),
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			switch {
			case tt.wantValidationFld != "":
				var ve *errors.ValidationError
				if !errors.As(err, &ve) {
					t.Fatalf("Validate() error = %v, want *ValidationError on field %q", err, tt.wantValidationFld)
				}
				if ve.Field != tt.wantValidationFld {
					t.Errorf("ValidationError.Field = %q, want %q", ve.Field, tt.wantValidationFld)
				}
			case tt.wantFileNotFound:
				var fe *errors.FileError
				if !errors.As(err, &fe) {
					t.Fatalf("Validate() error = %v, want *FileError", err)
				}
				if !errors.Is(err, os.ErrNotExist) {
					t.Errorf("Validate() error = %v, want it to wrap os.ErrNotExist", err)
				}
			case tt.wantNil:
				if err != nil {
					t.Errorf("Validate() error = %v, want nil", err)
				}
			}
		})
	}
}

func TestDecryptRequestValidateCredentials(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.pcv")
	if err := os.WriteFile(testFile, []byte("test content"), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name              string
		req               *DecryptRequest
		keyfilesRequired  bool
		wantSentinel      error  // non-nil => assert errors.Is(err, wantSentinel)
		wantValidationFld string // non-empty => assert *ValidationError with this Field
		wantNil           bool   // true => assert err == nil
	}{
		{
			name: "no credentials required",
			req: &DecryptRequest{
				InputFile:  testFile,
				OutputFile: filepath.Join(tmpDir, "out.txt"),
			},
			keyfilesRequired: false,
			wantSentinel:     errors.ErrNoCredentials,
		},
		{
			name: "keyfiles required but not provided",
			req: &DecryptRequest{
				InputFile:  testFile,
				OutputFile: filepath.Join(tmpDir, "out.txt"),
				Password:   []byte("test"),
			},
			keyfilesRequired:  true,
			wantValidationFld: "Keyfiles",
		},
		{
			name: "password only valid when no keyfiles required",
			req: &DecryptRequest{
				InputFile:  testFile,
				OutputFile: filepath.Join(tmpDir, "out.txt"),
				Password:   []byte("test"),
			},
			keyfilesRequired: false,
			wantNil:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.ValidateCredentials(tt.keyfilesRequired)
			switch {
			case tt.wantSentinel != nil:
				if !errors.Is(err, tt.wantSentinel) {
					t.Errorf("ValidateCredentials() error = %v, want %v", err, tt.wantSentinel)
				}
			case tt.wantValidationFld != "":
				var ve *errors.ValidationError
				if !errors.As(err, &ve) {
					t.Fatalf("ValidateCredentials() error = %v, want *ValidationError on field %q", err, tt.wantValidationFld)
				}
				if ve.Field != tt.wantValidationFld {
					t.Errorf("ValidationError.Field = %q, want %q", ve.Field, tt.wantValidationFld)
				}
			case tt.wantNil:
				if err != nil {
					t.Errorf("ValidateCredentials() error = %v, want nil", err)
				}
			}
		})
	}
}
