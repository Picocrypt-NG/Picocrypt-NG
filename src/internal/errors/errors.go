// Package errors provides typed errors for Picocrypt operations.
// This enables callers to use errors.Is() and errors.As() for specific error handling.
package errors

import (
	"errors"
	"fmt"
)

// Sentinel errors for common error conditions.
// Use errors.Is(err, errors.ErrCancelled) to check for specific errors.
var (
	// Operation errors
	ErrCancelled     = errors.New("operation cancelled")
	ErrAuthFailed    = errors.New("authentication failed")
	ErrCorruptHeader = errors.New("header corrupted")
	ErrCorruptData   = errors.New("data corrupted")

	// Input validation errors
	ErrNoInputFiles      = errors.New("no input files specified")
	ErrNoCredentials     = errors.New("no password or keyfiles provided")
	ErrPasswordMismatch  = errors.New("passwords do not match")
	ErrInvalidChunkSize  = errors.New("invalid chunk size")
	ErrDuplicateKeyfiles = errors.New("duplicate keyfiles detected")

	// File errors
	ErrFileNotFound    = errors.New("file not found")
	ErrFileExists      = errors.New("file already exists")
	ErrInvalidFormat   = errors.New("invalid volume format")
	ErrVersionMismatch = errors.New("unsupported volume version")

	// Crypto errors
	ErrRandFailure   = errors.New("crypto/rand failure")
	ErrKeyDerivation = errors.New("key derivation failed")
	ErrHKDFFailure   = errors.New("HKDF stream failure")
	ErrMACFailure    = errors.New("MAC computation failed")
	ErrCipherFailure = errors.New("cipher operation failed")

	// Reed-Solomon errors
	ErrRSEncode = errors.New("Reed-Solomon encoding failed")
	ErrRSDecode = errors.New("Reed-Solomon decoding failed")
)

// CryptoError represents an error during cryptographic operations.
// It wraps the underlying error with operation context.
type CryptoError struct {
	Op  string // Operation name: "rand", "argon2", "hkdf", "cipher", "mac"
	Err error  // Underlying error
}

func (e *CryptoError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("crypto %s: %v", e.Op, e.Err)
	}
	return fmt.Sprintf("crypto %s failed", e.Op)
}

func (e *CryptoError) Unwrap() error {
	return e.Err
}

// NewCryptoError creates a new CryptoError.
func NewCryptoError(op string, err error) *CryptoError {
	return &CryptoError{Op: op, Err: err}
}

// FileError represents an error during file operations.
type FileError struct {
	Op   string // Operation: "open", "read", "write", "stat", "create"
	Path string // File path
	Err  error  // Underlying error
}

func (e *FileError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s %s: %v", e.Op, e.Path, e.Err)
	}
	return fmt.Sprintf("%s %s failed", e.Op, e.Path)
}

func (e *FileError) Unwrap() error {
	return e.Err
}

// NewFileError creates a new FileError.
func NewFileError(op, path string, err error) *FileError {
	return &FileError{Op: op, Path: path, Err: err}
}

// ValidationError represents an input validation error.
type ValidationError struct {
	Field   string // Field name that failed validation
	Message string // Human-readable error message
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation: %s: %s", e.Field, e.Message)
}

// NewValidationError creates a new ValidationError.
func NewValidationError(field, message string) *ValidationError {
	return &ValidationError{Field: field, Message: message}
}

// HeaderError represents an error in volume header parsing or validation.
type HeaderError struct {
	Field string // Header field that caused the error
	Err   error  // Underlying error
}

func (e *HeaderError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("header %s: %v", e.Field, e.Err)
	}
	return fmt.Sprintf("header %s invalid", e.Field)
}

func (e *HeaderError) Unwrap() error {
	return e.Err
}

// NewHeaderError creates a new HeaderError.
func NewHeaderError(field string, err error) *HeaderError {
	return &HeaderError{Field: field, Err: err}
}

// Is checks if target matches any of our sentinel errors.
// This is a convenience function for common error checks.
func Is(err, target error) bool {
	return errors.Is(err, target)
}

// As finds the first error in err's chain that matches target.
func As(err error, target any) bool {
	return errors.As(err, target)
}

// Wrap wraps an error with additional context.
func Wrap(err error, message string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}

// IsCancelled checks if the error indicates a cancelled operation.
func IsCancelled(err error) bool {
	return errors.Is(err, ErrCancelled)
}

// IsAuthFailed checks if the error indicates authentication failure.
func IsAuthFailed(err error) bool {
	return errors.Is(err, ErrAuthFailed)
}

// IsCorrupt checks if the error indicates data corruption.
func IsCorrupt(err error) bool {
	return errors.Is(err, ErrCorruptHeader) || errors.Is(err, ErrCorruptData)
}
