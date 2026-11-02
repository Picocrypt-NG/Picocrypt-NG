package errors

import (
	"errors"
	"fmt"
	"testing"
)

func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrCancelled", ErrCancelled},
		{"ErrAuthFailed", ErrAuthFailed},
		{"ErrCorruptHeader", ErrCorruptHeader},
		{"ErrCorruptData", ErrCorruptData},
		{"ErrNoInputFiles", ErrNoInputFiles},
		{"ErrNoCredentials", ErrNoCredentials},
		{"ErrPasswordMismatch", ErrPasswordMismatch},
		{"ErrInvalidChunkSize", ErrInvalidChunkSize},
		{"ErrChunkSizeTooLarge", ErrChunkSizeTooLarge},
		{"ErrDuplicateKeyfiles", ErrDuplicateKeyfiles},
		{"ErrCommentTooLong", ErrCommentTooLong},
		{"ErrFileNotFound", ErrFileNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatal("sentinel error must not be nil")
			}
		})
	}

	// Callers must distinguish cancellation, authentication and corruption.
	for i := range tests {
		for j := i + 1; j < len(tests); j++ {
			a, b := tests[i], tests[j]
			if errors.Is(a.err, b.err) || errors.Is(b.err, a.err) {
				t.Errorf("%s and %s must remain distinct", a.name, b.name)
			}
		}
	}
}

func TestCryptoError(t *testing.T) {
	baseErr := errors.New("underlying error")
	cryptoErr := NewCryptoError("rand", baseErr)

	if cryptoErr.Error() != "crypto rand: underlying error" {
		t.Errorf("unexpected error message: %s", cryptoErr.Error())
	}

	if !errors.Is(cryptoErr.Unwrap(), baseErr) {
		t.Error("Unwrap should return underlying error")
	}

	// Test with nil error
	cryptoErrNil := NewCryptoError("hkdf", nil)
	if cryptoErrNil.Error() != "crypto hkdf failed" {
		t.Errorf("unexpected error message for nil: %s", cryptoErrNil.Error())
	}
}

func TestFileError(t *testing.T) {
	baseErr := errors.New("permission denied")
	fileErr := NewFileError("open", "/path/to/file", baseErr)

	if fileErr.Error() != "open /path/to/file: permission denied" {
		t.Errorf("unexpected error message: %s", fileErr.Error())
	}

	if !errors.Is(fileErr.Unwrap(), baseErr) {
		t.Error("Unwrap should return underlying error")
	}

	// Test with nil error
	fileErrNil := NewFileError("stat", "/some/path", nil)
	if fileErrNil.Error() != "stat /some/path failed" {
		t.Errorf("unexpected error message for nil: %s", fileErrNil.Error())
	}
}

func TestValidationError(t *testing.T) {
	validErr := NewValidationError("password", "must be at least 8 characters")

	expected := "validation: password: must be at least 8 characters"
	if validErr.Error() != expected {
		t.Errorf("unexpected error message: %s", validErr.Error())
	}
}

func TestHeaderError(t *testing.T) {
	baseErr := errors.New("decode failed")
	headerErr := NewHeaderError("version", baseErr)

	if headerErr.Error() != "header version: decode failed" {
		t.Errorf("unexpected error message: %s", headerErr.Error())
	}

	if !errors.Is(headerErr.Unwrap(), baseErr) {
		t.Error("Unwrap should return underlying error")
	}
}

func TestIs(t *testing.T) {
	wrapped := fmt.Errorf("operation: %w", ErrCancelled)
	if !Is(wrapped, ErrCancelled) {
		t.Error("Is lost the cancellation cause through a wrapper")
	}
	if Is(wrapped, ErrAuthFailed) {
		t.Error("Is confused cancellation with authentication failure")
	}
}

func TestAs(t *testing.T) {
	cryptoErr := NewCryptoError("test", errors.New("test"))

	var target *CryptoError
	if !As(fmt.Errorf("operation: %w", cryptoErr), &target) {
		t.Error("As should find CryptoError")
	}

	if target != cryptoErr {
		t.Error("As did not retain the original typed error")
	}
}

func TestWrap(t *testing.T) {
	baseErr := errors.New("base")
	wrapped := Wrap(baseErr, "context")

	if wrapped.Error() != "context: base" {
		t.Errorf("unexpected wrapped message: %s", wrapped.Error())
	}

	if !errors.Is(wrapped, baseErr) {
		t.Error("Wrap lost its underlying cause")
	}

	// Test with nil
	if Wrap(nil, "context") != nil {
		t.Error("Wrap(nil) should return nil")
	}
}

func TestConvenienceFunctions(t *testing.T) {
	for _, tc := range []struct {
		name  string
		check func(error) bool
		cause error
	}{
		{"cancelled", IsCancelled, ErrCancelled},
		{"authentication", IsAuthFailed, ErrAuthFailed},
		{"header corruption", IsCorrupt, ErrCorruptHeader},
		{"data corruption", IsCorrupt, ErrCorruptData},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.check(fmt.Errorf("operation: %w", tc.cause)) {
				t.Fatal("wrapped cause was not classified")
			}
			if tc.check(nil) || tc.check(ErrFileNotFound) {
				t.Fatal("unrelated error was misclassified")
			}
		})
	}
}
