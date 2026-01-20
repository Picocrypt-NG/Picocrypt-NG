package errors

import (
	"errors"
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
		{"ErrDuplicateKeyfiles", ErrDuplicateKeyfiles},
		{"ErrFileNotFound", ErrFileNotFound},
		{"ErrFileExists", ErrFileExists},
		{"ErrInvalidFormat", ErrInvalidFormat},
		{"ErrVersionMismatch", ErrVersionMismatch},
		{"ErrRandFailure", ErrRandFailure},
		{"ErrKeyDerivation", ErrKeyDerivation},
		{"ErrHKDFFailure", ErrHKDFFailure},
		{"ErrMACFailure", ErrMACFailure},
		{"ErrCipherFailure", ErrCipherFailure},
		{"ErrRSEncode", ErrRSEncode},
		{"ErrRSDecode", ErrRSDecode},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Error("sentinel error should not be nil")
			}
			if tt.err.Error() == "" {
				t.Error("sentinel error should have a message")
			}
		})
	}
}

func TestCryptoError(t *testing.T) {
	baseErr := errors.New("underlying error")
	cryptoErr := NewCryptoError("rand", baseErr)

	if cryptoErr.Error() != "crypto rand: underlying error" {
		t.Errorf("unexpected error message: %s", cryptoErr.Error())
	}

	if cryptoErr.Unwrap() != baseErr {
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

	if fileErr.Unwrap() != baseErr {
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

	if headerErr.Unwrap() != baseErr {
		t.Error("Unwrap should return underlying error")
	}
}

func TestIs(t *testing.T) {
	if !Is(ErrCancelled, ErrCancelled) {
		t.Error("Is should return true for same error")
	}

	if Is(ErrCancelled, ErrAuthFailed) {
		t.Error("Is should return false for different errors")
	}
}

func TestAs(t *testing.T) {
	cryptoErr := NewCryptoError("test", errors.New("test"))

	var target *CryptoError
	if !As(cryptoErr, &target) {
		t.Error("As should find CryptoError")
	}

	if target.Op != "test" {
		t.Errorf("unexpected Op: %s", target.Op)
	}
}

func TestWrap(t *testing.T) {
	baseErr := errors.New("base")
	wrapped := Wrap(baseErr, "context")

	if wrapped.Error() != "context: base" {
		t.Errorf("unexpected wrapped message: %s", wrapped.Error())
	}

	// Test with nil
	if Wrap(nil, "context") != nil {
		t.Error("Wrap(nil) should return nil")
	}
}

func TestConvenienceFunctions(t *testing.T) {
	if !IsCancelled(ErrCancelled) {
		t.Error("IsCancelled should return true for ErrCancelled")
	}

	if IsCancelled(ErrAuthFailed) {
		t.Error("IsCancelled should return false for other errors")
	}

	if !IsAuthFailed(ErrAuthFailed) {
		t.Error("IsAuthFailed should return true for ErrAuthFailed")
	}

	if !IsCorrupt(ErrCorruptHeader) {
		t.Error("IsCorrupt should return true for ErrCorruptHeader")
	}

	if !IsCorrupt(ErrCorruptData) {
		t.Error("IsCorrupt should return true for ErrCorruptData")
	}
}
