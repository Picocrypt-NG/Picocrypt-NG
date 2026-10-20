package cli

import (
	"Picocrypt-NG/internal/secret"
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestReadOwnedPasswordClearsPartialReadFailure(t *testing.T) {
	readErr := errors.New("synthetic password read failure")
	for _, length := range []int{0, 2} {
		t.Run(fmt.Sprintf("length %d", length), func(t *testing.T) {
			storage := []byte{'p', 'w', 'x', 'x'}
			got, err := readOwnedPassword(func() ([]byte, error) { return storage[:length], readErr })
			if got != nil || !errors.Is(err, readErr) {
				t.Errorf("partial read failure = (%v, %v), want nil and original error", got != nil, err)
			}
			assertPasswordStorageCleared(t, storage)
		})
	}
}

func TestReadOwnedPasswordClearsDeletedTailBeforeTransfer(t *testing.T) {
	for _, length := range []int{0, 2} {
		t.Run(fmt.Sprintf("length %d", length), func(t *testing.T) {
			storage := []byte{'p', 'w', 'x', 'x'}
			got, err := readOwnedPassword(func() ([]byte, error) { return storage[:length], nil })
			if err != nil {
				t.Fatalf("readOwnedPassword() error = %v", err)
			}
			if len(got) != length || cap(got) != len(storage) || &got[:cap(got)][0] != &storage[0] {
				t.Fatal("password read did not transfer the original owned allocation")
			}
			if length > 0 && !bytes.Equal(got, []byte{'p', 'w'}) {
				t.Fatal("password read changed the successful password bytes")
			}
			assertPasswordStorageCleared(t, storage[length:])
		})
	}
}

func TestReadPasswordLineDiscardsPartialReadFailure(t *testing.T) {
	readErr := errors.New("synthetic password read failure")
	reader := io.MultiReader(strings.NewReader("pw"), passwordFailureReader{readErr})
	got, err := readPasswordLine(bufio.NewReader(reader))
	if got != nil || !errors.Is(err, readErr) {
		t.Fatalf("partial line read failure = (%v, %v), want nil and original error", got != nil, err)
	}
}

type passwordFailureReader struct{ err error }

func (r passwordFailureReader) Read([]byte) (int, error) { return 0, r.err }

func TestReadPasswordInteractiveClearsOwnedBuffersOnFailure(t *testing.T) {
	readErr := errors.New("synthetic password read failure")
	tests := []struct {
		name          string
		passwordBytes int
		firstErr      error
		confirmErr    error
		wantErr       error
	}{
		{name: "mismatch", passwordBytes: 3, wantErr: ErrPasswordMismatch},
		{name: "first partial read error", passwordBytes: 3, firstErr: readErr, wantErr: readErr},
		{name: "confirmation partial read error", passwordBytes: 3, confirmErr: readErr, wantErr: readErr},
		{name: "empty after backspace", passwordBytes: 0, wantErr: ErrPasswordEmpty},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary := []byte{'o', 'n', 'e', 'x', 'x'}
			confirmation := []byte{'t', 'w', 'o', 'y', 'y'}
			readCount := 0
			got, err := readPasswordInteractive(true, false, func(string) ([]byte, error) {
				readCount++
				if readCount == 1 {
					return primary[:tt.passwordBytes], tt.firstErr
				}
				return confirmation[:3], tt.confirmErr
			})
			if got != nil || !errors.Is(err, tt.wantErr) {
				t.Fatalf("interactive failure = (%v, %v), want nil and %v", got != nil, err, tt.wantErr)
			}
			assertPasswordStorageCleared(t, primary)
			if readCount > 1 {
				assertPasswordStorageCleared(t, confirmation)
			}
		})
	}
}

func TestReadPasswordInteractiveTransfersPrimaryAndClearsConfirmation(t *testing.T) {
	primary := []byte{'p', 'w', 0, 0}
	confirmation := []byte{'p', 'w', 'x', 'x'}
	readCount := 0
	got, err := readPasswordInteractive(true, false, func(string) ([]byte, error) {
		readCount++
		if readCount == 1 {
			return primary[:2], nil
		}
		return confirmation[:2], nil
	})
	if err != nil {
		t.Fatalf("readPasswordInteractive() error = %v", err)
	}
	if !bytes.Equal(got, []byte{'p', 'w'}) || &got[0] != &primary[0] {
		t.Fatal("successful password did not transfer the intact primary allocation")
	}
	assertPasswordStorageCleared(t, confirmation)
	secret.SecureZero(got)
	assertPasswordStorageCleared(t, primary)
}

func TestReadPasswordInteractiveAllowsEmptySanitizedPassword(t *testing.T) {
	storage := []byte{'p', 'w', 'x', 'x'}
	got, err := readPasswordInteractive(true, true, func(prompt string) ([]byte, error) {
		if prompt != "Password: " {
			t.Fatal("empty password unexpectedly requested confirmation")
		}
		return readOwnedPassword(func() ([]byte, error) { return storage[:0], nil })
	})
	if err != nil || len(got) != 0 || cap(got) != len(storage) {
		t.Fatalf("allowed empty password = (length %d, capacity %d, %v)", len(got), cap(got), err)
	}
	if &got[:cap(got)][0] != &storage[0] {
		t.Fatal("empty password did not transfer the original allocation")
	}
	assertPasswordStorageCleared(t, storage)
}

func assertPasswordStorageCleared(t *testing.T, storage []byte) {
	t.Helper()
	for i, b := range storage {
		if b != 0 {
			t.Errorf("owned password byte %d retained sensitive data", i)
		}
	}
}
