package volume

import (
	"Picocrypt-NG/internal/crypto"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Tripwire: every *crypto.Secret field on OperationContext must be in this set.
// Adding/removing one without wiring it through a setter + ctx.secrets registry +
// Close() (and updating this list) fails the build's tests on purpose.
func TestOperationContextSecretFieldsAreManaged(t *testing.T) {
	want := map[string]bool{"Key": true, "KeyfileKey": true, "passwordBytes": true}
	got := map[string]bool{}
	secretPtr := reflect.TypeOf((*crypto.Secret)(nil))
	typ := reflect.TypeOf(OperationContext{})
	for i := range typ.NumField() {
		if typ.Field(i).Type == secretPtr {
			got[typ.Field(i).Name] = true
		}
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("secret fields changed: want %v got %v — wire any new *crypto.Secret "+
			"field through a setter + ctx.secrets + Close(), then update this list", want, got)
	}
}

func TestOperationContextCloseZerosAllSecrets(t *testing.T) {
	ctx := &OperationContext{}
	ctx.setKey(bytes.Repeat([]byte{0xAA}, 32))
	ctx.setKeyfileKey(bytes.Repeat([]byte{0xBB}, 32))
	ctx.setPasswordBytes(bytes.Repeat([]byte{0xCC}, 16))

	// snapshot backing arrays (still alias after Close, which zeros in place)
	snaps := map[string][]byte{
		"Key": ctx.Key.Bytes(), "KeyfileKey": ctx.KeyfileKey.Bytes(), "passwordBytes": ctx.passwordBytes.Bytes(),
	}
	ctx.Close()
	for name, b := range snaps {
		for i, x := range b {
			if x != 0 {
				t.Fatalf("%s byte %d not zeroed after Close: %d", name, i, x)
			}
		}
	}
}

func TestOperationContextClosesPinnedDecryptInput(t *testing.T) {
	input := filepath.Join(t.TempDir(), "legacy.pcv")
	if err := os.WriteFile(input, []byte("legacy-eligible input"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	ctx := NewDecryptContext(t.Context(), &DecryptRequest{InputFile: input})
	fin, err := os.Open(input)
	if err != nil {
		t.Fatalf("open input: %v", err)
	}
	if err := ctx.pinLegacyDecryptInput(fin, true); err != nil {
		_ = fin.Close()
		t.Fatalf("pinLegacyDecryptInput() = %v", err)
	}
	routed, err := ctx.openLegacyDecryptInput()
	if err != nil {
		t.Fatalf("openLegacyDecryptInput() = %v", err)
	}
	if routed != fin {
		t.Fatal("classified input ownership was left with a phase-local caller")
	}
	again, err := ctx.openLegacyDecryptInput()
	if err != nil {
		t.Fatalf("second openLegacyDecryptInput() = %v", err)
	}
	if again != fin {
		t.Fatal("later decrypt phase did not reuse the context-owned descriptor")
	}
	if err := ctx.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if _, err := fin.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("pinned descriptor after Close() = %v; want os.ErrClosed", err)
	}
}
