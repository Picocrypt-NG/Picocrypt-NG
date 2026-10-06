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

// This constructed internal state protects setter/registry cleanup, not a claim
// that user input reaches an empty-to-nonempty transition in a volume operation.
func TestOperationContextEmptySecretReplacementStaysOwnedUntilClose(t *testing.T) {
	for _, field := range []string{"key", "keyfile key", "password"} {
		t.Run(field, func(t *testing.T) {
			ctx := &OperationContext{}
			set := ctx.setKey
			switch field {
			case "keyfile key":
				set = ctx.setKeyfileKey
			case "password":
				set = ctx.setPasswordBytes
			}
			t.Cleanup(func() {
				if err := ctx.Close(); err != nil {
					t.Error(err)
				}
			})
			set(make([]byte, 0))
			next := []byte{8, 9, 10}
			set(next)
			if !bytes.Equal(next, []byte{8, 9, 10}) {
				t.Fatal("replacement wiped the newly adopted live secret")
			}
			if err := ctx.Close(); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(next, []byte{0, 0, 0}) {
				t.Fatal("context cleanup lost custody of the replacement")
			}
		})
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
		t.Fatal("classified input ownership was left with a local caller")
	}
	again, err := ctx.openLegacyDecryptInput()
	if err != nil {
		t.Fatalf("second openLegacyDecryptInput() = %v", err)
	}
	if again != fin {
		t.Fatal("later decrypt step did not reuse the context-owned descriptor")
	}
	if err := ctx.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if _, err := fin.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("pinned descriptor after Close() = %v; want os.ErrClosed", err)
	}
}
