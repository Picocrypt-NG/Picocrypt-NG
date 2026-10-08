package secret

import (
	"bytes"
	"testing"
)

func TestSecretCloseZeros(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	s := SecretFrom(b)
	if s.Len() != 4 || string(s.Bytes()) != string([]byte{1, 2, 3, 4}) {
		t.Fatal("Secret did not adopt bytes")
	}
	s.Close()
	for i, x := range b { // b still aliases the (now zeroed) backing array
		if x != 0 {
			t.Fatalf("byte %d not zeroed: %d", i, x)
		}
	}
	if s.Bytes() != nil || s.Len() != 0 {
		t.Fatal("closed Secret must report nil/0")
	}
}

func TestSecretCloseIdempotentAndNilSafe(t *testing.T) {
	var nilS *Secret
	nilS.Close() // must not panic
	if nilS.Bytes() != nil {
		t.Fatal("nil Secret.Bytes must be nil")
	}
	if nilS.Len() != 0 {
		t.Fatal("nil Secret.Len must be 0")
	}
	s := SecretFrom([]byte{9})
	s.Close()
	s.Close() // double close must not panic
}

func TestSecretSetWipesOldButNotSelfAssign(t *testing.T) {
	old := []byte{7, 7, 7, 7}
	s := SecretFrom(old)
	next := []byte{8, 8, 8, 8}
	s.Set(next)
	for i, x := range old {
		if x != 0 {
			t.Fatalf("old backing array byte %d not wiped: %d", i, x)
		}
	}
	// self-assign: setting the SAME backing array must NOT wipe the live key
	live := s.Bytes()
	want := append([]byte(nil), live...)
	s.Set(live)
	if !bytes.Equal(live, want) {
		t.Fatal("self-assign changed the live key — guard broken")
	}
}

func TestSecretSetAdoptsAfterNonNilEmptyBuffer(t *testing.T) {
	s := SecretFrom(make([]byte, 0))
	defer s.Close()
	next := []byte{8, 9, 10}
	s.Set(next)
	if !bytes.Equal(s.Bytes(), []byte{8, 9, 10}) || &s.Bytes()[0] != &next[0] {
		t.Fatal("empty owner did not adopt the replacement buffer")
	}
	s.Close()
	if !bytes.Equal(next, []byte{0, 0, 0}) || s.Bytes() != nil {
		t.Fatal("closing the owner did not wipe and release the replacement")
	}
}

func TestSecretSetThroughEmptyBufferPreservesCleanup(t *testing.T) {
	old := []byte{7, 7, 7}
	s := SecretFrom(old)
	defer s.Close()
	s.Set(make([]byte, 0))
	if !bytes.Equal(old, []byte{0, 0, 0}) || s.Bytes() == nil || s.Len() != 0 {
		t.Fatal("empty replacement did not wipe the predecessor and remain adopted")
	}
	next := []byte{8, 9, 10}
	s.Set(next)
	if !bytes.Equal(s.Bytes(), []byte{8, 9, 10}) || &s.Bytes()[0] != &next[0] {
		t.Fatal("owner did not adopt the nonempty replacement after an empty value")
	}
	s.Close()
	if !bytes.Equal(next, []byte{0, 0, 0}) || s.Bytes() != nil {
		t.Fatal("closing the owner did not wipe and release the final replacement")
	}
}

func TestSecretStringRedacts(t *testing.T) {
	s := SecretFrom([]byte("topsecret"))
	defer s.Close()
	if got := s.String(); got != "crypto.Secret([REDACTED])" {
		t.Fatalf("String must redact, got %q", got)
	}
}
