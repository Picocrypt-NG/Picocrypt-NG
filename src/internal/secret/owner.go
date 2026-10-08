package secret

// Secret owns a []byte of sensitive key material and zeros it on Close().
//
// Ownership/lifetime contract:
//   - SecretFrom TAKES ownership of the passed slice; the caller MUST NOT retain
//     or mutate it afterwards.
//   - Bytes() returns a BORROW of the live backing array, valid only until
//     Close(). Callers MUST NOT append to it (append may realloc-orphan a copy)
//     nor retain it past Close().
//   - Secret is NOT safe for concurrent use; it is owned by a single operation.
type Secret struct {
	b []byte
}

// SecretFrom takes ownership of b (no copy).
func SecretFrom(b []byte) *Secret { return &Secret{b: b} }

// Bytes returns the live backing array (a borrow). Nil-safe.
func (s *Secret) Bytes() []byte {
	if s == nil {
		return nil
	}
	return s.b
}

// Len reports the secret length. Nil-safe.
func (s *Secret) Len() int {
	if s == nil {
		return 0
	}
	return len(s.b)
}

// Set zeros the current backing array and adopts b.
//
// AUDIT-CRITICAL: the pointer-identity guard skips zeroing when b IS the current
// backing array, so a self-assign (e.g. the no-keyfile v1 decrypt path) does not
// wipe the live key.
func (s *Secret) Set(b []byte) {
	if len(s.b) > 0 && (len(b) == 0 || &b[0] != &s.b[0]) {
		SecureZero(s.b)
	}
	s.b = b
}

// Close zeros the backing array and drops it. Idempotent and nil-safe.
func (s *Secret) Close() {
	if s == nil {
		return
	}
	SecureZero(s.b)
	s.b = nil
}

// String redacts the secret so accidental %v/%s logging never leaks bytes.
func (s *Secret) String() string { return "crypto.Secret([REDACTED])" }
