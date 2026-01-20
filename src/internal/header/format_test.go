package header

import (
	"bytes"
	"testing"

	"Picocrypt-NG/internal/encoding"
)

func TestHeaderSize(t *testing.T) {
	// Base header size without comments
	if HeaderSize(0) != BaseHeaderSize {
		t.Errorf("HeaderSize(0) = %d; want %d", HeaderSize(0), BaseHeaderSize)
	}

	// Header with 10 comments
	expected := BaseHeaderSize + 10*3 // Each comment byte is rs1 encoded (1->3)
	if HeaderSize(10) != expected {
		t.Errorf("HeaderSize(10) = %d; want %d", HeaderSize(10), expected)
	}

	// Verify base header size calculation
	// 15 + 15 + 15 + 48 + 96 + 48 + 72 + 192 + 96 + 192 = 789
	expectedBase := 15 + 15 + 15 + 48 + 96 + 48 + 72 + 192 + 96 + 192
	if BaseHeaderSize != expectedBase {
		t.Errorf("BaseHeaderSize = %d; want %d", BaseHeaderSize, expectedBase)
	}
}

func TestFlags(t *testing.T) {
	// Test all flags set
	flags := Flags{
		Paranoid:       true,
		UseKeyfiles:    true,
		KeyfileOrdered: true,
		ReedSolomon:    true,
		Padded:         true,
	}

	b := flags.ToBytes()
	if len(b) != 5 {
		t.Fatalf("ToBytes() length = %d; want 5", len(b))
	}

	for i := range 5 {
		if b[i] != 1 {
			t.Errorf("ToBytes()[%d] = %d; want 1", i, b[i])
		}
	}

	// Round-trip
	parsed := FlagsFromBytes(b)
	if !parsed.Paranoid || !parsed.UseKeyfiles || !parsed.KeyfileOrdered ||
		!parsed.ReedSolomon || !parsed.Padded {
		t.Error("FlagsFromBytes did not preserve all flags")
	}

	// Test no flags set
	flags = Flags{}
	b = flags.ToBytes()
	for i := range 5 {
		if b[i] != 0 {
			t.Errorf("Empty flags ToBytes()[%d] = %d; want 0", i, b[i])
		}
	}
}

func TestFlagsFromBytesShort(t *testing.T) {
	// Should handle short/nil input gracefully
	flags := FlagsFromBytes(nil)
	if flags.Paranoid || flags.UseKeyfiles || flags.KeyfileOrdered ||
		flags.ReedSolomon || flags.Padded {
		t.Error("FlagsFromBytes(nil) should return empty flags")
	}

	flags = FlagsFromBytes([]byte{1, 1}) // Only 2 bytes
	if flags.Paranoid || flags.UseKeyfiles {
		t.Error("FlagsFromBytes with short input should return empty flags")
	}
}

func TestNewVolumeHeader(t *testing.T) {
	salt := make([]byte, SaltSize)
	hkdfSalt := make([]byte, HKDFSaltSize)
	serpentIV := make([]byte, SerpentIVSize)
	nonce := make([]byte, NonceSize)

	h := NewVolumeHeader(salt, hkdfSalt, serpentIV, nonce)

	if h.Version != CurrentVersion {
		t.Errorf("Version = %s; want %s", h.Version, CurrentVersion)
	}

	if len(h.Salt) != SaltSize {
		t.Errorf("Salt length = %d; want %d", len(h.Salt), SaltSize)
	}

	if len(h.KeyHash) != KeyHashSize {
		t.Errorf("KeyHash length = %d; want %d", len(h.KeyHash), KeyHashSize)
	}

	if len(h.KeyfileHash) != KeyfileHashSize {
		t.Errorf("KeyfileHash length = %d; want %d", len(h.KeyfileHash), KeyfileHashSize)
	}

	if len(h.AuthTag) != AuthTagSize {
		t.Errorf("AuthTag length = %d; want %d", len(h.AuthTag), AuthTagSize)
	}
}

func TestIsLegacyV1(t *testing.T) {
	tests := []struct {
		version  string
		expected bool
	}{
		{"v2.00", false},
		{"v2.02", false},
		{"v1.00", true},
		{"v1.34", true},
		{"v1.99", true},
		{"", false},
		{"v", false},
	}

	for _, tc := range tests {
		h := &VolumeHeader{Version: tc.version}
		if h.IsLegacyV1() != tc.expected {
			t.Errorf("IsLegacyV1(%q) = %v; want %v", tc.version, h.IsLegacyV1(), tc.expected)
		}
	}
}

func TestNewCodecs(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	codecs := NewCodecs(rs)
	if codecs.RSCodecs != rs {
		t.Error("NewCodecs did not wrap RSCodecs correctly")
	}
}

func TestHeaderWriteReadRoundtrip(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	// Create a header with known values
	original := &VolumeHeader{
		Version:  CurrentVersion,
		Comments: "Test comment",
		Flags: Flags{
			Paranoid:       true,
			UseKeyfiles:    true,
			KeyfileOrdered: false,
			ReedSolomon:    true,
			Padded:         false,
		},
		Salt:        bytes.Repeat([]byte{0x01}, SaltSize),
		HKDFSalt:    bytes.Repeat([]byte{0x02}, HKDFSaltSize),
		SerpentIV:   bytes.Repeat([]byte{0x03}, SerpentIVSize),
		Nonce:       bytes.Repeat([]byte{0x04}, NonceSize),
		KeyHash:     bytes.Repeat([]byte{0x05}, KeyHashSize),
		KeyfileHash: bytes.Repeat([]byte{0x06}, KeyfileHashSize),
		AuthTag:     bytes.Repeat([]byte{0x07}, AuthTagSize),
	}

	// Write header
	var buf bytes.Buffer
	writer := NewWriter(&buf, rs)
	n, err := writer.WriteHeader(original)
	if err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}

	expectedSize := HeaderSize(len(original.Comments))
	if n != expectedSize {
		t.Errorf("WriteHeader wrote %d bytes; want %d", n, expectedSize)
	}

	// Read header back
	reader := NewReader(&buf, rs)
	result, err := reader.ReadHeader()
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	if result.DecodeError != nil {
		t.Errorf("ReadHeader had decode errors: %v", result.DecodeError)
	}

	// Compare fields
	parsed := result.Header
	if parsed.Version != original.Version {
		t.Errorf("Version = %s; want %s", parsed.Version, original.Version)
	}

	if parsed.Comments != original.Comments {
		t.Errorf("Comments = %s; want %s", parsed.Comments, original.Comments)
	}

	if parsed.Flags.Paranoid != original.Flags.Paranoid {
		t.Errorf("Paranoid = %v; want %v", parsed.Flags.Paranoid, original.Flags.Paranoid)
	}

	if !bytes.Equal(parsed.Salt, original.Salt) {
		t.Error("Salt mismatch")
	}

	if !bytes.Equal(parsed.HKDFSalt, original.HKDFSalt) {
		t.Error("HKDFSalt mismatch")
	}

	if !bytes.Equal(parsed.SerpentIV, original.SerpentIV) {
		t.Error("SerpentIV mismatch")
	}

	if !bytes.Equal(parsed.Nonce, original.Nonce) {
		t.Error("Nonce mismatch")
	}
}

func TestHeaderWithEmptyComments(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	original := NewVolumeHeader(
		bytes.Repeat([]byte{0x01}, SaltSize),
		bytes.Repeat([]byte{0x02}, HKDFSaltSize),
		bytes.Repeat([]byte{0x03}, SerpentIVSize),
		bytes.Repeat([]byte{0x04}, NonceSize),
	)
	original.Comments = ""

	var buf bytes.Buffer
	writer := NewWriter(&buf, rs)
	if _, err := writer.WriteHeader(original); err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}

	reader := NewReader(&buf, rs)
	result, err := reader.ReadHeader()
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	if result.Header.Comments != "" {
		t.Errorf("Expected empty comments, got %q", result.Header.Comments)
	}
}

func TestHeaderWithLongComments(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	longComment := bytes.Repeat([]byte("X"), 1000) // 1000 character comment

	original := NewVolumeHeader(
		bytes.Repeat([]byte{0x01}, SaltSize),
		bytes.Repeat([]byte{0x02}, HKDFSaltSize),
		bytes.Repeat([]byte{0x03}, SerpentIVSize),
		bytes.Repeat([]byte{0x04}, NonceSize),
	)
	original.Comments = string(longComment)

	var buf bytes.Buffer
	writer := NewWriter(&buf, rs)
	if _, err := writer.WriteHeader(original); err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}

	reader := NewReader(&buf, rs)
	result, err := reader.ReadHeader()
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	if result.Header.Comments != string(longComment) {
		t.Errorf("Comments length = %d; want %d", len(result.Header.Comments), len(longComment))
	}
}

func TestHeaderWithSpecialCharComments(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	// Test Unicode, newlines, special chars
	specialComment := "Hello 世界!\nLine2\tTab\x00Null"

	original := NewVolumeHeader(
		bytes.Repeat([]byte{0x01}, SaltSize),
		bytes.Repeat([]byte{0x02}, HKDFSaltSize),
		bytes.Repeat([]byte{0x03}, SerpentIVSize),
		bytes.Repeat([]byte{0x04}, NonceSize),
	)
	original.Comments = specialComment

	var buf bytes.Buffer
	writer := NewWriter(&buf, rs)
	if _, err := writer.WriteHeader(original); err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}

	reader := NewReader(&buf, rs)
	result, err := reader.ReadHeader()
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	if result.Header.Comments != specialComment {
		t.Errorf("Comments = %q; want %q", result.Header.Comments, specialComment)
	}
}

func TestV2HeaderMAC(t *testing.T) {
	subkey := bytes.Repeat([]byte{0x42}, 64)
	keyfileHash := make([]byte, KeyfileHashSize)

	h := &VolumeHeader{
		Version:   CurrentVersion,
		Comments:  "Test",
		Flags:     Flags{Paranoid: true},
		Salt:      make([]byte, SaltSize),
		HKDFSalt:  make([]byte, HKDFSaltSize),
		SerpentIV: make([]byte, SerpentIVSize),
		Nonce:     make([]byte, NonceSize),
		KeyHash:   make([]byte, KeyHashSize),
	}

	// Compute MAC
	mac1 := ComputeV2HeaderMAC(subkey, h, keyfileHash)
	if len(mac1) != 64 {
		t.Errorf("MAC length = %d; want 64", len(mac1))
	}

	// Same inputs should produce same MAC
	mac2 := ComputeV2HeaderMAC(subkey, h, keyfileHash)
	if !bytes.Equal(mac1, mac2) {
		t.Error("Same inputs produced different MACs")
	}

	// Different subkey should produce different MAC
	differentSubkey := bytes.Repeat([]byte{0x43}, 64)
	mac3 := ComputeV2HeaderMAC(differentSubkey, h, keyfileHash)
	if bytes.Equal(mac1, mac3) {
		t.Error("Different subkeys produced same MAC")
	}

	// Different header field should produce different MAC
	h.Comments = "Different"
	mac4 := ComputeV2HeaderMAC(subkey, h, keyfileHash)
	if bytes.Equal(mac1, mac4) {
		t.Error("Different comments produced same MAC")
	}
}

func TestV1KeyHash(t *testing.T) {
	key := []byte("test-key")

	hash1 := ComputeV1KeyHash(key)
	if len(hash1) != 64 {
		t.Errorf("Hash length = %d; want 64", len(hash1))
	}

	// Same key should produce same hash
	hash2 := ComputeV1KeyHash(key)
	if !bytes.Equal(hash1, hash2) {
		t.Error("Same key produced different hashes")
	}

	// Different key should produce different hash
	hash3 := ComputeV1KeyHash([]byte("different-key"))
	if bytes.Equal(hash1, hash3) {
		t.Error("Different keys produced same hash")
	}
}

func TestVerifyV2Header(t *testing.T) {
	subkey := bytes.Repeat([]byte{0x42}, 64)
	keyfileHash := make([]byte, KeyfileHashSize)

	h := &VolumeHeader{
		Version:   CurrentVersion,
		Comments:  "Test",
		Flags:     Flags{},
		Salt:      make([]byte, SaltSize),
		HKDFSalt:  make([]byte, HKDFSaltSize),
		SerpentIV: make([]byte, SerpentIVSize),
		Nonce:     make([]byte, NonceSize),
	}

	// Set the correct MAC
	h.KeyHash = ComputeV2HeaderMAC(subkey, h, keyfileHash)

	// Verify should pass
	result := VerifyV2Header(subkey, h, keyfileHash)
	if !result.Valid {
		t.Error("VerifyV2Header failed for correct MAC")
	}

	// Modify header, verify should fail
	h.Comments = "Modified"
	result = VerifyV2Header(subkey, h, keyfileHash)
	if result.Valid {
		t.Error("VerifyV2Header passed for modified header")
	}
}

func TestVerifyV1Header(t *testing.T) {
	key := []byte("test-password-key")

	h := &VolumeHeader{
		KeyHash: ComputeV1KeyHash(key),
	}

	// Verify should pass with correct key
	result := VerifyV1Header(key, h)
	if !result.Valid {
		t.Error("VerifyV1Header failed for correct key")
	}

	// Verify should fail with wrong key
	result = VerifyV1Header([]byte("wrong-key"), h)
	if result.Valid {
		t.Error("VerifyV1Header passed for wrong key")
	}
}

func TestVerifyKeyfileHash(t *testing.T) {
	hash := bytes.Repeat([]byte{0x42}, 32)

	if !VerifyKeyfileHash(hash, hash) {
		t.Error("VerifyKeyfileHash failed for matching hashes")
	}

	differentHash := bytes.Repeat([]byte{0x43}, 32)
	if VerifyKeyfileHash(hash, differentHash) {
		t.Error("VerifyKeyfileHash passed for different hashes")
	}
}

func TestAuthErrors(t *testing.T) {
	// Test password error
	pwdErr := NewPasswordError()
	if !pwdErr.PasswordIncorrect {
		t.Error("NewPasswordError did not set PasswordIncorrect")
	}
	if pwdErr.Error() != "The provided password is incorrect" {
		t.Errorf("Unexpected error message: %s", pwdErr.Error())
	}

	// Test v2 password/tamper error
	v2Err := NewV2PasswordOrTamperError()
	if !v2Err.PasswordIncorrect {
		t.Error("NewV2PasswordOrTamperError did not set PasswordIncorrect")
	}

	// Test keyfile error (unordered)
	kfErr := NewKeyfileError(false)
	if !kfErr.KeyfileIncorrect {
		t.Error("NewKeyfileError did not set KeyfileIncorrect")
	}
	if kfErr.KeyfileOrdered {
		t.Error("NewKeyfileError(false) should not set KeyfileOrdered")
	}
	if kfErr.Error() != "Incorrect keyfiles" {
		t.Errorf("Unexpected error message: %s", kfErr.Error())
	}

	// Test keyfile error (ordered)
	kfOrdErr := NewKeyfileError(true)
	if !kfOrdErr.KeyfileOrdered {
		t.Error("NewKeyfileError(true) did not set KeyfileOrdered")
	}
	if kfOrdErr.Error() != "Incorrect keyfiles or ordering" {
		t.Errorf("Unexpected error message: %s", kfOrdErr.Error())
	}
}
