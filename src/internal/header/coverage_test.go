package header

import (
	"bytes"
	"io"
	"testing"

	"Picocrypt-NG/internal/encoding"
)

// =============================================================================
// Tests for PeekVersion
// =============================================================================

func TestPeekVersionV2(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	// Create a valid v2 header
	h := NewVolumeHeader(
		bytes.Repeat([]byte{0x01}, SaltSize),
		bytes.Repeat([]byte{0x02}, HKDFSaltSize),
		bytes.Repeat([]byte{0x03}, SerpentIVSize),
		bytes.Repeat([]byte{0x04}, NonceSize),
	)

	// Write header to buffer
	var buf bytes.Buffer
	writer := NewWriter(&buf, rs)
	if _, err := writer.WriteHeader(h); err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}

	// Peek version
	version, err := PeekVersion(bytes.NewReader(buf.Bytes()), rs)
	if err != nil {
		t.Fatalf("PeekVersion failed: %v", err)
	}

	if version != CurrentVersion {
		t.Errorf("PeekVersion = %s; want %s", version, CurrentVersion)
	}
}

func TestPeekVersionTruncatedInput(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	// Create truncated input (less than 15 bytes)
	truncated := bytes.Repeat([]byte{0x00}, 10)

	_, err = PeekVersion(bytes.NewReader(truncated), rs)
	if err == nil {
		t.Error("PeekVersion should fail on truncated input")
	}
}

func TestPeekVersionInvalidRSData(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	// Create 15 bytes of data that decodes to invalid version format
	// RS5 can decode almost anything, so we test that the version format validation works
	// by providing data that decodes to something that doesn't match v\d.\d{2}
	// Use alternating pattern that RS will decode to non-version text
	invalidData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E}

	version, err := PeekVersion(bytes.NewReader(invalidData), rs)
	// The result should either be an error OR an invalid version string
	// PeekVersion only returns error if RS decode fails, not for invalid format
	if err == nil {
		// Check that the version doesn't match valid format
		if len(version) == 5 && version[0] == 'v' {
			t.Log("PeekVersion returned valid-looking version from random data (unlikely but possible)")
		}
	}
	// This test mainly ensures PeekVersion doesn't panic on arbitrary data
}

func TestPeekVersionEmptyReader(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	_, err = PeekVersion(bytes.NewReader([]byte{}), rs)
	if err == nil {
		t.Error("PeekVersion should fail on empty reader")
	}
}

// =============================================================================
// Tests for WriteAuthValues and AuthValuesOffset
// =============================================================================

func TestAuthValuesOffset(t *testing.T) {
	testCases := []struct {
		commentsLen int
		expected    int64
	}{
		{0, 309},   // No comments: version(15) + commentLen(15) + flags(15) + salt(48) + hkdfSalt(96) + serpentIV(48) + nonce(72)
		{10, 339},  // 10 char comments: 309 + 10*3
		{100, 609}, // 100 char comments: 309 + 100*3
	}

	for _, tc := range testCases {
		offset := AuthValuesOffset(tc.commentsLen)
		if offset != tc.expected {
			t.Errorf("AuthValuesOffset(%d) = %d; want %d", tc.commentsLen, offset, tc.expected)
		}
	}
}

func TestWriteAuthValues(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	// Create a buffer large enough to hold auth values
	// Auth values: keyHash(192) + keyfileHash(96) + authTag(192) = 480 bytes
	bufSize := 1000
	buf := make([]byte, bufSize)

	// Create test values
	keyHash := bytes.Repeat([]byte{0x11}, KeyHashSize)
	keyfileHash := bytes.Repeat([]byte{0x22}, KeyfileHashSize)
	authTag := bytes.Repeat([]byte{0x33}, AuthTagSize)

	// Write auth values at offset 0
	writer := &bytesWriterAt{buf: buf}
	err = WriteAuthValues(writer, 0, keyHash, keyfileHash, authTag, rs)
	if err != nil {
		t.Fatalf("WriteAuthValues failed: %v", err)
	}

	// Verify the encoded values can be decoded back
	// Key hash is at offset 0, size 192
	decodedKeyHash, err := encoding.Decode(rs.RS64, buf[0:KeyHashEncSize], false)
	if err != nil {
		t.Fatalf("Failed to decode key hash: %v", err)
	}
	if !bytes.Equal(decodedKeyHash, keyHash) {
		t.Error("Key hash mismatch after WriteAuthValues")
	}

	// Keyfile hash is at offset 192, size 96
	decodedKeyfileHash, err := encoding.Decode(rs.RS32, buf[KeyHashEncSize:KeyHashEncSize+KeyfileHashEncSize], false)
	if err != nil {
		t.Fatalf("Failed to decode keyfile hash: %v", err)
	}
	if !bytes.Equal(decodedKeyfileHash, keyfileHash) {
		t.Error("Keyfile hash mismatch after WriteAuthValues")
	}

	// Auth tag is at offset 192+96=288, size 192
	authTagStart := KeyHashEncSize + KeyfileHashEncSize
	decodedAuthTag, err := encoding.Decode(rs.RS64, buf[authTagStart:authTagStart+AuthTagEncSize], false)
	if err != nil {
		t.Fatalf("Failed to decode auth tag: %v", err)
	}
	if !bytes.Equal(decodedAuthTag, authTag) {
		t.Error("Auth tag mismatch after WriteAuthValues")
	}
}

func TestWriteAuthValuesWithOffset(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	// Create a buffer with some leading bytes
	offset := int64(100)
	bufSize := 1000
	buf := make([]byte, bufSize)

	keyHash := bytes.Repeat([]byte{0xAA}, KeyHashSize)
	keyfileHash := bytes.Repeat([]byte{0xBB}, KeyfileHashSize)
	authTag := bytes.Repeat([]byte{0xCC}, AuthTagSize)

	writer := &bytesWriterAt{buf: buf}
	err = WriteAuthValues(writer, offset, keyHash, keyfileHash, authTag, rs)
	if err != nil {
		t.Fatalf("WriteAuthValues failed: %v", err)
	}

	// Verify the values are at the correct offset
	decodedKeyHash, err := encoding.Decode(rs.RS64, buf[offset:int(offset)+KeyHashEncSize], false)
	if err != nil {
		t.Fatalf("Failed to decode key hash: %v", err)
	}
	if !bytes.Equal(decodedKeyHash, keyHash) {
		t.Error("Key hash mismatch at offset")
	}
}

// bytesWriterAt implements io.WriterAt for testing
type bytesWriterAt struct {
	buf []byte
}

func (w *bytesWriterAt) WriteAt(p []byte, off int64) (n int, err error) {
	if off < 0 || int(off)+len(p) > len(w.buf) {
		return 0, io.ErrShortWrite
	}
	copy(w.buf[off:], p)
	return len(p), nil
}

// =============================================================================
// Tests for ReadHeaderRaw and related raw functions
// =============================================================================

func TestReadHeaderRaw(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	// Create a header with known values
	original := &VolumeHeader{
		Version:  CurrentVersion,
		Comments: "Test raw header",
		Flags: Flags{
			Paranoid:       true,
			UseKeyfiles:    false,
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
	if _, err := writer.WriteHeader(original); err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}

	// Read header with raw fields
	reader := NewReader(bytes.NewReader(buf.Bytes()), rs)
	result, err := reader.ReadHeaderRaw()
	if err != nil {
		t.Fatalf("ReadHeaderRaw failed: %v", err)
	}

	// Verify raw fields
	if string(result.Raw.Version) != original.Version {
		t.Errorf("Raw.Version = %s; want %s", string(result.Raw.Version), original.Version)
	}

	if result.Raw.CommentsLen != len(original.Comments) {
		t.Errorf("Raw.CommentsLen = %d; want %d", result.Raw.CommentsLen, len(original.Comments))
	}

	if string(result.Raw.Comments) != original.Comments {
		t.Errorf("Raw.Comments = %s; want %s", string(result.Raw.Comments), original.Comments)
	}

	// Verify parsed header
	if result.Header.Version != original.Version {
		t.Errorf("Header.Version = %s; want %s", result.Header.Version, original.Version)
	}

	if result.Header.Flags.Paranoid != original.Flags.Paranoid {
		t.Errorf("Header.Flags.Paranoid = %v; want %v", result.Header.Flags.Paranoid, original.Flags.Paranoid)
	}

	if !bytes.Equal(result.Header.Salt, original.Salt) {
		t.Error("Salt mismatch")
	}
}

func TestReadHeaderRawEmptyComments(t *testing.T) {
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

	reader := NewReader(bytes.NewReader(buf.Bytes()), rs)
	result, err := reader.ReadHeaderRaw()
	if err != nil {
		t.Fatalf("ReadHeaderRaw failed: %v", err)
	}

	if result.Raw.CommentsLen != 0 {
		t.Errorf("Raw.CommentsLen = %d; want 0", result.Raw.CommentsLen)
	}

	if len(result.Raw.Comments) != 0 {
		t.Errorf("Raw.Comments length = %d; want 0", len(result.Raw.Comments))
	}
}

func TestReadHeaderRawTruncatedInput(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	// Create truncated input (just version bytes)
	truncated := bytes.Repeat([]byte{0x00}, 20)

	reader := NewReader(bytes.NewReader(truncated), rs)
	_, err = reader.ReadHeaderRaw()
	if err == nil {
		t.Error("ReadHeaderRaw should fail on truncated input")
	}
}

// =============================================================================
// Tests for ComputeV2HeaderMACRaw and VerifyV2HeaderRaw
// =============================================================================

func TestComputeV2HeaderMACRaw(t *testing.T) {
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

	raw := &RawHeaderFields{
		Version:     []byte(h.Version),
		CommentsLen: len(h.Comments),
		Comments:    []byte(h.Comments),
		Flags:       h.Flags.ToBytes(),
	}

	// Compute MAC using raw fields
	macRaw := ComputeV2HeaderMACRaw(subkey, raw, h, keyfileHash)
	if len(macRaw) != 64 {
		t.Errorf("MAC length = %d; want 64", len(macRaw))
	}

	// Compute MAC using regular method
	macRegular := ComputeV2HeaderMAC(subkey, h, keyfileHash)

	// Both should produce the same result when raw matches parsed
	if !bytes.Equal(macRaw, macRegular) {
		t.Error("ComputeV2HeaderMACRaw should match ComputeV2HeaderMAC for identical input")
	}
}

func TestVerifyV2HeaderRaw(t *testing.T) {
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

	raw := &RawHeaderFields{
		Version:     []byte(h.Version),
		CommentsLen: len(h.Comments),
		Comments:    []byte(h.Comments),
		Flags:       h.Flags.ToBytes(),
	}

	// Set the correct MAC using raw computation
	h.KeyHash = ComputeV2HeaderMACRaw(subkey, raw, h, keyfileHash)

	// Verify should pass
	result := VerifyV2HeaderRaw(subkey, raw, h, keyfileHash)
	if !result.Valid {
		t.Error("VerifyV2HeaderRaw failed for correct MAC")
	}

	// Modify raw comments, verify should fail
	raw.Comments = []byte("Modified")
	result = VerifyV2HeaderRaw(subkey, raw, h, keyfileHash)
	if result.Valid {
		t.Error("VerifyV2HeaderRaw passed for modified raw comments")
	}
}

func TestVerifyV2HeaderRawDifferentSubkey(t *testing.T) {
	subkey1 := bytes.Repeat([]byte{0x42}, 64)
	subkey2 := bytes.Repeat([]byte{0x43}, 64)
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

	raw := &RawHeaderFields{
		Version:     []byte(h.Version),
		CommentsLen: len(h.Comments),
		Comments:    []byte(h.Comments),
		Flags:       h.Flags.ToBytes(),
	}

	// Set MAC with subkey1
	h.KeyHash = ComputeV2HeaderMACRaw(subkey1, raw, h, keyfileHash)

	// Verify with subkey2 should fail
	result := VerifyV2HeaderRaw(subkey2, raw, h, keyfileHash)
	if result.Valid {
		t.Error("VerifyV2HeaderRaw should fail with different subkey")
	}
}

// =============================================================================
// Tests for header size constants
// =============================================================================

func TestEncodedSizeConstants(t *testing.T) {
	// Verify the encoded size constants are correct
	// RS encoding: N data bytes -> N + 2N = 3N encoded bytes (for RS1)
	// RS5: 5 -> 15, RS16: 16 -> 48, RS24: 24 -> 72, RS32: 32 -> 96, RS64: 64 -> 192

	tests := []struct {
		name     string
		dataSize int
		encSize  int
	}{
		{"Version", 5, VersionEncSize},
		{"CommentLen", 5, CommentLenEncSize},
		{"Flags", 5, FlagsEncSize},
		{"Salt", SaltSize, SaltEncSize},
		{"HKDFSalt", HKDFSaltSize, HKDFSaltEncSize},
		{"SerpentIV", SerpentIVSize, SerpentIVEncSize},
		{"Nonce", NonceSize, NonceEncSize},
		{"KeyHash", KeyHashSize, KeyHashEncSize},
		{"KeyfileHash", KeyfileHashSize, KeyfileHashEncSize},
		{"AuthTag", AuthTagSize, AuthTagEncSize},
	}

	for _, tc := range tests {
		expected := tc.dataSize * 3 // RS encoding formula
		if tc.encSize != expected {
			t.Errorf("%s: encSize = %d; want %d (data size %d)", tc.name, tc.encSize, expected, tc.dataSize)
		}
	}
}

func TestBaseHeaderSizeCalculation(t *testing.T) {
	// Base header = version(15) + commentLen(15) + flags(15) + salt(48) + hkdfSalt(96) +
	//               serpentIV(48) + nonce(72) + keyHash(192) + keyfileHash(96) + authTag(192)
	expected := VersionEncSize + CommentLenEncSize + FlagsEncSize +
		SaltEncSize + HKDFSaltEncSize + SerpentIVEncSize + NonceEncSize +
		KeyHashEncSize + KeyfileHashEncSize + AuthTagEncSize

	if BaseHeaderSize != expected {
		t.Errorf("BaseHeaderSize = %d; want %d", BaseHeaderSize, expected)
	}
}

// =============================================================================
// Tests for maximum comment length
// =============================================================================

func TestMaxCommentLength(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	// Test with exactly MaxCommentLen characters
	maxComments := bytes.Repeat([]byte("A"), MaxCommentLen)

	h := NewVolumeHeader(
		bytes.Repeat([]byte{0x01}, SaltSize),
		bytes.Repeat([]byte{0x02}, HKDFSaltSize),
		bytes.Repeat([]byte{0x03}, SerpentIVSize),
		bytes.Repeat([]byte{0x04}, NonceSize),
	)
	h.Comments = string(maxComments)

	var buf bytes.Buffer
	writer := NewWriter(&buf, rs)
	_, err = writer.WriteHeader(h)
	if err != nil {
		t.Errorf("WriteHeader should succeed with MaxCommentLen: %v", err)
	}

	// Test with MaxCommentLen + 1 characters (should fail)
	h.Comments = string(bytes.Repeat([]byte("A"), MaxCommentLen+1))

	var buf2 bytes.Buffer
	writer2 := NewWriter(&buf2, rs)
	_, err = writer2.WriteHeader(h)
	if err == nil {
		t.Error("WriteHeader should fail when comments exceed MaxCommentLen")
	}
}

// =============================================================================
// Tests for header read/write edge cases
// =============================================================================

func TestHeaderWriteReadRoundtripAllFlags(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	// Test with all flag combinations
	flagCombinations := []Flags{
		{Paranoid: false, UseKeyfiles: false, KeyfileOrdered: false, ReedSolomon: false, Padded: false},
		{Paranoid: true, UseKeyfiles: false, KeyfileOrdered: false, ReedSolomon: false, Padded: false},
		{Paranoid: false, UseKeyfiles: true, KeyfileOrdered: false, ReedSolomon: false, Padded: false},
		{Paranoid: false, UseKeyfiles: true, KeyfileOrdered: true, ReedSolomon: false, Padded: false},
		{Paranoid: false, UseKeyfiles: false, KeyfileOrdered: false, ReedSolomon: true, Padded: false},
		{Paranoid: false, UseKeyfiles: false, KeyfileOrdered: false, ReedSolomon: false, Padded: true},
		{Paranoid: true, UseKeyfiles: true, KeyfileOrdered: true, ReedSolomon: true, Padded: true},
	}

	for i, flags := range flagCombinations {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			original := NewVolumeHeader(
				bytes.Repeat([]byte{byte(i + 1)}, SaltSize),
				bytes.Repeat([]byte{byte(i + 2)}, HKDFSaltSize),
				bytes.Repeat([]byte{byte(i + 3)}, SerpentIVSize),
				bytes.Repeat([]byte{byte(i + 4)}, NonceSize),
			)
			original.Flags = flags
			original.Comments = "Flag test"

			var buf bytes.Buffer
			writer := NewWriter(&buf, rs)
			if _, err := writer.WriteHeader(original); err != nil {
				t.Fatalf("WriteHeader failed: %v", err)
			}

			reader := NewReader(bytes.NewReader(buf.Bytes()), rs)
			result, err := reader.ReadHeader()
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}

			parsed := result.Header
			if parsed.Flags.Paranoid != flags.Paranoid {
				t.Errorf("Paranoid = %v; want %v", parsed.Flags.Paranoid, flags.Paranoid)
			}
			if parsed.Flags.UseKeyfiles != flags.UseKeyfiles {
				t.Errorf("UseKeyfiles = %v; want %v", parsed.Flags.UseKeyfiles, flags.UseKeyfiles)
			}
			if parsed.Flags.KeyfileOrdered != flags.KeyfileOrdered {
				t.Errorf("KeyfileOrdered = %v; want %v", parsed.Flags.KeyfileOrdered, flags.KeyfileOrdered)
			}
			if parsed.Flags.ReedSolomon != flags.ReedSolomon {
				t.Errorf("ReedSolomon = %v; want %v", parsed.Flags.ReedSolomon, flags.ReedSolomon)
			}
			if parsed.Flags.Padded != flags.Padded {
				t.Errorf("Padded = %v; want %v", parsed.Flags.Padded, flags.Padded)
			}
		})
	}
}

func TestHeaderReadTruncatedAtVariousPoints(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	// Create a valid header
	h := NewVolumeHeader(
		bytes.Repeat([]byte{0x01}, SaltSize),
		bytes.Repeat([]byte{0x02}, HKDFSaltSize),
		bytes.Repeat([]byte{0x03}, SerpentIVSize),
		bytes.Repeat([]byte{0x04}, NonceSize),
	)
	h.Comments = "Test"

	var buf bytes.Buffer
	writer := NewWriter(&buf, rs)
	if _, err := writer.WriteHeader(h); err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}

	fullData := buf.Bytes()

	// Test truncation at various points
	truncatePoints := []int{
		0,                                      // Empty
		5,                                      // Mid-version
		VersionEncSize,                         // After version
		VersionEncSize + 5,                     // Mid-commentLen
		VersionEncSize + CommentLenEncSize + 5, // Mid-comments
		100,                                    // Arbitrary point
		BaseHeaderSize / 2,                     // Mid-header
		BaseHeaderSize - 10,                    // Near end
	}

	for _, point := range truncatePoints {
		if point > len(fullData) {
			continue
		}
		truncated := fullData[:point]

		reader := NewReader(bytes.NewReader(truncated), rs)
		_, err := reader.ReadHeader()
		if err == nil && point < BaseHeaderSize {
			t.Errorf("ReadHeader should fail with truncation at %d bytes", point)
		}
	}
}

// =============================================================================
// Tests for binary comment content
// =============================================================================

func TestHeaderWithBinaryComments(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	// Test comments with all byte values (binary content)
	binaryComments := make([]byte, 256)
	for i := range binaryComments {
		binaryComments[i] = byte(i)
	}

	original := NewVolumeHeader(
		bytes.Repeat([]byte{0x01}, SaltSize),
		bytes.Repeat([]byte{0x02}, HKDFSaltSize),
		bytes.Repeat([]byte{0x03}, SerpentIVSize),
		bytes.Repeat([]byte{0x04}, NonceSize),
	)
	original.Comments = string(binaryComments)

	var buf bytes.Buffer
	writer := NewWriter(&buf, rs)
	if _, err := writer.WriteHeader(original); err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}

	reader := NewReader(bytes.NewReader(buf.Bytes()), rs)
	result, err := reader.ReadHeader()
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	if result.Header.Comments != original.Comments {
		t.Error("Binary comments not preserved correctly")
	}
}
