package header

import (
	"Picocrypt-NG/internal/encoding"
	"bytes"
	"fmt"
	"testing"
)

func TestHeaderSize(t *testing.T) {
	// Frozen-format tripwire: BaseHeaderSize is the sum of every RS-encoded
	// fixed field in the .pcv header. Changing any field's on-disk size breaks
	// 2.08/2.09 interop, so pin the byte count independently of the constant.
	// 15 + 15 + 15 + 48 + 96 + 48 + 72 + 192 + 96 + 192 = 789
	expectedBase := 15 + 15 + 15 + 48 + 96 + 48 + 72 + 192 + 96 + 192
	if BaseHeaderSize != expectedBase {
		t.Errorf("BaseHeaderSize = %d; want %d", BaseHeaderSize, expectedBase)
	}

	// Each comment byte is rs1-encoded (1->3); verify the expansion is applied.
	if got, want := HeaderSize(10), BaseHeaderSize+10*3; got != want {
		t.Errorf("HeaderSize(10) = %d; want %d", got, want)
	}
}

// Application releases must not turn the legacy writer's five-byte version
// into an application label or a header the v1/v2 reader refuses.
func TestDefaultWriterKeepsLegacyV2FormatAcrossApplicationVersions(t *testing.T) {
	h := NewVolumeHeader(
		repeatingBytes(0x11, SaltSize), repeatingBytes(0x22, HKDFSaltSize),
		repeatingBytes(0x33, SerpentIVSize), repeatingBytes(0x44, NonceSize),
	)
	encoded, written := writeFormatGuardHeader(t, h)
	if written != 789 || len(encoded) != 789 {
		t.Fatalf("default legacy header changed its frozen layout: wrote %d bytes, length %d", written, len(encoded))
	}
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatal(err)
	}
	read, err := NewReader(bytes.NewReader(encoded), rs).ReadHeader()
	if err != nil {
		t.Fatalf("default legacy writer produced an unreadable header: %v", err)
	}
	if read.DecodeError != nil || read.Header.Version != "v2.19" || read.BytesRead != 789 {
		t.Fatalf("default legacy header changed: version=%q bytes=%d decode=%v", read.Header.Version, read.BytesRead, read.DecodeError)
	}
}

func TestWriteHeaderVersionBumpChangesOnlyEncodedVersionField(t *testing.T) {
	const comments = "release guard"

	oldHeader := deterministicFormatGuardHeader("v2.12", comments)
	newHeader := deterministicFormatGuardHeader("v2.14", comments)

	oldEncoded, oldWritten := writeFormatGuardHeader(t, oldHeader)
	newEncoded, newWritten := writeFormatGuardHeader(t, newHeader)

	expectedSize := HeaderSize(len(comments))
	if oldWritten != expectedSize {
		t.Fatalf("v2.12 WriteHeader wrote %d bytes; want HeaderSize(%d) = %d", oldWritten, len(comments), expectedSize)
	}
	if newWritten != expectedSize {
		t.Fatalf("v2.14 WriteHeader wrote %d bytes; want HeaderSize(%d) = %d", newWritten, len(comments), expectedSize)
	}
	if len(oldEncoded) != expectedSize {
		t.Fatalf("v2.12 encoded header length = %d; want %d", len(oldEncoded), expectedSize)
	}
	if len(newEncoded) != expectedSize {
		t.Fatalf("v2.14 encoded header length = %d; want %d", len(newEncoded), expectedSize)
	}

	regions := encodedHeaderRegions(len(comments))
	assertEncodedHeaderRegionLayout(t, regions, len(comments), expectedSize)
	if err := versionOnlyHeaderDelta(oldEncoded, newEncoded, regions); err != nil {
		t.Fatal(err)
	}
}

// TestWriteHeaderVersionDeltaGuardRejectsNonVersionFieldMutation drives the REAL
// WriteHeader for two headers that differ ONLY in a source field (Flags.Padded),
// so the non-version delta is produced by production rather than fabricated. It
// pins the live flags-encoding path (writer.go: encoding.Encode(RS5,
// Flags.ToBytes())) by asserting the encoded flags region equals a recomputed
// RS5(Flags.ToBytes()) — zeroing that path is rejected — then confirms the
// version-delta guard rejects a header whose flags changed while the version did
// not. The sibling TestWriteHeaderVersionBumpChangesOnlyEncodedVersionField
// covers the complementary version-only direction.
func TestWriteHeaderVersionDeltaGuardRejectsNonVersionFieldMutation(t *testing.T) {
	const comments = "release guard"

	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	// Base header and a copy that differs ONLY in a source field (Flags.Padded).
	// Both go through the REAL WriteHeader so the non-version delta is produced by
	// production, not fabricated by the test.
	baseHeader := deterministicFormatGuardHeader("v2.14", comments)
	baseEncoded, _ := writeFormatGuardHeader(t, baseHeader)

	mutatedHeader := deterministicFormatGuardHeader("v2.14", comments)
	mutatedHeader.Flags.Padded = !mutatedHeader.Flags.Padded
	mutatedEncoded, _ := writeFormatGuardHeader(t, mutatedHeader)

	regions := encodedHeaderRegions(len(comments))
	flagsStart := regionStart(t, regions, "flags")

	// WriteHeader must encode the flags region from h.Flags.ToBytes(). This pins
	// the live flags path: zeroing it (writer.go -> encoding.Encode(RS5, make([]byte,5)))
	// is rejected. Recompute the expectation so it self-pins if Flags layout changes.
	wantFlags, err := encoding.Encode(rs.RS5, baseHeader.Flags.ToBytes())
	if err != nil {
		t.Fatalf("Encode base flags failed: %v", err)
	}
	gotFlags := baseEncoded[flagsStart : flagsStart+FlagsEncSize]
	if !bytes.Equal(gotFlags, wantFlags) {
		t.Fatalf("encoded flags region = %v; want RS5(Flags.ToBytes()) = %v", gotFlags, wantFlags)
	}

	// A Flags-only source change must move bytes in the flags region and nowhere else.
	for _, region := range regions {
		same := bytes.Equal(baseEncoded[region.start:region.end], mutatedEncoded[region.start:region.end])
		if region.name == "flags" {
			if same {
				t.Fatalf("flags region [%d:%d] unchanged after flipping Flags.Padded source field", region.start, region.end)
			}
			continue
		}
		if !same {
			t.Fatalf("%s region [%d:%d] changed from a Flags-only source mutation", region.name, region.start, region.end)
		}
	}

	// The version-delta guard must reject a header whose NON-version field changed
	// while the version stayed constant.
	if err := versionOnlyHeaderDelta(baseEncoded, mutatedEncoded, regions); err == nil {
		t.Fatal("versionOnlyHeaderDelta accepted a header whose flags source field changed but version did not")
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

type encodedHeaderRegion struct {
	name       string
	start, end int
}

func deterministicFormatGuardHeader(version, comments string) *VolumeHeader {
	return &VolumeHeader{
		Version:  version,
		Comments: comments,
		Flags: Flags{
			Paranoid:       true,
			UseKeyfiles:    true,
			KeyfileOrdered: true,
			ReedSolomon:    true,
			Padded:         false,
		},
		Salt:        repeatingBytes(0x11, SaltSize),
		HKDFSalt:    repeatingBytes(0x22, HKDFSaltSize),
		SerpentIV:   repeatingBytes(0x33, SerpentIVSize),
		Nonce:       repeatingBytes(0x44, NonceSize),
		KeyHash:     repeatingBytes(0x55, KeyHashSize),
		KeyfileHash: repeatingBytes(0x66, KeyfileHashSize),
		AuthTag:     repeatingBytes(0x77, AuthTagSize),
	}
}

func repeatingBytes(b byte, n int) []byte {
	return bytes.Repeat([]byte{b}, n)
}

func writeFormatGuardHeader(t *testing.T, h *VolumeHeader) ([]byte, int) {
	t.Helper()

	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	var buf bytes.Buffer
	n, err := NewWriter(&buf, rs).WriteHeader(h)
	if err != nil {
		t.Fatalf("WriteHeader(%q) failed: %v", h.Version, err)
	}
	return buf.Bytes(), n
}

func encodedHeaderRegions(commentsLen int) []encodedHeaderRegion {
	pos := 0
	next := func(name string, size int) encodedHeaderRegion {
		region := encodedHeaderRegion{name: name, start: pos, end: pos + size}
		pos += size
		return region
	}

	return []encodedHeaderRegion{
		next("version", VersionEncSize),
		next("comment length", CommentLenEncSize),
		next("comments", commentsLen*3),
		next("flags", FlagsEncSize),
		next("salt", SaltEncSize),
		next("hkdf salt", HKDFSaltEncSize),
		next("serpent iv", SerpentIVEncSize),
		next("nonce", NonceEncSize),
		next("key hash placeholder", KeyHashEncSize),
		next("keyfile hash placeholder", KeyfileHashEncSize),
		next("auth tag placeholder", AuthTagEncSize),
	}
}

func assertEncodedHeaderRegionLayout(t *testing.T, regions []encodedHeaderRegion, commentsLen, expectedSize int) {
	t.Helper()

	expectedWidths := map[string]int{
		"version":                  VersionEncSize,
		"comment length":           CommentLenEncSize,
		"comments":                 commentsLen * 3,
		"flags":                    FlagsEncSize,
		"salt":                     SaltEncSize,
		"hkdf salt":                HKDFSaltEncSize,
		"serpent iv":               SerpentIVEncSize,
		"nonce":                    NonceEncSize,
		"key hash placeholder":     KeyHashEncSize,
		"keyfile hash placeholder": KeyfileHashEncSize,
		"auth tag placeholder":     AuthTagEncSize,
	}

	pos := 0
	for _, region := range regions {
		if region.start != pos {
			t.Fatalf("%s start = %d; want %d", region.name, region.start, pos)
		}
		width := region.end - region.start
		if width != expectedWidths[region.name] {
			t.Fatalf("%s width = %d; want %d", region.name, width, expectedWidths[region.name])
		}
		pos = region.end
	}
	if pos != expectedSize {
		t.Fatalf("encoded header regions end at %d; want %d", pos, expectedSize)
	}
	if got := int(AuthValuesOffset(commentsLen)); got != regionStart(t, regions, "key hash placeholder") {
		t.Fatalf("AuthValuesOffset(%d) = %d; want key hash placeholder start %d",
			commentsLen, got, regionStart(t, regions, "key hash placeholder"))
	}
}

func versionOnlyHeaderDelta(oldEncoded, newEncoded []byte, regions []encodedHeaderRegion) error {
	if len(oldEncoded) != len(newEncoded) {
		return fmt.Errorf("encoded header lengths differ: %d vs %d", len(oldEncoded), len(newEncoded))
	}
	if len(oldEncoded) < VersionEncSize {
		return fmt.Errorf("encoded header length %d is shorter than VersionEncSize %d", len(oldEncoded), VersionEncSize)
	}
	if bytes.Equal(oldEncoded[:VersionEncSize], newEncoded[:VersionEncSize]) {
		return fmt.Errorf("encoded version region [0:%d] is identical", VersionEncSize)
	}
	if !bytes.Equal(oldEncoded[VersionEncSize:], newEncoded[VersionEncSize:]) {
		for _, region := range regions {
			if region.name == "version" {
				continue
			}
			if !bytes.Equal(oldEncoded[region.start:region.end], newEncoded[region.start:region.end]) {
				return fmt.Errorf("%s region [%d:%d] changed outside encoded version field", region.name, region.start, region.end)
			}
		}
		return fmt.Errorf("encoded bytes changed outside version region [%d:%d]", VersionEncSize, len(oldEncoded))
	}
	return nil
}

func regionStart(t *testing.T, regions []encodedHeaderRegion, name string) int {
	t.Helper()
	for _, region := range regions {
		if region.name == name {
			return region.start
		}
	}
	t.Fatalf("region %q not found", name)
	return 0
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

// TestVerifyV2HeaderAuthenticatesEveryField proves the live (struct-based) v2
// header MAC authenticates EVERY field it covers: tampering any one of them after
// the MAC is fixed must be rejected. This is the safety net that lets us retire the
// parallel raw-bytes header-MAC path — both the writer and reader use this live
// path, and a swap is detectable per-field here, so the retired twin guarded
// nothing the live path misses.
func TestVerifyV2HeaderAuthenticatesEveryField(t *testing.T) {
	subkey := bytes.Repeat([]byte{0x42}, 64)
	keyfileHash := bytes.Repeat([]byte{0x11}, KeyfileHashSize)

	base := func() *VolumeHeader {
		return &VolumeHeader{
			Version:   CurrentVersion,
			Comments:  "vector",
			Flags:     Flags{Paranoid: true, ReedSolomon: true},
			Salt:      bytes.Repeat([]byte{0x01}, SaltSize),
			HKDFSalt:  bytes.Repeat([]byte{0x02}, HKDFSaltSize),
			SerpentIV: bytes.Repeat([]byte{0x03}, SerpentIVSize),
			Nonce:     bytes.Repeat([]byte{0x04}, NonceSize),
		}
	}

	// Baseline: an untampered header with its correct MAC verifies.
	h := base()
	h.KeyHash = ComputeV2HeaderMAC(subkey, h, keyfileHash)
	if !VerifyV2Header(subkey, h, keyfileHash).Valid {
		t.Fatal("VerifyV2Header rejected an untampered header")
	}

	// Each authenticated field, tampered after the MAC is fixed, must be rejected.
	// mutate returns the keyfileHash to pass to VerifyV2Header (so the keyfileHash
	// case can tamper that argument without touching the header struct).
	cases := []struct {
		name   string
		mutate func(h *VolumeHeader, keyfileHash []byte) []byte
	}{
		{"version", func(h *VolumeHeader, kf []byte) []byte { h.Version = "v9.99"; return kf }},
		// Same length (6) isolates the comment-content write from the length prefix.
		{"comments_content", func(h *VolumeHeader, kf []byte) []byte { h.Comments = "VECTOR"; return kf }},
		// Different length (7) additionally exercises the %05d comment-length write.
		{"comments_length", func(h *VolumeHeader, kf []byte) []byte { h.Comments = "vectors"; return kf }},
		{"flags", func(h *VolumeHeader, kf []byte) []byte { h.Flags.Paranoid = !h.Flags.Paranoid; return kf }},
		{"salt", func(h *VolumeHeader, kf []byte) []byte { h.Salt[0] ^= 0xFF; return kf }},
		{"hkdfSalt", func(h *VolumeHeader, kf []byte) []byte { h.HKDFSalt[0] ^= 0xFF; return kf }},
		{"serpentIV", func(h *VolumeHeader, kf []byte) []byte { h.SerpentIV[0] ^= 0xFF; return kf }},
		{"nonce", func(h *VolumeHeader, kf []byte) []byte { h.Nonce[0] ^= 0xFF; return kf }},
		{"keyfileHash", func(h *VolumeHeader, kf []byte) []byte {
			c := append([]byte(nil), kf...)
			c[0] ^= 0xFF
			return c
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := base()
			h.KeyHash = ComputeV2HeaderMAC(subkey, h, keyfileHash)
			kf := tc.mutate(h, keyfileHash)
			if VerifyV2Header(subkey, h, kf).Valid {
				t.Errorf("tampering %s was NOT detected — the header MAC does not authenticate it", tc.name)
			}
		})
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
