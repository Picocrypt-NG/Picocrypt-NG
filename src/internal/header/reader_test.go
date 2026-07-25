package header

import (
	"Picocrypt-NG/internal/encoding"
	"bytes"
	"errors"
	"testing"
)

// TestMatchVersionAnchored verifies the shared version helper uses the single
// anchored pattern ^v\d\.\d{2}$ (QUAL-01/D-03). The anchoring matters: a
// trailing-garbage 5-byte value such as "v2.0X" must be rejected, unlike the
// historically-unanchored UI copy (Pitfall 5).
func TestMatchVersionAnchored(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"valid v2.09", "v2.09", true},
		{"valid v2.10", "v2.10", true},
		{"valid v2.11", "v2.11", true},
		{"valid v2.12", "v2.12", true},
		{"valid v2.13", "v2.13", true},
		{"valid v2.14", "v2.14", true},
		{"valid non-current v3.11", "v3.11", true},
		{"valid v1.49", "v1.49", true},
		{"trailing garbage", "v2.0X", false},
		{"too long", "v2.099", false},
		{"missing v", "2.09", false},
		{"leading space", " v2.0", false},
		{"empty", "", false},
		{"two digit major", "v22.0", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MatchVersion([]byte(tc.in)); got != tc.want {
				t.Errorf("MatchVersion(%q) = %v; want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestReadHeaderRejectsUnsupportedMajorBeforeReadingTheRest(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	// MatchVersion deliberately accepts well-formed future versions so
	// deniability detection does not mistake them for random-looking wrappers.
	// The reader must make the separate support decision immediately after the
	// encoded version field, before flags, credentials, or a KDF are considered.
	version := encodeField(t, rs, []byte("v3.11"))
	reader := NewReader(bytes.NewReader(version), rs)
	result, err := reader.ReadHeader()

	const want = `unsupported volume version "v3.11"`
	if err == nil || err.Error() != want {
		t.Fatalf("ReadHeader() error = %v; want %q", err, want)
	}
	if result.BytesRead != VersionEncSize {
		t.Fatalf("ReadHeader() consumed %d bytes; want only encoded version field (%d)", result.BytesRead, VersionEncSize)
	}
}

// encodeField RS5-encodes a 5-byte field for crafting header bytes inline.
func encodeField(t *testing.T, rs *encoding.RSCodecs, field []byte) []byte {
	t.Helper()
	if len(field) != 5 {
		t.Fatalf("encodeField: want 5 bytes, got %d", len(field))
	}
	enc, err := encoding.Encode(rs.RS5, field)
	if err != nil {
		t.Fatalf("encodeField: %v", err)
	}
	return enc
}

func testHeaderBytes(t *testing.T, rs *encoding.RSCodecs, comments string) []byte {
	t.Helper()

	h := NewVolumeHeader(
		bytes.Repeat([]byte{0x11}, SaltSize),
		bytes.Repeat([]byte{0x22}, HKDFSaltSize),
		bytes.Repeat([]byte{0x33}, SerpentIVSize),
		bytes.Repeat([]byte{0x44}, NonceSize),
	)
	h.Comments = comments

	var buf bytes.Buffer
	if _, err := NewWriter(&buf, rs).WriteHeader(h); err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}
	return buf.Bytes()
}

func TestReadHeaderDecodeErrorProvenanceCommentBytes(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	raw := testHeaderBytes(t, rs, "ok")
	commentOffset := VersionEncSize + CommentLenEncSize
	copy(raw[commentOffset:commentOffset+3], []byte{0x00, 0x01, 0x02})

	reader := NewReader(bytes.NewReader(raw), rs)
	res, err := reader.ReadHeader()
	if err != nil {
		t.Fatalf("ReadHeader returned hard error: %v", err)
	}
	if !errors.Is(res.DecodeError, ErrCorruptedHeader) {
		t.Fatalf("DecodeError = %v; want ErrCorruptedHeader", res.DecodeError)
	}
	if !res.CommentDecodeError {
		t.Fatal("CommentDecodeError = false; want true for corrupted comment bytes")
	}
	if res.NonCommentDecodeError {
		t.Fatal("NonCommentDecodeError = true; want false when only comment bytes are corrupted")
	}
}

func TestReadHeaderDecodeErrorProvenanceNonCommentField(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	raw := testHeaderBytes(t, rs, "ok")
	saltOffset := VersionEncSize + CommentLenEncSize + len("ok")*3 + FlagsEncSize
	for i := range 17 {
		raw[saltOffset+i] ^= 0xff
	}

	reader := NewReader(bytes.NewReader(raw), rs)
	res, err := reader.ReadHeader()
	if err != nil {
		t.Fatalf("ReadHeader returned hard error: %v", err)
	}
	if !errors.Is(res.DecodeError, ErrCorruptedHeader) {
		t.Fatalf("DecodeError = %v; want ErrCorruptedHeader", res.DecodeError)
	}
	if res.CommentDecodeError {
		t.Fatal("CommentDecodeError = true; want false for non-comment corruption")
	}
	if !res.NonCommentDecodeError {
		t.Fatal("NonCommentDecodeError = false; want true for corrupted non-comment header field")
	}
}

// TestReadHeaderRejectsBadCommentLen verifies the comment-length guard rejects
// a non-5-digit field and, per D-02, never over-allocates. A version field
// followed by a comment-length field that is not exactly 5 digits must return
// ErrInvalidCommentLength before any comment allocation occurs.
func TestReadHeaderRejectsBadCommentLen(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	version := encodeField(t, rs, []byte("v2.09"))

	// Comment-length field that decodes to something that is NOT five ASCII
	// digits (a leading '-' simulating a "negative"-looking field). The guard
	// must reject this and return ErrInvalidCommentLength.
	badLen := encodeField(t, rs, []byte("-0001"))

	var buf bytes.Buffer
	buf.Write(version)
	buf.Write(badLen)

	reader := NewReader(bytes.NewReader(buf.Bytes()), rs)
	_, err = reader.ReadHeader()
	if !errors.Is(err, ErrInvalidCommentLength) {
		t.Fatalf("ReadHeader() err = %v; want ErrInvalidCommentLength", err)
	}
}

// TestReadHeaderCommentLenBoundConstant verifies the D-02 comment-length bound
// (reader.go: `commentsLen > MaxCommentLen`) accepts values up to AND including
// MaxCommentLen, the documented cap. The numeric upper branch is otherwise
// unreachable through ReadHeader because the ^\d{5}$ guard already clamps the
// decoded length to [0,99999]==[0,MaxCommentLen]; this drives the reachable
// boundary (exactly MaxCommentLen) so an off-by-one in the bound (`>=` instead
// of `>`) or a downward drift of MaxCommentLen turns the test red. The constant
// pin keeps MaxCommentLen the single source of truth for that cap.
//
// Coverage split: the digit-guard rejection is covered by
// TestReadHeaderRejectsBadCommentLen and the writer-side cap by
// TestMaxCommentLength; this test uniquely pins the reader-side ACCEPTANCE
// boundary at exactly MaxCommentLen.
func TestReadHeaderCommentLenBoundConstant(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	if MaxCommentLen != 99999 {
		t.Fatalf("MaxCommentLen = %d; want 99999 (D-02 bound source of truth)", MaxCommentLen)
	}

	// A comment-length field equal to exactly MaxCommentLen must pass the bound
	// (it is the documented maximum). We stop the input right after the length
	// field: acceptance vs rejection is decided before any comment byte is read,
	// so a downstream EOF on the first comment char proves the bound accepted it.
	version := encodeField(t, rs, []byte("v2.09"))
	atMax := encodeField(t, rs, []byte("99999"))

	var buf bytes.Buffer
	buf.Write(version)
	buf.Write(atMax)

	reader := NewReader(bytes.NewReader(buf.Bytes()), rs)
	_, err = reader.ReadHeader()
	if errors.Is(err, ErrInvalidCommentLength) {
		t.Fatalf("ReadHeader rejected a comment length of exactly MaxCommentLen (%d) with %v; "+
			"the D-02 bound must accept values up to and including MaxCommentLen", MaxCommentLen, err)
	}
}
