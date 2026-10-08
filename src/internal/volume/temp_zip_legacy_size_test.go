package volume

import (
	"Picocrypt-NG/internal/encoding"
	"context"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyPreparedCiphertextLengthKeepsRSFinalPaddingAndHeaderBytes(t *testing.T) {
	for _, test := range []struct {
		name         string
		plain, want  uint64
		rs, deniable bool
		comment      string
	}{
		{"empty", 0, 789, false, false, ""},
		{"raw", 1, 790, false, false, ""},
		{"utf8 comment bytes", 1, 796, false, false, "é"},
		{"wrapper", 1, 830, false, true, ""},
		{"RS empty has no payload block", 0, 789, true, false, ""},
		{"RS short", 1, 925, true, false, ""},
		{"RS 127", 127, 925, true, false, ""},
		{"RS aligned partial adds padding", 128, 1061, true, false, ""},
		{"RS 129", 129, 1061, true, false, ""},
		{"RS before full padded block", 1048447, 1114765, true, false, ""},
		{"RS full padded partial", 1048448, 1114901, true, false, ""},
		{"RS last byte partial", 1048575, 1114901, true, false, ""},
		{"RS full block has no extra padding", 1048576, 1114901, true, false, ""},
		{"RS next aligned partial", 1048704, 1115173, true, false, ""},
		{"RS wrapper utf8", 128, 1107, true, true, "é"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := legacyPreparedCiphertextLength(&EncryptRequest{ReedSolomon: test.rs, Deniability: test.deniable, Comments: test.comment}, test.plain)
			if err != nil || got != test.want {
				t.Fatalf("length = %d, %v; want %d", got, err, test.want)
			}
		})
	}
	if got, err := legacyPreparedCiphertextLength(&EncryptRequest{}, math.MaxInt64-789); err != nil || got != math.MaxInt64 {
		t.Fatalf("last host-representable raw volume = %d, %v", got, err)
	}
	for _, request := range []*EncryptRequest{nil, {PCV3: true}, {Comments: strings.Repeat("c", 100000)}} {
		if _, err := legacyPreparedCiphertextLength(request, 0); err == nil {
			t.Fatal("invalid size request accepted")
		}
	}
	for _, plain := range []uint64{math.MaxInt64 - 788, math.MaxInt64, math.MaxUint64} {
		if _, err := legacyPreparedCiphertextLength(&EncryptRequest{}, plain); err == nil {
			t.Fatal("unrepresentable ciphertext accepted")
		}
	}
	if _, err := legacyPreparedCiphertextLength(&EncryptRequest{ReedSolomon: true}, math.MaxInt64-789); err == nil {
		t.Fatal("RS expansion overflow accepted")
	}
}

func TestLegacyPreparedCiphertextLengthMatchesPublishedWriter(t *testing.T) {
	codecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name         string
		n            int
		rs, deniable bool
		comment      string
	}{
		{"raw", 129, false, false, "é"},
		{"RS aligned", 128, true, false, ""},
		{"RS padded full", 1048448, true, false, ""},
		{"RS wrapper", 128, true, true, "é"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "source.bin")
			target := filepath.Join(dir, "result.pcv")
			if err := os.WriteFile(input, make([]byte, test.n), 0o600); err != nil {
				t.Fatal(err)
			}
			request := &EncryptRequest{InputFile: input, OutputFile: target, Password: []byte("public size fixture"), ReedSolomon: test.rs, Deniability: test.deniable, Paranoid: test.deniable, Comments: test.comment, RSCodecs: codecs}
			want, err := legacyPreparedCiphertextLength(request, uint64(test.n))
			if err != nil {
				t.Fatal(err)
			}
			if err := Encrypt(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(target)
			if err != nil || uint64(info.Size()) != want {
				t.Fatalf("published extent = %v, %v; want %d", info, err, want)
			}
		})
	}
}
