package pcv3

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"
)

type normalPreviewReader struct {
	*bytes.Reader
	front     int64
	calls     int
	maxChunk  int
	afterRead func()
	read      func([]byte, int64) (int, error)
}

func (r *normalPreviewReader) ReadAt(p []byte, off int64) (int, error) {
	r.calls++
	if off < 0 || off+int64(len(p)) > r.front {
		panic("preview read outside front")
	}
	if r.read != nil {
		return r.read(p, off)
	}
	if r.maxChunk > 0 && len(p) > r.maxChunk {
		p = p[:r.maxChunk]
	}
	n, err := r.Reader.ReadAt(p, off)
	if r.afterRead != nil {
		r.afterRead()
	}
	return n, err
}

func previewFixture(t *testing.T) []byte {
	t.Helper()
	f := requireNormalFixture(t, loadNormalFixtureManifest(t).FixturesByID(), "normal-standard-combined-ordered-one")
	return readNormalFixtureArtifact(t, f.Volume)
}

func TestNormalPreviewFrozenFrontOnlyWithoutCredentials(t *testing.T) {
	data := previewFixture(t)
	reader := &normalPreviewReader{Reader: bytes.NewReader(data), front: 1112}
	_, _ = reader.Seek(19, io.SeekStart)
	preview, err := PreviewNormal(context.Background(), reader, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	factors, ok := preview.Factors()
	if !ok || factors.Policy() != pcv3credential.FactorPolicyPasswordAndKeyfiles || factors.KeyfileMode() != pcv3credential.KeyfileModeOrdered || factors.KeyfileCount() != 2 {
		t.Fatalf("preview requirements unavailable or incorrect: %v", factors)
	}
	if comment, ok := preview.Comment(); !ok || comment != "TEST ONLY comment" {
		t.Fatalf("untrusted comment = %q available=%v", comment, ok)
	}
	if position, _ := reader.Seek(0, io.SeekCurrent); position != 19 {
		t.Fatalf("preview changed source position to %d", position)
	}
	for _, value := range []any{preview, &preview, factors, &factors} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
			formatted := fmt.Sprintf(format, value)
			if strings.Contains(formatted, "TEST ONLY comment") || strings.Contains(formatted, "keyfileCount") || strings.Contains(formatted, "policy:") {
				t.Fatalf("preview formatting disclosed claims: %s", formatted)
			}
		}
	}
}

func TestNormalPreviewOptionalDamageAndGeometry(t *testing.T) {
	for _, test := range []struct {
		name             string
		mutate           func([]byte) []byte
		factors, comment bool
	}{
		{"split front only", func(b []byte) []byte { return b[:1112] }, true, true},
		{"truncated metadata", func(b []byte) []byte { return b[:1000] }, true, false},
		{"truncated primary", func(b []byte) []byte { return b[:975] }, false, false},
		{"D1 or legacy", func(b []byte) []byte { copy(b[:4], "D1!!"); return b }, false, false},
		{"unsupported preamble", func(b []byte) []byte { b[5] = 4; return b }, false, false},
		{"oversize front", func(b []byte) []byte { binary.BigEndian.PutUint32(b[12:16], 107464); return b }, false, false},
		{"oversize comment", func(b []byte) []byte {
			rewriteCapsule(t, b, 16, func(c []byte) { binary.BigEndian.PutUint32(c[92:96], 100000) })
			return b
		}, false, false},
		{"preamble geometry mismatch", func(b []byte) []byte { binary.BigEndian.PutUint32(b[12:16], 1248); return b }, false, false},
		{"preamble suite mismatch", func(b []byte) []byte { binary.BigEndian.PutUint16(b[8:10], 2); return b }, false, false},
		{"preamble flags mismatch", func(b []byte) []byte { binary.BigEndian.PutUint16(b[10:12], 1); return b }, false, false},
		{"damaged primary no backup fallback", func(b []byte) []byte { clear(b[16:976]); return b }, false, false},
		{"damaged metadata", func(b []byte) []byte { clear(b[976:1112]); return b }, true, false},
		{"noncanonical metadata", func(b []byte) []byte { copy(b[976:1112], metadataFixture(t, "invalid_utf8.bin")); return b }, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := test.mutate(previewFixture(t))
			r := &normalPreviewReader{Reader: bytes.NewReader(data), front: int64(min(len(data), 1112))}
			p, err := PreviewNormal(context.Background(), r, int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := p.Factors(); ok != test.factors {
				t.Fatalf("factor availability=%v want %v", ok, test.factors)
			}
			if _, ok := p.Comment(); ok != test.comment {
				t.Fatalf("comment availability=%v want %v", ok, test.comment)
			}
		})
	}
}

func TestNormalPreviewReaderBoundsAndCancellation(t *testing.T) {
	for _, test := range []struct {
		name  string
		run   func(context.CancelFunc) func([]byte, int64) (int, error)
		calls int
	}{
		{"no progress", func(context.CancelFunc) func([]byte, int64) (int, error) {
			return func([]byte, int64) (int, error) { return 0, nil }
		}, 2},
		{"negative count", func(context.CancelFunc) func([]byte, int64) (int, error) {
			return func([]byte, int64) (int, error) { return -1, nil }
		}, 1},
		{"oversize count", func(context.CancelFunc) func([]byte, int64) (int, error) {
			return func(p []byte, _ int64) (int, error) { return len(p) + 1, nil }
		}, 1},
		{"cancellation", func(cancel context.CancelFunc) func([]byte, int64) (int, error) {
			return func([]byte, int64) (int, error) { cancel(); return 0, nil }
		}, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r := &normalPreviewReader{Reader: bytes.NewReader(previewFixture(t)), front: 1112, read: test.run(cancel)}
			p, err := PreviewNormal(ctx, r, r.Size())
			if err == nil || r.calls != test.calls {
				t.Fatalf("err=%v calls=%d want error/%d", err, r.calls, test.calls)
			}
			if _, ok := p.Factors(); ok {
				t.Fatal("reader failure released claims")
			}
		})
	}
	t.Run("short reads remain bounded", func(t *testing.T) {
		r := &normalPreviewReader{Reader: bytes.NewReader(previewFixture(t)), front: 1112, maxChunk: 1}
		p, err := PreviewNormal(context.Background(), r, r.Size())
		if comment, ok := p.Comment(); err != nil || !ok || comment != "TEST ONLY comment" || r.calls > 1112 {
			t.Fatalf("short-read preview err=%v available=%v calls=%d", err, ok, r.calls)
		}
	})
	t.Run("cancel between metadata blocks", func(t *testing.T) {
		core, err := hex.DecodeString(metadataTestStandardCore)
		if err != nil {
			t.Fatal(err)
		}
		data := make([]byte, 1248)
		copy(data, previewFixture(t))
		copy(data[4:16], core[4:16])
		rewriteCapsule(t, data, 16, func(decoded []byte) { copy(decoded[:96], core) })
		copy(data[976:], metadataFixture(t, "standard_unicode.bin"))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		r := &normalPreviewReader{Reader: bytes.NewReader(data), front: 1248}
		r.afterRead = func() {
			if r.calls == 3 {
				cancel()
			}
		}
		p, err := PreviewNormal(ctx, r, r.Size())
		if err == nil || r.calls != 3 {
			t.Fatalf("cancellation err=%v calls=%d; want stop after first of two metadata blocks", err, r.calls)
		}
		if _, ok := p.Factors(); ok {
			t.Fatal("cancelled metadata read released factor claims")
		}
		if _, ok := p.Comment(); ok {
			t.Fatal("cancelled read released comment")
		}
	})
}

func TestNormalPreviewCanonicalMetadataBounds(t *testing.T) {
	for _, test := range []struct {
		name, fixture, core string
		want                string
		available           bool
		front               int64
	}{
		{"Unicode across RS blocks", "standard_unicode.bin", metadataTestStandardCore, metadataTestUnicodeComment, true, 1248},
		{"maximum 99999 byte comment", "standard_max.bin", metadataTestMaximumCore, string(metadataMaximumComment()), true, 107328},
		{"valid empty comment", "paranoid_empty.bin", metadataTestParanoidEmptyCore, "", true, 1112},
		{"invalid magic", "invalid_magic.bin", metadataTestInvalidCore, "", false, 1112},
		{"invalid schema", "invalid_schema.bin", metadataTestInvalidCore, "", false, 1112},
		{"invalid encoding", "invalid_encoding.bin", metadataTestInvalidCore, "", false, 1112},
		{"nonzero reserved", "invalid_reserved.bin", metadataTestInvalidCore, "", false, 1112},
		{"raw hostile length", "invalid_length.bin", metadataTestInvalidCore, "", false, 1112},
		{"invalid UTF8", "invalid_utf8.bin", metadataTestInvalidCore, "", false, 1112},
		{"nonzero padding", "invalid_padding.bin", metadataTestInvalidCore, "", false, 1112},
	} {
		t.Run(test.name, func(t *testing.T) {
			core, err := hex.DecodeString(test.core)
			if err != nil {
				t.Fatal(err)
			}
			data := make([]byte, int(test.front))
			copy(data, previewFixture(t))
			copy(data[4:16], core[4:16])
			rewriteCapsule(t, data, 16, func(decoded []byte) {
				copy(decoded[:96], core)
				if core[9] == 2 {
					decoded[99] = 2
				}
			})
			copy(data[976:], metadataFixture(t, test.fixture))
			r := &normalPreviewReader{Reader: bytes.NewReader(data), front: test.front}
			preview, err := PreviewNormal(context.Background(), r, r.Size())
			comment, ok := preview.Comment()
			if err != nil || ok != test.available || comment != test.want {
				t.Fatalf("canonical preview err=%v available=%v want %v bytes=%d want %d", err, ok, test.available, len(comment), len(test.want))
			}
			if _, ok := preview.Factors(); !ok {
				t.Fatal("optional metadata failure discarded factor claims")
			}
			if r.calls > 785 {
				t.Fatalf("preview exceeded bounded front calls: %d", r.calls)
			}
		})
	}
}
