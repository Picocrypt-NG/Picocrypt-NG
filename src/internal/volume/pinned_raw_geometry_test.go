package volume

import (
	"Picocrypt-NG/internal/encoding"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

type pinnedRawGeometryReporter struct {
	GoldenTestReporter
	t    *testing.T
	path string
	done bool
}

func (r *pinnedRawGeometryReporter) SetStatus(s string) {
	if s != "Generating values..." || r.done {
		return
	}
	r.done = true
	if err := os.Rename(r.path, r.path+".selected"); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(r.path, []byte("foreign replacement"), 0o600); err != nil {
		r.t.Fatal(err)
	}
}

func TestLegacyPinnedRawGeometrySurvivesPathReplacement(t *testing.T) {
	previous := deriveVolumeKey
	deriveVolumeKey = func([]byte, []byte, bool) ([]byte, error) { return make([]byte, 32), nil }
	defer func() { deriveVolumeKey = previous }()
	for _, rs := range []bool{false, true} {
		t.Run(map[bool]string{false: "nonRS", true: "RS"}[rs], func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "selected")
			target := source + ".pcv"
			plain := bytes.Repeat([]byte("x"), (1<<20)-1)
			if err := os.WriteFile(source, plain, 0o600); err != nil {
				t.Fatal(err)
			}
			codecs, err := encoding.NewRSCodecs()
			if err != nil {
				t.Fatal(err)
			}
			report := &pinnedRawGeometryReporter{t: t, path: source}
			if err := Encrypt(context.Background(), &EncryptRequest{InputFile: source, OutputFile: target, Password: []byte("public-test-password"), ReedSolomon: rs, Reporter: report, RSCodecs: codecs}); err != nil {
				t.Fatal(err)
			}
			h := readVolumeHeader(t, target)
			t.Logf("RS=%v Padded=%v output successfully published", rs, h.Flags.Padded)
			for path, want := range map[string][]byte{source: []byte("foreign replacement"), source + ".selected": plain} {
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("source changed %s: %v", path, err)
				}
			}
			out := filepath.Join(dir, "restored")
			err = Decrypt(context.Background(), &DecryptRequest{InputFile: target, OutputFile: out, Password: []byte("public-test-password"), RSCodecs: codecs})
			if err != nil {
				t.Fatalf("published volume cannot restore pinned selected bytes: %v", err)
			}
			got, err := os.ReadFile(out)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("roundtrip mismatch: %v len=%d want=%d", err, len(got), len(plain))
			}
		})
	}
}
