package ui

import (
	"Picocrypt-NG/internal/encoding"
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyDecryptRetainsFrozenSources(t *testing.T) {
	golden := filepath.Join("..", "..", "testdata", "golden")
	want, err := os.ReadFile(filepath.Join(golden, "pico_test.txt"))
	if err != nil {
		t.Fatal(err)
	}
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, fixture        string
		autoUnzip, sameLevel bool
	}{
		{name: "v1", fixture: "pico_test_v1.txt.pcv"},
		{name: "v2", fixture: "pico_test_v2.txt.pcv"},
		{name: "archive", fixture: "pico_test_v2_compress.zip.pcv", autoUnzip: true},
		{name: "same-level archive", fixture: "pico_test_v2_compress.zip.pcv", autoUnzip: true, sameLevel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := os.ReadFile(filepath.Join(golden, tc.fixture))
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			source := filepath.Join(dir, tc.fixture)
			if err := os.WriteFile(source, ciphertext, 0o600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(dir, "output")
			extractTo := output
			if tc.sameLevel {
				output += ".zip"
				extractTo = dir
			}
			a := &App{operationSourceRemover: func(context.Context, deletionSource, bool) error {
				t.Error("legacy decrypt called the encrypted source remover")
				return nil
			}}
			result := a.runCapturedOperation(context.Background(), executeVolumeOperation, nil, operationInput{
				mode: "decrypt", inputFile: source, outputFile: output, password: []byte("test"),
				autoUnzip: tc.autoUnzip, sameLevel: tc.sameLevel, delete: true, rsCodecs: rs,
			})
			if result.err != nil || !result.completed || result.kept || result.cancelled || result.deleteFailed {
				t.Fatalf("legacy decryption failed: %+v", result)
			}

			plaintextPath := output
			if tc.autoUnzip {
				var extracted []string
				err := filepath.WalkDir(extractTo, func(path string, entry fs.DirEntry, walkErr error) error {
					if walkErr != nil {
						return walkErr
					}
					if entry.Type().IsRegular() && entry.Name() == "pico_test.txt" {
						extracted = append(extracted, path)
					}
					return nil
				})
				if err != nil || len(extracted) != 1 {
					t.Fatalf("expected one extracted pico_test.txt, got %v: %v", extracted, err)
				}
				plaintextPath = extracted[0]
			}
			if got, err := os.ReadFile(plaintextPath); err != nil || !bytes.Equal(got, want) {
				t.Fatalf("legacy plaintext changed: %q %v", got, err)
			}
			if got, err := os.ReadFile(source); err != nil || !bytes.Equal(got, ciphertext) {
				t.Fatalf("legacy encrypted source was not retained: %v", err)
			}
		})
	}
}
