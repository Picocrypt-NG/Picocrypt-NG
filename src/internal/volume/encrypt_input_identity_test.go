package volume

import (
	"Picocrypt-NG/internal/fileops"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestPreparedEncryptInputChecksIdentityAndPreservesBorrowedDescriptorOwnership(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "selected")
	foreign := filepath.Join(dir, "foreign")
	for path, value := range map[string]string{source: "selected contents", foreign: "unintended secret"} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	identity, err := fileops.CaptureZIPInput(source, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{source, foreign} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			borrowed, err := fileops.OpenRegularReadNoSymlink(path)
			if err != nil {
				t.Fatal(err)
			}
			defer borrowed.Close()
			prepared, err := PrepareEncryptInput(context.Background(), EncryptInputRequest{
				InputFile: source, InputIdentities: []fileops.ZIPInputIdentity{identity},
				OutputFile: filepath.Join(dir, "out.pcv"), BorrowedSource: borrowed,
			})
			if path == source {
				if err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(prepared.Reader())
				if err != nil || string(got) != "selected contents" || prepared.File() != borrowed {
					t.Fatalf("prepared source changed: %q, %v", got, err)
				}
				if err := prepared.Close(); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || prepared != nil {
				t.Fatalf("foreign borrowed descriptor accepted: %v, %v", prepared, err)
			}
			if _, err := borrowed.Stat(); err != nil {
				t.Fatalf("preparation closed caller-owned source: %v", err)
			}
		})
	}
}

func TestLegacyEncryptRejectsSelectionReplacementBeforeKDF(t *testing.T) {
	for _, compress := range []bool{false, true} {
		name := "raw"
		if compress {
			name = "archive"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "selected")
			if err := os.WriteFile(source, []byte("selected contents"), 0o600); err != nil {
				t.Fatal(err)
			}
			identity, err := fileops.CaptureZIPInput(source, false)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(source, source+".selected"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(source, []byte("unintended secret"), 0o600); err != nil {
				t.Fatal(err)
			}
			kdfCalls := 0
			previous := deriveVolumeKey
			deriveVolumeKey = func([]byte, []byte, bool) ([]byte, error) {
				kdfCalls++
				return nil, errors.New("test refuses KDF on replaced input")
			}
			defer func() { deriveVolumeKey = previous }()
			err = Encrypt(context.Background(), &EncryptRequest{
				InputFile: source, InputIdentities: []fileops.ZIPInputIdentity{identity},
				OutputFile: filepath.Join(dir, "out.pcv"), Password: []byte("public-test-password"), Compress: compress,
			})
			if err == nil || kdfCalls != 0 {
				t.Fatalf("replacement reached legacy encryption: %v, KDF calls=%d", err, kdfCalls)
			}
			for path, want := range map[string]string{source: "unintended secret", source + ".selected": "selected contents"} {
				got, err := os.ReadFile(path)
				if err != nil || string(got) != want {
					t.Fatalf("source %s changed: %q, %v", path, got, err)
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 2 {
				t.Fatalf("rejection left output or private stage: %v, %v", entries, err)
			}
		})
	}
}
