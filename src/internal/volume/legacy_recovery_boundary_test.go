package volume

import (
	"Picocrypt-NG/internal/header"
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	perrors "Picocrypt-NG/internal/errors"
)

// The finalizer owns publication and extraction; the synthetic decrypted stage
// isolates that boundary from KDF/cipher correctness, covered by golden reads.
func TestLegacyRecoveryNeverAutomaticallyExtractsUnverifiedPlaintext(t *testing.T) {
	for _, sameLevel := range []bool{false, true} {
		for _, mode := range []string{"authenticated", "authenticated_force", "reject", "payload_bypass", "earlier_auth_bypass"} {
			t.Run(fmt.Sprintf("samelevel=%t/%s", sameLevel, mode), func(t *testing.T) {
				dir := t.TempDir()
				source := filepath.Join(dir, "input.pcv")
				original := []byte("encrypted source must survive recovery")
				if err := os.WriteFile(source, original, 0o600); err != nil {
					t.Fatal(err)
				}
				var archive bytes.Buffer
				zw := zip.NewWriter(&archive)
				entry, err := zw.Create("payload.txt")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := entry.Write([]byte("recovered bytes")); err != nil {
					t.Fatal(err)
				}
				if err := zw.Close(); err != nil {
					t.Fatal(err)
				}
				output := filepath.Join(dir, "recovered.zip")
				ctx := legacyResourceFinalizeContext(t, output, archive.Bytes())
				ctx.protectedInputInfos = []os.FileInfo{mustStatRecoverySource(t, source)}
				if mode == "reject" || mode == "payload_bypass" {
					ctx.Header.AuthTag[0] ^= 0x80
				}
				ctx.Kept = mode == "earlier_auth_bypass"
				kept := ctx.Kept
				err = decryptFinalize(ctx, &DecryptRequest{InputFile: source, OutputFile: output, ForceDecrypt: mode != "authenticated" && mode != "reject", AutoUnzip: true, SameLevel: sameLevel, Kept: &kept})
				root := filepath.Join(dir, "recovered")
				if sameLevel {
					root = dir
				}
				extracted := filepath.Join(root, "payload.txt")
				switch mode {
				case "reject":
					if !errors.Is(err, perrors.ErrCorruptData) {
						t.Fatalf("MAC refusal = %v", err)
					}
				case "payload_bypass", "earlier_auth_bypass":
					if err != nil || !kept || !ctx.Kept {
						t.Fatalf("recovery trust: kept=%t context=%t err=%v", kept, ctx.Kept, err)
					}
					assertFileBytes(t, output, archive.Bytes())
				default:
					if err != nil || kept || ctx.Kept {
						t.Fatalf("authenticated result: kept=%t err=%v", kept, err)
					}
					assertFileBytes(t, extracted, []byte("recovered bytes"))
				}
				if mode == "reject" || ctx.Kept {
					if _, err := os.Lstat(extracted); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("unverified/refused output extracted content: %v", err)
					}
					if !sameLevel {
						if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
							t.Fatalf("unverified/refused output created extraction directory: %v", err)
						}
					}
				}
				if mode == "reject" {
					if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("MAC refusal published output: %v", err)
					}
				}
				if err := ctx.Close(); err != nil {
					t.Fatal(err)
				}
				assertNoPicocryptStages(t, dir)
				assertFileBytes(t, source, original)
				if ctx.Kept {
					entries, err := os.ReadDir(dir)
					if err != nil || len(entries) != 2 {
						t.Fatalf("recovery must retain only source and one recovery file: %v %v", entries, err)
					}
				}
			})
		}
	}
}

func mustStatRecoverySource(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestLegacyForcedOutputCloseFailureRetainsArtifactWithoutReleasingMetadata(t *testing.T) {
	dir := t.TempDir()
	source, encrypted, output := filepath.Join(dir, "source"), filepath.Join(dir, "source.pcv"), filepath.Join(dir, "output")
	if err := os.WriteFile(source, []byte("late close failure"), 0o600); err != nil {
		t.Fatal(err)
	}
	codecs := newRSCodecsT(t)
	if err := Encrypt(t.Context(), &EncryptRequest{InputFile: source, OutputFile: encrypted, Password: []byte("test"), RSCodecs: codecs}); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	var retained *os.File
	previous := newPayloadReader
	newPayloadReader = func(reader io.Reader) io.Reader { retained, _ = reader.(*os.File); return reader }
	t.Cleanup(func() { newPayloadReader = previous })
	closed := false
	reporter := &closeLegacyMetadataReporter{closeSource: func() {
		if retained == nil {
			t.Fatal("production legacy reader did not expose prepared source")
		}
		if !closed {
			if err := retained.Close(); err != nil {
				t.Fatal(err)
			}
			closed = true
		}
	}}
	kept := false
	metadata := header.LegacyMetadata{Version: "stale", CommentAuthenticity: header.CommentAuthenticated}
	err = Decrypt(context.Background(), &DecryptRequest{InputFile: encrypted, OutputFile: output, Password: []byte("wrong"), ForceDecrypt: true, RSCodecs: codecs, Reporter: reporter, Kept: &kept, LegacyMetadata: &metadata})
	if !closed || !kept || !errors.Is(err, os.ErrClosed) {
		t.Fatalf("actual forced publication/late-close failure not exercised: closed=%t kept=%t err=%v", closed, kept, err)
	}
	info, statErr := os.Stat(output)
	if statErr != nil || !info.Mode().IsRegular() || info.Size() != int64(len("late close failure")) {
		t.Fatalf("late-close failure lost retained artifact: %v %v", info, statErr)
	}
	if metadata != (header.LegacyMetadata{}) {
		t.Fatalf("failed operation released trust metadata: %+v", metadata)
	}
	assertFileBytes(t, encrypted, original)
	assertNoPicocryptStages(t, dir)
}
