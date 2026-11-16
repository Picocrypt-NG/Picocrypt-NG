package volume

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyDecryptReturnsFormatLimitationsWithoutChangingCompatibility(t *testing.T) {
	restore := useProductionTestKDF()
	defer restore()
	for _, test := range []struct {
		name, file, version string
		warning             header.LegacySecurityWarning
		keyfiles            []string
	}{
		{"v1", "pico_test_v1.txt.pcv", "v1.49", header.LegacyUnauthenticatedHeader, nil},
		{"v2", "pico_test_v2.txt.pcv", "v2.00", "", nil},
		{"v2 keyfile", "pico_test_v2_keyfile_single.txt.pcv", "v2.08", header.LegacyPasswordOnlyAuthentication, []string{"keyfile_alpha.bin"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			rs, err := encoding.NewRSCodecs()
			if err != nil {
				t.Fatal(err)
			}
			metadata := header.LegacyMetadata{Version: "stale", CommentAuthenticity: header.CommentAuthenticated}
			root := findTestdata(t)
			output := filepath.Join(t.TempDir(), "plaintext")
			err = Decrypt(context.Background(), &DecryptRequest{InputFile: filepath.Join(root, test.file), OutputFile: output, Password: []byte("test"), Keyfiles: goldenFixturePaths(root, test.keyfiles), RSCodecs: rs, LegacyMetadata: &metadata})
			if err != nil {
				t.Fatal(err)
			}
			assertFileBytes(t, output, []byte(expectedContent))
			if metadata.Version != test.version || metadata.SecurityWarning != test.warning || metadata.CommentAuthenticity != header.CommentUnavailable {
				t.Fatalf("wrong legacy result metadata: %+v", metadata)
			}
		})
	}
}

func TestLegacyMetadataFromEarlierOperationCannotSurviveRefusal(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		metadata := header.LegacyMetadata{Version: "v2.19", CommentAuthenticity: header.CommentAuthenticated}
		req := &DecryptRequest{InputFile: filepath.Join(t.TempDir(), "missing.pcv"), OutputFile: filepath.Join(t.TempDir(), "output"), Password: []byte("test"), LegacyMetadata: &metadata}
		var err error
		if prepared {
			err = DecryptPrepared(context.Background(), req, nil)
		} else {
			err = Decrypt(context.Background(), req)
		}
		if err == nil {
			t.Fatal("expected refused input")
		}
		if metadata != (header.LegacyMetadata{}) {
			t.Fatalf("refusal retained earlier authentication metadata: %+v", metadata)
		}
	}
}

func TestLegacyCommentTrustRequiresSuccessfulHeaderAuthentication(t *testing.T) {
	dir := t.TempDir()
	source, encrypted := filepath.Join(dir, "source"), filepath.Join(dir, "source.pcv")
	if err := os.WriteFile(source, []byte("metadata boundary fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatal(err)
	}
	if err := Encrypt(context.Background(), &EncryptRequest{InputFile: source, OutputFile: encrypted, Password: []byte("correct"), Comments: "actual read comment", RSCodecs: rs}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, password         string
		force, wantError, kept bool
		trust                  header.CommentAuthenticity
	}{
		{"ordinary authenticated", "correct", false, false, false, header.CommentAuthenticated},
		{"force authenticated", "correct", true, false, false, header.CommentAuthenticated},
		{"wrong password", "wrong", false, true, false, ""},
		{"forced header bypass", "wrong", true, false, true, header.CommentUnverified},
	} {
		t.Run(test.name, func(t *testing.T) {
			metadata := header.LegacyMetadata{Version: "stale", CommentAuthenticity: header.CommentAuthenticated}
			kept := false
			output := filepath.Join(t.TempDir(), "output")
			err := Decrypt(context.Background(), &DecryptRequest{InputFile: encrypted, OutputFile: output, Password: []byte(test.password), ForceDecrypt: test.force, RSCodecs: rs, Kept: &kept, LegacyMetadata: &metadata})
			if (err != nil) != test.wantError {
				t.Fatalf("unexpected outcome: %v", err)
			}
			if kept != test.kept || metadata.CommentAuthenticity != test.trust {
				t.Fatalf("wrong trust kept=%v metadata=%+v", kept, metadata)
			}
			if test.wantError {
				if metadata != (header.LegacyMetadata{}) {
					t.Fatal("failure released earlier metadata")
				}
				if _, err := os.Lstat(output); !os.IsNotExist(err) {
					t.Fatalf("failure published output: %v", err)
				}
			} else if !kept {
				assertFileBytes(t, output, []byte("metadata boundary fixture"))
			}
		})
	}
}
