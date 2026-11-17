package mobile

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyMetadataPreviewNeverClaimsCommentAuthentication(t *testing.T) {
	for _, version := range []string{"v1.33", "v2.00"} {
		for _, comment := range []string{"unverified metadata", ""} {
			t.Run(version+"/"+comment, func(t *testing.T) {
				rs, err := encoding.NewRSCodecs()
				if err != nil {
					t.Fatal(err)
				}
				h := header.NewVolumeHeader(make([]byte, header.SaltSize), make([]byte, header.HKDFSaltSize), make([]byte, header.SerpentIVSize), make([]byte, header.NonceSize))
				h.Version, h.Comments = version, comment
				var data bytes.Buffer
				if _, err := header.NewWriter(&data, rs).WriteHeader(h); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "preview.pcv")
				if err := os.WriteFile(path, data.Bytes(), 0o600); err != nil {
					t.Fatal(err)
				}
				preview, err := GetDecryptionInfo(path)
				if err != nil {
					t.Fatal(err)
				}
				var got map[string]any
				if err := json.Unmarshal([]byte(preview), &got); err != nil {
					t.Fatal(err)
				}
				if got["comments"] != comment || got["readable"] != true {
					t.Fatalf("lost readable preview: %s", preview)
				}
				want := "unverified"
				if comment == "" {
					want = "unavailable"
				}
				if got["version"] != version || got["commentAuthenticity"] != want {
					t.Fatalf("preview must identify its format and unverified comment: %s", preview)
				}
			})
		}
	}
}
