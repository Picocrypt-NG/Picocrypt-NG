package wasm

import (
	"Picocrypt-NG/internal/crypto"
	"encoding/json"
	"os"
	"testing"
)

func TestLegacyDecryptionReportsCommentTrustAndFormat(t *testing.T) {
	t.Run("v1 frozen compatibility", func(t *testing.T) {
		useProductionTestWASMKDF(t)
		data, err := os.ReadFile("../../testdata/golden/pico_test_v1.txt.pcv")
		if err != nil {
			t.Fatal(err)
		}
		res, code := DecryptVolume(data, []byte("test"), DecryptOptions{})
		if code != 0 {
			t.Fatalf("legacy read failed: %d", code)
		}
		defer crypto.SecureZero(res.Plaintext)
		requireLegacyResultMetadata(t, res, "v1.49", "unavailable", "LEGACY_V1_UNAUTHENTICATED_HEADER")
	})
	t.Run("v2 authenticated comment", func(t *testing.T) {
		data, code := EncryptVolume([]byte("transport fixture"), []byte("test"), EncryptOptions{Comments: "public comment"})
		if code != 0 {
			t.Fatalf("prepare fixture: %d", code)
		}
		res, code := DecryptVolume(data, []byte("test"), DecryptOptions{})
		if code != 0 || res.Comments != "public comment" {
			t.Fatalf("read fixture failed: %d", code)
		}
		defer crypto.SecureZero(res.Plaintext)
		requireLegacyResultMetadata(t, res, "v2.19", "authenticated", "")
	})
}

func requireLegacyResultMetadata(t *testing.T, result DecryptResult, version, trust, warning string) {
	t.Helper()
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got["version"] != version || got["commentAuthenticity"] != trust || got["securityWarning"] != warning {
		t.Fatalf("legacy result lost format/trust: version=%v trust=%v warning=%v; want %q %q %q", got["version"], got["commentAuthenticity"], got["securityWarning"], version, trust, warning)
	}
}
