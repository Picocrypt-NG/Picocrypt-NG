//go:build js && wasm

package main

import (
	"os"
	"path/filepath"
	"syscall/js"
	"testing"
)

func TestBridgeLegacyResultsExposeFormatAndCommentTrust(t *testing.T) {
	requireWASMProductionKDF(t)
	for _, test := range []struct{ name, file, version, warning string }{
		{"v1", "pico_test_v1.txt.pcv", "v1.49", "LEGACY_V1_UNAUTHENTICATED_HEADER"},
		{"v2", "pico_test_v2.txt.pcv", "v2.00", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", test.file))
			if err != nil {
				t.Fatal(err)
			}
			result := decrypt(js.Undefined(), []js.Value{newOpts(map[string]any{"data": mkU8FD(data), "password": "test"})}).(js.Value)
			if codeOf(result) != 0 || len(bytesOf(result)) == 0 {
				t.Fatalf("compatibility read failed: %d", codeOf(result))
			}
			if result.Get("version").String() != test.version || result.Get("commentAuthenticity").String() != "unavailable" || result.Get("securityWarning").String() != test.warning {
				t.Fatalf("bridge lost metadata: version=%s trust=%s warning=%s", result.Get("version"), result.Get("commentAuthenticity"), result.Get("securityWarning"))
			}
		})
	}
}
