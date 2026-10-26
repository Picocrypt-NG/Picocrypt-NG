//go:build js && wasm && pcv3_production_kdf

package main

import (
	"bytes"
	"syscall/js"
	"testing"
)

func TestBridgePCV3Unicode18NormalAndD1(t *testing.T) {
	// U+20C2 is new in Unicode 18. The suffix and its independent NFC
	// expectation come from NormalizationTest-18.0.0.txt line 18205.
	const password = "unicode18-\u20C2-a\u0315\u0300\u05AE\u1ADEb"
	const canonicalPassword = "unicode18-\u20C2-\u00E0\u05AE\u1ADE\u0315b"
	payload := []byte("Unicode 18 browser credential\x00payload")
	for _, mode := range []struct {
		name        string
		deniability bool
		readMode    int
	}{
		{"normal", false, 1},
		{"d1", true, 2},
	} {
		t.Run(mode.name, func(t *testing.T) {
			created := encrypt(js.Undefined(), []js.Value{newOpts(map[string]any{
				"data": mkU8Den(payload), "password": password, "deniability": mode.deniability,
			})})
			if codeOf(created) != 0 {
				t.Fatalf("Unicode-18 %s browser write code=%d", mode.name, codeOf(created))
			}
			opened := decrypt(js.Undefined(), []js.Value{newOpts(map[string]any{
				"data": mkU8Den(bytesOf(created)), "password": canonicalPassword, "pcv3Mode": mode.readMode,
			})})
			if codeOf(opened) != 0 || !bytes.Equal(bytesOf(opened), payload) {
				t.Fatalf("Unicode-18 %s browser NFC-equivalent read code=%d", mode.name, codeOf(opened))
			}
		})
	}
}
