//go:build js && wasm && pcv3_production_kdf

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"syscall/js"
	"testing"
)

func frozenBrowserFile(t *testing.T, name, checksum string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "pcv3operation", "internal", "pcv3", "testdata", "d1", "independent", name))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if checksum != "" && hex.EncodeToString(sum[:]) != checksum {
		t.Fatalf("independent fixture checksum changed: %s", name)
	}
	return data
}

func TestBridgeIndependentPCV3ProductionFixtures(t *testing.T) {
	for _, test := range []struct {
		name, checksum string
		mode           int
	}{
		{"normal.pcv", "a468f66c81849b03c58312acf7f2f90677e317ad200820e90ec38da5b0459bcb", 0},
		{"d1-standard.pcv", "22fda4fbe068d85f41d8fe22857320172c67fc5ba806823ce57bdd1072b113bf", 2},
		{"d1.pcv", "487a18056597d97e36ebcaf70aed25ec9cdbd306803ebaf618eba186e05d00bd", 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			keys := js.Global().Get("Array").New()
			keys.Call("push", mkU8Den(frozenBrowserFile(t, "keyfile-alpha.bin", "2300d62bf2bb24b5cfd294337ce09e851b99f1f1598c17bd3c064c221991e7e1")))
			keys.Call("push", mkU8Den(frozenBrowserFile(t, "keyfile-beta.bin", "2e2004c7040e3d7e85819090bcfbcd4beb0774772019ef021c5db566b057ae48")))
			opts := newOpts(map[string]any{
				"data":     mkU8Den(frozenBrowserFile(t, test.name, test.checksum)),
				"password": string(frozenBrowserFile(t, "password.bin", "e56cef65373463f9559e0f852b508b4fdb6af16b8a57c73f2a20bcc6f2a5e4f3")), "keyfiles": keys, "keyfileOrdered": true,
			})
			if test.mode != 0 {
				opts.Set("pcv3Mode", test.mode)
			}
			result := decrypt(js.Undefined(), []js.Value{opts})
			want := frozenBrowserFile(t, "plaintext.bin", "42ae995f0c0b4be8883494e43a5ebb425bbd7e70407c6316a2bbc2069299c93b")
			if codeOf(result) != 0 || !bytes.Equal(bytesOf(result), want) {
				t.Fatalf("independent browser read: code=%d", codeOf(result))
			}
		})
	}
}

func TestBridgeEmptyPCV3ProductionRoundTrip(t *testing.T) {
	result := encrypt(js.Undefined(), []js.Value{newOpts(map[string]any{"data": mkU8Den(nil), "password": "empty payload contract"})})
	if codeOf(result) != 0 {
		t.Fatalf("empty creation code=%d", codeOf(result))
	}
	volume := bytesOf(result)
	if len(volume) < 16 || !bytes.Equal(volume[:4], []byte{'P', 'C', 'V', 0}) {
		t.Fatal("empty writer lost PCV3 framing")
	}
	opened := decrypt(js.Undefined(), []js.Value{newOpts(map[string]any{"data": mkU8Den(volume), "password": "empty payload contract"})})
	if codeOf(opened) != 0 || len(bytesOf(opened)) != 0 {
		t.Fatalf("empty volume did not authenticate: code=%d", codeOf(opened))
	}
}

func TestBridgePCV3FinalDamageNeverPublishesPlaintext(t *testing.T) {
	volume := frozenBrowserFile(t, "normal.pcv", "a468f66c81849b03c58312acf7f2f90677e317ad200820e90ec38da5b0459bcb")
	volume[len(volume)-1008-1] ^= 0x80
	keys := js.Global().Get("Array").New()
	keys.Call("push", mkU8Den(frozenBrowserFile(t, "keyfile-alpha.bin", "2300d62bf2bb24b5cfd294337ce09e851b99f1f1598c17bd3c064c221991e7e1")))
	keys.Call("push", mkU8Den(frozenBrowserFile(t, "keyfile-beta.bin", "2e2004c7040e3d7e85819090bcfbcd4beb0774772019ef021c5db566b057ae48")))
	opts := newOpts(map[string]any{"data": mkU8Den(volume), "password": string(frozenBrowserFile(t, "password.bin", "e56cef65373463f9559e0f852b508b4fdb6af16b8a57c73f2a20bcc6f2a5e4f3")), "keyfiles": keys, "keyfileOrdered": true})
	result := decrypt(js.Undefined(), []js.Value{opts}).(js.Value)
	if codeOf(result) != 4 || !result.Get("data").IsUndefined() || !result.Get("comments").IsUndefined() {
		t.Fatal("failed final authentication exposed plaintext or metadata")
	}
	opts.Set("forceDecrypt", true)
	forced := decrypt(js.Undefined(), []js.Value{opts})
	if codeOf(forced) != 10 || !bytes.Equal(bytesOf(forced), frozenBrowserFile(t, "plaintext.bin", "42ae995f0c0b4be8883494e43a5ebb425bbd7e70407c6316a2bbc2069299c93b")) {
		t.Fatal("explicit Force lost recoverable data or labeled incomplete authentication successful")
	}
}

func TestBridgeLegacyV1ProductionFixture(t *testing.T) {
	volume, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "pico_test_v1.txt.pcv"))
	if err != nil {
		t.Fatal(err)
	}
	result := decrypt(js.Undefined(), []js.Value{newOpts(map[string]any{"data": mkU8Den(volume), "password": "test"})})
	if codeOf(result) != 0 || !bytes.Equal(bytesOf(result), []byte("There is a test file for Picocrypt validation.\n")) {
		t.Fatalf("legacy v1 bridge read code=%d", codeOf(result))
	}
}
