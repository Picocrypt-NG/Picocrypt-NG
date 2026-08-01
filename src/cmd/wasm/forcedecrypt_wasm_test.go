//go:build js && wasm

package main

import (
	"Picocrypt-NG/internal/header"
	"syscall/js"
	"testing"
)

func mkU8FD(b []byte) js.Value {
	u := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(u, b)
	return u
}

func bytesOf(v any) []byte {
	jv := v.(js.Value)
	d := jv.Get("data")
	if d.Type() != js.TypeObject {
		return nil
	}
	out := make([]byte, d.Get("length").Int())
	js.CopyBytesToGo(out, d)
	return out
}

// forceDecrypt:true over a tampered volume must return code 10 WITH data; the same
// volume with force off returns code 4 (no data). Proves the bridge forwards the
// flag and special-cases the kept code to carry bytes.
func TestBridgeForceDecryptKeepsDataCode10(t *testing.T) {
	plaintext := []byte("bridge force decrypt payload, long enough")
	password := "bridge-force-pw"

	enc := encrypt(js.Undefined(), []js.Value{newOpts(map[string]any{
		"data": mkU8FD(plaintext), "password": password,
	})})
	if codeOf(enc) != 0 {
		t.Fatalf("encrypt code %d", codeOf(enc))
	}
	vol := bytesOf(enc)
	vol[header.HeaderSize(0)+3] ^= 0xFF // break the MAC

	off := decrypt(js.Undefined(), []js.Value{newOpts(map[string]any{
		"data": mkU8FD(vol), "password": password,
	})})
	if codeOf(off) != 4 {
		t.Fatalf("force=off: code %d, want 4", codeOf(off))
	}

	on := decrypt(js.Undefined(), []js.Value{newOpts(map[string]any{
		"data": mkU8FD(vol), "password": password, "forceDecrypt": true,
	})})
	if codeOf(on) != 10 {
		t.Fatalf("force=on: code %d, want 10", codeOf(on))
	}
	got := bytesOf(on)
	if len(got) != len(plaintext) {
		t.Fatalf("kept data len %d, want %d", len(got), len(plaintext))
	}
	// Anti-vacuity: exactly the flipped byte differs.
	for i := range plaintext {
		want := plaintext[i]
		if i == 3 {
			want ^= 0xFF
		}
		if got[i] != want {
			t.Fatalf("kept byte %d = %#x, want %#x", i, got[i], want)
		}
	}
}
