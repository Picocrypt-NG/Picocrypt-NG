//go:build js && wasm

package main

import (
	"syscall/js"
	"testing"
)

func TestBridgePCV3UnsupportedBeforeKDF(t *testing.T) {
	for _, tc := range []struct {
		name  string
		force bool
	}{
		{name: "without force"},
		{name: "with force", force: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			volume := js.Global().Get("Uint8Array").New(4)
			js.CopyBytesToJS(volume, []byte{'P', 'C', 'V', 0})
			keyfiles := js.Global().Get("Array").New()
			keyfile := js.Global().Get("Uint8Array").New(18)
			js.CopyBytesToJS(keyfile, []byte("misleading keyfile"))
			keyfiles.Call("push", keyfile)

			got := decrypt(js.Undefined(), []js.Value{newOpts(map[string]any{
				"data":         volume,
				"password":     "misleading password",
				"keyfiles":     keyfiles,
				"forceDecrypt": tc.force,
				"comments":     "must not be returned",
				"metadata":     "must not be returned",
			})})

			result, ok := got.(js.Value)
			if !ok || result.Type() != js.TypeObject {
				t.Fatalf("decrypt() result = %T; want JavaScript object", got)
			}
			code := result.Get("code")
			if code.Type() != js.TypeNumber || code.Int() != 1 {
				t.Fatalf("decrypt() code = %v; want numeric 1", code)
			}

			keys := js.Global().Get("Object").Call("keys", result)
			if keys.Length() != 1 || keys.Index(0).String() != "code" {
				gotKeys := make([]string, keys.Length())
				for i := range keys.Length() {
					gotKeys[i] = keys.Index(i).String()
				}
				t.Fatalf("decrypt() enumerable keys = %v; want [code]", gotKeys)
			}
			for _, property := range []string{"data", "comments", "metadata"} {
				if result.Get(property).Type() != js.TypeUndefined {
					t.Fatalf("decrypt() unexpectedly exposed %q", property)
				}
			}
		})
	}
}
