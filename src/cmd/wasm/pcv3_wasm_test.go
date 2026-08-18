//go:build js && wasm

package main

import (
	"Picocrypt-NG/internal/pcv3operation"
	"reflect"
	"syscall/js"
	"testing"
)

// installCountingGetter defines an accessor property that records every read
// in log before yielding value. An untouched log proves a rejection path never
// read the data, credential, or option property it guards.
func installCountingGetter(t *testing.T, obj, log js.Value, name string, value js.Value) {
	t.Helper()
	getter := js.FuncOf(func(this js.Value, args []js.Value) any {
		log.Call("push", name)
		return value
	})
	t.Cleanup(getter.Release)
	descriptor := js.Global().Get("Object").New()
	descriptor.Set("get", getter.Value)
	js.Global().Get("Object").Call("defineProperty", obj, name, descriptor)
}

func loggedReads(log js.Value) []string {
	reads := make([]string, log.Length())
	for i := range reads {
		reads[i] = log.Index(i).String()
	}
	return reads
}

// observeCopySizes swaps the JS-to-Go copy seam with a size recorder until the
// test ends.
func observeCopySizes(t *testing.T) *[]int {
	t.Helper()
	copySizes := []int{}
	previousCopy := copyBytesFromJS
	copyBytesFromJS = func(dst []byte, src js.Value) int {
		copySizes = append(copySizes, len(dst))
		return previousCopy(dst, src)
	}
	t.Cleanup(func() { copyBytesFromJS = previousCopy })
	return &copySizes
}

// requireUnsupportedCodeOnly requires the stable code-only unsupported result:
// exactly one enumerable "code" key with the numeric unsupported value and no
// data, comments, or metadata properties.
func requireUnsupportedCodeOnly(t *testing.T, got any) {
	t.Helper()
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
}

// pseudoRandomBytes is a deterministic random-looking fill. Its first bytes
// (7, 38, 69, 100) never form the normal PCV discriminator.
func pseudoRandomBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31 + 7)
	}
	return b
}

func TestBridgePCV3UnsupportedBeforeKDF(t *testing.T) {
	for _, tc := range []struct {
		name  string
		force bool
	}{
		{name: "without force"},
		{name: "with force", force: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			volume := js.Global().Get("Uint8Array").New(64 * 1024)
			js.CopyBytesToJS(volume.Call("subarray", 0, 4), []byte{'P', 'C', 'V', 0})

			reads := js.Global().Get("Array").New()
			opts := js.Global().Get("Object").New()
			opts.Set("data", volume)
			// Credential and option properties must stay unread on this path;
			// force in particular can never force a claimed PCV3 volume through.
			for _, property := range []string{"password", "keyfiles", "forceDecrypt", "comments", "metadata"} {
				installCountingGetter(t, opts, reads, property, js.Undefined())
			}

			copySizes := observeCopySizes(t)

			requireUnsupportedCodeOnly(t, decrypt(js.Undefined(), []js.Value{opts}))

			if got := loggedReads(reads); len(got) != 0 {
				t.Fatalf("decrypt() read credential/option properties %v on the normal-PCV3 rejection path", got)
			}
			if len(*copySizes) != 1 || (*copySizes)[0] != 4 {
				t.Fatalf("decrypt() JS-to-Go copy sizes = %v; want only the fixed 4-byte routing prefix", *copySizes)
			}
		})
	}
}

// Explicit PCV3 operation intent is rejected before the bridge reads data,
// credentials, options, or copies a single byte; the closed Phase 8 operation
// mode discriminator is the only property consumed.
func TestBridgeExplicitPCV3IntentRejectsBeforeData(t *testing.T) {
	modes := []struct {
		name string
		mode pcv3operation.Mode
	}{
		{"read-normal", pcv3operation.ModeReadNormal},
		{"read-d1", pcv3operation.ModeReadD1},
		{"recover-normal", pcv3operation.ModeRecoverNormal},
		{"recover-d1", pcv3operation.ModeRecoverD1},
		{"force-normal", pcv3operation.ModeForceNormal},
		{"force-d1", pcv3operation.ModeForceD1},
		{"force-unverified-normal", pcv3operation.ModeForceUnverifiedNormal},
		{"force-unverified-d1", pcv3operation.ModeForceUnverifiedD1},
		{"migrate", pcv3operation.ModeMigrate},
	}
	for _, tc := range modes {
		t.Run(tc.name, func(t *testing.T) {
			// D1 volumes are deliberately random-looking, so the data below
			// carries no recognizable claim; intent alone must drive rejection.
			volume := js.Global().Get("Uint8Array").New(64 * 1024)
			js.CopyBytesToJS(volume, pseudoRandomBytes(64*1024))

			reads := js.Global().Get("Array").New()
			opts := js.Global().Get("Object").New()
			opts.Set("pcv3Mode", int(tc.mode))
			for _, property := range []string{"data", "password", "keyfiles", "forceDecrypt", "comments", "metadata"} {
				installCountingGetter(t, opts, reads, property, js.Undefined())
			}

			copySizes := observeCopySizes(t)

			requireUnsupportedCodeOnly(t, decrypt(js.Undefined(), []js.Value{opts}))

			if got := loggedReads(reads); len(got) != 0 {
				t.Fatalf("decrypt() read properties %v despite explicit PCV3 intent; want rejection before any data/credential access", got)
			}
			if len(*copySizes) != 0 {
				t.Fatalf("decrypt() JS-to-Go copy sizes = %v; explicit intent must reject before any byte copy", *copySizes)
			}
		})
	}
}

// Random-looking input without explicit intent keeps the existing legacy
// behavior: it is never labeled D1 or rejected as PCV3 by content. A large
// random-looking buffer is exactly what a deniable wrapper looks like, so the
// legacy bridge probes it with the supplied password and reports the existing
// wrong-password outcome — never the PCV3 unsupported code.
func TestBridgeRandomLookingInputDoesNotSelectD1(t *testing.T) {
	volume := js.Global().Get("Uint8Array").New(64 * 1024)
	js.CopyBytesToJS(volume, pseudoRandomBytes(64*1024))

	reads := js.Global().Get("Array").New()
	opts := js.Global().Get("Object").New()
	installCountingGetter(t, opts, reads, "data", volume)
	installCountingGetter(t, opts, reads, "password", js.ValueOf("irrelevant"))
	installCountingGetter(t, opts, reads, "keyfiles", js.Global().Get("Array").New())
	installCountingGetter(t, opts, reads, "forceDecrypt", js.ValueOf(false))

	copySizes := observeCopySizes(t)

	got := decrypt(js.Undefined(), []js.Value{opts})
	result, ok := got.(js.Value)
	if !ok || result.Type() != js.TypeObject {
		t.Fatalf("decrypt() result = %T; want JavaScript object", got)
	}
	code := result.Get("code")
	if code.Type() != js.TypeNumber || code.Int() != 3 {
		t.Fatalf("decrypt() code = %v; want the legacy wrong-password code (3), never the PCV3 unsupported code", code)
	}
	keys := js.Global().Get("Object").Call("keys", result)
	if keys.Length() != 1 || keys.Index(0).String() != "code" {
		gotKeys := make([]string, keys.Length())
		for i := range keys.Length() {
			gotKeys[i] = keys.Index(i).String()
		}
		t.Fatalf("decrypt() enumerable keys = %v; want [code]", gotKeys)
	}

	wantReads := map[string]int{"data": 1, "password": 1, "keyfiles": 1, "forceDecrypt": 1}
	gotReads := map[string]int{}
	for _, name := range loggedReads(reads) {
		gotReads[name]++
	}
	if !reflect.DeepEqual(gotReads, wantReads) {
		t.Fatalf("decrypt() property reads = %v; want the full legacy read set %v", gotReads, wantReads)
	}
	if len(*copySizes) != 2 || (*copySizes)[0] != 4 || (*copySizes)[1] != 64*1024 {
		t.Fatalf("decrypt() JS-to-Go copy sizes = %v; want the legacy 4-byte probe plus the full-volume copy", *copySizes)
	}
}
