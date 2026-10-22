//go:build js && wasm

package main

import (
	"Picocrypt-NG/internal/pcv3operation"
	"math"
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

func TestBridgeUnknownPCVMajorRejectsBeforeCredentialsAndWholeCopy(t *testing.T) {
	volume := js.Global().Get("Uint8Array").New(64 * 1024)
	js.CopyBytesToJS(volume.Call("subarray", 0, 6), []byte{'P', 'C', 'V', 0, 255, 255})
	reads := js.Global().Get("Array").New()
	opts := newOpts(map[string]any{"data": volume})
	for _, name := range []string{"password", "keyfiles", "forceDecrypt", "comments", "metadata"} {
		installCountingGetter(t, opts, reads, name, js.Undefined())
	}
	copies := observeCopySizes(t)
	requireUnsupportedCodeOnly(t, decrypt(js.Undefined(), []js.Value{opts}))
	if len(loggedReads(reads)) != 0 {
		t.Fatal("unknown format accessed credentials or options")
	}
	total := 0
	for _, n := range *copies {
		total += n
	}
	if total > 20 {
		t.Fatalf("unknown-major routing copied %d bytes, want only bounded preamble", total)
	}
}

func TestBridgeExplicitUnverifiedForceRequiresConsentAndRoleBeforeData(t *testing.T) {
	for _, mode := range []pcv3operation.Mode{pcv3operation.ModeForceUnverifiedNormal, pcv3operation.ModeForceUnverifiedD1} {
		for _, fields := range []map[string]any{{}, {"pcv3ForceUnverifiedConsent": true}, {"pcv3ForceUnverifiedConsent": true, "pcv3Role": 257}, {"pcv3ForceUnverifiedConsent": true, "pcv3Role": 0.5}} {
			fields["pcv3Mode"] = int(mode)
			opts := newOpts(fields)
			reads := js.Global().Get("Array").New()
			installCountingGetter(t, opts, reads, "data", js.Undefined())
			copies := observeCopySizes(t)
			if codeOf(decrypt(js.Undefined(), []js.Value{opts})) != errInvalidArg || len(loggedReads(reads)) != 0 || len(*copies) != 0 {
				t.Fatal("unverified Force accessed input without valid physical consent")
			}
		}
	}
}

func TestBridgeRejectsMalformedModeBeforeData(t *testing.T) {
	for _, mode := range []float64{257, -255, 1.5, 255, math.NaN(), math.Inf(1), 1 << 53} {
		opts := newOpts(map[string]any{"pcv3Mode": mode})
		reads := js.Global().Get("Array").New()
		installCountingGetter(t, opts, reads, "data", js.Undefined())
		if codeOf(decrypt(js.Undefined(), []js.Value{opts})) != errInvalidArg || len(loggedReads(reads)) != 0 {
			t.Fatal("malformed mode was narrowed or accessed data")
		}
	}
}

func TestBridgeCapabilitiesAndPrecopyResourceBounds(t *testing.T) {
	caps := capabilities(js.Undefined(), nil).(js.Value)
	if !caps.Get("pcv3").Bool() || caps.Get("apiVersion").Int() != 3 || caps.Get("maxKeyfileBytes").Int() != pcv3operation.BrowserMaxKeyfileBytes {
		t.Fatal("capability contract changed")
	}
	oversized := js.Global().Get("Uint8Array").New(pcv3operation.BrowserMaxPlaintextBytes + 1)
	opts := newOpts(map[string]any{"data": oversized})
	reads := js.Global().Get("Array").New()
	installCountingGetter(t, opts, reads, "password", js.Undefined())
	copies := observeCopySizes(t)
	if codeOf(encrypt(js.Undefined(), []js.Value{opts})) != 14 || len(loggedReads(reads)) != 0 || len(*copies) != 0 {
		t.Fatal("oversized plaintext reached a whole-file copy or credential getter")
	}
	keys := js.Global().Get("Array").New()
	backing := js.Global().Get("Uint8Array").New((pcv3operation.BrowserMaxKeyfileBytes / 2) + 1)
	keys.Call("push", backing, backing)
	opts = newOpts(map[string]any{"data": mkU8Den([]byte("x")), "password": "pw", "keyfiles": keys})
	if codeOf(encrypt(js.Undefined(), []js.Value{opts})) != 14 || len(*copies) != 0 {
		t.Fatal("aggregate keyfile overflow reached a Go input copy")
	}
}

func TestBridgePCV3EmptyKeyfileRejectsBeforeWholeCopy(t *testing.T) {
	for _, decrypting := range []bool{false, true} {
		keys := js.Global().Get("Array").New()
		keys.Call("push", mkU8Den(nil))
		opts := newOpts(map[string]any{"data": mkU8Den([]byte("payload")), "password": "pw", "keyfiles": keys})
		callback := encrypt
		if decrypting {
			callback = decrypt
			opts.Set("pcv3Mode", int(pcv3operation.ModeReadD1))
		}
		copies := observeCopySizes(t)
		if codeOf(callback(js.Undefined(), []js.Value{opts})) != errInvalidArg {
			t.Fatal("PCV3 accepted an empty keyfile")
		}
		for _, n := range *copies {
			if n > 4 {
				t.Fatal("empty PCV3 keyfile reached a whole-input copy")
			}
		}
	}
}

func TestBridgeSharedStorageRejectsBeforeCredentialAccess(t *testing.T) {
	shared := js.Global().Get("SharedArrayBuffer")
	if shared.Type() != js.TypeFunction {
		t.Skip("SharedArrayBuffer unavailable in this runtime")
	}
	data := js.Global().Get("Uint8Array").New(shared.New(8))
	for _, callback := range []func(js.Value, []js.Value) any{encrypt, decrypt} {
		opts := newOpts(map[string]any{"data": data})
		reads := js.Global().Get("Array").New()
		installCountingGetter(t, opts, reads, "password", js.ValueOf("pw"))
		copies := observeCopySizes(t)
		if codeOf(callback(js.Undefined(), []js.Value{opts})) != errInvalidArg || len(loggedReads(reads)) != 0 || len(*copies) != 0 {
			t.Fatal("shared storage reached a credential getter or input copy")
		}
	}
}

func TestBridgeInputGetterCannotReenterEitherOperation(t *testing.T) {
	for _, outer := range []func(js.Value, []js.Value) any{encrypt, decrypt} {
		for _, inner := range []func(js.Value, []js.Value) any{encrypt, decrypt} {
			innerReads := js.Global().Get("Array").New()
			innerOpts := newOpts(nil)
			installCountingGetter(t, innerOpts, innerReads, "data", js.Undefined())
			innerCode := -1
			innerExport := js.FuncOf(inner)
			t.Cleanup(innerExport.Release)
			reenter := js.FuncOf(func(js.Value, []js.Value) any {
				innerCode = codeOf(innerExport.Invoke(innerOpts))
				return nil
			})
			t.Cleanup(reenter.Release)
			getter := js.Global().Get("Function").New("reenter", "return function(){ reenter(); throw new Error('outer getter failed'); }").Invoke(reenter)
			opts := newOpts(map[string]any{"data": mkU8Den([]byte{1, 2, 3})})
			js.Global().Get("Object").Call("defineProperty", opts, "password", newOpts(map[string]any{"get": getter}))
			copies := observeCopySizes(t)
			result := outer(js.Undefined(), []js.Value{opts})
			if codeOf(result) != errInvalidArg || innerCode != errInvalidArg || len(loggedReads(innerReads)) != 0 || len(*copies) != 0 {
				t.Fatal("reentrant input getter reached another operation's input or copy boundary")
			}
			// The throwing outer getter must release the guard for later calls.
			inner(js.Undefined(), []js.Value{innerOpts})
			if len(loggedReads(innerReads)) != 1 {
				t.Fatal("operation guard remained set after a throwing getter")
			}
		}
	}
}

// Random-looking input without explicit intent keeps the existing legacy
// behavior: it is never labeled D1 or rejected as PCV3 by content. A large
// random-looking buffer is exactly what a deniable wrapper looks like, so the
// legacy bridge probes it with the supplied password and reports the existing
// wrong-password outcome — never the PCV3 unsupported code.
func TestBridgeRandomLookingInputDoesNotSelectD1(t *testing.T) {
	requireWASMProductionKDF(t)
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
