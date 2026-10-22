//go:build js && wasm

package main

import (
	"Picocrypt-NG/internal/pcv3operation"
	internalwasm "Picocrypt-NG/internal/wasm"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall/js"
	"testing"
)

// Pins the bridge error code: non-zero and distinct from every internal/wasm
// result code exposed through this public bridge.
func TestInvalidArgErrorCodeContract(t *testing.T) {
	if errInvalidArg == 0 {
		t.Fatal("errInvalidArg must be non-zero")
	}
	internalCodes := []struct {
		name string
		code int
	}{
		{name: "unsupported", code: internalwasm.ErrUnsupported},
		{name: "corrupted header", code: internalwasm.ErrCorruptedHeader},
		{name: "wrong password", code: internalwasm.ErrWrongPassword},
		{name: "modified data", code: internalwasm.ErrModifiedData},
		{name: "random failure", code: internalwasm.ErrRandomFailure},
		{name: "keyfiles required", code: internalwasm.ErrKeyfilesRequired},
		{name: "keyfiles incorrect", code: internalwasm.ErrKeyfilesIncorrect},
		{name: "duplicate keyfiles", code: internalwasm.ErrKeyfilesDuplicate},
		{name: "modified but kept", code: internalwasm.ErrModifiedButKept},
		{name: "deniability password required", code: internalwasm.ErrDeniabilityPasswordRequired},
		{name: "keyfile writes disabled", code: internalwasm.ErrKeyfileWritesDisabled},
		{name: "encryption password required", code: internalwasm.ErrEncryptionPasswordRequired},
	}
	for _, internal := range internalCodes {
		if errInvalidArg == internal.code {
			t.Fatalf(
				"errInvalidArg=%d collides with internal/wasm %s code",
				errInvalidArg,
				internal.name,
			)
		}
	}
}

// codeOf extracts result.code from a bridge return; -1 if the shape is wrong.
func codeOf(v any) int {
	jv, ok := v.(js.Value)
	if !ok || jv.Type() != js.TypeObject {
		return -1
	}
	c := jv.Get("code")
	if c.Type() != js.TypeNumber {
		return -1
	}
	return c.Int()
}

func newOpts(fields map[string]any) js.Value {
	o := js.Global().Get("Object").New()
	for k, val := range fields {
		o.Set(k, val)
	}
	return o
}

// Malformed inputs must return {code: errInvalidArg}, never panic out of FuncOf.
func TestBridgeRejectsBadInput(t *testing.T) {
	u8 := js.Global().Get("Uint8Array").New(4)
	cases := []struct {
		name string
		arg  js.Value
	}{
		{"non-object arg", js.ValueOf(42)},
		{"missing data", newOpts(map[string]any{"password": "pw"})},
		{"data not uint8array", newOpts(map[string]any{"data": "nope", "password": "pw"})},
		{"missing password", newOpts(map[string]any{"data": u8})},
		{"password not string", newOpts(map[string]any{"data": u8, "password": 7})},
	}
	for _, cb := range []struct {
		name string
		fn   func(js.Value, []js.Value) any
	}{{"encrypt", encrypt}, {"decrypt", decrypt}} {
		for _, tc := range cases {
			t.Run(cb.name+"/"+tc.name, func(t *testing.T) {
				if got := codeOf(cb.fn(js.Undefined(), []js.Value{tc.arg})); got != errInvalidArg {
					t.Fatalf("%s(%s) code=%d; want errInvalidArg=%d", cb.name, tc.name, got, errInvalidArg)
				}
			})
		}
	}
}

// Over-long comments are rejected at the bridge with errInvalidArg.
func TestBridgeRejectsLongComments(t *testing.T) {
	u8 := js.Global().Get("Uint8Array").New(4)
	long := []byte(strings.Repeat("a", 100000)) // > header.MaxCommentLen (99999)
	arg := newOpts(map[string]any{"data": u8, "password": "pw", "comments": string(long)})
	if got := codeOf(encrypt(js.Undefined(), []js.Value{arg})); got != errInvalidArg {
		t.Fatalf("over-long comments code=%d; want errInvalidArg=%d", got, errInvalidArg)
	}
}

// readKeyfiles must reject a non-array and a non-Uint8Array element.
func TestReadKeyfilesRejectsBadShapes(t *testing.T) {
	if _, ok := readKeyfiles(js.ValueOf("nope")); ok {
		t.Fatal("non-array keyfiles accepted")
	}
	arr := js.Global().Get("Array").New()
	arr.Call("push", js.ValueOf(42)) // not a Uint8Array
	if _, ok := readKeyfiles(arr); ok {
		t.Fatal("non-Uint8Array keyfile element accepted")
	}
}

// readKeyfiles(undefined) and readKeyfiles(null) must both return (nil, true):
// no keyfiles, ok — exercising the IsUndefined/IsNull early-return paths.
func TestReadKeyfilesNilIsOK(t *testing.T) {
	if kfs, ok := readKeyfiles(js.Undefined()); !ok || kfs != nil {
		t.Fatalf("readKeyfiles(undefined) = (%v, %v); want (nil, true)", kfs, ok)
	}
	if kfs, ok := readKeyfiles(js.Null()); !ok || kfs != nil {
		t.Fatalf("readKeyfiles(null) = (%v, %v); want (nil, true)", kfs, ok)
	}
}

func TestBridgeMalformedOptionsRejectBeforeOwnedCopies(t *testing.T) {
	for _, callback := range []struct {
		name string
		run  func(js.Value, []js.Value) any
	}{{"encrypt", encrypt}, {"decrypt", decrypt}} {
		for _, failure := range []string{"password", "later keyfile", "keyfile getter", "option getter"} {
			t.Run(callback.name+"/"+failure, func(t *testing.T) {
				previousCopy := copyBytesFromJS
				var owned [][]byte
				copyBytesFromJS = func(dst []byte, src js.Value) int {
					n := previousCopy(dst, src)
					owned = append(owned, dst)
					return n
				}
				t.Cleanup(func() { copyBytesFromJS = previousCopy })
				data := js.Global().Get("Uint8Array").New(3)
				key := js.Global().Get("Uint8Array").New(3)
				js.CopyBytesToJS(data, []byte{1, 2, 3})
				js.CopyBytesToJS(key, []byte{4, 5, 6})
				keys := js.Global().Get("Array").New()
				keys.Call("push", key)
				opts := newOpts(map[string]any{"data": data, "password": "pw", "keyfiles": keys})
				throwingGetter := js.Global().Get("Function").New("throw new Error('unavailable')")
				installThrow := func(obj js.Value, name string) {
					descriptor := newOpts(map[string]any{"get": throwingGetter})
					js.Global().Get("Object").Call("defineProperty", obj, name, descriptor)
				}
				switch failure {
				case "password":
					opts.Set("password", 42)
				case "later keyfile":
					keys.Call("push", 42)
				case "keyfile getter":
					installThrow(keys, "1")
				case "option getter":
					property := "forceDecrypt"
					if callback.name == "encrypt" {
						property = "keyfileOrdered"
					}
					installThrow(opts, property)
				}
				result := callback.run(js.Undefined(), []js.Value{opts}).(js.Value)
				if codeOf(result) != errInvalidArg || js.Global().Get("Object").Call("keys", result).Length() != 1 {
					t.Fatal("malformed options must return only the failure code")
				}
				if len(owned) != 0 {
					t.Fatal("malformed options reached a Go whole-input or keyfile copy")
				}
				for i, b := range owned {
					if !bytes.Equal(b, make([]byte, len(b))) {
						t.Errorf("owned copy %d remains live after rejection: %x", i, b)
					}
				}
				for _, input := range []struct {
					value js.Value
					want  []byte
				}{{data, []byte{1, 2, 3}}, {key, []byte{4, 5, 6}}} {
					got := make([]byte, len(input.want))
					js.CopyBytesToGo(got, input.value)
					if !bytes.Equal(got, input.want) {
						t.Fatalf("caller JavaScript input changed: %x", got)
					}
				}
			})
		}
	}
	t.Run("long comments", func(t *testing.T) {
		previousCopy := copyBytesFromJS
		var owned []byte
		copyBytesFromJS = func(dst []byte, src js.Value) int {
			n := previousCopy(dst, src)
			owned = dst
			return n
		}
		t.Cleanup(func() { copyBytesFromJS = previousCopy })
		data := js.Global().Get("Uint8Array").New(3)
		js.CopyBytesToJS(data, []byte{7, 8, 9})
		result := encrypt(js.Undefined(), []js.Value{newOpts(map[string]any{
			"data": data, "password": "pw", "comments": strings.Repeat("x", 100000),
		})}).(js.Value)
		if codeOf(result) != errInvalidArg || js.Global().Get("Object").Call("keys", result).Length() != 1 {
			t.Fatal("long comments must return only the failure code")
		}
		if len(owned) != 0 {
			t.Fatalf("owned plaintext remains live after comment rejection: %x", owned)
		}
		got := make([]byte, 3)
		js.CopyBytesToGo(got, data)
		if !bytes.Equal(got, []byte{7, 8, 9}) {
			t.Fatalf("caller JavaScript plaintext changed: %x", got)
		}
	})
}

func TestBridgeCopyPanicWipesOwnedPlaintext(t *testing.T) {
	previousCopy := copyBytesFromJS
	var owned []byte
	copyBytesFromJS = func(dst []byte, src js.Value) int {
		previousCopy(dst, src)
		owned = dst
		panic("copy interrupted")
	}
	t.Cleanup(func() { copyBytesFromJS = previousCopy })
	data := js.Global().Get("Uint8Array").New(3)
	js.CopyBytesToJS(data, []byte{1, 2, 3})
	result := encrypt(js.Undefined(), []js.Value{newOpts(map[string]any{"data": data, "password": "pw"})}).(js.Value)
	if codeOf(result) != errInvalidArg || js.Global().Get("Object").Call("keys", result).Length() != 1 {
		t.Fatal("interrupted copy must return only the failure code")
	}
	if !bytes.Equal(owned, []byte{0, 0, 0}) {
		t.Fatalf("owned plaintext remains live after interrupted copy: %x", owned)
	}
	got := make([]byte, 3)
	js.CopyBytesToGo(got, data)
	if !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Fatalf("caller JavaScript plaintext changed: %x", got)
	}
}

func TestBridgeInputOwnedPropertiesCannotRedirectCopy(t *testing.T) {
	for _, property := range []string{"subarray", "buffer", "byteOffset"} {
		t.Run(property, func(t *testing.T) {
			data := mkU8Den([]byte{1, 2, 3})
			getter := js.Global().Get("Function").New("throw new Error('input-owned property')")
			js.Global().Get("Object").Call("defineProperty", data, property, newOpts(map[string]any{"get": getter}))
			copied := copyUint8Array(data, 3)
			if !bytes.Equal(copied, []byte{1, 2, 3}) {
				t.Fatal("input-owned property redirected intrinsic copy")
			}
			clear(copied)
		})
	}
}

func TestBridgeProxyPrototypeCannotEscapeValidation(t *testing.T) {
	for _, callback := range []struct {
		name string
		run  func(js.Value, []js.Value) any
	}{{"encrypt", encrypt}, {"decrypt", decrypt}} {
		for _, proxyProperty := range []string{"data", "keyfiles"} {
			t.Run(callback.name+"/"+proxyProperty, func(t *testing.T) {
				previousCopy := copyBytesFromJS
				var owned [][]byte
				copyBytesFromJS = func(dst []byte, src js.Value) int {
					n := previousCopy(dst, src)
					owned = append(owned, dst)
					return n
				}
				t.Cleanup(func() { copyBytesFromJS = previousCopy })
				data := js.Global().Get("Uint8Array").New(3)
				js.CopyBytesToJS(data, []byte{1, 2, 3})
				key := js.Global().Get("Uint8Array").New(3)
				js.CopyBytesToJS(key, []byte{4, 5, 6})
				keys := js.Global().Get("Array").New()
				keys.Call("push", key)
				keys.Call("push", 42)
				opts := newOpts(map[string]any{"data": data, "password": "pw", "keyfiles": keys})
				trap := js.Global().Get("Function").New("throw new Error('prototype trap')")
				handler := newOpts(map[string]any{"getPrototypeOf": trap})
				opts.Set(proxyProperty, js.Global().Get("Proxy").New(opts.Get(proxyProperty), handler))
				result := callback.run(js.Undefined(), []js.Value{opts}).(js.Value)
				if codeOf(result) != errInvalidArg || js.Global().Get("Object").Call("keys", result).Length() != 1 {
					t.Fatal("malformed proxy input must return only the failure code")
				}
				if len(owned) != 0 {
					t.Fatalf("malformed keyfiles reached a whole-data copy: %d", len(owned))
				}
			})
		}
	}
}

func TestBridgeDecryptsLegacyOrderedKeyfileVolume(t *testing.T) {
	requireWASMProductionKDF(t)
	mkU8 := func(b []byte) js.Value {
		u := js.Global().Get("Uint8Array").New(len(b))
		js.CopyBytesToJS(u, b)
		return u
	}

	testdata := filepath.Join("..", "..", "testdata", "golden")
	volumeData, err := os.ReadFile(filepath.Join(testdata, "pico_test_v2_keyfile_multi_ordered.txt.pcv"))
	if err != nil {
		t.Fatalf("read legacy volume fixture: %v", err)
	}
	keyfileAlpha, err := os.ReadFile(filepath.Join(testdata, "keyfile_alpha.bin"))
	if err != nil {
		t.Fatalf("read first legacy keyfile: %v", err)
	}
	keyfileBeta, err := os.ReadFile(filepath.Join(testdata, "keyfile_beta.bin"))
	if err != nil {
		t.Fatalf("read second legacy keyfile: %v", err)
	}

	kf := js.Global().Get("Array").New()
	kf.Call("push", mkU8(keyfileAlpha))
	// An empty legacy ordered factor contributes no bytes to the frozen
	// concatenation. Rejecting it would strand previously supported volumes.
	kf.Call("push", mkU8(nil))
	kf.Call("push", mkU8(keyfileBeta))
	volume := mkU8(volumeData)

	// Missing keyfiles on decrypt → code 7.
	miss := decrypt(js.Undefined(), []js.Value{newOpts(map[string]any{
		"data": volume, "password": "test",
	})}).(js.Value)
	if miss.Get("code").Int() != 7 {
		t.Fatalf("missing-keyfiles code=%d; want 7", miss.Get("code").Int())
	}
	// Correct ordered keyfiles must preserve pre-2.19 read compatibility.
	dec := decrypt(js.Undefined(), []js.Value{newOpts(map[string]any{
		"data": volume, "password": "test", "keyfiles": kf,
	})}).(js.Value)
	if dec.Get("code").Int() != 0 {
		t.Fatalf("decrypt code=%d; want 0", dec.Get("code").Int())
	}
	if got := dataBytesDen(t, dec); !bytes.Equal(got, []byte("There is a test file for Picocrypt validation.\n")) {
		t.Fatalf("legacy decrypt plaintext = %q; want golden content", got)
	}
}

func TestBridgeEncryptReedSolomonSetsPCV3Feature(t *testing.T) {
	requireWASMProductionKDF(t)
	rv := encrypt(js.Undefined(), []js.Value{newOpts(map[string]any{"data": mkU8Den([]byte("rs payload")), "password": "bridge-rs", "reedSolomon": true})}).(js.Value)
	if codeOf(rv) != 0 {
		t.Fatalf("encrypt code=%d", codeOf(rv))
	}
	data := dataBytesDen(t, rv)
	if len(data) < 16 || !bytes.Equal(data[:4], []byte{'P', 'C', 'V', 0}) || data[10] != 0 || data[11] != 1 {
		t.Fatal("writer lost PCV3 RS feature flag")
	}
	if route, err := pcv3operation.Probe(bytes.NewReader(data), int64(len(data))); err != nil || route != pcv3operation.RouteNormalPCV {
		t.Fatal("writer emitted an invalid PCV3 container")
	}
}

// A valid encrypt then decrypt round-trips through the bridge objects, carrying comments.
func TestBridgeRoundTrip(t *testing.T) {
	requireWASMProductionKDF(t)
	plain := []byte("bridge round trip")
	u8 := js.Global().Get("Uint8Array").New(len(plain))
	js.CopyBytesToJS(u8, plain)

	encArg := newOpts(map[string]any{"data": u8, "password": "pw", "paranoid": true, "comments": "hi"})
	encRes := encrypt(js.Undefined(), []js.Value{encArg}).(js.Value)
	if encRes.Get("code").Int() != 0 {
		t.Fatalf("encrypt code=%d; want 0", encRes.Get("code").Int())
	}

	decArg := newOpts(map[string]any{"data": encRes.Get("data"), "password": "pw"})
	decRes := decrypt(js.Undefined(), []js.Value{decArg}).(js.Value)
	if decRes.Get("code").Int() != 0 {
		t.Fatalf("decrypt code=%d; want 0", decRes.Get("code").Int())
	}
	if decRes.Get("comments").String() != "hi" {
		t.Fatalf("comments=%q; want %q", decRes.Get("comments").String(), "hi")
	}
	out := decRes.Get("data")
	got := make([]byte, out.Get("length").Int())
	js.CopyBytesToGo(got, out)
	if string(got) != string(plain) {
		t.Fatalf("round-trip data=%q; want %q", got, plain)
	}
}
