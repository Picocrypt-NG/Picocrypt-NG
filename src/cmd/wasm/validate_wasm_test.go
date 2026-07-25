//go:build js && wasm

package main

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
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

func TestBridgeDecryptsLegacyOrderedKeyfileVolume(t *testing.T) {
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

func TestBridgeEncryptReedSolomonSetsHeaderFlag(t *testing.T) {
	opts := newOpts(map[string]any{
		"data":        js.Global().Get("Uint8Array").New(64),
		"password":    "bridge-rs",
		"reedSolomon": true,
	})

	rv := encrypt(js.Undefined(), []js.Value{opts}).(js.Value)
	if code := rv.Get("code").Int(); code != 0 {
		t.Fatalf("encrypt code %d", code)
	}

	out := rv.Get("data")
	volBytes := make([]byte, out.Get("length").Int())
	js.CopyBytesToGo(volBytes, out)

	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}
	res, err := header.NewReader(bytes.NewReader(volBytes), rs).ReadHeader()
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if !res.Header.Flags.ReedSolomon {
		t.Fatal("reedSolomon option did not set the header RS flag")
	}
}

// A valid encrypt then decrypt round-trips through the bridge objects, carrying comments.
func TestBridgeRoundTrip(t *testing.T) {
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
