//go:build js && wasm

package main

import (
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/secret"
	"Picocrypt-NG/internal/wasm"
	"syscall/js"
)

func main() {
	js.Global().Set("picocryptEncrypt", js.FuncOf(encrypt))
	js.Global().Set("picocryptDecrypt", js.FuncOf(decrypt))
	<-make(chan struct{})
}

const (
	// errInvalidArg is the bridge-level failure code for a malformed options
	// object. It is non-zero and distinct from internal/wasm result codes so the
	// site keeps treating it as failure.
	errInvalidArg = 6
	// maxVolumeBytes caps the in-memory whole-file model at 1 GiB.
	maxVolumeBytes = 1 << 30
)

// copyBytesFromJS is the syscall boundary used by bridge input copies. Tests
// observe destination sizes to prove claimed PCV3 input is rejected before a
// whole-volume Go allocation/copy.
var copyBytesFromJS = js.CopyBytesToGo

// External getters can throw. Value.Get/Index let JavaScript exceptions escape
// the Go runtime, while Call converts them into panics handled by the bridge.
func readProperty(obj js.Value, key any) js.Value {
	return js.Global().Get("Reflect").Call("get", obj, key)
}

func typedArrayProperty(v js.Value, key any) js.Value {
	object := js.Global().Get("Object")
	prototype := object.Call("getPrototypeOf", js.Global().Get("Uint8Array").Get("prototype"))
	getter := object.Call("getOwnPropertyDescriptor", prototype, key).Get("get")
	return getter.Call("call", v)
}

// errorResult builds {code: N}.
func errorResult(code int) any {
	o := js.Global().Get("Object").New()
	o.Set("code", code)
	return o
}

// readUint8Array copies a real Uint8Array to a Go slice. ok=false for any other
// shape (undefined, null, wrong typed array, plain object) — checked before any
// length/byte access so a bad value cannot panic.
func uint8ArrayLength(v js.Value) (int, bool) {
	// Intrinsic brand/length access cannot invoke input-owned prototype traps
	// or storage getters. Other typed-array brands remain malformed input.
	brand := typedArrayProperty(v, js.Global().Get("Symbol").Get("toStringTag"))
	if brand.Type() != js.TypeString || brand.String() != "Uint8Array" {
		return 0, false
	}
	return typedArrayProperty(v, "length").Int(), true
}

func copyArrayBytes(dst []byte, v js.Value) int {
	// The runtime copy import invokes src.subarray without catching JavaScript
	// exceptions. A fresh view avoids input-owned methods without copying data.
	view := js.Global().Get("Uint8Array").New(typedArrayProperty(v, "buffer"), typedArrayProperty(v, "byteOffset"), len(dst))
	return copyBytesFromJS(dst, view)
}

func copyUint8Array(v js.Value, n int) []byte {
	b := make([]byte, n)
	complete := false
	defer func() {
		if !complete {
			secret.SecureZero(b)
		}
	}()
	copyArrayBytes(b, v)
	complete = true
	return b
}

func readUint8Array(v js.Value) ([]byte, bool) {
	n, ok := uint8ArrayLength(v)
	if !ok {
		return nil, false
	}
	b := copyUint8Array(v, n)
	return b, true
}

// optBool reads obj[key] as a boolean, defaulting to false.
func optBool(obj js.Value, key string) bool {
	v := readProperty(obj, key)
	return v.Type() == js.TypeBoolean && v.Bool()
}

// explicitPCV3Intent reports whether opts carries a supported operation
// mode discriminator as a JS number holding one of the closed valid modes.
// The browser bridge implements no PCV3 operation, so recognized intent is the
// only property consumed before rejection. A missing, non-numeric, or
// out-of-registry value is not explicit intent and leaves the legacy path
// untouched; D1 content is never sniffed.
func explicitPCV3Intent(opts js.Value) bool {
	v := readProperty(opts, "pcv3Mode")
	if v.Type() != js.TypeNumber {
		return false
	}
	switch v.Float() {
	case float64(pcv3operation.ModeReadNormal), float64(pcv3operation.ModeReadD1),
		float64(pcv3operation.ModeRecoverNormal), float64(pcv3operation.ModeRecoverD1),
		float64(pcv3operation.ModeForceNormal), float64(pcv3operation.ModeForceD1),
		float64(pcv3operation.ModeForceUnverifiedNormal), float64(pcv3operation.ModeForceUnverifiedD1):
		return true
	}
	return false
}

// optString reads obj[key] as a string, defaulting to "".
func optString(obj js.Value, key string) string {
	v := readProperty(obj, key)
	if v.Type() == js.TypeString {
		return v.String()
	}
	return ""
}

// readKeyfiles reads v as an Array of Uint8Array into [][]byte.
// ok=false if v is present but malformed (non-array, or any element not a
// Uint8Array). A missing/undefined/null value yields (nil, true) — no keyfiles.
func readKeyfiles(v js.Value) ([][]byte, bool) {
	if v.IsUndefined() || v.IsNull() {
		return nil, true
	}
	if !js.Global().Get("Array").Call("isArray", v).Bool() {
		return nil, false
	}
	n := readProperty(v, "length").Int()
	out := make([][]byte, 0, n)
	complete := false
	defer func() {
		if !complete {
			for _, b := range out {
				secret.SecureZero(b)
			}
		}
	}()
	for i := range n {
		b, ok := readUint8Array(readProperty(v, i))
		if !ok {
			return nil, false
		}
		out = append(out, b)
	}
	complete = true
	return out, true
}

// successData builds {code:0, data: Uint8Array}.
func successData(data []byte) any {
	out := js.Global().Get("Uint8Array").New(len(data))
	js.CopyBytesToJS(out, data)
	o := js.Global().Get("Object").New()
	o.Set("code", 0)
	o.Set("data", out)
	return o
}

func encrypt(this js.Value, args []js.Value) (result any) {
	// A panic between validation and use must not escape FuncOf and kill the
	// instance; convert it to the same malformed-argument code.
	defer func() {
		if r := recover(); r != nil {
			result = errorResult(errInvalidArg)
		}
	}()

	if len(args) < 1 || args[0].Type() != js.TypeObject {
		return errorResult(errInvalidArg)
	}
	opts := args[0]

	dataValue := readProperty(opts, "data")
	dataLength, ok := uint8ArrayLength(dataValue)
	if !ok || dataLength == 0 || dataLength > maxVolumeBytes {
		return errorResult(errInvalidArg)
	}
	data := copyUint8Array(dataValue, dataLength)
	defer secret.SecureZero(data)
	pw := readProperty(opts, "password")
	if pw.Type() != js.TypeString {
		return errorResult(errInvalidArg)
	}
	comments := optString(opts, "comments")
	if len(comments) > header.MaxCommentLen {
		return errorResult(errInvalidArg)
	}
	paranoid := optBool(opts, "paranoid")
	keyfiles, ok := readKeyfiles(readProperty(opts, "keyfiles"))
	if !ok {
		return errorResult(errInvalidArg)
	}
	for _, kf := range keyfiles {
		defer secret.SecureZero(kf)
	}
	keyfileOrdered := optBool(opts, "keyfileOrdered")
	reedSolomon := optBool(opts, "reedSolomon")
	deniability := optBool(opts, "deniability")

	passwordBytes := []byte(pw.String())
	defer secret.SecureZero(passwordBytes)

	volumeData, code := wasm.EncryptVolume(data, passwordBytes, wasm.EncryptOptions{
		Paranoid:       paranoid,
		Comments:       comments,
		Keyfiles:       keyfiles,
		KeyfileOrdered: keyfileOrdered,
		ReedSolomon:    reedSolomon,
		Deniability:    deniability,
	})
	if code != 0 {
		return errorResult(code)
	}
	defer secret.SecureZero(volumeData)
	return successData(volumeData)
}

func decrypt(this js.Value, args []js.Value) (result any) {
	defer func() {
		if r := recover(); r != nil {
			result = errorResult(errInvalidArg)
		}
	}()

	if len(args) < 1 || args[0].Type() != js.TypeObject {
		return errorResult(errInvalidArg)
	}
	opts := args[0]

	// Explicit PCV3 intent is terminal before any data, credential, or option
	// access; every closed operation mode gets the same stable code-only
	// unsupported result.
	if explicitPCV3Intent(opts) {
		return errorResult(wasm.ErrUnsupported)
	}

	dataValue := readProperty(opts, "data")
	dataLength, ok := uint8ArrayLength(dataValue)
	if !ok || dataLength == 0 || dataLength > maxVolumeBytes {
		return errorResult(errInvalidArg)
	}
	if dataLength >= 4 {
		var prefix [4]byte
		defer secret.SecureZero(prefix[:])
		if copyArrayBytes(prefix[:], dataValue) != len(prefix) {
			return errorResult(errInvalidArg)
		}
		if pcv3operation.DetectPrefix(prefix[:]) == pcv3operation.RouteNormalPCV {
			return errorResult(wasm.ErrUnsupported)
		}
	}
	data := copyUint8Array(dataValue, dataLength)
	defer secret.SecureZero(data)
	pw := readProperty(opts, "password")
	if pw.Type() != js.TypeString {
		return errorResult(errInvalidArg)
	}

	keyfiles, ok := readKeyfiles(readProperty(opts, "keyfiles"))
	if !ok {
		return errorResult(errInvalidArg)
	}
	for _, kf := range keyfiles {
		defer secret.SecureZero(kf)
	}

	passwordBytes := []byte(pw.String())
	defer secret.SecureZero(passwordBytes)

	res, code := wasm.DecryptVolume(data, passwordBytes, wasm.DecryptOptions{
		Keyfiles: keyfiles,
		Force:    optBool(opts, "forceDecrypt"),
	})
	// code 0 = verified; code 10 = kept-but-unverified (force). Both carry data;
	// every other non-zero code is a plain failure with no payload.
	if code != 0 && code != wasm.ErrModifiedButKept {
		return errorResult(code)
	}
	defer secret.SecureZero(res.Plaintext)

	out := js.Global().Get("Uint8Array").New(len(res.Plaintext))
	js.CopyBytesToJS(out, res.Plaintext)
	o := js.Global().Get("Object").New()
	o.Set("code", code)
	o.Set("data", out)
	o.Set("comments", res.Comments)
	return o
}
