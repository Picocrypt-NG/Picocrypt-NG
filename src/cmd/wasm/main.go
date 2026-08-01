//go:build js && wasm

package main

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/pcv3"
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
	if !v.InstanceOf(js.Global().Get("Uint8Array")) {
		return 0, false
	}
	return v.Get("length").Int(), true
}

func copyUint8Array(v js.Value, n int) []byte {
	b := make([]byte, n)
	copyBytesFromJS(b, v)
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
	v := obj.Get(key)
	return v.Type() == js.TypeBoolean && v.Bool()
}

// optString reads obj[key] as a string, defaulting to "".
func optString(obj js.Value, key string) string {
	v := obj.Get(key)
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
	if !v.InstanceOf(js.Global().Get("Array")) {
		return nil, false
	}
	n := v.Length()
	out := make([][]byte, 0, n)
	for i := range n {
		b, ok := readUint8Array(v.Index(i))
		if !ok {
			return nil, false
		}
		out = append(out, b)
	}
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

	dataValue := opts.Get("data")
	dataLength, ok := uint8ArrayLength(dataValue)
	if !ok || dataLength == 0 || dataLength > maxVolumeBytes {
		return errorResult(errInvalidArg)
	}
	data := copyUint8Array(dataValue, dataLength)
	pw := opts.Get("password")
	if pw.Type() != js.TypeString {
		return errorResult(errInvalidArg)
	}
	comments := optString(opts, "comments")
	if len(comments) > header.MaxCommentLen {
		return errorResult(errInvalidArg)
	}
	paranoid := optBool(opts, "paranoid")
	keyfiles, ok := readKeyfiles(opts.Get("keyfiles"))
	if !ok {
		return errorResult(errInvalidArg)
	}
	keyfileOrdered := optBool(opts, "keyfileOrdered")
	reedSolomon := optBool(opts, "reedSolomon")
	deniability := optBool(opts, "deniability")

	passwordBytes := []byte(pw.String())
	defer crypto.SecureZero(passwordBytes)
	defer crypto.SecureZero(data)
	for _, kf := range keyfiles {
		defer crypto.SecureZero(kf)
	}

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
	defer crypto.SecureZero(volumeData)
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

	dataValue := opts.Get("data")
	dataLength, ok := uint8ArrayLength(dataValue)
	if !ok || dataLength == 0 || dataLength > maxVolumeBytes {
		return errorResult(errInvalidArg)
	}
	if dataLength >= 4 {
		var prefix [4]byte
		if copyBytesFromJS(prefix[:], dataValue) != len(prefix) {
			return errorResult(errInvalidArg)
		}
		if pcv3.DetectPrefix(prefix[:]) == pcv3.RouteNormalPCV {
			return errorResult(wasm.ErrUnsupported)
		}
	}
	data := copyUint8Array(dataValue, dataLength)
	pw := opts.Get("password")
	if pw.Type() != js.TypeString {
		return errorResult(errInvalidArg)
	}

	keyfiles, ok := readKeyfiles(opts.Get("keyfiles"))
	if !ok {
		return errorResult(errInvalidArg)
	}

	passwordBytes := []byte(pw.String())
	defer crypto.SecureZero(passwordBytes)
	defer crypto.SecureZero(data)
	for _, kf := range keyfiles {
		defer crypto.SecureZero(kf)
	}

	res, code := wasm.DecryptVolume(data, passwordBytes, wasm.DecryptOptions{
		Keyfiles: keyfiles,
		Force:    optBool(opts, "forceDecrypt"),
	})
	// code 0 = verified; code 10 = kept-but-unverified (force). Both carry data;
	// every other non-zero code is a plain failure with no payload.
	if code != 0 && code != wasm.ErrModifiedButKept {
		return errorResult(code)
	}
	defer crypto.SecureZero(res.Plaintext)

	out := js.Global().Get("Uint8Array").New(len(res.Plaintext))
	js.CopyBytesToJS(out, res.Plaintext)
	o := js.Global().Get("Object").New()
	o.Set("code", code)
	o.Set("data", out)
	o.Set("comments", res.Comments)
	return o
}
