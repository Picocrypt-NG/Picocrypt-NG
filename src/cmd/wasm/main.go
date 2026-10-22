//go:build js && wasm

package main

import (
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/secret"
	"Picocrypt-NG/internal/wasm"
	"context"
	"io"
	"math"
	"syscall/js"
)

func main() {
	js.Global().Set("picocryptEncrypt", js.FuncOf(encrypt))
	js.Global().Set("picocryptDecrypt", js.FuncOf(decrypt))
	js.Global().Set("picocryptCapabilities", js.FuncOf(capabilities))
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
// observe destination sizes to verify bounded preflight before whole-input copies.
var copyBytesFromJS = js.CopyBytesToGo

// js/wasm executes on one thread, but an input getter can synchronously call
// either export again. One shared guard keeps admission operation-scoped.
var operationActive bool

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

// uint8ArrayLength rejects non-Uint8Array values before reading their length or bytes.
func uint8ArrayLength(v js.Value) (int, bool) {
	// Intrinsic brand/length access cannot invoke input-owned prototype traps
	// or storage getters. Other typed-array brands remain malformed input.
	brand := typedArrayProperty(v, js.Global().Get("Symbol").Get("toStringTag"))
	if brand.Type() != js.TypeString || brand.String() != "Uint8Array" {
		return 0, false
	}
	buffer := typedArrayProperty(v, "buffer")
	// ArrayBuffer's intrinsic brand getter rejects SharedArrayBuffer storage.
	// Shared storage could otherwise change between routing and the owned copy.
	descriptor := js.Global().Get("Object").Call("getOwnPropertyDescriptor", js.Global().Get("ArrayBuffer").Get("prototype"), "byteLength")
	descriptor.Get("get").Call("call", buffer)
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
	if copyArrayBytes(b, v) != n {
		panic("incomplete byte copy")
	}
	complete = true
	return b
}

// optBool reads obj[key] as a boolean, defaulting to false.
func optBool(obj js.Value, key string) bool {
	v := readProperty(obj, key)
	return v.Type() == js.TypeBoolean && v.Bool()
}

// readMode rejects numeric narrowing, fractions, and unknown explicit modes.
func readMode(opts js.Value) (pcv3operation.Mode, bool) {
	v := readProperty(opts, "pcv3Mode")
	if v.IsUndefined() || v.IsNull() {
		return 0, true
	}
	if v.Type() != js.TypeNumber {
		return 0, false
	}
	f := v.Float()
	if math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) || f < 1 || f > 8 {
		return 0, false
	}
	return pcv3operation.Mode(int(f)), true //nolint:gosec // Exact integer registry 1..8 was validated above.
}

// inspectKeyfiles validates the complete aggregate before copying any factor.
func inspectKeyfiles(v js.Value, allowEmpty bool) ([]js.Value, []int, int) {
	if v.IsUndefined() || v.IsNull() {
		return nil, nil, 0
	}
	if !js.Global().Get("Array").Call("isArray", v).Bool() {
		return nil, nil, errInvalidArg
	}
	length := readProperty(v, "length")
	if length.Type() != js.TypeNumber {
		return nil, nil, errInvalidArg
	}
	n := length.Float()
	if math.IsNaN(n) || n < 0 || n != math.Trunc(n) {
		return nil, nil, errInvalidArg
	}
	if n > pcv3operation.MaxKeyfiles {
		return nil, nil, 14
	}
	values, sizes := make([]js.Value, int(n)), make([]int, int(n))
	total := 0
	for i := range values {
		values[i] = readProperty(v, i)
		size, ok := uint8ArrayLength(values[i])
		if !ok || (size == 0 && !allowEmpty) {
			return nil, nil, errInvalidArg
		}
		if size > pcv3operation.BrowserMaxKeyfileBytes-total {
			return nil, nil, 14
		}
		sizes[i], total = size, total+size
	}
	return values, sizes, 0
}

func copyKeyfiles(values []js.Value, sizes []int) (out [][]byte) {
	complete := false
	defer func() {
		if !complete {
			for _, b := range out {
				secret.SecureZero(b)
			}
		}
	}()
	for i, value := range values {
		out = append(out, copyUint8Array(value, sizes[i]))
	}
	complete = true
	return out
}

func readKeyfiles(v js.Value) ([][]byte, bool) {
	values, sizes, code := inspectKeyfiles(v, true)
	if code != 0 {
		return nil, false
	}
	return copyKeyfiles(values, sizes), true
}

func capabilities(this js.Value, args []js.Value) any {
	o := js.Global().Get("Object").New()
	o.Set("pcv3", true)
	o.Set("apiVersion", 3)
	o.Set("maxPlaintextBytes", pcv3operation.BrowserMaxPlaintextBytes)
	o.Set("maxPCV3VolumeBytes", pcv3operation.BrowserMaxPCV3VolumeBytes)
	o.Set("maxLegacyVolumeBytes", pcv3operation.BrowserMaxLegacyVolumeBytes)
	o.Set("maxKeyfileBytes", pcv3operation.BrowserMaxKeyfileBytes)
	o.Set("maxKeyfiles", pcv3operation.MaxKeyfiles)
	return o
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
	if operationActive {
		return errorResult(errInvalidArg)
	}
	operationActive = true
	defer func() { operationActive = false }()
	defer func() {
		if recover() != nil {
			result = errorResult(errInvalidArg)
		}
	}()
	if len(args) < 1 || args[0].Type() != js.TypeObject {
		return errorResult(errInvalidArg)
	}
	opts := args[0]
	dataValue := readProperty(opts, "data")
	dataLength, ok := uint8ArrayLength(dataValue)
	if !ok {
		return errorResult(errInvalidArg)
	}
	if dataLength > pcv3operation.BrowserMaxPlaintextBytes {
		return errorResult(14)
	}
	pw := readProperty(opts, "password")
	if pw.Type() != js.TypeString {
		return errorResult(errInvalidArg)
	}
	if js.Global().Get("String").New(pw).Length() > pcv3operation.BrowserMaxPasswordBytes {
		return errorResult(14)
	}
	comments := ""
	commentValue := readProperty(opts, "comments")
	if commentValue.Type() == js.TypeString {
		if js.Global().Get("String").New(commentValue).Length() > pcv3operation.BrowserMaxCommentBytes {
			return errorResult(errInvalidArg)
		}
		comments = commentValue.String()
	}
	if len(comments) > pcv3operation.BrowserMaxCommentBytes {
		return errorResult(errInvalidArg)
	}
	values, sizes, code := inspectKeyfiles(readProperty(opts, "keyfiles"), false)
	if code != 0 {
		return errorResult(code)
	}
	paranoid, ordered := optBool(opts, "paranoid"), optBool(opts, "keyfileOrdered")
	rs, deniability := optBool(opts, "reedSolomon"), optBool(opts, "deniability")
	mode := pcv3operation.WriteModeNormal
	if deniability {
		mode = pcv3operation.WriteModeD1
	}
	length, err := pcv3operation.WriteCiphertextLength(mode, uint64(dataLength), uint32(len(comments)), rs) //nolint:gosec // Intrinsic Uint8Array length and comment bounds were validated above.
	if err != nil || length > pcv3operation.BrowserMaxPCV3VolumeBytes {
		return errorResult(14)
	}
	data := copyUint8Array(dataValue, dataLength)
	defer secret.SecureZero(data)
	files := copyKeyfiles(values, sizes)
	for _, file := range files {
		defer secret.SecureZero(file)
	}
	password := []byte(pw.String())
	defer secret.SecureZero(password)
	suite := pcv3operation.SuiteStandard
	if paranoid {
		suite = pcv3operation.SuiteParanoid
	}
	output := pcv3operation.BrowserWrite(context.Background(), &pcv3operation.BrowserWriteRequest{
		Data: data, Password: password,
		Keyfiles: files, KeyfileOrdered: ordered, Suite: suite, Comment: []byte(comments), ReedSolomon: rs, Deniability: deniability,
	})
	defer output.Close()
	if output.Code() != 0 {
		return errorResult(output.Code())
	}
	return successData(output.Bytes())
}

// jsArrayReaderAt is used only for bounded pre-KDF Probe reads. It never
// allocates or copies the whole JavaScript input to establish format ownership.
type jsArrayReaderAt struct {
	value js.Value
	size  int
}

func (r jsArrayReaderAt) ReadAt(dst []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, io.EOF
	}
	if offset >= int64(r.size) {
		return 0, io.EOF
	}
	n := min(len(dst), r.size-int(offset))
	view := js.Global().Get("Uint8Array").New(typedArrayProperty(r.value, "buffer"), typedArrayProperty(r.value, "byteOffset").Int()+int(offset), n)
	copied := copyBytesFromJS(dst[:n], view)
	if copied < len(dst) {
		return copied, io.EOF
	}
	return copied, nil
}

func readForceAuthority(opts js.Value, mode pcv3operation.Mode) (pcv3operation.PhysicalRole, pcv3operation.Suite, bool, bool) {
	role, hint, consent := readProperty(opts, "pcv3Role"), readProperty(opts, "pcv3D1SuiteHint"), readProperty(opts, "pcv3ForceUnverifiedConsent")
	if mode != pcv3operation.ModeForceUnverifiedNormal && mode != pcv3operation.ModeForceUnverifiedD1 {
		return pcv3operation.RoleNone, 0, false, role.IsUndefined() && hint.IsUndefined() && consent.IsUndefined()
	}
	if consent.Type() != js.TypeBoolean || !consent.Bool() || role.Type() != js.TypeNumber || (role.Float() != 0 && role.Float() != 1) {
		return 0, 0, false, false
	}
	var selected pcv3operation.PhysicalRole
	if mode == pcv3operation.ModeForceUnverifiedNormal {
		if !hint.IsUndefined() {
			return 0, 0, false, false
		}
		selected = pcv3operation.RolePrimary
		if role.Float() == 1 {
			selected = pcv3operation.RoleBackup
		}
	} else {
		selected = pcv3operation.RoleD1Front
		if role.Float() == 1 {
			selected = pcv3operation.RoleD1Tail
		}
	}
	var suite pcv3operation.Suite
	if !hint.IsUndefined() {
		if hint.Type() != js.TypeNumber || (hint.Float() != 1 && hint.Float() != 2) {
			return 0, 0, false, false
		}
		if hint.Float() == 1 {
			suite = pcv3operation.SuiteStandard
		} else {
			suite = pcv3operation.SuiteParanoid
		}
	}
	return selected, suite, true, true
}

func decrypt(this js.Value, args []js.Value) (result any) {
	if operationActive {
		return errorResult(errInvalidArg)
	}
	operationActive = true
	defer func() { operationActive = false }()
	defer func() {
		if recover() != nil {
			result = errorResult(errInvalidArg)
		}
	}()
	if len(args) < 1 || args[0].Type() != js.TypeObject {
		return errorResult(errInvalidArg)
	}
	opts := args[0]
	mode, ok := readMode(opts)
	if !ok {
		return errorResult(errInvalidArg)
	}
	var role pcv3operation.PhysicalRole
	var hint pcv3operation.Suite
	var consent bool
	if mode == pcv3operation.ModeForceUnverifiedNormal || mode == pcv3operation.ModeForceUnverifiedD1 {
		role, hint, consent, ok = readForceAuthority(opts, mode)
		if !ok {
			return errorResult(errInvalidArg)
		}
	}
	dataValue := readProperty(opts, "data")
	dataLength, ok := uint8ArrayLength(dataValue)
	if !ok || dataLength == 0 {
		return errorResult(errInvalidArg)
	}
	if dataLength > maxVolumeBytes {
		return errorResult(14)
	}
	normal := false
	if dataLength >= 4 {
		var prefix [4]byte
		defer secret.SecureZero(prefix[:])
		if copyArrayBytes(prefix[:], dataValue) != 4 {
			return errorResult(errInvalidArg)
		}
		normal = pcv3operation.DetectPrefix(prefix[:]) == pcv3operation.RouteNormalPCV
	}
	pcv3 := normal || mode != 0
	if pcv3 && dataLength > pcv3operation.BrowserMaxPCV3VolumeBytes {
		return errorResult(14)
	}
	// Explicit D1 routes remain content-independent; no D1 detection occurs.
	normalRoute := mode == 0 || mode == pcv3operation.ModeReadNormal || mode == pcv3operation.ModeRecoverNormal || mode == pcv3operation.ModeForceNormal || mode == pcv3operation.ModeForceUnverifiedNormal
	if normal && normalRoute {
		var major [2]byte
		if n, _ := (jsArrayReaderAt{dataValue, dataLength}).ReadAt(major[:], 4); n != 2 {
			return errorResult(2)
		}
		if major != [2]byte{0, 3} {
			return errorResult(1)
		}
	}
	force := optBool(opts, "forceDecrypt")
	if normal && mode == 0 {
		mode = pcv3operation.ModeReadNormal
		if force {
			mode = pcv3operation.ModeForceNormal
		}
	}
	if mode == pcv3operation.ModeReadNormal {
		if code := pcv3operation.BrowserInspectNormal(jsArrayReaderAt{dataValue, dataLength}, int64(dataLength)); code != 0 {
			return errorResult(code)
		}
	}
	if pcv3 && mode != pcv3operation.ModeForceUnverifiedNormal && mode != pcv3operation.ModeForceUnverifiedD1 {
		role, hint, consent, ok = readForceAuthority(opts, mode)
		if !ok {
			return errorResult(errInvalidArg)
		}
	}
	pw := readProperty(opts, "password")
	if pw.Type() != js.TypeString {
		return errorResult(errInvalidArg)
	}
	if js.Global().Get("String").New(pw).Length() > pcv3operation.BrowserMaxPasswordBytes {
		return errorResult(14)
	}
	// Empty legacy factors are valid inputs to the frozen keyfile combiner.
	// PCV3 factors retain their stricter nonempty contract.
	values, sizes, code := inspectKeyfiles(readProperty(opts, "keyfiles"), !pcv3)
	if code != 0 {
		return errorResult(code)
	}
	ordered := false
	if pcv3 {
		ordered = optBool(opts, "keyfileOrdered")
	}
	data := copyUint8Array(dataValue, dataLength)
	defer secret.SecureZero(data)
	files := copyKeyfiles(values, sizes)
	for _, file := range files {
		defer secret.SecureZero(file)
	}
	password := []byte(pw.String())
	defer secret.SecureZero(password)
	if pcv3 {
		output := pcv3operation.BrowserRead(context.Background(), &pcv3operation.BrowserReadRequest{
			Data: data, Password: password,
			Keyfiles: files, KeyfileOrdered: ordered, Mode: mode, Role: role, D1SuiteHint: hint, ForceUnverifiedConsent: consent,
		})
		defer output.Close()
		if output.Code() != 0 && output.Code() != wasm.ErrModifiedButKept {
			return errorResult(output.Code())
		}
		o := successData(output.Bytes()).(js.Value)
		o.Set("code", output.Code())
		o.Set("comments", output.Comment())
		if output.Recovered() {
			o.Set("recovered", true)
		}
		return o
	}
	res, code := wasm.DecryptVolume(data, password, wasm.DecryptOptions{Keyfiles: files, Force: force})
	if code != 0 && code != wasm.ErrModifiedButKept {
		return errorResult(code)
	}
	defer secret.SecureZero(res.Plaintext)
	o := successData(res.Plaintext).(js.Value)
	o.Set("code", code)
	o.Set("comments", res.Comments)
	return o
}
