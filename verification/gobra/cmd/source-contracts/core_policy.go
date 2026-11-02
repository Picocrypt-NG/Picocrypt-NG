package main

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/tools/go/packages"
)

const corePolicyTemplateSHA256 = "703e168f4803370c1fe67834dd6107843b3c539db8b2f0ad325882740a6abf61"
const corePolicyTemplate = `package pcv3

import "math/bits"

//@ requires 0 <= left && left <= 18446744073709551615
//@ requires 0 <= right && right <= 18446744073709551615
//@ ensures 0 <= result && result <= 18446744073709551615
//@ ensures integer(result) == (integer(left) + integer(right)) % 18446744073709551616
//@ ensures ok == (integer(left) + integer(right) < 18446744073709551616)
func checkedAdd64(left, right uint64) (/*@ result @*/ uint64, /*@ ok @*/ bool) {
	sum, carry := bits.Add64(left, right, 0)
	return sum, carry == 0
}

//@ requires 0 <= left && left <= 18446744073709551615
//@ requires 0 <= right && right <= 18446744073709551615
//@ ensures 0 <= result && result <= 18446744073709551615
//@ ensures integer(result) == (integer(left) * integer(right)) % 18446744073709551616
//@ ensures ok == (integer(left) * integer(right) < 18446744073709551616)
func checkedMul64(left, right uint64) (/*@ result @*/ uint64, /*@ ok @*/ bool) {
	high, pcv3LowWord := bits.Mul64(left, right)
	return pcv3LowWord, high == 0
}

//@ requires 0 <= value && value <= 18446744073709551615
//@ requires 0 < divisor && divisor <= 18446744073709551615
//@ ensures 0 <= result && result <= 18446744073709551615
//@ ensures integer(result) == integer(value) / integer(divisor) + (integer(value) % integer(divisor) == 0 ? 0 : 1)
//@ ensures ok
func checkedCeilDiv64(value, divisor uint64) (/*@ result @*/ uint64, /*@ ok @*/ bool) {
	quotient := value / divisor
	if value%divisor == 0 {
		return quotient, true
	}
	return checkedAdd64(quotient, 1)
}

const (
frontHeaderBase uint64 = 976
metadataDecodedBase uint64 = 80
rs128DataLength uint64 = 128
rs128CodewordLength uint64 = 136
formatMajor uint16 = 3
formatSchema uint16 = 1
payloadBodyRSFeatureMask uint16 = 1
d1DerivedRootFeatureMask uint16 = 2
supportedFeatureMask uint16 = 1
maximumCommentLength = 99999
recordPlaintextMax = 1048576
maximumRecordCount uint64 = 281474976710656
normalDiscriminator = "PCV\x00"
)

type Suite uint16

type PayloadKind uint8

type logicalCore struct {
	magic              [4]byte
	major              uint16
	schema             uint16
	suite              Suite
	featureFlags       uint16
	frontHeaderLength  uint32
	volumeID           [32]byte
	payloadKind        PayloadKind
	recordProfile      uint8
	metadataProfile    uint8
	reserved           uint8
	plaintextLength    uint64
	recordCount        uint64
	xChaChaNoncePrefix [16]byte
	serpentIVPrefix    [8]byte
	commentLength      uint32
}

const (
	PayloadKindRaw PayloadKind = iota + 1
	PayloadKindArchive
)

const (
	SuiteStandard Suite = iota + 1
	SuiteParanoid
)

//@ requires 0 <= commentLength && commentLength <= 4294967295
//@ ensures ok && 1 <= blocks && blocks <= 33554433 && 1112 <= frontHeaderLength && frontHeaderLength <= 4563403864 && integer(blocks) == (80 + integer(commentLength)) / 128 + ((80 + integer(commentLength)) % 128 == 0 ? 0 : 1) && integer(frontHeaderLength) == 976 + 136*integer(blocks) && (commentLength <= 99999 ==> blocks <= 782 && frontHeaderLength <= 107328)

func canonicalMetadataGeometry(commentLength uint32) (blocks, frontHeaderLength uint64, ok bool) {
	decodedLength, ok := checkedAdd64(metadataDecodedBase, uint64(commentLength))
	if !ok {
		return 0, 0, false
	}
	blocks, ok = checkedCeilDiv64(decodedLength, rs128DataLength)
	if !ok {
		return 0, 0, false
	}
	encodedLength, ok := checkedMul64(blocks, rs128CodewordLength)
	if !ok {
		return 0, 0, false
	}
	frontHeaderLength, ok = checkedAdd64(frontHeaderBase, encodedLength)
	return blocks, frontHeaderLength, ok
}

//@ requires 0 <= plaintextLength && plaintextLength <= 18446744073709551615
//@ ensures 0 <= count && count <= 17592186044416
//@ ensures plaintextLength % recordPlaintextMax == 0 ==> count == plaintextLength / recordPlaintextMax
//@ ensures plaintextLength % recordPlaintextMax != 0 ==> count == plaintextLength / recordPlaintextMax + 1
//@ ensures (count == 0) == (plaintextLength == 0)

func canonicalRecordCount(plaintextLength uint64) (/*@ count @*/ uint64) {
	if plaintextLength == 0 {
		return 0
	}
	return (plaintextLength-1)/recordPlaintextMax + 1
}

//@ ensures supported == (suite == SuiteStandard || suite == SuiteParanoid)

func isSupportedSuite(suite Suite) (/*@ supported @*/ bool) {
	return suite == SuiteStandard || suite == SuiteParanoid
}

//@ requires 0 <= core.plaintextLength && core.plaintextLength <= 18446744073709551615
//@ requires 0 <= core.recordCount && core.recordCount <= 18446744073709551615
//@ requires 0 <= core.commentLength && core.commentLength <= 4294967295
//@ requires acc(magicOut)
//@ ensures acc(magicOut)
//@ ensures accepted == ((*magicOut) && core.major == formatMajor && core.schema == formatSchema && (core.suite == SuiteStandard || core.suite == SuiteParanoid) && core.featureFlags&^(supportedFeatureMask|d1DerivedRootFeatureMask) == 0 && PayloadKindRaw <= core.payloadKind && core.payloadKind <= PayloadKindArchive && core.recordProfile == 1 && core.metadataProfile == 1 && core.reserved == 0 && core.commentLength <= maximumCommentLength && integer(core.recordCount) == integer(core.plaintextLength)/1048576 + (integer(core.plaintextLength)%1048576 == 0 ? 0 : 1) && core.recordCount < maximumRecordCount && (core.suite != SuiteStandard || core.serpentIVPrefix == [8]byte{}) && integer(core.frontHeaderLength) == 976 + 136*((80+integer(core.commentLength))/128 + ((80+integer(core.commentLength))%128 == 0 ? 0 : 1)))

func validLogicalCore(core logicalCore /*@ , ghost magicOut gpointer[bool] @*/) (/*@ accepted @*/ bool) {
// @ share core
//@ *magicOut = string(core.magic[:]) == normalDiscriminator
	if string(core.magic[:]) != normalDiscriminator ||
		core.major != formatMajor || core.schema != formatSchema ||
		!isSupportedSuite(core.suite) || core.featureFlags&^(supportedFeatureMask|d1DerivedRootFeatureMask) != 0 ||
		core.payloadKind < PayloadKindRaw || core.payloadKind > PayloadKindArchive ||
		core.recordProfile != 1 || core.metadataProfile != 1 || core.reserved != 0 ||
		core.commentLength > maximumCommentLength ||
		core.recordCount != canonicalRecordCount(core.plaintextLength) ||
		core.recordCount >= maximumRecordCount ||
		(core.suite == SuiteStandard && core.serpentIVPrefix != [8]byte{}) {
		return false
	}
	_, expectedFrontHeader, ok := canonicalMetadataGeometry(core.commentLength)
	return ok && uint64(core.frontHeaderLength) == expectedFrontHeader
}

const (
 recordDescriptorSize uint64=48
 recordTagSize uint64=64
 nonRSPayloadOverhead uint64=112
 fullRSPayloadRecord uint64=1114296
 finalRSPayloadRecord uint64=184
)
/*@
ghost
decreases
pure func PayloadCount(n integer) integer {
 return n / 1048576 + (n % 1048576 == 0 ? 0 : 1)
}
ghost
decreases
pure func PayloadEncoded(c integer, rs bool) integer {
 return rs ? 136 * ((c + 64) / 128 + ((c + 64) % 128 == 0 ? 0 : 1)) : c + 64
}
ghost
decreases
pure func PayloadData(n integer, rs bool) integer {
 return rs ? (n / 1048576) * 1114296 + (n % 1048576 == 0 ? 0 : 48 + PayloadEncoded(n % 1048576, true)) : n + PayloadCount(n) * 112
}
ghost
decreases
pure func PayloadTotal(n integer, rs bool) integer {
 return PayloadData(n, rs) + (rs ? 184 : 112)
}
ghost
decreases
pure func PayloadValid(n integer, count integer) bool {
 return count == PayloadCount(n) && count < 281474976710656
}
@*/
//@ requires 0 <= plaintextLength && plaintextLength <= 18446744073709551615
//@ requires 0 <= recordCount && recordCount <= 18446744073709551615
//@ ensures 0 <= resultValue && resultValue <= 18446744073709551615
//@ ensures integer(resultValue) == (!PayloadValid(integer(plaintextLength), integer(recordCount)) || (payloadBodyRS && PayloadData(integer(plaintextLength), payloadBodyRS) >= 18446744073709551616) ? 0 : PayloadTotal(integer(plaintextLength), payloadBodyRS) % 18446744073709551616)
//@ ensures successFlag == (PayloadValid(integer(plaintextLength), integer(recordCount)) && PayloadTotal(integer(plaintextLength), payloadBodyRS) < 18446744073709551616)
func canonicalPayloadLength(plaintextLength, recordCount uint64, payloadBodyRS bool) (/*@ resultValue @*/ uint64, /*@ successFlag @*/ bool) {
	if recordCount != canonicalRecordCount(plaintextLength) || recordCount >= maximumRecordCount {
		return 0, false
	}
	if !payloadBodyRS {
		withFinal, ok := checkedAdd64(recordCount, 1)
		if !ok {
			return 0, false
		}
		overhead, ok := checkedMul64(withFinal, nonRSPayloadOverhead)
		if !ok {
			return 0, false
		}
		return checkedAdd64(plaintextLength, overhead)
	}

	fullRecords := plaintextLength / recordPlaintextMax
	partialLength := plaintextLength % recordPlaintextMax
	payloadLength, ok := checkedMul64(fullRecords, fullRSPayloadRecord)
	if !ok {
		return 0, false
	}
	if partialLength != 0 {
		bodyLength, ok := checkedAdd64(partialLength, recordTagSize)
		if !ok {
			return 0, false
		}
		blocks, ok := checkedCeilDiv64(bodyLength, rs128DataLength)
		if !ok {
			return 0, false
		}
		encodedBodyLength, ok := checkedMul64(blocks, rs128CodewordLength)
		if !ok {
			return 0, false
		}
		partialRecordLength, ok := checkedAdd64(recordDescriptorSize, encodedBodyLength)
		if !ok {
			return 0, false
		}
		payloadLength, ok = checkedAdd64(payloadLength, partialRecordLength)
		if !ok {
			return 0, false
		}
	}
	return checkedAdd64(payloadLength, finalRSPayloadRecord)
}
type Geometry struct {
	metadataBlocks      uint64
	payloadBodyRS       bool
	recordCount         uint64
	frontHeaderLength   int64
	payloadLength       int64
	backupCapsuleOffset int64
	trailerOffset       int64
	fileSize            int64
}
//@ requires 0 <= core.plaintextLength && core.plaintextLength <= 18446744073709551615
//@ requires 0 <= core.recordCount && core.recordCount <= 18446744073709551615
//@ requires 0 <= core.commentLength && core.commentLength <= 4294967295
//@ requires -9223372036854775808 <= geometry.frontHeaderLength && geometry.frontHeaderLength <= 9223372036854775807
//@ requires -9223372036854775808 <= geometry.payloadLength && geometry.payloadLength <= 9223372036854775807
//@ requires -9223372036854775808 <= geometry.backupCapsuleOffset && geometry.backupCapsuleOffset <= 9223372036854775807
//@ requires 0 <= geometry.recordCount && geometry.recordCount <= 18446744073709551615
//@ requires acc(magicOut)
//@ ensures acc(magicOut)
//@ ensures matches == ((((*magicOut) && core.major == formatMajor && core.schema == formatSchema && (core.suite == SuiteStandard || core.suite == SuiteParanoid) && core.featureFlags&^(supportedFeatureMask|d1DerivedRootFeatureMask) == 0 && PayloadKindRaw <= core.payloadKind && core.payloadKind <= PayloadKindArchive && core.recordProfile == 1 && core.metadataProfile == 1 && core.reserved == 0 && core.commentLength <= maximumCommentLength && integer(core.recordCount) == integer(core.plaintextLength)/1048576 + (integer(core.plaintextLength)%1048576 == 0 ? 0 : 1) && core.recordCount < maximumRecordCount && (core.suite != SuiteStandard || core.serpentIVPrefix == [8]byte{}) && integer(core.frontHeaderLength) == 976 + 136*((80+integer(core.commentLength))/128 + ((80+integer(core.commentLength))%128 == 0 ? 0 : 1)))) && geometry.frontHeaderLength >= 0 && geometry.payloadLength >= 0 && geometry.backupCapsuleOffset >= 0 && geometry.recordCount == core.recordCount && geometry.payloadBodyRS == (core.featureFlags & payloadBodyRSFeatureMask != 0) && integer(geometry.frontHeaderLength) == integer(core.frontHeaderLength) && PayloadValid(integer(core.plaintextLength), integer(core.recordCount)) && PayloadTotal(integer(core.plaintextLength), geometry.payloadBodyRS) < 18446744073709551616 && integer(geometry.payloadLength) == PayloadTotal(integer(core.plaintextLength), geometry.payloadBodyRS) && integer(geometry.frontHeaderLength) + PayloadTotal(integer(core.plaintextLength), geometry.payloadBodyRS) < 18446744073709551616 && integer(geometry.backupCapsuleOffset) == integer(geometry.frontHeaderLength) + PayloadTotal(integer(core.plaintextLength), geometry.payloadBodyRS))
func recordGeometryMatchesCore(core logicalCore, geometry Geometry /*@ , ghost magicOut gpointer[bool] @*/) (/*@ matches @*/ bool) {
	if !validLogicalCore(core) /*@ with: magicOut @*/ ||
		geometry.frontHeaderLength < 0 || geometry.payloadLength < 0 ||
		geometry.backupCapsuleOffset < 0 ||
		geometry.recordCount != core.recordCount ||
		geometry.payloadBodyRS != (core.featureFlags&payloadBodyRSFeatureMask != 0) ||
		uint64(geometry.frontHeaderLength) != uint64(core.frontHeaderLength) {
		return false
	}
	payloadLength, ok := canonicalPayloadLength(
		core.plaintextLength,
		core.recordCount,
		geometry.payloadBodyRS,
	)
	if !ok || uint64(geometry.payloadLength) != payloadLength {
		return false
	}
	backupOffset, ok := checkedAdd64(uint64(geometry.frontHeaderLength), payloadLength)
	return ok && uint64(geometry.backupCapsuleOffset) == backupOffset
}
`

var corePolicyPaths = map[string]string{
	"canonicalMetadataGeometry": "src/internal/pcv3operation/internal/pcv3/preamble.go",
	"canonicalPayloadLength":    "src/internal/pcv3operation/internal/pcv3/geometry.go",
	"canonicalRecordCount":      "src/internal/pcv3operation/internal/pcv3/capsule.go",
	"checkedAdd64":              "src/internal/pcv3operation/internal/pcv3/arithmetic.go",
	"checkedCeilDiv64":          "src/internal/pcv3operation/internal/pcv3/arithmetic.go",
	"checkedMul64":              "src/internal/pcv3operation/internal/pcv3/arithmetic.go",
	"isSupportedSuite":          "src/internal/pcv3operation/internal/pcv3/preamble.go",
	"recordGeometryMatchesCore": "src/internal/pcv3operation/internal/pcv3/records.go",
	"validLogicalCore":          "src/internal/pcv3operation/internal/pcv3/capsule.go",
}
var corePolicyTypePaths = map[string]string{
	"Geometry":    "src/internal/pcv3operation/internal/pcv3/geometry.go",
	"PayloadKind": "src/internal/pcv3operation/internal/pcv3/capsule.go",
	"Suite":       "src/internal/pcv3operation/internal/pcv3/preamble.go",
	"logicalCore": "src/internal/pcv3operation/internal/pcv3/capsule.go",
}
var corePolicyScalarExpected = map[string]struct{ Value, Type, Path string }{
	"d1DerivedRootFeatureMask": {"2", "uint16", "src/internal/pcv3operation/internal/pcv3/preamble.go"},
	"finalRSPayloadRecord":     {"184", "uint64", "src/internal/pcv3operation/internal/pcv3/geometry.go"},
	"formatMajor":              {"3", "uint16", "src/internal/pcv3operation/internal/pcv3/preamble.go"},
	"formatSchema":             {"1", "uint16", "src/internal/pcv3operation/internal/pcv3/preamble.go"},
	"frontHeaderBase":          {"976", "uint64", "src/internal/pcv3operation/internal/pcv3/preamble.go"},
	"fullRSPayloadRecord":      {"1114296", "uint64", "src/internal/pcv3operation/internal/pcv3/geometry.go"},
	"maximumCommentLength":     {"99999", "untyped int", "src/internal/pcv3operation/internal/pcv3/capsule.go"},
	"maximumRecordCount":       {"281474976710656", "uint64", "src/internal/pcv3operation/internal/pcv3/capsule.go"},
	"metadataDecodedBase":      {"80", "uint64", "src/internal/pcv3operation/internal/pcv3/preamble.go"},
	"nonRSPayloadOverhead":     {"112", "uint64", "src/internal/pcv3operation/internal/pcv3/geometry.go"},
	"normalDiscriminator":      {"\"PCV\\x00\"", "untyped string", "src/internal/pcv3operation/internal/pcv3/route.go"},
	"payloadBodyRSFeatureMask": {"1", "uint16", "src/internal/pcv3operation/internal/pcv3/preamble.go"},
	"recordDescriptorSize":     {"48", "uint64", "src/internal/pcv3operation/internal/pcv3/geometry.go"},
	"recordPlaintextMax":       {"1048576", "untyped int", "src/internal/pcv3operation/internal/pcv3/capsule.go"},
	"recordTagSize":            {"64", "uint64", "src/internal/pcv3operation/internal/pcv3/geometry.go"},
	"rs128CodewordLength":      {"136", "uint64", "src/internal/pcv3operation/internal/pcv3/preamble.go"},
	"rs128DataLength":          {"128", "uint64", "src/internal/pcv3operation/internal/pcv3/preamble.go"},
	"supportedFeatureMask":     {"1", "uint16", "src/internal/pcv3operation/internal/pcv3/preamble.go"},
}
var corePolicyEnumExpected = map[string]struct{ Value, Type, Path string }{
	"SuiteStandard":      {"1", "Suite", "src/internal/pcv3operation/internal/pcv3/preamble.go"},
	"SuiteParanoid":      {"2", "Suite", "src/internal/pcv3operation/internal/pcv3/preamble.go"},
	"PayloadKindRaw":     {"1", "PayloadKind", "src/internal/pcv3operation/internal/pcv3/capsule.go"},
	"PayloadKindArchive": {"2", "PayloadKind", "src/internal/pcv3operation/internal/pcv3/capsule.go"},
}

var corePolicyNames = []string{"checkedAdd64", "checkedMul64", "checkedCeilDiv64", "canonicalRecordCount", "canonicalMetadataGeometry", "isSupportedSuite", "validLogicalCore", "canonicalPayloadLength", "recordGeometryMatchesCore"}
var corePolicyTypeNames = []string{"Suite", "PayloadKind", "logicalCore", "Geometry"}
var corePolicyOwnedComments = []string{"// @ share core\n", "//@ *magicOut = string(core.magic[:]) == normalDiscriminator\n", " /*@ with: magicOut @*/"}

const corePolicyCountBefore = "geometry.recordCount != core.recordCount"
const corePolicyCountAfter = "geometry.recordCount == core.recordCount"

var corePolicyPost = strings.Split(strings.Split(corePolicyTemplate, "//@ ensures matches == ")[1], "\n")[0]

type corePolicyTarget struct {
	Metadata  metadataTarget
	Snapshots map[string][]byte
	Functions map[string][]byte
	Types     map[string][]byte
	Enums     [][]byte
	Constants []payloadConstant
	Original  []byte
	Graphs    map[string][]string
}
type corePolicyEvidence struct {
	Functions         []arithmeticIdentity `json:"functions"`
	CompleteTypes     bool                 `json:"full_core_geometry_and_defined_enum_declarations_identical"`
	ConstantsEqual    bool                 `json:"all_22_native_constant_types_values_equal"`
	BindingGraphs     bool                 `json:"nine_body_binding_graphs_equal_after_owned_inverse"`
	MaskUnion         string               `json:"native_flag_union_type_value"`
	GhostInterface    []string             `json:"owned_ghost_out_body_comments"`
	Alpha             []alphaReplacement   `json:"owned_mul_alpha_replacements"`
	Control           string               `json:"controlled_mutation,omitempty"`
	PostconditionLine int                  `json:"postcondition_line,omitempty"`
}

func corePolicyNormalizedType(pkg *types.Package, value types.Type) string {
	return strings.ReplaceAll(value.String(), pkg.Path()+".", "")
}

func corePolicyGraph(pkg *types.Package, info *types.Info, fn *ast.FuncDecl) ([]string, error) {
	var ids []*ast.Ident
	ast.Inspect(fn, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			ids = append(ids, id)
		}
		return true
	})
	locals := map[types.Object]int{}
	for i, id := range ids {
		if object := info.Defs[id]; object != nil && object != pkg.Scope().Lookup(fn.Name.Name) {
			if _, ok := object.(*types.Var); !ok {
				return nil, errors.New("core policy lexical definition is not a variable")
			}
			locals[object] = i
		}
	}
	fields := map[types.Object]string{}
	for _, name := range []string{"logicalCore", "Geometry"} {
		object := pkg.Scope().Lookup(name)
		if object == nil {
			return nil, errors.New("core policy full struct missing")
		}
		structure, ok := object.Type().Underlying().(*types.Struct)
		if !ok {
			return nil, errors.New("core policy named struct changed")
		}
		for i := 0; i < structure.NumFields(); i++ {
			field := structure.Field(i)
			fields[field] = fmt.Sprintf("field:%s:%d:%s:%s", name, i, field.Name(), corePolicyNormalizedType(pkg, field.Type()))
		}
	}
	constants := map[string]bool{}
	for name := range corePolicyScalarExpected {
		constants[name] = true
	}
	for name := range corePolicyEnumExpected {
		constants[name] = true
	}
	var result []string
	for i, id := range ids {
		object := info.Uses[id]
		if object == nil {
			if definition := info.Defs[id]; definition != nil {
				if index, ok := locals[definition]; ok {
					result = append(result, fmt.Sprintf("%d:def:%d:%s", i, index, corePolicyNormalizedType(pkg, definition.Type())))
				}
			}
			continue
		}
		label := ""
		if index, ok := locals[object]; ok {
			label = fmt.Sprintf("local:%d:%s", index, corePolicyNormalizedType(pkg, object.Type()))
		} else if fields[object] != "" {
			label = fields[object]
		} else if object == types.Universe.Lookup(id.Name) {
			label = "builtin:" + id.Name + ":" + corePolicyNormalizedType(pkg, object.Type())
		} else if object == pkg.Scope().Lookup(id.Name) {
			switch {
			case slices.Contains(corePolicyNames, id.Name):
				label = "own-body:" + id.Name + ":" + corePolicyNormalizedType(pkg, object.Type())
			case constants[id.Name]:
				constant, ok := object.(*types.Const)
				if !ok {
					return nil, errors.New("core policy constant binding changed")
				}
				label = "constant:" + id.Name + ":" + corePolicyNormalizedType(pkg, constant.Type()) + ":" + constant.Val().ExactString()
			case slices.Contains(corePolicyTypeNames, id.Name):
				label = "type:" + id.Name
			}
		} else if imported, ok := object.(*types.PkgName); ok && imported.Imported().Path() == "math/bits" {
			label = "import:math/bits"
		} else if object.Pkg() != nil && object.Pkg().Path() == "math/bits" && (id.Name == "Add64" || id.Name == "Mul64") && object.Pkg().Scope().Lookup(id.Name) == object {
			label = "standard:math/bits." + id.Name
		}
		if label == "" {
			return nil, fmt.Errorf("unreviewed core policy binding %q", id.Name)
		}
		result = append(result, fmt.Sprintf("%d:%s", i, label))
	}
	return result, nil
}

func corePolicyDeclarations(pkg *packages.Package, repo string, snapshots map[string][]byte) (map[string][]byte, map[string][]byte, [][]byte, error) {
	functions, declaredTypes := map[string][]byte{}, map[string][]byte{}
	enumGroups := map[string][]byte{}
	allowedTypes := map[types.Object]bool{}
	for _, name := range []string{"uint8", "uint16", "uint32", "uint64", "int64", "bool", "byte"} {
		allowedTypes[types.Universe.Lookup(name)] = true
	}
	for _, name := range corePolicyTypeNames {
		object, ok := pkg.Types.Scope().Lookup(name).(*types.TypeName)
		if !ok || object.IsAlias() {
			return nil, nil, nil, errors.New("core policy full defined type missing")
		}
		allowedTypes[object] = true
	}
	for name, kind := range map[string]types.BasicKind{"Suite": types.Uint16, "PayloadKind": types.Uint8} {
		if !types.Identical(pkg.Types.Scope().Lookup(name).Type().Underlying(), types.Typ[kind]) {
			return nil, nil, nil, errors.New("core policy nominal enum width changed")
		}
	}
	for _, syntax := range pkg.Syntax {
		for _, decl := range syntax.Decls {
			switch node := decl.(type) {
			case *ast.FuncDecl:
				path, selected := corePolicyPaths[node.Name.Name]
				if !selected {
					continue
				}
				start, end := pkg.Fset.PositionFor(node.Pos(), false), pkg.Fset.PositionFor(node.End(), false)
				if node.Recv != nil || start.Filename != filepath.Join(repo, path) || pkg.TypesInfo.Defs[node.Name] != pkg.Types.Scope().Lookup(node.Name.Name) {
					return nil, nil, nil, errors.New("core policy function origin or binding changed")
				}
				functions[node.Name.Name] = slices.Clone(snapshots[path][start.Offset:end.Offset])
			case *ast.GenDecl:
				for _, item := range node.Specs {
					switch spec := item.(type) {
					case *ast.TypeSpec:
						path, selected := corePolicyTypePaths[spec.Name.Name]
						if !selected {
							continue
						}
						start, end := pkg.Fset.PositionFor(node.Pos(), false), pkg.Fset.PositionFor(node.End(), false)
						if len(node.Specs) != 1 || spec.Assign != token.NoPos || spec.TypeParams != nil || start.Filename != filepath.Join(repo, path) || pkg.TypesInfo.Defs[spec.Name] != pkg.Types.Scope().Lookup(spec.Name.Name) {
							return nil, nil, nil, errors.New("core policy full type declaration changed")
						}
						var failure error
						ast.Inspect(node, func(n ast.Node) bool {
							if id, ok := n.(*ast.Ident); ok {
								if used := pkg.TypesInfo.Uses[id]; used != nil && !allowedTypes[used] {
									failure = fmt.Errorf("unreviewed core policy type binding %q", id.Name)
								}
							}
							return true
						})
						if failure != nil {
							return nil, nil, nil, failure
						}
						declaredTypes[spec.Name.Name] = slices.Clone(snapshots[path][start.Offset:end.Offset])
					case *ast.ValueSpec:
						for _, name := range spec.Names {
							want, selected := corePolicyEnumExpected[name.Name]
							if !selected {
								continue
							}
							start, end := pkg.Fset.PositionFor(node.Pos(), false), pkg.Fset.PositionFor(node.End(), false)
							object, ok := pkg.Types.Scope().Lookup(name.Name).(*types.Const)
							if !ok || pkg.TypesInfo.Defs[name] != object || object.Val().ExactString() != want.Value || corePolicyNormalizedType(pkg.Types, object.Type()) != want.Type || start.Filename != filepath.Join(repo, want.Path) {
								return nil, nil, nil, errors.New("core policy enum constant binding changed")
							}
							for id, used := range pkg.TypesInfo.Uses {
								position := pkg.Fset.PositionFor(id.Pos(), false)
								if position.Filename != start.Filename || position.Offset < start.Offset || position.Offset >= end.Offset {
									continue
								}
								if used != types.Universe.Lookup("iota") && used != pkg.Types.Scope().Lookup("Suite") && used != pkg.Types.Scope().Lookup("PayloadKind") {
									return nil, nil, nil, fmt.Errorf("unreviewed enum-group dependency %q", id.Name)
								}
							}
							enumGroups[fmt.Sprintf("%s:%d", want.Path, start.Offset)] = slices.Clone(snapshots[want.Path][start.Offset:end.Offset])
						}
					}
				}
			}
		}
	}
	if len(functions) != len(corePolicyNames) || len(declaredTypes) != len(corePolicyTypeNames) || len(enumGroups) != 2 {
		return nil, nil, nil, errors.New("core policy full source declaration closure missing")
	}
	keys := make([]string, 0, len(enumGroups))
	for key := range enumGroups {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	var enums [][]byte
	for _, key := range keys {
		enums = append(enums, enumGroups[key])
	}
	return functions, declaredTypes, enums, nil
}

func corePolicyMaskUnion(pkg *packages.Package, fn *ast.FuncDecl) error {
	found := false
	var failure error
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		expression, ok := n.(*ast.BinaryExpr)
		if !ok || expression.Op != token.OR {
			return true
		}
		left, lok := expression.X.(*ast.Ident)
		right, rok := expression.Y.(*ast.Ident)
		if !lok || !rok || left.Name != "supportedFeatureMask" || right.Name != "d1DerivedRootFeatureMask" {
			return true
		}
		value := pkg.TypesInfo.Types[expression]
		if found || pkg.TypesInfo.Uses[left] != pkg.Types.Scope().Lookup(left.Name) || pkg.TypesInfo.Uses[right] != pkg.Types.Scope().Lookup(right.Name) || !types.Identical(value.Type, types.Typ[types.Uint16]) || value.Value == nil || value.Value.ExactString() != "3" {
			failure = errors.New("core policy actual flag union constant changed")
		}
		found = true
		return true
	})
	if failure != nil {
		return failure
	}
	if !found {
		return errors.New("core policy actual flag union missing")
	}
	return nil
}

func loadCorePolicy(repo, cache string, metadata metadataTarget, payload payloadTarget) (corePolicyTarget, error) {
	var result corePolicyTarget
	paths := []string{arithmeticRelative, recordCountRelative, preambleRelative, "src/internal/pcv3operation/internal/pcv3/route.go", geometryRelative, recordsRelative}
	pkg, snapshots, err := loadSourceSnapshots(repo, cache, paths, "./internal/pcv3operation/internal/pcv3")
	if err != nil {
		return result, err
	}
	for _, source := range snapshots {
		if sourceAnnotationPattern.Match(source) {
			return result, errors.New("core policy source contains unowned verifier markers")
		}
	}
	if err = mergeSourceSnapshots(snapshots, metadata.Snapshots); err != nil {
		return result, err
	}
	if err = mergeSourceSnapshots(snapshots, payload.Snapshots); err != nil {
		return result, err
	}
	functions, fullTypes, enums, err := corePolicyDeclarations(pkg, repo, snapshots)
	if err != nil {
		return result, err
	}
	constants, originalConstants, err := sourceConstantDeclarations(pkg, repo, snapshots, corePolicyScalarExpected)
	if err != nil {
		return result, err
	}
	graphs := map[string][]string{}
	fresh := []string{"accepted", "supported", "matches", "magicOut", "resultValue", "successFlag", arithmeticFreshName, "PayloadCount", "PayloadEncoded", "PayloadData", "PayloadTotal", "PayloadValid"}
	for _, name := range fresh {
		if pkg.Types.Scope().Lookup(name) != nil {
			return result, fmt.Errorf("core policy ghost name %q shadows an actual package object", name)
		}
	}
	for _, syntax := range pkg.Syntax {
		for _, decl := range syntax.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !slices.Contains(corePolicyNames, fn.Name.Name) {
				continue
			}
			if err = payloadFresh(fn, fresh); err != nil {
				return result, err
			}
			graph, graphErr := corePolicyGraph(pkg.Types, pkg.TypesInfo, fn)
			if graphErr != nil {
				return result, graphErr
			}
			graphs[fn.Name.Name] = graph
			if fn.Name.Name == "validLogicalCore" {
				if err = corePolicyMaskUnion(pkg, fn); err != nil {
					return result, err
				}
			}
		}
	}
	var original bytes.Buffer
	original.WriteString("package pcv3\nimport \"math/bits\"\n")
	for _, name := range corePolicyTypeNames {
		original.Write(fullTypes[name])
		original.WriteByte('\n')
	}
	original.Write(originalConstants)
	for _, group := range enums {
		original.Write(group)
		original.WriteByte('\n')
	}
	for _, name := range corePolicyNames {
		original.Write(functions[name])
		original.WriteByte('\n')
	}
	result = corePolicyTarget{Metadata: metadata, Snapshots: snapshots, Functions: functions, Types: fullTypes, Enums: enums, Constants: constants, Original: original.Bytes(), Graphs: graphs}
	if _, _, err = annotateCorePolicy(result, "core-policy-positive"); err != nil {
		return corePolicyTarget{}, err
	}
	return result, nil
}

func corePolicyInverse(source []byte, imports actualImporter) ([]byte, []int, error) {
	recovered := slices.Clone(source)
	for _, comment := range corePolicyOwnedComments {
		if bytes.Count(recovered, []byte(comment)) != 1 {
			return nil, nil, errors.New("core policy owned body comment changed")
		}
		recovered = bytes.Replace(recovered, []byte(comment), nil, 1)
	}
	alpha, err := arithmeticFreshBindings(recovered, imports)
	if err != nil {
		return nil, nil, err
	}
	recovered, err = replaceArithmeticTokens(recovered, alpha, arithmeticFreshName, "low")
	return recovered, alpha, err
}

func corePolicyCountMutation(source []byte, from, to token.Token) ([]byte, error) {
	set, functions, err := namedSourceFunctions(source, corePolicyNames)
	if err != nil {
		return nil, err
	}
	fn := functions["recordGeometryMatchesCore"]
	if fn == nil || len(fn.Body.List) == 0 {
		return nil, errors.New("core policy count guard is missing")
	}
	offset := -1
	ast.Inspect(fn.Body.List[0], func(n ast.Node) bool {
		expression, ok := n.(*ast.BinaryExpr)
		if !ok || expression.Op != from {
			return true
		}
		left, lok := expression.X.(*ast.SelectorExpr)
		right, rok := expression.Y.(*ast.SelectorExpr)
		if !lok || !rok || left.Sel.Name != "recordCount" || right.Sel.Name != "recordCount" {
			return true
		}
		lbase, lok := left.X.(*ast.Ident)
		rbase, rok := right.X.(*ast.Ident)
		if lok && rok && lbase.Name == "geometry" && rbase.Name == "core" {
			if offset != -1 {
				offset = -2
				return false
			}
			offset = set.PositionFor(expression.OpPos, false).Offset
		}
		return true
	})
	if offset < 0 || string(source[offset:offset+2]) != from.String() {
		return nil, errors.New("core policy count mutation operator changed")
	}
	result := slices.Clone(source)
	copy(result[offset:offset+2], to.String())
	return result, nil
}

func annotateCorePolicy(target corePolicyTarget, name string) ([]byte, corePolicyEvidence, error) {
	var evidence corePolicyEvidence
	positive := []byte(corePolicyTemplate)
	if digest(positive) != corePolicyTemplateSHA256 {
		return nil, evidence, errors.New("reviewed core policy proof template changed")
	}
	for _, contract := range []string{arithmeticContracts["checkedAdd64"], arithmeticContracts["checkedMul64"], arithmeticContracts["checkedCeilDiv64"], recordCountContract, metadataContract, payloadLengthContract, payloadGhost} {
		if bytes.Count(positive, []byte(contract)) != 1 {
			return nil, evidence, errors.New("core policy helper contract differs from its maintained overflow lane")
		}
	}
	generated := slices.Clone(positive)
	negative := name == "core-policy-count-mismatch"
	if negative {
		var err error
		generated, err = corePolicyCountMutation(generated, token.NEQ, token.EQL)
		if err != nil {
			return nil, evidence, err
		}
		evidence.Control = corePolicyCountBefore + " -> " + corePolicyCountAfter
	} else if name != "core-policy-positive" {
		return nil, evidence, errors.New("unknown core policy proof case")
	}
	if _, _, _, _, err := sourceCopyInfo(generated, target.Metadata.Arithmetic.Imports, corePolicyNames); err != nil {
		return nil, evidence, err
	}
	inverse := slices.Clone(generated)
	if negative {
		var err error
		inverse, err = corePolicyCountMutation(inverse, token.EQL, token.NEQ)
		if err != nil {
			return nil, evidence, err
		}
	}
	if !bytes.Equal(inverse, positive) {
		return nil, evidence, errors.New("core policy defect inverse changed another expression")
	}
	recovered, alpha, err := corePolicyInverse(inverse, target.Metadata.Arithmetic.Imports)
	if err != nil {
		return nil, evidence, err
	}
	pkg, info, set, restored, err := sourceCopyInfo(recovered, target.Metadata.Arithmetic.Imports, corePolicyNames)
	if err != nil {
		return nil, evidence, err
	}
	proofSet, proofs, err := namedSourceFunctions(generated, corePolicyNames)
	if err != nil {
		return nil, evidence, err
	}
	for _, constant := range target.Constants {
		object, ok := pkg.Scope().Lookup(constant.Name).(*types.Const)
		if !ok || object.Val().ExactString() != constant.Value || corePolicyNormalizedType(pkg, object.Type()) != constant.Type {
			return nil, evidence, errors.New("core policy scalar constant representation changed")
		}
	}
	for name, want := range corePolicyEnumExpected {
		object, ok := pkg.Scope().Lookup(name).(*types.Const)
		if !ok || object.Val().ExactString() != want.Value || corePolicyNormalizedType(pkg, object.Type()) != want.Type {
			return nil, evidence, errors.New("core policy defined enum constant changed")
		}
	}
	file, err := parser.ParseFile(set, "types-check.go", recovered, parser.ParseComments)
	if err != nil {
		return nil, evidence, err
	}
	for _, typeName := range corePolicyTypeNames {
		found := false
		for _, decl := range file.Decls {
			group, ok := decl.(*ast.GenDecl)
			if !ok || group.Tok != token.TYPE {
				continue
			}
			for _, item := range group.Specs {
				spec := item.(*ast.TypeSpec)
				if spec.Name.Name != typeName {
					continue
				}
				f := set.File(group.Pos())
				if !bytes.Equal(recovered[f.Offset(group.Pos()):f.Offset(group.End())], target.Types[typeName]) {
					return nil, evidence, errors.New("core policy full type declaration bytes changed")
				}
				found = true
			}
		}
		if !found {
			return nil, evidence, errors.New("core policy full type declaration omitted")
		}
	}
	for _, group := range target.Enums {
		if bytes.Count(recovered, group) != 1 {
			return nil, evidence, errors.New("core policy actual enum iota group changed")
		}
	}
	for _, function := range corePolicyNames {
		original := append([]byte("package pcv3\n"), target.Functions[function]...)
		sourceSet, sources, parseErr := namedSourceFunctions(original, corePolicyNames)
		if parseErr != nil {
			return nil, evidence, parseErr
		}
		fn := sources[function]
		before := d1Body(original, sourceSet, fn)
		body := d1Body(generated, proofSet, proofs[function])
		entry := arithmeticIdentity{Function: function, ASTRecovered: bytes.Equal(structuralAST(fn), structuralAST(restored[function])), BodyRecovered: bytes.Equal(before, d1Body(recovered, set, restored[function])), RawASTIdentical: bytes.Equal(structuralAST(fn), structuralAST(proofs[function])), RawBodyIdentical: bytes.Equal(before, body), OriginalBody: digest(before), GeneratedBody: digest(body)}
		if !entry.ASTRecovered || !entry.BodyRecovered {
			return nil, evidence, fmt.Errorf("%s actual core policy source was not recovered", function)
		}
		graph, graphErr := corePolicyGraph(pkg, info, restored[function])
		if graphErr != nil {
			return nil, evidence, graphErr
		}
		if !slices.Equal(graph, target.Graphs[function]) {
			return nil, evidence, fmt.Errorf("%s core policy native binding graph changed", function)
		}
		evidence.Functions = append(evidence.Functions, entry)
	}
	for i, offset := range alpha {
		role := "definition"
		if i > 0 {
			role = "use"
		}
		evidence.Alpha = append(evidence.Alpha, alphaReplacement{SourceOffset: target.Metadata.Arithmetic.LowOffsets[i], ProofOffset: offset, Original: "low", Replacement: arithmeticFreshName, Role: role})
	}
	evidence.BindingGraphs = true
	evidence.CompleteTypes = true
	evidence.ConstantsEqual = true
	evidence.MaskUnion = "uint16(3)"
	evidence.GhostInterface = slices.Clone(corePolicyOwnedComments)
	if negative {
		start := bytes.Index(generated, []byte("//@ ensures matches == "))
		evidence.PostconditionLine = bytes.Count(generated[:start], []byte("\n")) + 1
	}
	return generated, evidence, nil
}

func corePolicyRejected(code int, log string, line int) bool {
	lower := strings.ToLower(log)
	return code == 1 && strings.Contains(log, "Gobra found 1 error.") && strings.Contains(log, fmt.Sprintf("</workspace/core-policy-count-mismatch/core_policy.go:%d:9> Postcondition might not hold.", line)) && strings.Contains(log, "Assertion matches == "+corePolicyPost+" might not hold.") && !strings.Contains(lower, "timeout") && !strings.Contains(lower, "outofmemory") && !strings.Contains(lower, "integer overflow")
}

const corePolicyOracle = `package main
import("fmt";"os")
func main(){
 core:=logicalCore{magic:[4]byte{'P','C','V',0},major:3,schema:1,suite:SuiteStandard,frontHeaderLength:1112,payloadKind:PayloadKindRaw,recordProfile:1,metadataProfile:1}
 good:=Geometry{metadataBlocks:777,payloadBodyRS:false,recordCount:0,frontHeaderLength:1112,payloadLength:112,backupCapsuleOffset:1224,trailerOffset:-17,fileSize:-99}
 badCount:=good;badCount.recordCount=1
 badBackup:=good;badBackup.backupCapsuleOffset=1225
 badRS:=good;badRS.payloadBodyRS=true
 negativeH:=good;negativeH.frontHeaderLength=-1
 negativeP:=good;negativeP.payloadLength=-1
 negativeB:=good;negativeB.backupCapsuleOffset=-1
 failed:=false
 for _,c:=range []struct{name string;geometry Geometry;want bool}{{"valid_with_unchecked_fields",good,true},{"count_mismatch",badCount,false},{"backup_mismatch",badBackup,false},{"rs_mismatch",badRS,false},{"negative_header",negativeH,false},{"negative_payload",negativeP,false},{"negative_backup",negativeB,false}} {
  got:=recordGeometryMatchesCore(core,c.geometry);fmt.Printf("%s=%t\n",c.name,got);if got!=c.want{failed=true}
 }
 if failed{os.Exit(1)}
}
`
const corePolicyOraclePositiveOutput = "valid_with_unchecked_fields=true\ncount_mismatch=false\nbackup_mismatch=false\nrs_mismatch=false\nnegative_header=false\nnegative_payload=false\nnegative_backup=false\n"
const corePolicyOracleNegativeOutput = "valid_with_unchecked_fields=false\ncount_mismatch=true\nbackup_mismatch=false\nrs_mismatch=false\nnegative_header=false\nnegative_payload=false\nnegative_backup=false\n"

func runCorePolicy(repo, runDir, imageID string, target corePolicyTarget, report map[string]any) error {
	cases, ok := report["cases"].([]caseResult)
	if !ok || len(cases) != 20 {
		return errors.New("all twenty earlier proof cases required before core policy")
	}
	natives, ok := report["native_controls"].([]caseResult)
	if !ok || len(natives) != 20 {
		return errors.New("all twenty earlier native controls required before core policy")
	}
	hashes := map[string]string{}
	for path, source := range target.Snapshots {
		hashes[path] = digest(source)
	}
	report["core_policy_source"] = map[string]any{"source_snapshots": hashes, "own_bodies": corePolicyNames, "constants": target.Constants, "enum_constants": corePolicyEnumExpected, "geometry_postcondition": "matches == " + corePolicyPost, "mode": "--nooverflow: exact parametric core/geometry policy; standard bits API only bodyless; prior arithmetic/count/metadata/payload overflow lanes mandatory", "ghost_interface": "one runtime bool; ghost gpointer[bool] OUT observation with returned acc; only owned body comments and finite Mul alpha erased", "native_mask_union": "uint16(3)", "trusted_dependencies": "Go/Gobra raw string, UInt16 AND_NOT/AND and zero-array interpretation; source/compiler and std bits interface; no automatic cross-logic proof transport", "caller_obligations": "structural policy and intrinsic H/P/B agreement only; metadataBlocks/trailerOffset/fileSize, complete file/suffix/EOF/authentication/publication remain unchecked"}
	sources := map[string][]byte{"core-policy-original": target.Original}
	for _, name := range []string{"core-policy-positive", "core-policy-count-mismatch"} {
		generated, evidence, err := annotateCorePolicy(target, name)
		if err != nil {
			return err
		}
		directory := filepath.Join(runDir, name)
		if err = os.MkdirAll(directory, 0755); err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(directory, "core_policy.go"), generated, 0644); err != nil {
			return err
		}
		result, err := runCase(runDir, name, "core_policy.go", imageID, generated, identity{PostconditionLine: evidence.PostconditionLine})
		result.Identity = nil
		result.CorePolicyIdentity = &evidence
		cases = append(cases, result)
		report["cases"] = cases
		if err != nil {
			return err
		}
		sources[name] = generated
	}
	for _, name := range []string{"core-policy-original", "core-policy-positive", "core-policy-count-mismatch"} {
		code, expected := 0, corePolicyOraclePositiveOutput
		if name == "core-policy-count-mismatch" {
			code, expected = 1, corePolicyOracleNegativeOutput
		}
		command, err := compileOracle(repo, runDir, name, "core_policy.go", sources[name], []byte(corePolicyOracle), []byte("module picocrypt_ng_core_policy_oracle\n\ngo 1.27.3\n"), nil)
		if err != nil {
			return err
		}
		report[name+"_native_compile_command"] = command
		native, output, err := runIsolated(runDir, name+"-native", imageID, "/workspace/"+name+"-oracle", nil)
		native.Mode = "native frozen core/geometry proof-control witnesses; not authentication or full-application coverage"
		if err == nil {
			native.Passed = native.ExitCode == code && string(output) == expected
			if !native.Passed {
				err = fmt.Errorf("%s native frozen core policy oracle mismatch", name)
			}
		}
		natives = append(natives, native)
		report["native_controls"] = natives
		if err != nil {
			return err
		}
	}
	return nil
}
