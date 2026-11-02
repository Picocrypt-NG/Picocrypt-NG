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
)

const offsetFunctionName = "recordOffsetWithinPayload"
const offsetReviewed = `package pcv3
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
func recordOffsetWithinPayload(
	core logicalCore,
	payloadBodyRS bool,
	index uint64,
) (uint64, bool) {
	if !payloadBodyRS {
		plaintextBefore := core.plaintextLength
		if index < core.recordCount {
			var ok bool
			plaintextBefore, ok = checkedMul64(index, recordPlaintextMax)
			if !ok {
				return 0, false
			}
		}
		overheadBefore, ok := checkedMul64(index, nonRSPayloadOverhead)
		if !ok {
			return 0, false
		}
		return checkedAdd64(plaintextBefore, overheadBefore)
	}

	if index < core.recordCount {
		return checkedMul64(index, fullRSPayloadRecord)
	}
	fullRecords := core.plaintextLength / recordPlaintextMax
	offset, ok := checkedMul64(fullRecords, fullRSPayloadRecord)
	if !ok {
		return 0, false
	}
	partialLength := core.plaintextLength % recordPlaintextMax
	if partialLength == 0 {
		return offset, true
	}
	partialBodyLength, ok := encodedRecordBodyLength(partialLength, true)
	if !ok {
		return 0, false
	}
	partialRecordLength, ok := checkedAdd64(recordDescriptorSize, partialBodyLength)
	if !ok {
		return 0, false
	}
	return checkedAdd64(offset, partialRecordLength)
}
`
const offsetGhost = `/*@
ghost
decreases
pure func OffsetMath(length integer, count integer, rs bool, index integer) integer {
 return rs ? (index < count ? index * 1114296 : PayloadData(length, true)) : (index < count ? index * 1048576 : length) + index * 112
}
ghost
decreases
pure func OffsetEarly(length integer, count integer, rs bool, index integer) bool {
 return rs ? (index >= count && (length / 1048576) * 1114296 >= 18446744073709551616) : ((index < count && index * 1048576 >= 18446744073709551616) || index * 112 >= 18446744073709551616)
}
@*/
`
const offsetContract = `//@ requires 0 <= core.plaintextLength && core.plaintextLength <= 18446744073709551615
//@ requires 0 <= core.recordCount && core.recordCount <= 18446744073709551615
//@ requires 0 <= index && index <= 18446744073709551615
//@ ensures 0 <= resultValue && resultValue <= 18446744073709551615
//@ ensures integer(resultValue) == (OffsetEarly(integer(core.plaintextLength), integer(core.recordCount), payloadBodyRS, integer(index)) ? 0 : OffsetMath(integer(core.plaintextLength), integer(core.recordCount), payloadBodyRS, integer(index)) % 18446744073709551616)
//@ ensures successFlag == (OffsetMath(integer(core.plaintextLength), integer(core.recordCount), payloadBodyRS, integer(index)) < 18446744073709551616)
`

var offsetNames = append(slices.Clone(payloadNames), offsetFunctionName)
var offsetTypePaths = map[string]string{"logicalCore": recordCountRelative, "Suite": preambleRelative, "PayloadKind": recordCountRelative}

type offsetType struct{ Name, Path, Declaration, SHA256 string }
type offsetTarget struct {
	Payload   payloadTarget
	Snapshots map[string][]byte
	Types     []offsetType
	Function  []byte
	Graph     []string
	Locals    []payloadLocal
}
type offsetEvidence struct {
	Functions         []arithmeticIdentity `json:"functions"`
	CompleteTypes     bool                 `json:"full_struct_enum_declarations_and_go_bindings_identical"`
	BindingGraphs     bool                 `json:"seven_body_binding_graphs_match_after_owned_inverse"`
	Alpha             []alphaReplacement   `json:"owned_mul_alpha_replacements"`
	FreshResults      []string             `json:"fresh_results"`
	Control           string               `json:"controlled_mutation,omitempty"`
	PostconditionLine int                  `json:"postcondition_line,omitempty"`
}
type offsetControl struct {
	Before, After string
	Occurrences   int
}

var offsetControls = map[string]offsetControl{
	"offset-boundary-inclusive": {"if index < core.recordCount {", "if index <= core.recordCount {", 2},
	"offset-rs-wrong-width":     {"return checkedMul64(index, fullRSPayloadRecord)", "return checkedMul64(index, nonRSPayloadOverhead)", 1},
	"offset-partial-omitted":    {"return checkedAdd64(offset, partialRecordLength)", "return checkedAdd64(offset, 0*partialRecordLength)", 1},
}
var offsetPost = strings.Split(strings.Split(offsetContract, "//@ ensures ")[2], "\n")[0]

func offsetTypeDeclarations(source []byte) (*token.FileSet, map[string]*ast.GenDecl, error) {
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "types.go", source, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, nil, err
	}
	selected := map[string]*ast.GenDecl{}
	for _, decl := range file.Decls {
		if group, ok := decl.(*ast.GenDecl); ok && group.Tok == token.TYPE {
			for _, item := range group.Specs {
				spec := item.(*ast.TypeSpec)
				if _, wanted := offsetTypePaths[spec.Name.Name]; !wanted {
					continue
				}
				if len(group.Specs) != 1 || spec.Assign != token.NoPos || spec.TypeParams != nil {
					return nil, nil, errors.New("offset types must be complete non-alias non-generic declarations")
				}
				selected[spec.Name.Name] = group
			}
		}
	}
	return set, selected, nil
}

func logicalCoreLabels(pkg *types.Package) (map[types.Object]string, error) {
	labels := map[types.Object]string{}
	for name, kind := range map[string]types.BasicKind{"Suite": types.Uint16, "PayloadKind": types.Uint8} {
		object, ok := pkg.Scope().Lookup(name).(*types.TypeName)
		if !ok || object.IsAlias() {
			return nil, errors.New("offset enum must retain its defined type")
		}
		basic, ok := object.Type().Underlying().(*types.Basic)
		if !ok || basic.Kind() != kind {
			return nil, errors.New("offset enum underlying type changed")
		}
		labels[object] = "type:" + name
	}
	object, ok := pkg.Scope().Lookup("logicalCore").(*types.TypeName)
	if !ok || object.IsAlias() {
		return nil, errors.New("offset must use the complete defined logicalCore")
	}
	structure, ok := object.Type().Underlying().(*types.Struct)
	if !ok {
		return nil, errors.New("offset logicalCore is not a struct")
	}
	labels[object] = "type:logicalCore"
	for i := 0; i < structure.NumFields(); i++ {
		field := structure.Field(i)
		label := field.Type().String()
		if labels[pkg.Scope().Lookup("Suite")] != "" && types.Identical(field.Type(), pkg.Scope().Lookup("Suite").Type()) {
			label = "Suite"
		}
		if labels[pkg.Scope().Lookup("PayloadKind")] != "" && types.Identical(field.Type(), pkg.Scope().Lookup("PayloadKind").Type()) {
			label = "PayloadKind"
		}
		labels[field] = "field:logicalCore." + field.Name() + ":" + label
	}
	return labels, nil
}

func offsetTypeBindings(pkg *types.Package, info *types.Info, set *token.FileSet, declarationSet *token.FileSet, typesByName map[string]*ast.GenDecl, paths map[string]string) error {
	labels, err := logicalCoreLabels(pkg)
	if err != nil {
		return err
	}
	allowed := map[types.Object]bool{}
	for _, name := range []string{"byte", "uint8", "uint16", "uint32", "uint64"} {
		allowed[types.Universe.Lookup(name)] = true
	}
	for object := range labels {
		allowed[object] = true
	}
	for name, decl := range typesByName {
		spec := decl.Specs[0].(*ast.TypeSpec)
		object := pkg.Scope().Lookup(name)
		definition := false
		wanted := declarationSet.PositionFor(spec.Name.Pos(), false).Offset
		for id, bound := range info.Defs {
			p := set.PositionFor(id.Pos(), false)
			if bound == object && p.Filename == paths[name] && p.Offset == wanted {
				definition = true
			}
		}
		if !definition {
			return errors.New("offset type declaration definition binding changed")
		}
		start, end := declarationSet.PositionFor(decl.Pos(), false).Offset, declarationSet.PositionFor(decl.End(), false).Offset
		for id, object := range info.Uses {
			p := set.PositionFor(id.Pos(), false)
			if p.Filename == paths[name] && start <= p.Offset && p.Offset < end && !allowed[object] {
				return fmt.Errorf("offset type %s has unreviewed field/type binding %q", name, id.Name)
			}
		}
	}
	return nil
}

func loadOffset(repo, cache string, payload payloadTarget) (offsetTarget, error) {
	var result offsetTarget
	paths := []string{arithmeticRelative, recordCountRelative, geometryRelative, recordsRelative, preambleRelative}
	pkg, snapshots, err := loadSourceSnapshots(repo, cache, paths, "./internal/pcv3operation/internal/pcv3")
	if err != nil {
		return result, err
	}
	union := map[string][]byte{}
	if err = mergeSourceSnapshots(union, payload.Snapshots); err != nil {
		return result, err
	}
	if err = mergeSourceSnapshots(union, snapshots); err != nil {
		return result, err
	}
	_, reviewedTypes, err := offsetTypeDeclarations([]byte(offsetReviewed))
	if err != nil {
		return result, err
	}
	typeNodes := map[string]*ast.GenDecl{}
	typePaths := map[string]string{}
	var declarations []offsetType
	for _, name := range []string{"Suite", "PayloadKind", "logicalCore"} {
		relative := offsetTypePaths[name]
		source := snapshots[relative]
		set, found, err := offsetTypeDeclarations(source)
		if err != nil {
			return result, err
		}
		declaration := found[name]
		if declaration == nil || !bytes.Equal(structuralAST(declaration), structuralAST(reviewedTypes[name])) {
			return result, fmt.Errorf("offset full %s declaration left the reviewed type closure", name)
		}
		file := set.File(declaration.Pos())
		text := source[file.Offset(declaration.Pos()):file.Offset(declaration.End())]
		var actual *ast.GenDecl
		for _, syntax := range pkg.Syntax {
			for _, item := range syntax.Decls {
				if group, ok := item.(*ast.GenDecl); ok && group.Tok == token.TYPE {
					for _, item := range group.Specs {
						if spec, ok := item.(*ast.TypeSpec); ok && spec.Name.Name == name && pkg.Fset.PositionFor(spec.Pos(), false).Filename == filepath.Join(repo, relative) {
							actual = group
						}
					}
				}
			}
		}
		if actual == nil || !bytes.Equal(structuralAST(actual), structuralAST(declaration)) {
			return result, errors.New("offset type differs from actual parsed package")
		}
		typeNodes[name], typePaths[name] = actual, filepath.Join(repo, relative)
		declarations = append(declarations, offsetType{name, relative, string(text), digest(text)})
	}
	if err = offsetTypeBindings(pkg.Types, pkg.TypesInfo, pkg.Fset, pkg.Fset, typeNodes, typePaths); err != nil {
		return result, err
	}
	set, functions, err := namedSourceFunctions(snapshots[recordsRelative], offsetNames)
	if err != nil {
		return result, err
	}
	_, expected, err := namedSourceFunctions([]byte(offsetReviewed), offsetNames)
	if err != nil {
		return result, err
	}
	fn := functions[offsetFunctionName]
	if fn == nil || !bytes.Equal(structuralAST(fn), structuralAST(expected[offsetFunctionName])) {
		return result, errors.New("offset body left the reviewed source subset")
	}
	if err = payloadFresh(fn, payloadResultNames); err != nil {
		return result, err
	}
	if err = payloadFresh(fn, []string{"OffsetMath", "OffsetEarly"}); err != nil {
		return result, err
	}
	for _, name := range []string{"OffsetMath", "OffsetEarly"} {
		if pkg.Types.Scope().Lookup(name) != nil {
			return result, errors.New("offset ghost name collides with an actual package object")
		}
	}
	var actual *ast.FuncDecl
	for _, syntax := range pkg.Syntax {
		for _, item := range syntax.Decls {
			if candidate, ok := item.(*ast.FuncDecl); ok && candidate.Name.Name == offsetFunctionName && pkg.Fset.PositionFor(candidate.Pos(), false).Filename == filepath.Join(repo, recordsRelative) {
				actual = candidate
			}
		}
	}
	if actual == nil || !bytes.Equal(structuralAST(fn), structuralAST(actual)) {
		return result, errors.New("offset function differs from parsed actual package")
	}
	object, ok := pkg.Types.Scope().Lookup(offsetFunctionName).(*types.Func)
	file := set.File(fn.Pos())
	if !ok || pkg.Fset.PositionFor(object.Pos(), false).Filename != filepath.Join(repo, recordsRelative) || pkg.Fset.PositionFor(object.Pos(), false).Offset != file.Offset(fn.Name.Pos()) {
		return result, errors.New("offset function declaration binding changed")
	}
	constants := map[string]*types.Const{}
	for name := range payloadConstantExpected {
		constants[name] = pkg.Types.Scope().Lookup(name).(*types.Const)
	}
	graph, locals, err := payloadBindingGraph(pkg.Types, pkg.TypesInfo, pkg.Fset, actual, filepath.Join(repo, recordsRelative), constants)
	if err != nil {
		return result, err
	}
	result = offsetTarget{Payload: payload, Snapshots: snapshots, Types: declarations, Function: slices.Clone(snapshots[recordsRelative][file.Offset(fn.Pos()):file.Offset(fn.End())]), Graph: graph, Locals: locals}
	return result, nil
}

func offsetAnnotateFunction(source []byte) ([]byte, error) {
	prefix := []byte("package pcv3\n")
	full := append(slices.Clone(prefix), source...)
	set, functions, err := namedSourceFunctions(full, offsetNames)
	if err != nil {
		return nil, err
	}
	fn := functions[offsetFunctionName]
	if fn == nil {
		return nil, errors.New("offset declaration missing")
	}
	if err = payloadFresh(fn, payloadResultNames); err != nil {
		return nil, err
	}
	file := set.File(fn.Pos())
	generated := slices.Clone(source)
	for i := len(payloadResultNames) - 1; i >= 0; i-- {
		offset := file.Offset(fn.Type.Results.List[i].Type.Pos()) - len(prefix)
		generated = append(generated[:offset], append([]byte("/*@ "+payloadResultNames[i]+" @*/ "), generated[offset:]...)...)
	}
	return append([]byte(offsetContract), generated...), nil
}

func annotateOffset(target offsetTarget, name string) ([]byte, offsetEvidence, error) {
	var evidence offsetEvidence
	generated, payload, err := annotatePayload(target.Payload, "payload-positive")
	if err != nil {
		return nil, evidence, err
	}
	for _, declaration := range target.Types {
		generated = append(generated, []byte(declaration.Declaration+"\n")...)
	}
	generated = append(generated, []byte(offsetGhost)...)
	declaration, err := offsetAnnotateFunction(target.Function)
	if err != nil {
		return nil, evidence, err
	}
	generated = append(generated, declaration...)
	generated = append(generated, '\n')
	positive := slices.Clone(generated)
	control, negative := offsetControls[name]
	if negative {
		if bytes.Count(generated, []byte(control.Before)) != control.Occurrences {
			return nil, evidence, errors.New("offset controlled mutation site changed")
		}
		generated = bytes.Replace(generated, []byte(control.Before), []byte(control.After), 1)
		evidence.Control = control.Before + " -> " + control.After
		evidence.PostconditionLine = bytes.Count(generated[:bytes.Index(generated, []byte("//@ ensures "+offsetPost))], []byte("\n")) + 1
	} else if name != "offset-positive" {
		return nil, evidence, errors.New("unknown offset proof case")
	}
	if _, _, _, _, err = sourceCopyInfo(generated, target.Payload.Arithmetic.Imports, offsetNames); err != nil {
		return nil, evidence, err
	}
	inverse := slices.Clone(generated)
	if negative {
		inverse = bytes.Replace(inverse, []byte(control.After), []byte(control.Before), 1)
	}
	if !bytes.Equal(inverse, positive) {
		return nil, evidence, errors.New("offset mutation inverse changed more than its owned expression")
	}
	alpha, err := arithmeticFreshBindings(inverse, target.Payload.Arithmetic.Imports)
	if err != nil {
		return nil, evidence, err
	}
	recovered, err := replaceArithmeticTokens(inverse, alpha, arithmeticFreshName, "low")
	if err != nil {
		return nil, evidence, err
	}
	pkg, info, set, restored, err := sourceCopyInfo(recovered, target.Payload.Arithmetic.Imports, offsetNames)
	if err != nil {
		return nil, evidence, err
	}
	typeSet, typeNodes, err := offsetTypeDeclarations(recovered)
	if err != nil {
		return nil, evidence, err
	}
	typePaths := map[string]string{}
	for _, declaration := range target.Types {
		node := typeNodes[declaration.Name]
		if node == nil {
			return nil, evidence, errors.New("offset copy omits a full type declaration")
		}
		file := typeSet.File(node.Pos())
		if string(recovered[file.Offset(node.Pos()):file.Offset(node.End())]) != declaration.Declaration {
			return nil, evidence, errors.New("offset type declaration bytes changed")
		}
		typePaths[declaration.Name] = "payload.go"
	}
	if err = offsetTypeBindings(pkg, info, set, typeSet, typeNodes, typePaths); err != nil {
		return nil, evidence, err
	}
	proofSet, proofs, err := namedSourceFunctions(generated, offsetNames)
	if err != nil {
		return nil, evidence, err
	}
	constants := map[string]*types.Const{}
	for _, constant := range target.Payload.Constants {
		object, ok := pkg.Scope().Lookup(constant.Name).(*types.Const)
		if !ok || object.Type().String() != constant.Type || object.Val().ExactString() != constant.Value {
			return nil, evidence, errors.New("offset copied constant type/value changed")
		}
		constants[constant.Name] = object
	}
	for _, function := range offsetNames {
		source := target.Payload.Functions[function]
		wantGraph := target.Payload.Graphs[function]
		if function == offsetFunctionName {
			source = target.Function
			wantGraph = target.Graph
		}
		original := append([]byte("package pcv3\n"), source...)
		sourceSet, sources, err := namedSourceFunctions(original, offsetNames)
		if err != nil {
			return nil, evidence, err
		}
		fn := sources[function]
		before := d1Body(original, sourceSet, fn)
		body := d1Body(generated, proofSet, proofs[function])
		entry := arithmeticIdentity{Function: function, ASTRecovered: bytes.Equal(structuralAST(fn), structuralAST(restored[function])), BodyRecovered: bytes.Equal(before, d1Body(recovered, set, restored[function])), RawASTIdentical: bytes.Equal(structuralAST(fn), structuralAST(proofs[function])), RawBodyIdentical: bytes.Equal(before, body), OriginalBody: digest(before), GeneratedBody: digest(body)}
		if !entry.ASTRecovered || !entry.BodyRecovered {
			return nil, evidence, errors.New("offset source declaration was not recovered by only its owned edits")
		}
		graph, _, err := payloadBindingGraph(pkg, info, set, restored[function], "payload.go", constants)
		if err != nil {
			return nil, evidence, err
		}
		if !slices.Equal(graph, wantGraph) {
			return nil, evidence, fmt.Errorf("%s offset-module binding graph differs from actual source", function)
		}
		evidence.Functions = append(evidence.Functions, entry)
	}
	evidence.CompleteTypes = true
	evidence.BindingGraphs = true
	evidence.Alpha = payload.Alpha
	evidence.FreshResults = slices.Clone(payloadResultNames)
	return generated, evidence, nil
}

func offsetRejected(code int, log, name string, line int) bool {
	if _, ok := offsetControls[name]; !ok {
		return false
	}
	lower := strings.ToLower(log)
	return code == 1 && strings.Contains(log, "Gobra found 1 error.") && strings.Contains(log, fmt.Sprintf("</workspace/%s/offset.go:%d:9> Postcondition might not hold.", name, line)) && strings.Contains(log, "Assertion "+offsetPost+" might not hold.") && !strings.Contains(lower, "timeout") && !strings.Contains(lower, "outofmemory") && !strings.Contains(lower, "integer overflow")
}

const offsetOraclePrefix = `package main
import ("fmt"; "os")
var failed bool
func expectOffset(label string,length,count,index uint64,rs bool,want uint64,wantFlag bool) {
 core:=logicalCore{magic:[4]byte{'B','A','D','!'},major:65535,schema:65535,suite:Suite(65535),featureFlags:65535,frontHeaderLength:4294967295,volumeID:[32]byte{7},payloadKind:PayloadKind(255),recordProfile:255,metadataProfile:255,reserved:255,plaintextLength:length,recordCount:count,xChaChaNoncePrefix:[16]byte{8},serpentIVPrefix:[8]byte{9},commentLength:4294967295}
 value,flag:=recordOffsetWithinPayload(core,rs,index)
 fmt.Printf("%s=%d,%t\n",label,value,flag)
 if value!=want || flag!=wantFlag {failed=true}
}
func main() {
`
const offsetOraclePositive = `expectOffset("zero_nonrs",0,0,0,false,0,true)
expectOffset("zero_rs",0,0,0,true,0,true)
expectOffset("final_nonrs",1,1,1,false,113,true)
expectOffset("final_rs",1,1,1,true,184,true)
expectOffset("after_final_nonrs",1,1,2,false,225,true)
expectOffset("after_final_rs",1,1,2,true,184,true)
expectOffset("independent_count_nonrs",1,0,0,false,1,true)
expectOffset("independent_count_rs",1,0,0,true,184,true)
expectOffset("early_plaintext",0,17592186044417,17592186044416,false,0,false)
expectOffset("early_overhead",0,0,164703072086692426,false,0,false)
expectOffset("sum_wrap",18446744073709551615,0,1,false,111,false)
expectOffset("rs_data_width",2097152,2,1,true,1114296,true)
expectOffset("rs_data_wrap",18446744073709551615,17592186044416,16554617510706,true,101360,false)
expectOffset("rs_final_early",18446744073709551615,17592186044416,17592186044416,true,0,false)
expectOffset("rs_final_wrap",17358774610905959233,16554617510706,16554617510706,true,40,false)
expectOffset("nonrs_final_wrap",18446744073709551615,17592186044416,17592186044416,false,1970324836974591,false)
`
const offsetOraclePositiveOutput = "zero_nonrs=0,true\nzero_rs=0,true\nfinal_nonrs=113,true\nfinal_rs=184,true\nafter_final_nonrs=225,true\nafter_final_rs=184,true\nindependent_count_nonrs=1,true\nindependent_count_rs=184,true\nearly_plaintext=0,false\nearly_overhead=0,false\nsum_wrap=111,false\nrs_data_width=1114296,true\nrs_data_wrap=101360,false\nrs_final_early=0,false\nrs_final_wrap=40,false\nnonrs_final_wrap=1970324836974591,false\n"

func offsetNative(name string) ([]byte, int, string) {
	body, code, expected := offsetOraclePositive, 0, offsetOraclePositiveOutput
	switch name {
	case "offset-boundary-inclusive":
		body = "expectOffset(\"final_nonrs\",1,1,1,false,113,true)\n"
		code, expected = 1, "final_nonrs=1048688,true\n"
	case "offset-rs-wrong-width":
		body = "expectOffset(\"rs_data_width\",2097152,2,1,true,1114296,true)\n"
		code, expected = 1, "rs_data_width=112,true\n"
	case "offset-partial-omitted":
		body = "expectOffset(\"final_rs\",1,1,1,true,184,true)\n"
		code, expected = 1, "final_rs=0,true\n"
	}
	return []byte(offsetOraclePrefix + body + "if failed {os.Exit(1)}\n}\n"), code, expected
}

func runOffset(repo, runDir, imageID string, target offsetTarget, report map[string]any) error {
	cases, ok := report["cases"].([]caseResult)
	if !ok {
		return errors.New("earlier mandatory source proofs missing before offset")
	}
	natives, ok := report["native_controls"].([]caseResult)
	if !ok {
		return errors.New("earlier mandatory native controls missing before offset")
	}
	hashes := map[string]string{}
	for path, source := range target.Snapshots {
		hashes[path] = digest(source)
	}
	report["offset_source"] = map[string]any{
		"path": recordsRelative, "source_snapshots": hashes, "own_bodies": offsetNames, "types": target.Types, "locals": target.Locals, "ghost_math": offsetGhost, "contract": offsetContract,
		"representation":         "complete by-value logicalCore, defined Suite(uint16) and PayloadKind(uint8); unused fields arbitrary well-typed values; full U64 plaintextLength/recordCount/index and both independent RS flags",
		"mode":                   "--overflow; no canonical count, index bound, schema or feature-flag premise",
		"trusted_dependencies":   "existing standard bits API, finite Mul alpha, compiler-evaluated constants; reviewed complete named-type/field embedding and Go/Gobra frontend, not automatic cross-logic transport",
		"control_classification": "exact offset result postcondition failures and frozen native witnesses; no observed SAT certificate",
		"caller_obligations":     "only canonical count plus index<=count and a fitting extent joins the valid-caller record_offset model; this raw helper validates none of those conditions",
	}
	var original bytes.Buffer
	original.WriteString("package pcv3\nimport \"math/bits\"\n")
	original.Write(target.Payload.OriginalConstants)
	for _, declaration := range target.Types {
		original.WriteString(declaration.Declaration + "\n")
	}
	for _, function := range payloadNames {
		original.Write(target.Payload.Functions[function])
		original.WriteByte('\n')
	}
	original.Write(target.Function)
	original.WriteByte('\n')
	sources := map[string][]byte{"offset-original": original.Bytes()}
	for _, name := range []string{"offset-positive", "offset-boundary-inclusive", "offset-rs-wrong-width", "offset-partial-omitted"} {
		generated, evidence, err := annotateOffset(target, name)
		if err != nil {
			return err
		}
		directory := filepath.Join(runDir, name)
		if err = os.MkdirAll(directory, 0755); err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(directory, "offset.go"), generated, 0644); err != nil {
			return err
		}
		result, err := runCase(runDir, name, "offset.go", imageID, generated, identity{PostconditionLine: evidence.PostconditionLine})
		result.Identity = nil
		result.OffsetIdentity = &evidence
		cases = append(cases, result)
		report["cases"] = cases
		if err != nil {
			return err
		}
		sources[name] = generated
	}
	for _, name := range []string{"offset-original", "offset-positive", "offset-boundary-inclusive", "offset-rs-wrong-width", "offset-partial-omitted"} {
		oracle, code, expected := offsetNative(name)
		command, err := compileOracle(repo, runDir, name, "offset.go", sources[name], oracle, []byte("module picocrypt_ng_offset_oracle\n\ngo 1.27.3\n"), nil)
		if err != nil {
			return err
		}
		report[name+"_native_compile_command"] = command
		native, output, err := runIsolated(runDir, name+"-native", imageID, "/workspace/"+name+"-oracle", nil)
		native.Mode = "native frozen offset helper proof-control oracle with complete invalid-schema core values; not caller validation or whole-application coverage"
		if err == nil {
			native.Passed = native.ExitCode == code && string(output) == expected
			if !native.Passed {
				err = fmt.Errorf("%s native frozen offset oracle mismatch", name)
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
