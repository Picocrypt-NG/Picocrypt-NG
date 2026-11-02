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
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

const geometryRelative = "src/internal/pcv3operation/internal/pcv3/geometry.go"
const recordsRelative = "src/internal/pcv3operation/internal/pcv3/records.go"
const preambleRelative = "src/internal/pcv3operation/internal/pcv3/preamble.go"
const payloadReviewed = `package pcv3
func canonicalRecordCount(plaintextLength uint64) uint64 {
	if plaintextLength == 0 {
		return 0
	}
	return (plaintextLength-1)/recordPlaintextMax + 1
}
func canonicalPayloadLength(plaintextLength, recordCount uint64, payloadBodyRS bool) (uint64, bool) {
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
func encodedRecordBodyLength(ciphertextLength uint64, payloadBodyRS bool) (uint64, bool) {
	semanticLength, ok := checkedAdd64(ciphertextLength, recordTagSize)
	if !ok {
		return 0, false
	}
	if !payloadBodyRS {
		return semanticLength, true
	}
	blocks, ok := checkedCeilDiv64(semanticLength, rs128DataLength)
	if !ok {
		return 0, false
	}
	return checkedMul64(blocks, rs128CodewordLength)
}
`
const payloadGhost = `/*@
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
`
const payloadCountContract = `//@ requires 0 <= plaintextLength && plaintextLength <= 18446744073709551615
//@ ensures 0 <= count && count <= 17592186044416
//@ ensures plaintextLength % recordPlaintextMax == 0 ==> count == plaintextLength / recordPlaintextMax
//@ ensures plaintextLength % recordPlaintextMax != 0 ==> count == plaintextLength / recordPlaintextMax + 1
//@ ensures (count == 0) == (plaintextLength == 0)
//@ ensures integer(count) == PayloadCount(integer(plaintextLength))
`
const payloadLengthContract = `//@ requires 0 <= plaintextLength && plaintextLength <= 18446744073709551615
//@ requires 0 <= recordCount && recordCount <= 18446744073709551615
//@ ensures 0 <= resultValue && resultValue <= 18446744073709551615
//@ ensures integer(resultValue) == (!PayloadValid(integer(plaintextLength), integer(recordCount)) || (payloadBodyRS && PayloadData(integer(plaintextLength), payloadBodyRS) >= 18446744073709551616) ? 0 : PayloadTotal(integer(plaintextLength), payloadBodyRS) % 18446744073709551616)
//@ ensures successFlag == (PayloadValid(integer(plaintextLength), integer(recordCount)) && PayloadTotal(integer(plaintextLength), payloadBodyRS) < 18446744073709551616)
`
const encodedBodyContract = `//@ requires 0 <= ciphertextLength && ciphertextLength <= 18446744073709551615
//@ ensures 0 <= resultValue && resultValue <= 18446744073709551615
//@ ensures integer(resultValue) == (integer(ciphertextLength) + 64 >= 18446744073709551616 ? 0 : PayloadEncoded(integer(ciphertextLength), payloadBodyRS) % 18446744073709551616)
//@ ensures successFlag == (PayloadEncoded(integer(ciphertextLength), payloadBodyRS) < 18446744073709551616)
`

var payloadNames = []string{"checkedAdd64", "checkedMul64", "checkedCeilDiv64", "canonicalRecordCount", "canonicalPayloadLength", "encodedRecordBodyLength"}
var payloadPaths = map[string]string{"checkedAdd64": arithmeticRelative, "checkedMul64": arithmeticRelative, "checkedCeilDiv64": arithmeticRelative, "canonicalRecordCount": recordCountRelative, "canonicalPayloadLength": geometryRelative, "encodedRecordBodyLength": recordsRelative}
var payloadResultNames = []string{"resultValue", "successFlag"}
var payloadConstantExpected = map[string]struct{ Value, Type, Path string }{
	"recordPlaintextMax": {"1048576", "untyped int", recordCountRelative}, "maximumRecordCount": {"281474976710656", "uint64", recordCountRelative},
	"recordDescriptorSize": {"48", "uint64", geometryRelative}, "recordTagSize": {"64", "uint64", geometryRelative}, "nonRSPayloadOverhead": {"112", "uint64", geometryRelative},
	"rs128DataLength": {"128", "uint64", preambleRelative}, "rs128CodewordLength": {"136", "uint64", preambleRelative}, "fullRSPayloadRecord": {"1114296", "uint64", geometryRelative}, "finalRSPayloadRecord": {"184", "uint64", geometryRelative},
}

type payloadConstant struct {
	Name, Type, Value, Path, Initializer string
	Dependencies                         []string
	Offset                               int
}
type payloadLocal struct {
	Function, Name, Type string
	Definition           int
	Uses                 []int
}
type payloadTarget struct {
	Arithmetic        arithmeticTarget
	Snapshots         map[string][]byte
	Functions         map[string][]byte
	Constants         []payloadConstant
	OriginalConstants []byte
	Locals            []payloadLocal
	Graphs            map[string][]string
}
type payloadControl struct{ Function, Before, After, Post string }

var payloadControls = map[string]payloadControl{
	"payload-final-omitted":      {"canonicalPayloadLength", "checkedAdd64(recordCount, 1)", "checkedAdd64(recordCount, 0)", strings.Split(strings.Split(payloadLengthContract, "//@ ensures ")[2], "\n")[0]},
	"payload-rs-floored":         {"encodedRecordBodyLength", "return checkedMul64(blocks, rs128CodewordLength)", "return checkedMul64(semanticLength / rs128DataLength + 0*blocks, rs128CodewordLength)", strings.Split(strings.Split(encodedBodyContract, "//@ ensures ")[2], "\n")[0]},
	"payload-bad-count-accepted": {"canonicalPayloadLength", "recordCount != canonicalRecordCount(plaintextLength) || recordCount >= maximumRecordCount", "recordCount != canonicalRecordCount(plaintextLength) && recordCount >= maximumRecordCount", strings.Split(strings.Split(payloadLengthContract, "//@ ensures ")[2], "\n")[0]},
}

type payloadEvidence struct {
	Functions         []arithmeticIdentity `json:"functions"`
	Alpha             []alphaReplacement   `json:"owned_mul_alpha_replacements"`
	BindingGraphs     bool                 `json:"six_function_go_binding_graphs_match_after_owned_inverse"`
	FreshResults      []string             `json:"fresh_results"`
	Control           string               `json:"controlled_mutation,omitempty"`
	PostconditionLine int                  `json:"postcondition_line,omitempty"`
}

func namedPayloadFunctions(source []byte) (*token.FileSet, map[string]*ast.FuncDecl, error) {
	return namedSourceFunctions(source, payloadNames)
}

func namedSourceFunctions(source []byte, names []string) (*token.FileSet, map[string]*ast.FuncDecl, error) {
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "payload.go", source, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, nil, err
	}
	functions := map[string]*ast.FuncDecl{}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && slices.Contains(names, fn.Name.Name) {
			functions[fn.Name.Name] = fn
		}
	}
	return set, functions, nil
}

func payloadFresh(fn *ast.FuncDecl, names []string) error {
	var rejected error
	ast.Inspect(fn, func(node ast.Node) bool {
		if id, ok := node.(*ast.Ident); ok && slices.Contains(names, id.Name) {
			rejected = fmt.Errorf("owned payload result name %q collides with a source identifier", id.Name)
		}
		return rejected == nil
	})
	return rejected
}

func payloadConstantDeclarations(pkg *packages.Package, repo string, snapshots map[string][]byte) ([]payloadConstant, []byte, error) {
	return sourceConstantDeclarations(pkg, repo, snapshots, payloadConstantExpected)
}

func sourceConstantDeclarations(pkg *packages.Package, repo string, snapshots map[string][]byte, expected map[string]struct{ Value, Type, Path string }) ([]payloadConstant, []byte, error) {
	allowed := map[types.Object]bool{types.Universe.Lookup("uint64"): true, types.Universe.Lookup("uint16"): true}
	for name, want := range expected {
		constant, ok := pkg.Types.Scope().Lookup(name).(*types.Const)
		if !ok || constant.Val().ExactString() != want.Value || constant.Type().String() != want.Type || pkg.Fset.PositionFor(constant.Pos(), false).Filename != filepath.Join(repo, want.Path) {
			return nil, nil, fmt.Errorf("payload constant %s type/value/origin changed", name)
		}
		allowed[constant] = true
	}
	var constants []payloadConstant
	var original bytes.Buffer
	original.WriteString("const (\n")
	for _, syntax := range pkg.Syntax {
		for _, decl := range syntax.Decls {
			group, ok := decl.(*ast.GenDecl)
			if !ok || group.Tok != token.CONST {
				continue
			}
			for _, specification := range group.Specs {
				spec := specification.(*ast.ValueSpec)
				for _, name := range spec.Names {
					want, selected := expected[name.Name]
					if !selected {
						continue
					}
					if len(spec.Names) != 1 || len(spec.Values) != 1 {
						return nil, nil, errors.New("payload constant initializer must remain explicit and single-name")
					}
					start, end := pkg.Fset.PositionFor(spec.Pos(), false), pkg.Fset.PositionFor(spec.End(), false)
					if start.Filename != filepath.Join(repo, want.Path) || pkg.TypesInfo.Defs[name] != pkg.Types.Scope().Lookup(name.Name) {
						return nil, nil, errors.New("payload constant declaration binding changed")
					}
					var rejected error
					ast.Inspect(spec, func(node ast.Node) bool {
						if node == nil || rejected != nil {
							return false
						}
						switch e := node.(type) {
						case *ast.ValueSpec, *ast.Ident, *ast.ParenExpr:
							return true
						case *ast.BasicLit:
							if e.Kind == token.INT || e.Kind == token.STRING {
								return true
							}
						case *ast.BinaryExpr:
							if slices.Contains([]token.Token{token.ADD, token.SUB, token.MUL, token.QUO, token.SHL}, e.Op) {
								return true
							}
						case *ast.CallExpr:
							if id, ok := e.Fun.(*ast.Ident); ok && id.Name == "uint64" && len(e.Args) == 1 && e.Ellipsis == token.NoPos {
								return true
							}
						}
						rejected = fmt.Errorf("unreviewed payload constant syntax %T", node)
						return false
					})
					if rejected != nil {
						return nil, nil, rejected
					}
					deps := []string{}
					for id, used := range pkg.TypesInfo.Uses {
						position := pkg.Fset.PositionFor(id.Pos(), false)
						if position.Filename != start.Filename || position.Offset < start.Offset || position.Offset >= end.Offset {
							continue
						}
						if !allowed[used] {
							return nil, nil, fmt.Errorf("payload constant %s has unreviewed dependency %q", name.Name, id.Name)
						}
						if used != types.Universe.Lookup("uint64") {
							deps = append(deps, used.Name())
						}
					}
					slices.Sort(deps)
					deps = slices.Compact(deps)
					text := snapshots[want.Path][start.Offset:end.Offset]
					original.Write(text)
					original.WriteByte('\n')
					constants = append(constants, payloadConstant{name.Name, want.Type, want.Value, want.Path, string(text), deps, start.Offset})
				}
			}
		}
	}
	if len(constants) != len(expected) {
		return nil, nil, errors.New("payload constant dependency closure missing")
	}
	sort.Slice(constants, func(i, j int) bool { return constants[i].Name < constants[j].Name })
	original.WriteString(")\n")
	return constants, original.Bytes(), nil
}

func payloadBindingGraph(pkg *types.Package, info *types.Info, set *token.FileSet, fn *ast.FuncDecl, path string, constants map[string]*types.Const) ([]string, []payloadLocal, error) {
	object, ok := pkg.Scope().Lookup(fn.Name.Name).(*types.Func)
	if !ok {
		return nil, nil, errors.New("payload function object missing")
	}
	signature := object.Type().(*types.Signature)
	metadata := fn.Name.Name == metadataFunctionName
	labels := map[types.Object]string{}
	standard := map[types.Object]string{}
	coreLabels := map[types.Object]string{}
	if fn.Name.Name == offsetFunctionName {
		var err error
		coreLabels, err = logicalCoreLabels(pkg)
		if err != nil {
			return nil, nil, err
		}
	}
	for _, imported := range pkg.Imports() {
		if imported.Path() == "math/bits" {
			for _, name := range []string{"Add64", "Mul64"} {
				standard[imported.Scope().Lookup(name)] = "standard:math/bits." + name
			}
		}
	}
	for i := 0; i < signature.Params().Len(); i++ {
		p := signature.Params().At(i)
		expected := types.Typ[types.Uint64]
		if metadata {
			expected = types.Typ[types.Uint32]
		}
		if p.Name() == "payloadBodyRS" {
			expected = types.Typ[types.Bool]
		}
		if fn.Name.Name == offsetFunctionName && p.Name() == "core" {
			core := pkg.Scope().Lookup("logicalCore")
			if core == nil || !types.Identical(p.Type(), core.Type()) {
				return nil, nil, errors.New("offset core parameter must be the complete by-value logicalCore")
			}
			labels[p] = fmt.Sprintf("param:%d:core:logicalCore", i)
			continue
		}
		if !types.Identical(p.Type(), expected) {
			return nil, nil, errors.New("payload parameter type changed")
		}
		labels[p] = fmt.Sprintf("param:%d:%s:%s", i, p.Name(), p.Type())
	}
	for i := 0; i < signature.Results().Len(); i++ {
		expected := types.Typ[types.Uint64]
		if (!metadata && i == 1) || (metadata && i == 2) {
			expected = types.Typ[types.Bool]
		}
		if !types.Identical(signature.Results().At(i).Type(), expected) {
			return nil, nil, errors.New("payload result type changed")
		}
		if metadata {
			result := signature.Results().At(i)
			labels[result] = fmt.Sprintf("result:%d:%s:%s", i, result.Name(), result.Type())
		}
	}
	body := set.PositionFor(fn.Body.Pos(), false).Offset
	start, end := set.PositionFor(fn.Pos(), false).Offset, set.PositionFor(fn.End(), false).Offset
	inside := func(pos token.Pos) bool {
		p := set.PositionFor(pos, false)
		return p.Filename == path && start <= p.Offset && p.Offset < end
	}
	var locals []payloadLocal
	for id, definition := range info.Defs {
		if !inside(id.Pos()) || set.PositionFor(id.Pos(), false).Offset < body {
			continue
		}
		local, ok := definition.(*types.Var)
		if !ok || local.IsField() || local.Parent() == pkg.Scope() {
			return nil, nil, errors.New("payload local is not a lexical variable")
		}
		expected := types.Typ[types.Uint64]
		if id.Name == "ok" {
			expected = types.Typ[types.Bool]
		}
		if !types.Identical(local.Type(), expected) {
			return nil, nil, errors.New("payload local type changed")
		}
		offset := set.PositionFor(id.Pos(), false).Offset - body
		labels[local] = fmt.Sprintf("local:%d:%s:%s", offset, id.Name, local.Type())
		entry := payloadLocal{Function: fn.Name.Name, Name: id.Name, Type: local.Type().String(), Definition: offset}
		for usedID, used := range info.Uses {
			if used == local && inside(usedID.Pos()) {
				entry.Uses = append(entry.Uses, set.PositionFor(usedID.Pos(), false).Offset-body)
			}
		}
		slices.Sort(entry.Uses)
		locals = append(locals, entry)
	}
	var graph []string
	for id, used := range info.Uses {
		if !inside(id.Pos()) {
			continue
		}
		if set.PositionFor(id.Pos(), false).Offset < body {
			if used != types.Universe.Lookup("uint64") && used != types.Universe.Lookup("bool") && (!metadata || used != types.Universe.Lookup("uint32")) && (fn.Name.Name != offsetFunctionName || used != pkg.Scope().Lookup("logicalCore")) {
				return nil, nil, errors.New("payload signature contains an unreviewed type binding")
			}
			continue
		}
		label := labels[used]
		if label == "" {
			label = coreLabels[used]
		}
		if label == "" {
			if used == types.Universe.Lookup(id.Name) {
				label = "builtin:" + id.Name
			} else if constant, ok := used.(*types.Const); ok && constants[id.Name] == constant {
				label = "constant:" + id.Name + ":" + constant.Type().String() + ":" + constant.Val().ExactString()
			} else if function, ok := used.(*types.Func); ok && (slices.Contains(payloadNames, function.Name()) || function.Name() == offsetFunctionName) && pkg.Scope().Lookup(function.Name()) == function {
				label = "own-body:" + function.Name()
			} else if standard[used] != "" {
				label = standard[used]
			} else if imported, ok := used.(*types.PkgName); ok && imported.Imported().Path() == "math/bits" {
				label = "import:math/bits"
			}
		}
		if label == "" {
			return nil, nil, fmt.Errorf("unreviewed payload binding %q", id.Name)
		}
		graph = append(graph, fmt.Sprintf("%d:%s", set.PositionFor(id.Pos(), false).Offset-body, label))
	}
	slices.Sort(graph)
	sort.Slice(locals, func(i, j int) bool { return locals[i].Definition < locals[j].Definition })
	return graph, locals, nil
}

func loadPayload(repo, cache string, arithmetic arithmeticTarget) (payloadTarget, error) {
	var result payloadTarget
	paths := []string{arithmeticRelative, recordCountRelative, geometryRelative, recordsRelative, preambleRelative}
	pkg, snapshots, err := loadSourceSnapshots(repo, cache, paths, "./internal/pcv3operation/internal/pcv3")
	if err != nil {
		return result, err
	}
	for _, source := range snapshots {
		if sourceAnnotationPattern.Match(source) {
			return result, errors.New("payload source closure contains verifier input markers")
		}
	}
	if !bytes.Equal(snapshots[arithmeticRelative], arithmetic.Source) {
		return result, errors.New("arithmetic source snapshot changed before payload closure")
	}
	_, reviewed, err := namedPayloadFunctions([]byte(payloadReviewed))
	if err != nil {
		return result, err
	}
	functions := map[string][]byte{}
	graphs := map[string][]string{}
	var locals []payloadLocal
	constants, originalConstants, err := payloadConstantDeclarations(pkg, repo, snapshots)
	if err != nil {
		return result, err
	}
	constObjects := map[string]*types.Const{}
	for name := range payloadConstantExpected {
		constObjects[name] = pkg.Types.Scope().Lookup(name).(*types.Const)
	}
	for _, name := range payloadNames {
		path := payloadPaths[name]
		source := snapshots[path]
		set, found, err := namedPayloadFunctions(source)
		if err != nil {
			return result, err
		}
		fn := found[name]
		if fn == nil || fn.Body == nil {
			return result, errors.New("payload own function body missing")
		}
		if template := reviewed[name]; template != nil && !bytes.Equal(structuralAST(fn), structuralAST(template)) {
			return result, fmt.Errorf("%s left the reviewed payload source subset", name)
		}
		if name == "canonicalPayloadLength" || name == "encodedRecordBodyLength" {
			if err = payloadFresh(fn, payloadResultNames); err != nil {
				return result, err
			}
		}
		if err = payloadFresh(fn, []string{"PayloadCount", "PayloadEncoded", "PayloadData", "PayloadTotal", "PayloadValid"}); err != nil {
			return result, err
		}
		file := set.File(fn.Pos())
		functions[name] = slices.Clone(source[file.Offset(fn.Pos()):file.Offset(fn.End())])
		var actual *ast.FuncDecl
		for _, syntax := range pkg.Syntax {
			for _, decl := range syntax.Decls {
				if candidate, ok := decl.(*ast.FuncDecl); ok && candidate.Name.Name == name && pkg.Fset.PositionFor(candidate.Pos(), false).Filename == filepath.Join(repo, path) {
					actual = candidate
				}
			}
		}
		if actual == nil || !bytes.Equal(structuralAST(fn), structuralAST(actual)) {
			return result, errors.New("payload AST differs from the actual parsed package")
		}
		object, ok := pkg.Types.Scope().Lookup(name).(*types.Func)
		if !ok || pkg.Fset.PositionFor(object.Pos(), false).Filename != filepath.Join(repo, path) || pkg.Fset.PositionFor(object.Pos(), false).Offset != file.Offset(fn.Name.Pos()) {
			return result, errors.New("payload actual function declaration changed")
		}
		graph, bound, err := payloadBindingGraph(pkg.Types, pkg.TypesInfo, pkg.Fset, actual, filepath.Join(repo, path), constObjects)
		if err != nil {
			return result, err
		}
		graphs[name] = graph
		locals = append(locals, bound...)
	}
	for _, name := range []string{"PayloadCount", "PayloadEncoded", "PayloadData", "PayloadTotal", "PayloadValid"} {
		if pkg.Types.Scope().Lookup(name) != nil {
			return result, errors.New("payload ghost function collides with an actual package object")
		}
	}
	result = payloadTarget{Arithmetic: arithmetic, Snapshots: snapshots, Functions: functions, Constants: constants, OriginalConstants: originalConstants, Locals: locals, Graphs: graphs}
	return result, nil
}

func payloadCopyInfo(source []byte, imports actualImporter) (*types.Package, *types.Info, *token.FileSet, map[string]*ast.FuncDecl, error) {
	return sourceCopyInfo(source, imports, payloadNames)
}

func sourceCopyInfo(source []byte, imports actualImporter, names []string) (*types.Package, *types.Info, *token.FileSet, map[string]*ast.FuncDecl, error) {
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "payload.go", source, parser.ParseComments)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	info := &types.Info{Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
	config := types.Config{GoVersion: "go1.27", Importer: imports}
	checked, err := config.Check("pcv3_payload_proof", set, []*ast.File{file}, info)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	functions := map[string]*ast.FuncDecl{}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && slices.Contains(names, fn.Name.Name) {
			functions[fn.Name.Name] = fn
		}
	}
	if len(functions) != len(names) {
		return nil, nil, nil, nil, errors.New("source proof copy must include every reviewed actual body")
	}
	return checked, info, set, functions, nil
}

func payloadAnnotateFunction(name string, source []byte) ([]byte, error) {
	prefix := []byte("package pcv3\n")
	full := append(slices.Clone(prefix), source...)
	set, functions, err := namedPayloadFunctions(full)
	if err != nil {
		return nil, err
	}
	fn := functions[name]
	if fn == nil {
		return nil, errors.New("payload annotation declaration missing")
	}
	type insertion struct {
		offset int
		text   string
	}
	var additions []insertion
	file := set.File(fn.Pos())
	contract := payloadLengthContract
	if name == "canonicalRecordCount" {
		contract = payloadCountContract
		if err = payloadFresh(fn, []string{"count"}); err != nil {
			return nil, err
		}
		additions = append(additions, insertion{file.Offset(fn.Type.Results.List[0].Type.Pos()) - len(prefix), "/*@ (count @*/ "}, insertion{file.Offset(fn.Type.Results.List[0].Type.End()) - len(prefix), " /*@ ) @*/"})
	} else {
		if name == "encodedRecordBodyLength" {
			contract = encodedBodyContract
		}
		if err = payloadFresh(fn, payloadResultNames); err != nil {
			return nil, err
		}
		for i, result := range payloadResultNames {
			additions = append(additions, insertion{file.Offset(fn.Type.Results.List[i].Type.Pos()) - len(prefix), "/*@ " + result + " @*/ "})
		}
	}
	additions = append(additions, insertion{0, contract})
	generated := slices.Clone(source)
	slices.SortFunc(additions, func(a, b insertion) int { return b.offset - a.offset })
	for _, addition := range additions {
		generated = append(generated[:addition.offset], append([]byte(addition.text), generated[addition.offset:]...)...)
	}
	return generated, nil
}

func payloadMaterializedConstants(constants []payloadConstant) []byte {
	var out strings.Builder
	out.WriteString("const (\n")
	for _, constant := range constants {
		kind := "uint64 "
		if constant.Type == "untyped int" {
			kind = ""
		}
		out.WriteString(constant.Name + " " + kind + "= " + constant.Value + "\n")
	}
	out.WriteString(")\n")
	return []byte(out.String())
}

func annotatePayload(target payloadTarget, name string) ([]byte, payloadEvidence, error) {
	var evidence payloadEvidence
	generated, arithmetic, err := annotateArithmetic(target.Arithmetic, "arithmetic-positive")
	if err != nil {
		return nil, evidence, err
	}
	generated = append(generated, payloadMaterializedConstants(target.Constants)...)
	generated = append(generated, []byte(payloadGhost)...)
	for _, function := range []string{"canonicalRecordCount", "canonicalPayloadLength", "encodedRecordBodyLength"} {
		declaration, err := payloadAnnotateFunction(function, target.Functions[function])
		if err != nil {
			return nil, evidence, err
		}
		generated = append(generated, declaration...)
		generated = append(generated, '\n')
	}
	positive := slices.Clone(generated)
	control, negative := payloadControls[name]
	if negative {
		if bytes.Count(generated, []byte(control.Before)) != 1 {
			return nil, evidence, errors.New("payload control site changed")
		}
		generated = bytes.Replace(generated, []byte(control.Before), []byte(control.After), 1)
		evidence.Control = control.Before + " -> " + control.After
		evidence.PostconditionLine = bytes.Count(generated[:bytes.Index(generated, []byte("//@ ensures "+control.Post))], []byte("\n")) + 1
	} else if name != "payload-positive" {
		return nil, evidence, errors.New("unknown payload proof case")
	}
	if _, _, _, _, err = payloadCopyInfo(generated, target.Arithmetic.Imports); err != nil {
		return nil, evidence, err
	}
	inverse := slices.Clone(generated)
	if negative {
		inverse = bytes.Replace(inverse, []byte(control.After), []byte(control.Before), 1)
	}
	if !bytes.Equal(inverse, positive) {
		return nil, evidence, errors.New("payload control inverse changed more than its owned expression")
	}
	alphaOffsets, err := arithmeticFreshBindings(inverse, target.Arithmetic.Imports)
	if err != nil {
		return nil, evidence, err
	}
	recovered, err := replaceArithmeticTokens(inverse, alphaOffsets, arithmeticFreshName, "low")
	if err != nil {
		return nil, evidence, err
	}
	pkg, info, set, restored, err := payloadCopyInfo(recovered, target.Arithmetic.Imports)
	if err != nil {
		return nil, evidence, err
	}
	generatedSet, proofs, err := namedPayloadFunctions(generated)
	if err != nil {
		return nil, evidence, err
	}
	constants := map[string]*types.Const{}
	for _, constant := range target.Constants {
		object, ok := pkg.Scope().Lookup(constant.Name).(*types.Const)
		if !ok || object.Val().ExactString() != constant.Value || object.Type().String() != constant.Type {
			return nil, evidence, errors.New("materialized payload constant failed actual Go type/value equality")
		}
		constants[constant.Name] = object
	}
	for _, function := range payloadNames {
		original := append([]byte("package pcv3\n"), target.Functions[function]...)
		originalSet, sourceFunctions, err := namedPayloadFunctions(original)
		if err != nil {
			return nil, evidence, err
		}
		fn := sourceFunctions[function]
		originalBody := d1Body(original, originalSet, fn)
		proofBody := d1Body(generated, generatedSet, proofs[function])
		entry := arithmeticIdentity{Function: function, ASTRecovered: bytes.Equal(structuralAST(fn), structuralAST(restored[function])), BodyRecovered: bytes.Equal(originalBody, d1Body(recovered, set, restored[function])), RawASTIdentical: bytes.Equal(structuralAST(fn), structuralAST(proofs[function])), RawBodyIdentical: bytes.Equal(originalBody, proofBody), OriginalBody: digest(originalBody), GeneratedBody: digest(proofBody)}
		if !entry.ASTRecovered || !entry.BodyRecovered {
			return nil, evidence, errors.New("payload original body/AST not recovered by only controlled edits")
		}
		graph, _, err := payloadBindingGraph(pkg, info, set, restored[function], "payload.go", constants)
		if err != nil {
			return nil, evidence, err
		}
		if !slices.Equal(graph, target.Graphs[function]) {
			return nil, evidence, fmt.Errorf("%s generated-copy binding graph differs from the actual source", function)
		}
		evidence.Functions = append(evidence.Functions, entry)
	}
	evidence.Alpha = arithmetic.Alpha
	evidence.BindingGraphs = true
	evidence.FreshResults = slices.Clone(payloadResultNames)
	return generated, evidence, nil
}

func payloadRejected(code int, log, name string, line int) bool {
	control, ok := payloadControls[name]
	if !ok {
		return false
	}
	lower := strings.ToLower(log)
	return code == 1 && strings.Contains(log, "Gobra found 1 error.") && strings.Contains(log, fmt.Sprintf("</workspace/%s/payload.go:%d:9> Postcondition might not hold.", name, line)) && strings.Contains(log, "Assertion "+control.Post+" might not hold.") && !strings.Contains(lower, "timeout") && !strings.Contains(lower, "outofmemory") && !strings.Contains(lower, "integer overflow")
}

const payloadOraclePrefix = `package main
import ("fmt"; "os")
var failed bool
func expect(label string,value uint64,flag bool,want uint64,wantFlag bool) {
 fmt.Printf("%s=%d,%t\n",label,value,flag)
 if value!=want || flag!=wantFlag {failed=true}
}
func main() {
`
const payloadOraclePositive = `v,ok:=encodedRecordBodyLength(64,true); expect("encoded64",v,ok,136,true)
v,ok=encodedRecordBodyLength(65,true); expect("encoded65",v,ok,272,true)
v,ok=encodedRecordBodyLength(18446744073709551551,true); expect("encoded_late",v,ok,1152921504606846976,false)
v,ok=encodedRecordBodyLength(18446744073709551552,true); expect("encoded_early",v,ok,0,false)
v,ok=encodedRecordBodyLength(18446744073709551615,false); expect("encoded_early_nonrs",v,ok,0,false)
v,ok=encodedRecordBodyLength(17361641481138401345,true); expect("encoded_wrap16",v,ok,16,false)
v,ok=canonicalPayloadLength(0,0,false); expect("empty_nonrs",v,ok,112,true)
v,ok=canonicalPayloadLength(0,0,true); expect("empty_rs",v,ok,184,true)
v,ok=canonicalPayloadLength(1,0,false); expect("bad_count",v,ok,0,false)
v,ok=canonicalPayloadLength(51,1,false); expect("frozen_payload",v,ok,275,true)
v,ok=canonicalPayloadLength(18446744073709551615,17592186044416,false); expect("payload_wrap",v,ok,1970324836974703,false)
v,ok=canonicalPayloadLength(18446744073709551615,17592186044416,true); expect("payload_early",v,ok,0,false)
v,ok=canonicalPayloadLength(17358774610905959105,16554617510706,true); expect("payload_wrap88",v,ok,88,false)
`
const payloadOraclePositiveOutput = "encoded64=136,true\nencoded65=272,true\nencoded_late=1152921504606846976,false\nencoded_early=0,false\nencoded_early_nonrs=0,false\nencoded_wrap16=16,false\nempty_nonrs=112,true\nempty_rs=184,true\nbad_count=0,false\nfrozen_payload=275,true\npayload_wrap=1970324836974703,false\npayload_early=0,false\npayload_wrap88=88,false\n"

func payloadNative(name string) ([]byte, int, string) {
	body, code, expected := payloadOraclePositive, 0, payloadOraclePositiveOutput
	switch name {
	case "payload-final-omitted":
		body = "v,ok:=canonicalPayloadLength(0,0,false); expect(\"empty_nonrs\",v,ok,112,true)\n"
		code, expected = 1, "empty_nonrs=0,true\n"
	case "payload-rs-floored":
		body = "v,ok:=encodedRecordBodyLength(65,true); expect(\"encoded65\",v,ok,272,true)\n"
		code, expected = 1, "encoded65=136,true\n"
	case "payload-bad-count-accepted":
		body = "v,ok:=canonicalPayloadLength(1,0,false); expect(\"bad_count\",v,ok,0,false)\n"
		code, expected = 1, "bad_count=113,true\n"
	}
	return []byte(payloadOraclePrefix + body + "if failed {os.Exit(1)}\n}\n"), code, expected
}

func runPayload(repo, runDir, imageID string, target payloadTarget, report map[string]any) error {
	cases, ok := report["cases"].([]caseResult)
	if !ok {
		return errors.New("prior mandatory source proof cases missing")
	}
	natives, ok := report["native_controls"].([]caseResult)
	if !ok {
		return errors.New("prior mandatory native controls missing")
	}
	hashes := map[string]string{}
	for path, source := range target.Snapshots {
		hashes[path] = digest(source)
	}
	report["payload_source"] = map[string]any{
		"source_snapshots": hashes, "same_parsed_bytes": "all five body/constant dependency files compared to actual go/packages ParseFile bytes",
		"own_bodies": payloadNames, "constants": target.Constants, "actual_locals": target.Locals, "ghost_math": payloadGhost, "contracts": map[string]string{"count": payloadCountContract, "payload": payloadLengthContract, "encoded_body": encodedBodyContract},
		"mode":                   "--overflow; all uint64 lengths/counts and both Boolean values; stage-sensitive refusal output, no <=1MiB premise",
		"trusted_dependencies":   "standard math/bits API and existing reviewed two-token Mul alpha-equivalence; compiler-evaluated constant type/value materialization; Go/Gobra frontend and integer embedding",
		"output_bindings":        "fresh resultValue/successFlag absent from all identifiers of each actual target function; three lexical canonicalPayloadLength ok locals remain distinct",
		"control_classification": "exact helper result postcondition rejection plus independent native frozen witnesses; no observed SAT certificate",
		"easycrypt":              "PayloadGeometry.ec independently joins ghost C/E/D/P/V and source contracts; automatic cross-logic proof transport remains unestablished",
	}
	var original bytes.Buffer
	original.WriteString("package pcv3\nimport \"math/bits\"\n")
	original.Write(target.OriginalConstants)
	for _, function := range payloadNames {
		original.Write(target.Functions[function])
		original.WriteByte('\n')
	}
	sources := map[string][]byte{"payload-original": original.Bytes()}
	for _, name := range []string{"payload-positive", "payload-final-omitted", "payload-rs-floored", "payload-bad-count-accepted"} {
		generated, evidence, err := annotatePayload(target, name)
		if err != nil {
			return err
		}
		directory := filepath.Join(runDir, name)
		if err = os.MkdirAll(directory, 0755); err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(directory, "payload.go"), generated, 0644); err != nil {
			return err
		}
		result, err := runCase(runDir, name, "payload.go", imageID, generated, identity{PostconditionLine: evidence.PostconditionLine})
		result.Identity = nil
		result.PayloadIdentity = &evidence
		cases = append(cases, result)
		report["cases"] = cases
		if err != nil {
			return err
		}
		sources[name] = generated
	}
	for _, name := range []string{"payload-original", "payload-positive", "payload-final-omitted", "payload-rs-floored", "payload-bad-count-accepted"} {
		oracle, code, expected := payloadNative(name)
		command, err := compileOracle(repo, runDir, name, "payload.go", sources[name], oracle, []byte("module picocrypt_ng_payload_oracle\n\ngo 1.27.3\n"), nil)
		if err != nil {
			return err
		}
		report[name+"_native_compile_command"] = command
		native, output, err := runIsolated(runDir, name+"-native", imageID, "/workspace/"+name+"-oracle", nil)
		native.Mode = "native frozen payload helper proof-control oracle; original constant expressions vs materialized proof copy; not whole-application coverage"
		if err == nil {
			native.Passed = native.ExitCode == code && string(output) == expected
			if !native.Passed {
				err = fmt.Errorf("%s native frozen payload oracle mismatch", name)
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

func mergeSourceSnapshots(snapshots, incoming map[string][]byte) error {
	for path, source := range incoming {
		if previous, exists := snapshots[path]; exists && !bytes.Equal(previous, source) {
			return fmt.Errorf("source snapshot changed between proof lanes: %s", path)
		}
	}
	for path, source := range incoming {
		if _, exists := snapshots[path]; !exists {
			snapshots[path] = slices.Clone(source)
		}
	}
	return nil
}
