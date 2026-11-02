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

const arithmeticRelative = "src/internal/pcv3operation/internal/pcv3/arithmetic.go"
const bitsHeaderRelative = "verification/gobra/specs/math/bits/bits.gobra"
const arithmeticFreshName = "pcv3LowWord"
const arithmeticReviewed = `package pcv3
import "math/bits"
func checkedAdd64(left, right uint64) (uint64, bool) {
 sum, carry := bits.Add64(left, right, 0)
 return sum, carry == 0
}
func checkedMul64(left, right uint64) (uint64, bool) {
 high, low := bits.Mul64(left, right)
 return low, high == 0
}
func checkedCeilDiv64(value, divisor uint64) (uint64, bool) {
 quotient := value / divisor
 if value%divisor == 0 {
  return quotient, true
 }
 return checkedAdd64(quotient, 1)
}
`

var arithmeticNames = []string{"checkedAdd64", "checkedMul64", "checkedCeilDiv64"}
var arithmeticContracts = map[string]string{
	"checkedAdd64": "//@ requires 0 <= left && left <= 18446744073709551615\n" +
		"//@ requires 0 <= right && right <= 18446744073709551615\n" +
		"//@ ensures 0 <= result && result <= 18446744073709551615\n" +
		"//@ ensures integer(result) == (integer(left) + integer(right)) % 18446744073709551616\n" +
		"//@ ensures ok == (integer(left) + integer(right) < 18446744073709551616)\n",
	"checkedMul64": "//@ requires 0 <= left && left <= 18446744073709551615\n" +
		"//@ requires 0 <= right && right <= 18446744073709551615\n" +
		"//@ ensures 0 <= result && result <= 18446744073709551615\n" +
		"//@ ensures integer(result) == (integer(left) * integer(right)) % 18446744073709551616\n" +
		"//@ ensures ok == (integer(left) * integer(right) < 18446744073709551616)\n",
	"checkedCeilDiv64": "//@ requires 0 <= value && value <= 18446744073709551615\n" +
		"//@ requires 0 < divisor && divisor <= 18446744073709551615\n" +
		"//@ ensures 0 <= result && result <= 18446744073709551615\n" +
		"//@ ensures integer(result) == integer(value) / integer(divisor) + (integer(value) % integer(divisor) == 0 ? 0 : 1)\n" +
		"//@ ensures ok\n",
}

type arithmeticControl struct{ Function, Before, After, Post string }

var arithmeticControls = map[string]arithmeticControl{
	"arithmetic-add-ignores-carry": {"checkedAdd64", "return sum, carry == 0", "return sum, carry >= 0", "ok == (integer(left) + integer(right) < 18446744073709551616)"},
	"arithmetic-mul-returns-high":  {"checkedMul64", "return pcv3LowWord, high == 0", "return high + 0*pcv3LowWord, high == 0", "integer(result) == (integer(left) * integer(right)) % 18446744073709551616"},
	"arithmetic-ceil-floors":       {"checkedCeilDiv64", "return checkedAdd64(quotient, 1)", "return checkedAdd64(quotient, 0)", "integer(result) == integer(value) / integer(divisor) + (integer(value) % integer(divisor) == 0 ? 0 : 1)"},
}

type arithmeticTarget struct {
	Source, Header []byte
	Imports        actualImporter
	LowOffsets     []int
}

type arithmeticIdentity struct {
	Function         string `json:"function"`
	ASTRecovered     bool   `json:"signature_body_ast_identical_after_inverse_owned_edits"`
	BodyRecovered    bool   `json:"body_bytes_identical_after_inverse_owned_edits"`
	RawASTIdentical  bool   `json:"signature_body_ast_identical"`
	RawBodyIdentical bool   `json:"body_bytes_identical"`
	OriginalBody     string `json:"original_body_sha256"`
	GeneratedBody    string `json:"generated_body_sha256"`
}

type alphaReplacement struct {
	SourceOffset int    `json:"original_source_byte_offset"`
	ProofOffset  int    `json:"proof_copy_byte_offset_after_control_undo"`
	Original     string `json:"original_token"`
	Replacement  string `json:"replacement_token"`
	Role         string `json:"binding_role"`
}

type arithmeticEvidence struct {
	Functions         []arithmeticIdentity `json:"functions"`
	Alpha             []alphaReplacement   `json:"owned_alpha_replacements"`
	VariableType      string               `json:"alpha_local_go_type"`
	InverseOrder      string               `json:"inverse_order"`
	Control           string               `json:"controlled_mutation,omitempty"`
	PostconditionLine int                  `json:"control_postcondition_line,omitempty"`
}

func arithmeticDeclarations(source []byte) (*token.FileSet, map[string]*ast.FuncDecl, error) {
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "arithmetic.go", source, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, nil, err
	}
	result := map[string]*ast.FuncDecl{}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && slices.Contains(arithmeticNames, fn.Name.Name) {
			result[fn.Name.Name] = fn
		}
	}
	if len(result) != 3 {
		return nil, nil, errors.New("all three arithmetic function bodies are required")
	}
	return set, result, nil
}

func reviewArithmetic(source []byte) error {
	if sourceAnnotationPattern.Match(source) {
		return errors.New("arithmetic source contains verifier input markers")
	}
	file, err := parser.ParseFile(token.NewFileSet(), "arithmetic.go", source, parser.SkipObjectResolution)
	if err != nil {
		return err
	}
	if len(file.Decls) != 4 || len(file.Imports) != 1 || file.Imports[0].Path.Value != `"math/bits"` || file.Imports[0].Name != nil {
		return errors.New("arithmetic file must retain only its standard bits import and three reviewed functions")
	}
	_, functions, err := arithmeticDeclarations(source)
	if err != nil {
		return err
	}
	_, reviewed, err := arithmeticDeclarations([]byte(arithmeticReviewed))
	if err != nil {
		return err
	}
	for _, name := range arithmeticNames {
		if !bytes.Equal(structuralAST(functions[name]), structuralAST(reviewed[name])) {
			return fmt.Errorf("%s is outside the reviewed arithmetic source subset", name)
		}
	}
	return nil
}

func loadArithmetic(repo, cache string) (arithmeticTarget, error) {
	var result arithmeticTarget
	pkg, source, err := loadSource(repo, cache, arithmeticRelative, "./internal/pcv3operation/internal/pcv3")
	if err != nil {
		return result, err
	}
	if err = reviewArithmetic(source); err != nil {
		return result, err
	}
	set, functions, err := arithmeticDeclarations(source)
	if err != nil {
		return result, err
	}
	standard := pkg.Imports["math/bits"]
	if standard == nil {
		return result, errors.New("arithmetic actual standard math/bits import missing")
	}
	allowedStandard := map[types.Object]bool{}
	for name, arguments := range map[string]int{"Add64": 3, "Mul64": 2} {
		function, ok := standard.Types.Scope().Lookup(name).(*types.Func)
		if !ok {
			return result, errors.New("standard bits callee is not a function")
		}
		signature := function.Type().(*types.Signature)
		if signature.Recv() != nil || signature.Variadic() || signature.Params().Len() != arguments || signature.Results().Len() != 2 {
			return result, errors.New("standard bits signature changed")
		}
		for _, tuple := range []*types.Tuple{signature.Params(), signature.Results()} {
			for i := 0; i < tuple.Len(); i++ {
				if !types.Identical(tuple.At(i).Type(), types.Typ[types.Uint64]) {
					return result, errors.New("standard bits word type changed")
				}
			}
		}
		allowedStandard[function] = true
	}
	path := filepath.Join(repo, arithmeticRelative)
	var lowObject types.Object
	lowDefinition := -1
	var lowUses []int
	for _, name := range arithmeticNames {
		fn := functions[name]
		file := set.File(fn.Pos())
		inside := func(position token.Pos) bool {
			p := pkg.Fset.PositionFor(position, false)
			return p.Filename == path && file.Offset(fn.Pos()) <= p.Offset && p.Offset < file.Offset(fn.End())
		}
		object, ok := pkg.Types.Scope().Lookup(name).(*types.Func)
		if !ok || pkg.Fset.PositionFor(object.Pos(), false).Filename != path || pkg.Fset.PositionFor(object.Pos(), false).Offset != file.Offset(fn.Name.Pos()) {
			return result, errors.New("arithmetic function declaration binding changed")
		}
		signature := object.Type().(*types.Signature)
		if signature.Recv() != nil || signature.Variadic() || signature.Params().Len() != 2 || signature.Results().Len() != 2 ||
			!types.Identical(signature.Params().At(0).Type(), types.Typ[types.Uint64]) || !types.Identical(signature.Params().At(1).Type(), types.Typ[types.Uint64]) ||
			!types.Identical(signature.Results().At(0).Type(), types.Typ[types.Uint64]) || !types.Identical(signature.Results().At(1).Type(), types.Typ[types.Bool]) {
			return result, errors.New("arithmetic actual signature changed")
		}
		allowed := map[types.Object]bool{signature.Params().At(0): true, signature.Params().At(1): true, types.Universe.Lookup("uint64"): true, types.Universe.Lookup("bool"): true, types.Universe.Lookup("true"): true, pkg.Types.Scope().Lookup("checkedAdd64"): true}
		for object := range allowedStandard {
			allowed[object] = true
		}
		locals := map[string][]string{"checkedAdd64": {"sum", "carry"}, "checkedMul64": {"high", "low"}, "checkedCeilDiv64": {"quotient"}}[name]
		found := map[string]bool{}
		for id, definition := range pkg.TypesInfo.Defs {
			if !inside(id.Pos()) || !slices.Contains(locals, id.Name) {
				continue
			}
			local, ok := definition.(*types.Var)
			if !ok || local.IsField() || local.Parent() == pkg.Types.Scope() || !types.Identical(local.Type(), types.Typ[types.Uint64]) || found[id.Name] {
				return result, errors.New("arithmetic local definition/type changed")
			}
			found[id.Name], allowed[definition] = true, true
			if name == "checkedMul64" && id.Name == "low" {
				lowObject, lowDefinition = definition, pkg.Fset.PositionFor(id.Pos(), false).Offset
			}
		}
		if len(found) != len(locals) {
			return result, errors.New("arithmetic local bindings missing")
		}
		for id, used := range pkg.TypesInfo.Uses {
			if !inside(id.Pos()) {
				continue
			}
			if imported, ok := used.(*types.PkgName); ok && imported.Imported() == standard.Types {
				allowed[used] = true
			}
			if !allowed[used] {
				return result, fmt.Errorf("arithmetic unreviewed actual binding %q", id.Name)
			}
			if used == lowObject {
				lowUses = append(lowUses, pkg.Fset.PositionFor(id.Pos(), false).Offset)
			}
		}
	}
	if lowDefinition < 0 || len(lowUses) != 1 {
		return result, errors.New("mul low alpha adapter requires one definition and one bound use")
	}
	collision := false
	ast.Inspect(functions["checkedMul64"], func(node ast.Node) bool {
		if id, ok := node.(*ast.Ident); ok && id.Name == arithmeticFreshName {
			collision = true
		}
		return true
	})
	if collision || strings.Contains(arithmeticContracts["checkedMul64"], arithmeticFreshName) {
		return result, errors.New("mul alpha adapter fresh-name collision")
	}
	header, err := os.ReadFile(filepath.Join(repo, bitsHeaderRelative))
	if err != nil {
		return result, err
	}
	result = arithmeticTarget{Source: source, Header: header, Imports: actualImporter{"math/bits": standard.Types}, LowOffsets: []int{lowDefinition, lowUses[0]}}
	return result, nil
}

func replaceArithmeticTokens(source []byte, offsets []int, before, after string) ([]byte, error) {
	result := slices.Clone(source)
	offsets = slices.Clone(offsets)
	slices.Sort(offsets)
	slices.Reverse(offsets)
	for _, offset := range offsets {
		if offset < 0 || offset+len(before) > len(result) || string(result[offset:offset+len(before)]) != before {
			return nil, errors.New("owned alpha token does not match its physical source position")
		}
		result = append(result[:offset], append([]byte(after), result[offset+len(before):]...)...)
	}
	return result, nil
}

func arithmeticFreshBindings(source []byte, imports actualImporter) ([]int, error) {
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "arithmetic.go", source, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	info := types.Info{Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
	config := types.Config{GoVersion: "go1.27", Importer: imports}
	checked, err := config.Check("pcv3_arithmetic_proof", set, []*ast.File{file}, &info)
	if err != nil {
		return nil, err
	}
	var fresh types.Object
	var definitions, uses []int
	for id, object := range info.Defs {
		if id.Name != arithmeticFreshName {
			continue
		}
		local, ok := object.(*types.Var)
		if !ok || local.IsField() || local.Parent() == checked.Scope() || !types.Identical(local.Type(), types.Typ[types.Uint64]) {
			return nil, errors.New("proof alpha target is not a uint64 local")
		}
		fresh = object
		definitions = append(definitions, set.PositionFor(id.Pos(), false).Offset)
	}
	for id, object := range info.Uses {
		if id.Name == arithmeticFreshName {
			if object != fresh {
				return nil, errors.New("proof alpha use captured another object")
			}
			uses = append(uses, set.PositionFor(id.Pos(), false).Offset)
		}
	}
	if len(definitions) != 1 || len(uses) != 1 {
		return nil, errors.New("proof alpha target requires one definition and one bound use")
	}
	return []int{definitions[0], uses[0]}, nil
}

func annotateArithmetic(target arithmeticTarget, name string) ([]byte, arithmeticEvidence, error) {
	var evidence arithmeticEvidence
	if err := reviewArithmetic(target.Source); err != nil {
		return nil, evidence, err
	}
	generated, err := replaceArithmeticTokens(target.Source, target.LowOffsets, "low", arithmeticFreshName)
	if err != nil {
		return nil, evidence, err
	}
	set, functions, err := arithmeticDeclarations(generated)
	if err != nil {
		return nil, evidence, err
	}
	type insertion struct {
		offset int
		text   string
	}
	var additions []insertion
	for _, function := range arithmeticNames {
		fn := functions[function]
		file := set.File(fn.Pos())
		additions = append(additions, insertion{file.Offset(fn.Pos()), arithmeticContracts[function]}, insertion{file.Offset(fn.Type.Results.List[0].Type.Pos()), "/*@ result @*/ "}, insertion{file.Offset(fn.Type.Results.List[1].Type.Pos()), "/*@ ok @*/ "})
	}
	slices.SortFunc(additions, func(a, b insertion) int { return b.offset - a.offset })
	for _, addition := range additions {
		generated = append(generated[:addition.offset], append([]byte(addition.text), generated[addition.offset:]...)...)
	}
	positive := slices.Clone(generated)
	inverse := slices.Clone(positive)
	control, negative := arithmeticControls[name]
	if negative {
		if bytes.Count(generated, []byte(control.Before)) != 1 {
			return nil, evidence, errors.New("arithmetic control site changed")
		}
		generated = bytes.Replace(generated, []byte(control.Before), []byte(control.After), 1)
		evidence.Control = control.Before + " -> " + control.After
		evidence.PostconditionLine = bytes.Count(generated[:bytes.Index(generated, []byte("//@ ensures "+control.Post))], []byte("\n")) + 1
	} else if name != "arithmetic-positive" {
		return nil, evidence, errors.New("unknown arithmetic proof case")
	}
	if negative {
		inverse = bytes.Replace(generated, []byte(control.After), []byte(control.Before), 1)
		if !bytes.Equal(inverse, positive) {
			return nil, evidence, errors.New("arithmetic control undo failed")
		}
	}
	offsets, err := arithmeticFreshBindings(inverse, target.Imports)
	if err != nil {
		return nil, evidence, err
	}
	recovered, err := replaceArithmeticTokens(inverse, offsets, arithmeticFreshName, "low")
	if err != nil {
		return nil, evidence, err
	}
	originalSet, originals, err := arithmeticDeclarations(target.Source)
	if err != nil {
		return nil, evidence, err
	}
	recoveredSet, restored, err := arithmeticDeclarations(recovered)
	if err != nil {
		return nil, evidence, err
	}
	generatedSet, proofs, err := arithmeticDeclarations(generated)
	if err != nil {
		return nil, evidence, err
	}
	for _, function := range arithmeticNames {
		originalBody := d1Body(target.Source, originalSet, originals[function])
		body := d1Body(generated, generatedSet, proofs[function])
		entry := arithmeticIdentity{Function: function, ASTRecovered: bytes.Equal(structuralAST(originals[function]), structuralAST(restored[function])), BodyRecovered: bytes.Equal(originalBody, d1Body(recovered, recoveredSet, restored[function])), RawASTIdentical: bytes.Equal(structuralAST(originals[function]), structuralAST(proofs[function])), RawBodyIdentical: bytes.Equal(originalBody, body), OriginalBody: digest(originalBody), GeneratedBody: digest(body)}
		if !entry.ASTRecovered || !entry.BodyRecovered {
			return nil, evidence, errors.New("arithmetic source was not recovered by only owned alpha/control edits")
		}
		evidence.Functions = append(evidence.Functions, entry)
	}
	for i, role := range []string{"definition", "use"} {
		evidence.Alpha = append(evidence.Alpha, alphaReplacement{target.LowOffsets[i], offsets[i], "low", arithmeticFreshName, role})
	}
	evidence.VariableType = "Go uint64; one local definition and one use of the same go/types object"
	evidence.InverseOrder = "undo the single control expression (if any), then only the two owned alpha tokens; result-name comments are outside all bodies"
	// Mutants must still compile against real imports and bind the alpha local, too.
	if _, err = arithmeticFreshBindings(generated, target.Imports); err != nil {
		return nil, evidence, err
	}
	return generated, evidence, nil
}

func arithmeticRejected(code int, log, name string, line int) bool {
	control, ok := arithmeticControls[name]
	if !ok {
		return false
	}
	lower := strings.ToLower(log)
	return code == 1 && strings.Contains(log, "Gobra found 1 error.") && strings.Contains(log, fmt.Sprintf("</workspace/%s/arithmetic.go:%d:9> Postcondition might not hold.", name, line)) && strings.Contains(log, "Assertion "+control.Post+" might not hold.") && !strings.Contains(lower, "timeout") && !strings.Contains(lower, "outofmemory") && !strings.Contains(lower, "integer overflow")
}

const arithmeticOracle = `package main
import ("fmt"; "os")
func main() {
 a, aok := checkedAdd64(18446744073709551615, 2)
 m, mok := checkedMul64(3, 7)
 c, cok := checkedCeilDiv64(129, 128)
 r, rok := checkedMul64(18446744073709551615, 2)
 fmt.Printf("add=%d,%t\nmul=%d,%t\nceil=%d,%t\nmul_refusal=%d,%t\n",a,aok,m,mok,c,cok,r,rok)
 if a!=1 || aok || m!=21 || !mok || c!=2 || !cok || r!=18446744073709551614 || rok { os.Exit(1) }
}
`

func arithmeticNativeExpected(name string) (int, string) {
	switch name {
	case "arithmetic-add-ignores-carry":
		return 1, "add=1,true\nmul=21,true\nceil=2,true\nmul_refusal=18446744073709551614,false\n"
	case "arithmetic-mul-returns-high":
		return 1, "add=1,false\nmul=0,true\nceil=2,true\nmul_refusal=1,false\n"
	case "arithmetic-ceil-floors":
		return 1, "add=1,false\nmul=21,true\nceil=1,true\nmul_refusal=18446744073709551614,false\n"
	default:
		return 0, "add=1,false\nmul=21,true\nceil=2,true\nmul_refusal=18446744073709551614,false\n"
	}
}

func runArithmetic(repo, runDir, imageID string, target arithmeticTarget, report map[string]any, cases, natives []caseResult) error {
	path := filepath.Join(runDir, "stubs/math/bits/bits.gobra")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(path, target.Header, 0644); err != nil {
		return err
	}
	report["arithmetic_source"] = map[string]any{
		"path": arithmeticRelative, "sha256": digest(target.Source), "bits_header_path": bitsHeaderRelative, "bits_header_sha256": digest(target.Header), "contracts": arithmeticContracts,
		"mode":                    "--overflow for all four arithmetic cases; full U64 inputs; positive divisor for normal-return ceil contract",
		"trusted_dependencies":    "standard math/bits Add64(sum,carry) and Mul64(high,low) API, not implementation/intrinsic proof; reviewed Go/Gobra integer embedding and finite local alpha-equivalence",
		"local_alpha":             "ONLY checkedMul64 local low definition+one bound use -> fresh pcv3LowWord; inverse tokens recover exact original body/AST; production source unchanged",
		"negative_classification": "three actual-code defect controls plus frozen native witnesses; exact postcondition rejection, no observed SAT certificate",
		"easycrypt":               "WordArithmetic.ec; separate source-contract representation lemmas, not automatic cross-logic proof transport",
	}
	nativeSources := map[string][]byte{"arithmetic-original": target.Source}
	for _, name := range []string{"arithmetic-positive", "arithmetic-add-ignores-carry", "arithmetic-mul-returns-high", "arithmetic-ceil-floors"} {
		generated, evidence, err := annotateArithmetic(target, name)
		if err != nil {
			return err
		}
		directory := filepath.Join(runDir, name)
		if err = os.MkdirAll(directory, 0755); err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(directory, "arithmetic.go"), generated, 0644); err != nil {
			return err
		}
		result, err := runCase(runDir, name, "arithmetic.go", imageID, generated, identity{PostconditionLine: evidence.PostconditionLine})
		result.Identity = nil
		result.ArithmeticIdentity = &evidence
		cases = append(cases, result)
		report["cases"] = cases
		if err != nil {
			return err
		}
		nativeSources[name] = generated
	}
	for _, name := range []string{"arithmetic-original", "arithmetic-positive", "arithmetic-add-ignores-carry", "arithmetic-mul-returns-high", "arithmetic-ceil-floors"} {
		command, err := compileOracle(repo, runDir, name, "arithmetic.go", nativeSources[name], []byte(arithmeticOracle), []byte("module picocrypt_ng_arithmetic_oracle\n\ngo 1.27.3\n"), nil)
		if err != nil {
			return err
		}
		report[name+"_native_compile_command"] = command
		native, output, err := runIsolated(runDir, name+"-native", imageID, "/workspace/"+name+"-oracle", nil)
		native.Mode = "native frozen arithmetic proof-control oracle; original vs alpha proof copy; not application coverage"
		if err == nil {
			code, expected := arithmeticNativeExpected(name)
			native.Passed = native.ExitCode == code && string(output) == expected
			if !native.Passed {
				err = fmt.Errorf("%s native frozen oracle mismatch", name)
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
