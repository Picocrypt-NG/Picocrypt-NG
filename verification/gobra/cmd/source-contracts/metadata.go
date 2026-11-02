package main

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const metadataFunctionName = "canonicalMetadataGeometry"
const metadataReviewed = `package pcv3
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
`
const metadataContract = `//@ requires 0 <= commentLength && commentLength <= 4294967295
//@ ensures ok && 1 <= blocks && blocks <= 33554433 && 1112 <= frontHeaderLength && frontHeaderLength <= 4563403864 && integer(blocks) == (80 + integer(commentLength)) / 128 + ((80 + integer(commentLength)) % 128 == 0 ? 0 : 1) && integer(frontHeaderLength) == 976 + 136*integer(blocks) && (commentLength <= 99999 ==> blocks <= 782 && frontHeaderLength <= 107328)
`

var metadataNames = append(slices.Clone(arithmeticNames), metadataFunctionName)
var metadataExpected = map[string]struct{ Value, Type, Path string }{
	"frontHeaderBase": {"976", "uint64", preambleRelative}, "metadataDecodedBase": {"80", "uint64", preambleRelative}, "rs128DataLength": {"128", "uint64", preambleRelative}, "rs128CodewordLength": {"136", "uint64", preambleRelative},
}

const metadataBefore = "checkedCeilDiv64(decodedLength, rs128DataLength)"
const metadataAfter = "checkedCeilDiv64(decodedLength - decodedLength%rs128DataLength, rs128DataLength)"

type metadataTarget struct {
	Arithmetic        arithmeticTarget
	Snapshots         map[string][]byte
	Function          []byte
	Constants         []payloadConstant
	OriginalConstants []byte
	Graphs            map[string][]string
	Locals            []payloadLocal
}
type metadataEvidence struct {
	Functions         []arithmeticIdentity `json:"functions"`
	BindingGraphs     bool                 `json:"four_body_go_binding_graphs_equal_after_owned_inverse"`
	NamedOutputs      []string             `json:"actual_named_outputs_preserved"`
	Alpha             []alphaReplacement   `json:"owned_mul_alpha_replacements"`
	Control           string               `json:"controlled_mutation,omitempty"`
	PostconditionLine int                  `json:"postcondition_line,omitempty"`
}

func loadMetadata(repo, cache string, arithmetic arithmeticTarget) (metadataTarget, error) {
	var result metadataTarget
	pkg, snapshots, err := loadSourceSnapshots(repo, cache, []string{arithmeticRelative, preambleRelative}, "./internal/pcv3operation/internal/pcv3")
	if err != nil {
		return result, err
	}
	if !bytes.Equal(snapshots[arithmeticRelative], arithmetic.Source) {
		return result, errors.New("metadata arithmetic snapshot changed")
	}
	for _, source := range snapshots {
		if sourceAnnotationPattern.Match(source) {
			return result, errors.New("metadata source contains unowned verifier markers")
		}
	}
	set, functions, err := namedSourceFunctions(snapshots[preambleRelative], metadataNames)
	if err != nil {
		return result, err
	}
	_, expected, err := namedSourceFunctions([]byte(metadataReviewed), metadataNames)
	if err != nil {
		return result, err
	}
	fn := functions[metadataFunctionName]
	if fn == nil || !bytes.Equal(structuralAST(fn), structuralAST(expected[metadataFunctionName])) {
		return result, errors.New("metadata function left the reviewed named-output source subset")
	}
	file := set.File(fn.Pos())
	object, ok := pkg.Types.Scope().Lookup(metadataFunctionName).(*types.Func)
	if !ok || pkg.Fset.PositionFor(object.Pos(), false).Filename != filepath.Join(repo, preambleRelative) || pkg.Fset.PositionFor(object.Pos(), false).Offset != file.Offset(fn.Name.Pos()) {
		return result, errors.New("metadata actual function declaration binding changed")
	}
	signature := object.Type().(*types.Signature)
	if signature.Results().Len() != 3 {
		return result, errors.New("metadata named result arity changed")
	}
	for i, name := range []string{"blocks", "frontHeaderLength", "ok"} {
		if signature.Results().At(i).Name() != name {
			return result, errors.New("metadata actual named return object changed")
		}
	}
	constants, original, err := sourceConstantDeclarations(pkg, repo, snapshots, metadataExpected)
	if err != nil {
		return result, err
	}
	objects := map[string]*types.Const{}
	for name := range metadataExpected {
		objects[name] = pkg.Types.Scope().Lookup(name).(*types.Const)
	}
	graphs := map[string][]string{}
	var locals []payloadLocal
	for _, name := range metadataNames {
		relative := arithmeticRelative
		if name == metadataFunctionName {
			relative = preambleRelative
		}
		var actual *ast.FuncDecl
		for _, syntax := range pkg.Syntax {
			for _, decl := range syntax.Decls {
				if found, ok := decl.(*ast.FuncDecl); ok && found.Name.Name == name && pkg.Fset.PositionFor(found.Pos(), false).Filename == filepath.Join(repo, relative) {
					actual = found
				}
			}
		}
		if actual == nil {
			return result, errors.New("metadata module actual function missing")
		}
		graph, bound, err := payloadBindingGraph(pkg.Types, pkg.TypesInfo, pkg.Fset, actual, filepath.Join(repo, relative), objects)
		if err != nil {
			return result, err
		}
		graphs[name] = graph
		locals = append(locals, bound...)
	}
	result = metadataTarget{Arithmetic: arithmetic, Snapshots: snapshots, Function: slices.Clone(snapshots[preambleRelative][file.Offset(fn.Pos()):file.Offset(fn.End())]), Constants: constants, OriginalConstants: original, Graphs: graphs, Locals: locals}
	return result, nil
}

func annotateMetadata(target metadataTarget, name string) ([]byte, metadataEvidence, error) {
	var evidence metadataEvidence
	generated, arithmetic, err := annotateArithmetic(target.Arithmetic, "arithmetic-positive")
	if err != nil {
		return nil, evidence, err
	}
	generated = append(generated, payloadMaterializedConstants(target.Constants)...)
	generated = append(generated, []byte(metadataContract)...)
	generated = append(generated, target.Function...)
	generated = append(generated, '\n')
	positive := slices.Clone(generated)
	negative := name == "metadata-ceil-floor"
	if negative {
		if bytes.Count(generated, []byte(metadataBefore)) != 1 {
			return nil, evidence, errors.New("metadata ceil-floor control site changed")
		}
		generated = bytes.Replace(generated, []byte(metadataBefore), []byte(metadataAfter), 1)
		evidence.Control = metadataBefore + " -> " + metadataAfter
		evidence.PostconditionLine = bytes.Count(generated[:bytes.Index(generated, []byte("//@ ensures ok && 1 <= blocks"))], []byte("\n")) + 1
	} else if name != "metadata-positive" {
		return nil, evidence, errors.New("unknown metadata proof case")
	}
	if _, _, _, _, err = sourceCopyInfo(generated, target.Arithmetic.Imports, metadataNames); err != nil {
		return nil, evidence, err
	}
	inverse := slices.Clone(generated)
	if negative {
		inverse = bytes.Replace(inverse, []byte(metadataAfter), []byte(metadataBefore), 1)
	}
	if !bytes.Equal(inverse, positive) {
		return nil, evidence, errors.New("metadata control undo changed more than its owned argument")
	}
	alpha, err := arithmeticFreshBindings(inverse, target.Arithmetic.Imports)
	if err != nil {
		return nil, evidence, err
	}
	recovered, err := replaceArithmeticTokens(inverse, alpha, arithmeticFreshName, "low")
	if err != nil {
		return nil, evidence, err
	}
	pkg, info, set, restored, err := sourceCopyInfo(recovered, target.Arithmetic.Imports, metadataNames)
	if err != nil {
		return nil, evidence, err
	}
	proofSet, proofs, err := namedSourceFunctions(generated, metadataNames)
	if err != nil {
		return nil, evidence, err
	}
	constants := map[string]*types.Const{}
	for _, constant := range target.Constants {
		object, ok := pkg.Scope().Lookup(constant.Name).(*types.Const)
		if !ok || object.Type().String() != constant.Type || object.Val().ExactString() != constant.Value {
			return nil, evidence, errors.New("metadata materialized constant type/value changed")
		}
		constants[constant.Name] = object
	}
	arithmeticSet, arithmeticFns, err := namedSourceFunctions(target.Arithmetic.Source, metadataNames)
	if err != nil {
		return nil, evidence, err
	}
	for _, function := range metadataNames {
		source := target.Function
		if function != metadataFunctionName {
			node := arithmeticFns[function]
			file := arithmeticSet.File(node.Pos())
			source = target.Arithmetic.Source[file.Offset(node.Pos()):file.Offset(node.End())]
		}
		original := append([]byte("package pcv3\n"), source...)
		sourceSet, sourceFns, err := namedSourceFunctions(original, metadataNames)
		if err != nil {
			return nil, evidence, err
		}
		fn := sourceFns[function]
		before := d1Body(original, sourceSet, fn)
		body := d1Body(generated, proofSet, proofs[function])
		entry := arithmeticIdentity{Function: function, ASTRecovered: bytes.Equal(structuralAST(fn), structuralAST(restored[function])), BodyRecovered: bytes.Equal(before, d1Body(recovered, set, restored[function])), RawASTIdentical: bytes.Equal(structuralAST(fn), structuralAST(proofs[function])), RawBodyIdentical: bytes.Equal(before, body), OriginalBody: digest(before), GeneratedBody: digest(body)}
		if !entry.ASTRecovered || !entry.BodyRecovered {
			return nil, evidence, errors.New("metadata actual function body/signature was not recovered")
		}
		graph, _, err := payloadBindingGraph(pkg, info, set, restored[function], "payload.go", constants)
		if err != nil {
			return nil, evidence, err
		}
		if !slices.Equal(graph, target.Graphs[function]) {
			return nil, evidence, fmt.Errorf("%s metadata-module named/local/free binding graph differs", function)
		}
		evidence.Functions = append(evidence.Functions, entry)
	}
	evidence.BindingGraphs = true
	evidence.NamedOutputs = []string{"blocks:uint64", "frontHeaderLength:uint64", "ok:bool"}
	evidence.Alpha = arithmetic.Alpha
	return generated, evidence, nil
}

func metadataRejected(code int, log string, line int) bool {
	lower := strings.ToLower(log)
	return code == 1 && strings.Contains(log, "Gobra found 1 error.") && strings.Contains(log, fmt.Sprintf("</workspace/metadata-ceil-floor/metadata.go:%d:9> Postcondition might not hold.", line)) && strings.Contains(log, "Assertion 1 <= blocks might not hold.") && !strings.Contains(lower, "timeout") && !strings.Contains(lower, "outofmemory") && !strings.Contains(lower, "integer overflow")
}

const metadataOraclePrefix = `package main
import ("fmt"; "os")
var failed bool
func expectMetadata(comment uint32,wantBlocks,wantHeader uint64) {
 blocks,header,ok:=canonicalMetadataGeometry(comment)
 fmt.Printf("%d=%d,%d,%t\n",comment,blocks,header,ok)
 if blocks!=wantBlocks || header!=wantHeader || !ok {failed=true}
}
func main() {
`
const metadataOraclePositive = `expectMetadata(0,1,1112)
expectMetadata(48,1,1112)
expectMetadata(49,2,1248)
expectMetadata(99999,782,107328)
expectMetadata(4294967295,33554433,4563403864)
`
const metadataOraclePositiveOutput = "0=1,1112,true\n48=1,1112,true\n49=2,1248,true\n99999=782,107328,true\n4294967295=33554433,4563403864,true\n"

func runMetadata(repo, runDir, imageID string, target metadataTarget, report map[string]any) error {
	cases, ok := report["cases"].([]caseResult)
	if !ok {
		return errors.New("earlier mandatory proof cases missing before metadata")
	}
	natives, ok := report["native_controls"].([]caseResult)
	if !ok {
		return errors.New("earlier mandatory native controls missing before metadata")
	}
	hashes := map[string]string{}
	for path, source := range target.Snapshots {
		hashes[path] = digest(source)
	}
	report["metadata_source"] = map[string]any{
		"path": preambleRelative, "source_snapshots": hashes, "own_bodies": metadataNames, "constants": target.Constants, "locals": target.Locals, "contract": metadataContract,
		"representation":         "all uint32 commentLength inputs; original named blocks:uint64/frontHeaderLength:uint64/ok:bool outputs preserved and bound to their actual result objects; no99999inputpremise",
		"mode":                   "--overflow; four actual own bodies, only existing standard math/bits API bodyless trust",
		"trusted_dependencies":   "standard bits implementation/compiler, Go/Gobra integer embedding and existing finite Mul local alpha; no automatic cross-logic proof transport",
		"control_classification": "exact metadata lower-block postcondition rejection plus frozen native comment0 counterexample; not an observed SAT certificate",
		"caller_obligations":     "comment admission, narrowing header to uint32, metadata/core/header compatibility and caller validation remain separate",
	}
	original := append(slices.Clone(target.Arithmetic.Source), target.OriginalConstants...)
	original = append(original, target.Function...)
	original = append(original, '\n')
	sources := map[string][]byte{"metadata-original": original}
	for _, name := range []string{"metadata-positive", "metadata-ceil-floor"} {
		generated, evidence, err := annotateMetadata(target, name)
		if err != nil {
			return err
		}
		directory := filepath.Join(runDir, name)
		if err = os.MkdirAll(directory, 0755); err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(directory, "metadata.go"), generated, 0644); err != nil {
			return err
		}
		result, err := runCase(runDir, name, "metadata.go", imageID, generated, identity{PostconditionLine: evidence.PostconditionLine})
		result.Identity = nil
		result.MetadataIdentity = &evidence
		cases = append(cases, result)
		report["cases"] = cases
		if err != nil {
			return err
		}
		sources[name] = generated
	}
	for _, name := range []string{"metadata-original", "metadata-positive", "metadata-ceil-floor"} {
		body, code, expected := metadataOraclePositive, 0, metadataOraclePositiveOutput
		if name == "metadata-ceil-floor" {
			body = "expectMetadata(0,1,1112)\n"
			code, expected = 1, "0=0,976,true\n"
		}
		oracle := []byte(metadataOraclePrefix + body + "if failed {os.Exit(1)}\n}\n")
		command, err := compileOracle(repo, runDir, name, "metadata.go", sources[name], oracle, []byte("module picocrypt_ng_metadata_oracle\n\ngo 1.27.3\n"), nil)
		if err != nil {
			return err
		}
		report[name+"_native_compile_command"] = command
		native, output, err := runIsolated(runDir, name+"-native", imageID, "/workspace/"+name+"-oracle", nil)
		native.Mode = "native frozen full-uint32 metadata helper proof-control oracle, including H>MaxUint32; not comment admission or whole-application coverage"
		if err == nil {
			native.Passed = native.ExitCode == code && string(output) == expected
			if !native.Passed {
				err = fmt.Errorf("%s native frozen metadata oracle mismatch", name)
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
