package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/tools/go/packages"
)

const sourceRelative = "src/internal/util/safecast.go"
const recordCountRelative = "src/internal/pcv3operation/internal/pcv3/capsule.go"
const image = "ghcr.io/viperproject/gobra@sha256:775879e8483561186291653d4c8a818c222eafd38f4b50a42d4b8873eebc9481"
const revision = "d2c5af5450540c502855e53f4a5af1ba7630c41f"
const maxInt64 = "9223372036854775807"
const contract = "//@ requires 0 <= v && v <= 18446744073709551615\n" +
	"//@ ensures ok == (v <= math.MaxInt64)\n" +
	"//@ ensures ok ==> (value >= 0 && uint64(value) == v)\n" +
	"//@ ensures !ok ==> value == 0\n" +
	"//@ ensures -9223372036854775808 <= value && value <= 9223372036854775807\n"
const recordCountContract = "//@ requires 0 <= plaintextLength && plaintextLength <= 18446744073709551615\n" +
	"//@ ensures 0 <= count && count <= 17592186044416\n" +
	"//@ ensures plaintextLength % recordPlaintextMax == 0 ==> count == plaintextLength / recordPlaintextMax\n" +
	"//@ ensures plaintextLength % recordPlaintextMax != 0 ==> count == plaintextLength / recordPlaintextMax + 1\n" +
	"//@ ensures (count == 0) == (plaintextLength == 0)\n"

// Gobrafier strips openers and bare closers globally, including inside strings.
var sourceAnnotationPattern = regexp.MustCompile(`(?://|/\*)[ \t\n\x0b\f\r]*@|@[ \t\n\x0b\f\r]*\*/`)

type identity struct {
	ASTIdentical      bool   `json:"signature_body_ast_identical"`
	BodyIdentical     bool   `json:"body_bytes_identical"`
	OriginalAST       string `json:"original_signature_body_ast_sha256"`
	GeneratedAST      string `json:"generated_signature_body_ast_sha256"`
	OriginalBody      string `json:"original_body_sha256"`
	GeneratedBody     string `json:"generated_body_sha256"`
	ConversionLine    int    `json:"conversion_line"`
	ConversionColumn  int    `json:"conversion_column"`
	PostconditionLine int    `json:"postcondition_line,omitempty"`
}

type target struct {
	Source        []byte
	ConstantValue string
	Math          *types.Package
}

func annotateRecordCount(source []byte, chunk string, negative bool) ([]byte, identity, error) {
	fset, _, fn, err := declaration(source, "canonicalRecordCount")
	if err != nil {
		return nil, identity{}, err
	}
	if chunk != "1048576" || sourceAnnotationPattern.Match(source) {
		return nil, identity{}, errors.New("record-count constant or annotation boundary changed")
	}
	file := fset.File(fn.Pos())
	function := slices.Clone(source[file.Offset(fn.Pos()):file.Offset(fn.End())])
	if negative {
		var decrement *ast.BinaryExpr
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			if expression, ok := node.(*ast.BinaryExpr); ok && expression.Op == token.SUB {
				decrement = expression
			}
			return true
		})
		if decrement == nil {
			return nil, identity{}, errors.New("record-count decrement is missing")
		}
		var printed bytes.Buffer
		if err := format.Node(&printed, fset, decrement); err != nil {
			return nil, identity{}, err
		}
		if printed.String() != "plaintextLength - 1" {
			return nil, identity{}, errors.New("record-count decrement changed; control needs review")
		}
		begin := file.Offset(decrement.X.End()) - file.Offset(fn.Pos())
		end := file.Offset(decrement.End()) - file.Offset(fn.Pos())
		function = append(function[:begin], function[end:]...)
	}
	generated := append([]byte("package pcv3\n\nconst recordPlaintextMax = "+chunk+"\n\n"), function...)
	generated = append(generated, '\n')
	generatedSet, _, generatedFn, err := declaration(generated, "canonicalRecordCount")
	if err != nil {
		return nil, identity{}, err
	}
	generatedFile := generatedSet.File(generatedFn.Pos())
	end := generatedFile.Offset(generatedFn.Type.Results.List[0].Type.End())
	generated = append(generated[:end], append([]byte(" /*@ ) @*/"), generated[end:]...)...)
	start := generatedFile.Offset(generatedFn.Type.Results.List[0].Type.Pos())
	generated = append(generated[:start], append([]byte("/*@ (count @*/ "), generated[start:]...)...)
	start = generatedFile.Offset(generatedFn.Pos())
	generated = append(generated[:start], append([]byte(recordCountContract), generated[start:]...)...)
	result, err := compareFunctions(source, generated, "canonicalRecordCount")
	result.PostconditionLine = bytes.Count(generated[:bytes.Index(generated, []byte("//@ ensures plaintextLength % recordPlaintextMax == 0"))], []byte("\n")) + 1
	if err == nil && !negative && (!result.ASTIdentical || !result.BodyIdentical) {
		err = errors.New("record-count comments changed the executable declaration")
	}
	return generated, result, err
}

func digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func declaration(source []byte, selected ...string) (*token.FileSet, *ast.File, *ast.FuncDecl, error) {
	name, parameter := "SafeUint64ToInt64", "v"
	expected := []string{"uint64", "int64", "bool"}
	if len(selected) != 0 {
		name, parameter = selected[0], "plaintextLength"
		expected = []string{"uint64", "uint64"}
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "safecast.go", source, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name {
			continue
		}
		if fn.Recv != nil || fn.Type.TypeParams != nil || fn.Body == nil ||
			len(fn.Type.Params.List) != 1 || len(fn.Type.Params.List[0].Names) != 1 ||
			fn.Type.Params.List[0].Names[0].Name != parameter || fn.Type.Results == nil || len(fn.Type.Results.List) != len(expected)-1 {
			return nil, nil, nil, errors.New("source signature is outside the reviewed contract")
		}
		fields := append([]*ast.Field{fn.Type.Params.List[0]}, fn.Type.Results.List...)
		for i, name := range expected {
			id, ok := fields[i].Type.(*ast.Ident)
			if !ok || id.Name != name || i > 0 && len(fields[i].Names) != 0 {
				return nil, nil, nil, errors.New("source must retain the reviewed builtin types and unnamed results")
			}
		}
		return fset, file, fn, nil
	}
	return nil, nil, nil, fmt.Errorf("%s declaration not found", name)
}

func astBytes(fn *ast.FuncDecl) ([]byte, error) {
	var result bytes.Buffer
	copy := &ast.FuncDecl{Name: fn.Name, Type: fn.Type, Body: fn.Body}
	err := format.Node(&result, token.NewFileSet(), copy)
	return result.Bytes(), err
}

func annotate(source []byte, negative bool) ([]byte, identity, error) {
	var result identity
	if sourceAnnotationPattern.Match(source) {
		return nil, result, errors.New("source already contains verifier annotations")
	}
	fset, _, fn, err := declaration(source)
	if err != nil {
		return nil, result, err
	}
	file := fset.File(fn.Pos())
	type insertion struct {
		offset int
		text   string
	}
	inserts := []insertion{
		{file.Offset(fn.Pos()), contract},
		{file.Offset(fn.Type.Results.List[0].Type.Pos()), "/*@ value @*/ "},
		{file.Offset(fn.Type.Results.List[1].Type.Pos()), "/*@ ok @*/ "},
	}
	if negative {
		var guard *ast.IfStmt
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			candidate, ok := node.(*ast.IfStmt)
			if ok && guard == nil {
				guard = candidate
			}
			return true
		})
		var condition bytes.Buffer
		if guard == nil {
			return nil, result, errors.New("reviewed overflow guard is missing")
		}
		if err := format.Node(&condition, fset, guard.Cond); err != nil {
			return nil, result, err
		}
		if condition.String() != "v > math.MaxInt64" {
			return nil, result, errors.New("reviewed overflow guard changed; negative control needs review")
		}
		inserts = append(inserts, insertion{file.Offset(guard.Cond.Pos()), "false && ("}, insertion{file.Offset(guard.Cond.End()), ")"})
	}
	sort.Slice(inserts, func(i, j int) bool { return inserts[i].offset > inserts[j].offset })
	generated := slices.Clone(source)
	for _, insert := range inserts {
		generated = append(generated[:insert.offset], append([]byte(insert.text), generated[insert.offset:]...)...)
	}
	result, err = compareFunctions(source, generated)
	if err == nil && (!negative && (!result.ASTIdentical || !result.BodyIdentical) || result.ConversionLine == 0) {
		err = errors.New("generated source does not preserve the reviewed executable target")
	}
	return generated, result, err
}

func compareFunctions(source, generated []byte, selected ...string) (identity, error) {
	var result identity
	fset, _, fn, err := declaration(source, selected...)
	if err != nil {
		return result, err
	}
	file := fset.File(fn.Pos())
	generatedSet, _, generatedFn, err := declaration(generated, selected...)
	if err != nil {
		return result, err
	}
	originalAST, err := astBytes(fn)
	if err != nil {
		return result, err
	}
	generatedAST, err := astBytes(generatedFn)
	if err != nil {
		return result, err
	}
	generatedFile := generatedSet.File(generatedFn.Pos())
	originalBody := source[file.Offset(fn.Body.Pos()):file.Offset(fn.Body.End())]
	generatedBody := generated[generatedFile.Offset(generatedFn.Body.Pos()):generatedFile.Offset(generatedFn.Body.End())]
	result = identity{
		ASTIdentical: bytes.Equal(originalAST, generatedAST), BodyIdentical: bytes.Equal(originalBody, generatedBody),
		OriginalAST: digest(originalAST), GeneratedAST: digest(generatedAST),
		OriginalBody: digest(originalBody), GeneratedBody: digest(generatedBody),
	}
	ast.Inspect(generatedFn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok {
			id, ok := call.Fun.(*ast.Ident)
			if ok && id.Name == "int64" {
				position := generatedSet.PositionFor(call.Pos(), false)
				result.ConversionLine, result.ConversionColumn = position.Line, position.Column
			}
		}
		return true
	})
	return result, nil
}

func loadSource(repo, cache, relative, pattern string) (*packages.Package, []byte, error) {
	pkg, snapshots, err := loadSourceSnapshots(repo, cache, []string{relative}, pattern)
	return pkg, snapshots[relative], err
}

func loadSourceSnapshots(repo, cache string, relatives []string, pattern string) (*packages.Package, map[string][]byte, error) {
	snapshots := map[string][]byte{}
	watched := map[string]string{}
	for _, relative := range relatives {
		path := filepath.Join(repo, relative)
		source, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		snapshots[relative], watched[path] = source, relative
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	parsed := map[string][]byte{}
	var lock sync.Mutex
	loaded, err := packages.Load(&packages.Config{
		Context: ctx, Dir: filepath.Join(repo, "src"), Mode: packages.LoadSyntax,
		BuildFlags: []string{"-mod=readonly"},
		Env: append(os.Environ(), "GOPACKAGESDRIVER=off", "GOFLAGS=", "GOWORK=off", "GOENV=off", "GOTOOLCHAIN=local",
			"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOPROXY=off", "GOSUMDB=off", "GOCACHE="+cache),
		ParseFile: func(fset *token.FileSet, filename string, content []byte) (*ast.File, error) {
			if relative, ok := watched[filepath.Clean(filename)]; ok {
				lock.Lock()
				parsed[relative] = slices.Clone(content)
				lock.Unlock()
			}
			return parser.ParseFile(fset, filename, content, parser.ParseComments)
		},
	}, pattern)
	if err != nil {
		return nil, nil, err
	}
	if len(loaded) != 1 {
		return nil, nil, fmt.Errorf("expected one actual source package, got %d", len(loaded))
	}
	if len(loaded[0].Errors) != 0 || loaded[0].IllTyped {
		return nil, nil, fmt.Errorf("actual source package did not typecheck: %v", loaded[0].Errors)
	}
	for relative, source := range snapshots {
		if !bytes.Equal(source, parsed[relative]) {
			return nil, nil, fmt.Errorf("go/packages parsed bytes differ from the actual source snapshot: %s", relative)
		}
	}
	return loaded[0], snapshots, nil
}

func loadTarget(repo, cache string) (target, error) {
	var result target
	pkg, source, err := loadSource(repo, cache, sourceRelative, "./internal/util")
	if err != nil {
		return result, err
	}
	path := filepath.Join(repo, sourceRelative)
	object, ok := pkg.Types.Scope().Lookup("SafeUint64ToInt64").(*types.Func)
	if !ok {
		return result, errors.New("actual target is not a function")
	}
	signature, ok := object.Type().(*types.Signature)
	if !ok || signature.Recv() != nil || signature.Variadic() || signature.Params().Len() != 1 || signature.Results().Len() != 2 ||
		!types.Identical(signature.Params().At(0).Type(), types.Typ[types.Uint64]) ||
		!types.Identical(signature.Results().At(0).Type(), types.Typ[types.Int64]) ||
		!types.Identical(signature.Results().At(1).Type(), types.Typ[types.Bool]) {
		return result, errors.New("actual resolved target signature is not uint64 -> (int64, bool)")
	}
	fset, _, fn, err := declaration(source)
	if err != nil {
		return result, err
	}
	constantFound := false
	allowed := map[types.Object]bool{
		signature.Params().At(0): true, types.Universe.Lookup("uint64"): true,
		types.Universe.Lookup("int64"): true, types.Universe.Lookup("bool"): true,
		types.Universe.Lookup("true"): true, types.Universe.Lookup("false"): true,
	}
	for id, used := range pkg.TypesInfo.Uses {
		if name, ok := used.(*types.PkgName); ok && id.Name == "math" && name.Imported().Path() == "math" {
			allowed[name] = true
		}
		if filepath.Clean(pkg.Fset.PositionFor(id.Pos(), false).Filename) != path || id.Name != "MaxInt64" {
			continue
		}
		value, ok := used.(*types.Const)
		if !ok || value.Pkg() == nil || value.Pkg().Path() != "math" || value.Val().ExactString() != maxInt64 {
			return result, errors.New("source MaxInt64 is not the exact actual math.MaxInt64 constant")
		}
		result.Math = value.Pkg()
		allowed[value] = true
		constantFound = true
	}
	if !constantFound {
		return result, errors.New("actual math.MaxInt64 binding is missing")
	}
	if err := validateReviewedBody(pkg, path, fset, fn, allowed, true); err != nil {
		return result, err
	}
	result.Source, result.ConstantValue = source, maxInt64
	return result, nil
}

func loadRecordCount(repo, cache string) (target, error) {
	var result target
	pkg, source, err := loadSource(repo, cache, recordCountRelative, "./internal/pcv3operation/internal/pcv3")
	if err != nil {
		return result, err
	}
	object, ok := pkg.Types.Scope().Lookup("canonicalRecordCount").(*types.Func)
	if !ok {
		return result, errors.New("actual record-count target is not a function")
	}
	signature, ok := object.Type().(*types.Signature)
	if !ok || signature.Recv() != nil || signature.Variadic() || signature.Params().Len() != 1 || signature.Results().Len() != 1 ||
		!types.Identical(signature.Params().At(0).Type(), types.Typ[types.Uint64]) ||
		!types.Identical(signature.Results().At(0).Type(), types.Typ[types.Uint64]) {
		return result, errors.New("actual record-count signature must be uint64 -> uint64")
	}
	chunk, ok := pkg.Types.Scope().Lookup("recordPlaintextMax").(*types.Const)
	if !ok || chunk.Val().ExactString() != "1048576" || chunk.Type() != types.Typ[types.UntypedInt] ||
		filepath.Clean(pkg.Fset.PositionFor(chunk.Pos(), false).Filename) != filepath.Join(repo, recordCountRelative) {
		return result, errors.New("actual recordPlaintextMax is not the reviewed untyped integer constant 1048576")
	}
	fset, syntax, fn, err := declaration(source, "canonicalRecordCount")
	if err != nil {
		return result, err
	}
	literal := false
	for _, declaration := range syntax.Decls {
		group, ok := declaration.(*ast.GenDecl)
		if !ok || group.Tok != token.CONST {
			continue
		}
		for _, specification := range group.Specs {
			value, ok := specification.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || value.Names[0].Name != "recordPlaintextMax" || len(value.Values) != 1 {
				continue
			}
			initializer, ok := value.Values[0].(*ast.BasicLit)
			literal = ok && initializer.Kind == token.INT
		}
	}
	if !literal {
		return result, errors.New("record-count chunk constant needs a literal initializer")
	}
	file := fset.File(fn.Pos())
	used := false
	for id, object := range pkg.TypesInfo.Uses {
		position := pkg.Fset.PositionFor(id.Pos(), false)
		if position.Filename != filepath.Join(repo, recordCountRelative) || position.Offset < file.Offset(fn.Pos()) ||
			position.Offset >= file.Offset(fn.End()) || id.Name != "recordPlaintextMax" {
			continue
		}
		if object != chunk {
			return result, errors.New("record-count constant binding is shadowed or changed")
		}
		used = true
	}
	if !used {
		return result, errors.New("record-count constant binding is missing")
	}
	allowed := map[types.Object]bool{signature.Params().At(0): true, chunk: true, types.Universe.Lookup("uint64"): true}
	if err := validateReviewedBody(pkg, filepath.Join(repo, recordCountRelative), fset, fn, allowed, false); err != nil {
		return result, err
	}
	result.Source, result.ConstantValue = source, chunk.Val().ExactString()
	return result, nil
}

func validateReviewedBody(pkg *packages.Package, path string, fset *token.FileSet, fn *ast.FuncDecl, allowed map[types.Object]bool, allowCast bool) error {
	var rejected error
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if rejected != nil || node == nil {
			return false
		}
		switch expression := node.(type) {
		case *ast.BlockStmt, *ast.IfStmt, *ast.ReturnStmt, *ast.ParenExpr, *ast.Ident:
			return true
		case *ast.BasicLit:
			if expression.Kind == token.INT {
				return true
			}
		case *ast.BinaryExpr:
			if slices.Contains([]token.Token{token.ADD, token.SUB, token.QUO, token.REM, token.EQL, token.GTR}, expression.Op) {
				return true
			}
		case *ast.SelectorExpr:
			name, ok := expression.X.(*ast.Ident)
			if allowCast && ok && name.Name == "math" && expression.Sel.Name == "MaxInt64" {
				return true
			}
		case *ast.CallExpr:
			name, ok := expression.Fun.(*ast.Ident)
			if allowCast && ok && name.Name == "int64" && len(expression.Args) == 1 && expression.Ellipsis == token.NoPos {
				return true
			}
		}
		rejected = fmt.Errorf("unreviewed source syntax %T; the extracted scalar subset requires review", node)
		return false
	})
	if rejected != nil {
		return rejected
	}
	file := fset.File(fn.Pos())
	for id, object := range pkg.TypesInfo.Uses {
		position := pkg.Fset.PositionFor(id.Pos(), false)
		if position.Filename == path && file.Offset(fn.Pos()) <= position.Offset && position.Offset < file.Offset(fn.End()) && !allowed[object] {
			return fmt.Errorf("unreviewed source identifier binding %q", id.Name)
		}
	}
	return nil
}

type mathImporter struct{ actual *types.Package }

func (i mathImporter) Import(path string) (*types.Package, error) {
	if path != "math" || i.actual == nil {
		return nil, fmt.Errorf("unreviewed generated import %q", path)
	}
	return i.actual, nil
}

func typecheckCopy(source []byte, math *types.Package) error {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "generated.go", source, parser.ParseComments)
	if err != nil {
		return err
	}
	config := types.Config{GoVersion: "go1.27", Importer: mathImporter{math}}
	_, err = config.Check(file.Name.Name, fset, []*ast.File{file}, nil)
	return err
}

func overflowRejected(code int, log string, line, column int) bool {
	lower := strings.ToLower(log)
	return code == 1 && strings.Contains(log, "Gobra found 1 error.") &&
		strings.Contains(log, fmt.Sprintf("</workspace/guard-disabled/safecast.go:%d:%d> Expression may cause integer overflow.", line, column)) &&
		strings.Contains(log, "Expression int64(v) might cause integer overflow.") &&
		!strings.Contains(lower, "timeout") && !strings.Contains(lower, "outofmemory")
}

func recordCountRejected(code int, log string, line int) bool {
	lower := strings.ToLower(log)
	return code == 1 && strings.Contains(log, "Gobra found 1 error.") &&
		strings.Contains(log, fmt.Sprintf("</workspace/record-count-extra-record/records.go:%d:9> Postcondition might not hold.", line)) &&
		strings.Contains(log, "Assertion plaintextLength % recordPlaintextMax == 0 ==> count == plaintextLength / recordPlaintextMax might not hold.") &&
		!strings.Contains(lower, "timeout") && !strings.Contains(lower, "outofmemory") &&
		!strings.Contains(lower, "integer overflow")
}

type imageInfo struct {
	ID          string   `json:"Id"`
	RepoDigests []string `json:"RepoDigests"`
	Config      struct{ Labels map[string]string }
}

type containerInfo struct {
	Image      string
	Config     struct{ User string }
	HostConfig struct {
		Memory, MemorySwap, NanoCpus, PidsLimit int64
		ReadonlyRootfs                          bool
		NetworkMode                             string
		CapDrop, CapAdd, SecurityOpt            []string
		Tmpfs                                   map[string]string
	}
	Mounts []struct {
		Type, Source, Destination string
		RW                        bool
	}
	State struct {
		ExitCode  int
		Running   bool
		OOMKilled bool
		Error     string
	}
}

type caseResult struct {
	Name               string              `json:"name"`
	Command            []string            `json:"create_command"`
	ID                 string              `json:"container_id"`
	Before             json.RawMessage     `json:"inspect_before_execution"`
	After              json.RawMessage     `json:"inspect_after_execution"`
	ExitCode           int                 `json:"exit_code"`
	Seconds            float64             `json:"seconds"`
	Removed            bool                `json:"container_removed"`
	Passed             bool                `json:"passed"`
	TimedOut           bool                `json:"timed_out"`
	SourceSHA256       string              `json:"generated_source_sha256"`
	Identity           *identity           `json:"source_identity,omitempty"`
	D1Identity         *d1Identity         `json:"d1_source_identity,omitempty"`
	ArithmeticIdentity *arithmeticEvidence `json:"arithmetic_source_identity,omitempty"`
	PayloadIdentity    *payloadEvidence    `json:"payload_source_identity,omitempty"`
	OffsetIdentity     *offsetEvidence     `json:"offset_source_identity,omitempty"`
	MetadataIdentity   *metadataEvidence   `json:"metadata_source_identity,omitempty"`
	CorePolicyIdentity *corePolicyEvidence `json:"core_policy_source_identity,omitempty"`
	Mode               string              `json:"mode,omitempty"`
}

func docker(timeout time.Duration, args ...string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	code := 0
	if err != nil {
		code = -1
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		}
	}
	if ctx.Err() != nil {
		return output, code, ctx.Err()
	}
	return output, code, err
}

func inspectContainer(id string) (containerInfo, []byte, error) {
	var objects []containerInfo
	output, _, err := docker(15*time.Second, "container", "inspect", id)
	if err == nil {
		err = json.Unmarshal(output, &objects)
	}
	if err != nil || len(objects) != 1 {
		return containerInfo{}, output, fmt.Errorf("inspect owned container: %w", errors.Join(err, errors.New("expected exactly one object")))
	}
	return objects[0], output, nil
}

func runIsolated(runDir, name, imageID, entrypoint string, command []string) (result caseResult, output []byte, err error) {
	result = caseResult{Name: name, ExitCode: -1}
	args := []string{"create", "--pull=never", "--label", "picocrypt-ng.verification=source-contracts",
		"--memory", "3g", "--memory-swap", "3g", "--cpus", "2", "--network", "none", "--read-only",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "1000:1000", "--pids-limit", "256",
		"--tmpfs", "/tmp:rw,nosuid,nodev,size=134217728", "--mount", "type=bind,src=" + runDir + ",dst=/workspace,readonly",
		"--workdir", "/tmp", "--entrypoint", entrypoint, image}
	args = append(args, command...)
	result.Command = append([]string{"docker"}, args...)
	created, _, err := docker(15*time.Second, args...)
	if err != nil {
		return result, output, fmt.Errorf("create %s: %w: %s", name, err, created)
	}
	result.ID = strings.TrimSpace(string(created))
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(result.ID) {
		return result, output, errors.New("docker create did not return an exact container ID")
	}
	defer func() {
		output, _, cleanupErr := docker(15*time.Second, "container", "rm", "--force", result.ID)
		result.Removed = cleanupErr == nil
		if cleanupErr != nil {
			result.Passed = false
			err = errors.Join(err, fmt.Errorf("remove owned container %s: %w: %s", result.ID, cleanupErr, output))
		}
	}()
	container, raw, err := inspectContainer(result.ID)
	if err != nil {
		return result, output, err
	}
	result.Before = raw
	host := container.HostConfig
	if container.Image != imageID || container.Config.User != "1000:1000" || host.Memory != 3221225472 ||
		host.MemorySwap != host.Memory || host.NanoCpus != 2000000000 || host.PidsLimit != 256 ||
		!host.ReadonlyRootfs || host.NetworkMode != "none" || !slices.Equal(host.CapDrop, []string{"ALL"}) ||
		len(host.CapAdd) != 0 || !slices.Contains(host.SecurityOpt, "no-new-privileges") ||
		len(host.Tmpfs) != 1 || host.Tmpfs["/tmp"] != "rw,nosuid,nodev,size=134217728" || len(container.Mounts) != 1 {
		return result, output, errors.New("owned container isolation readback does not match required settings")
	}
	mount := container.Mounts[0]
	if mount.Type != "bind" || mount.Source != runDir || mount.Destination != "/workspace" || mount.RW {
		return result, output, errors.New("owned container must mount only this generated run directory read-only")
	}
	started := time.Now()
	output, code, startErr := docker(90*time.Second, "start", "--attach", result.ID)
	result.Seconds, result.ExitCode = time.Since(started).Seconds(), code
	result.TimedOut = errors.Is(startErr, context.DeadlineExceeded)
	if writeErr := os.WriteFile(filepath.Join(runDir, name+".log"), output, 0644); writeErr != nil {
		return result, output, writeErr
	}
	container, raw, err = inspectContainer(result.ID)
	if err != nil {
		return result, output, err
	}
	result.After = raw
	if result.TimedOut || container.State.Running || container.State.OOMKilled || container.State.Error != "" || container.State.ExitCode != code {
		return result, output, fmt.Errorf("%s did not finish as an ordinary prover result", name)
	}
	return result, output, nil
}

func runCase(runDir, name, filename, imageID string, source []byte, identity identity) (caseResult, error) {
	mode := "--overflow"
	if strings.HasPrefix(name, "d1-parameters-") || strings.HasPrefix(name, "core-policy-") {
		mode = "--nooverflow"
	}
	command := []string{"-Xss128m", "-Xmx2048m", "-jar", "/gobra/gobra.jar", mode, "--assertTimeout", "5000", "-i", "/workspace/" + name + "/" + filename, "-I", "/workspace/stubs"}
	result, output, err := runIsolated(runDir, name, imageID, "java", command)
	result.Identity, result.SourceSHA256, result.Mode = &identity, digest(source), mode
	if err != nil {
		return result, err
	}
	if strings.HasSuffix(name, "positive") {
		result.Passed = result.ExitCode == 0 && strings.Contains(string(output), "Gobra found 0 errors.")
	} else if name == "record-count-extra-record" {
		result.Passed = recordCountRejected(result.ExitCode, string(output), identity.PostconditionLine)
	} else if name == "d1-parameters-wrong-index" {
		result.Passed = d1Rejected(result.ExitCode, string(output), identity.PostconditionLine)
	} else if strings.HasPrefix(name, "arithmetic-") {
		result.Passed = arithmeticRejected(result.ExitCode, string(output), name, identity.PostconditionLine)
	} else if strings.HasPrefix(name, "payload-") {
		result.Passed = payloadRejected(result.ExitCode, string(output), name, identity.PostconditionLine)
	} else if strings.HasPrefix(name, "offset-") {
		result.Passed = offsetRejected(result.ExitCode, string(output), name, identity.PostconditionLine)
	} else if name == "metadata-ceil-floor" {
		result.Passed = metadataRejected(result.ExitCode, string(output), identity.PostconditionLine)
	} else if name == "core-policy-count-mismatch" {
		result.Passed = corePolicyRejected(result.ExitCode, string(output), identity.PostconditionLine)
	} else {
		result.Passed = overflowRejected(result.ExitCode, string(output), identity.ConversionLine, identity.ConversionColumn)
	}
	if !result.Passed {
		return result, fmt.Errorf("%s failed its required proof outcome; see %s.log", name, name)
	}
	return result, nil
}

func run(repo string) (err error) {
	repo, err = filepath.Abs(repo)
	if err != nil {
		return err
	}
	build := filepath.Join(repo, "verification/gobra/_build")
	if err := os.MkdirAll(filepath.Join(build, "runs"), 0755); err != nil {
		return err
	}
	runDir, err := os.MkdirTemp(filepath.Join(build, "runs"), "source-contracts-")
	if err != nil {
		return err
	}
	if err := os.Chmod(runDir, 0755); err != nil {
		return err
	}
	if strings.Contains(runDir, ",") {
		return errors.New("repository path contains a Docker mount-option separator")
	}
	report := map[string]any{
		"schema": 1, "scope": "actual-Go-source-contracts", "passed": false, "status": "running",
		"go_version": runtime.Version(), "go_packages_version": "v0.52.0", "gobra_image": image, "gobra_revision": revision,
		"run_directory": runDir, "contract": contract,
		"cross_logic_refinement":             "open: typed Go/Gobra and EasyCrypt input/output embeddings and proof composition remain trusted obligations",
		"representation":                     map[string]string{"input": "all uint64: 0 <= v < 2^64", "output": "actual Go int64 result type, plus separately checked Gobra range postcondition"},
		"derived_result_range_postcondition": "-9223372036854775808 <= value && value <= 9223372036854775807",
		"loader_environment":                 "GOPACKAGESDRIVER=off GOFLAGS= GOWORK=off GOENV=off GOTOOLCHAIN=local GOOS=linux GOARCH=amd64 CGO_ENABLED=0; -mod=readonly; no overlay",
	}
	defer func() {
		report["status"] = "finished"
		if err != nil {
			report["status"] = "failed"
			report["error"] = err.Error()
			report["passed"] = false
		}
		data, marshalErr := json.MarshalIndent(report, "", "  ")
		if marshalErr == nil {
			data = append(data, '\n')
			marshalErr = errors.Join(os.WriteFile(filepath.Join(runDir, "results.json"), data, 0644), os.WriteFile(filepath.Join(build, "results.json"), data, 0644))
		}
		err = errors.Join(err, marshalErr)
		fmt.Println(filepath.Join(build, "results.json"))
	}()
	initial, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(build, "results.json"), append(initial, '\n'), 0644); err != nil {
		return err
	}
	if runtime.Version() != "go1.27.3" {
		return fmt.Errorf("required Go 1.27.3, running %s", runtime.Version())
	}
	buildInfo, available := debug.ReadBuildInfo()
	if !available {
		return errors.New("dependency build information is unavailable")
	}
	packagesVersion := ""
	for _, dependency := range buildInfo.Deps {
		if dependency.Path == "golang.org/x/tools" && dependency.Replace == nil {
			packagesVersion = dependency.Version
		}
	}
	if packagesVersion != "v0.52.0" {
		return fmt.Errorf("required unmodified go/packages module v0.52.0, built with %q", packagesVersion)
	}
	report["go_packages_version"] = packagesVersion
	report["easycrypt_representation_lemma"] = map[string]string{
		"source": "verification/easycrypt/models/SafeCastRepresentation.ec", "theorem": "typed_source_contract_refines_model",
		"verification": "separate EasyCrypt runner; Go/Gobra-to-EasyCrypt transport is not established",
	}
	if _, err := os.Stat(filepath.Join(repo, "verification/SOURCE-CORRESPONDENCE.md")); err == nil {
		report["reviewed_conditional_composition"] = "verification/SOURCE-CORRESPONDENCE.md; reviewed theorem composition under explicit TCB, not automatic common-kernel proof transport"
	}
	inputContext, err := captureSourceContext(repo)
	if err != nil {
		return err
	}
	contextEvidence := map[string]any{"initial": inputContext, "checks": "before loaders, after all package loaders before proofs, and after all proof/native jobs; hash-only own-module context policy, not product coverage"}
	report["source_context"] = contextEvidence
	actual, err := loadTarget(repo, filepath.Join(build, "go-cache"))
	if err != nil {
		return err
	}
	report["source"] = map[string]any{"path": sourceRelative, "sha256": digest(actual.Source), "signature": "func SafeUint64ToInt64(v uint64) (int64, bool)", "math_MaxInt64": actual.ConstantValue}
	records, err := loadRecordCount(repo, filepath.Join(build, "go-cache"))
	if err != nil {
		return err
	}
	report["record_count_source"] = map[string]any{
		"path": recordCountRelative, "sha256": digest(records.Source), "signature": "func canonicalRecordCount(plaintextLength uint64) uint64",
		"recordPlaintextMax": records.ConstantValue, "contract": recordCountContract,
		"projection":      "actual function declaration and exact resolved constant; surrounding unrelated declarations are omitted",
		"easycrypt_model": "verification/easycrypt/models/CanonicalRecords.ec; checked separately",
	}

	d1, err := loadD1(repo, filepath.Join(build, "go-cache"))
	if err != nil {
		return err
	}
	d1Snapshots := map[string]string{}
	for path, source := range d1.Snapshots {
		d1Snapshots[path] = digest(source)
	}
	report["d1_parameters_source"] = map[string]any{
		"path": d1Relative, "snapshots": d1Snapshots, "contract": d1Contract,
		"mode":                 "--nooverflow: parametric layout only; shift is uninterpreted; no arithmetic/no-reuse conclusion",
		"projection":           "full actual structs, receiver and method; actual import/field/copy bindings; exact reviewed body only",
		"owned_comments":       "four body line comments and two result-name comments outside body; executable AST identity plus exact body recovery",
		"trusted_dependencies": "standard encoding/binary.PutUint64 byte contract; actual D1Profile underlying uint16 type; Go/Gobra slice/copy/shift semantics",
		"negative":             "index+1 at index=0, nonceOut[23]=0 consequence; native concrete counterexample; no observed SAT certificate",
	}
	arithmetic, err := loadArithmetic(repo, filepath.Join(build, "go-cache"))
	if err != nil {
		return err
	}
	payload, err := loadPayload(repo, filepath.Join(build, "go-cache"), arithmetic)
	if err != nil {
		return err
	}
	offset, err := loadOffset(repo, filepath.Join(build, "go-cache"), payload)
	if err != nil {
		return err
	}
	metadata, err := loadMetadata(repo, filepath.Join(build, "go-cache"), arithmetic)
	if err != nil {
		return err
	}
	corePolicy, err := loadCorePolicy(repo, filepath.Join(build, "go-cache"), metadata, payload)
	if err != nil {
		return err
	}
	snapshots := map[string][]byte{sourceRelative: actual.Source, recordCountRelative: records.Source, arithmeticRelative: arithmetic.Source, bitsHeaderRelative: arithmetic.Header}
	if err = mergeSourceSnapshots(snapshots, d1.Snapshots); err != nil {
		return err
	}
	if err = mergeSourceSnapshots(snapshots, payload.Snapshots); err != nil {
		return err
	}
	if err = mergeSourceSnapshots(snapshots, offset.Snapshots); err != nil {
		return err
	}
	if err = mergeSourceSnapshots(snapshots, metadata.Snapshots); err != nil {
		return err
	}
	if err = mergeSourceSnapshots(snapshots, corePolicy.Snapshots); err != nil {
		return err
	}
	loadedContext, contextErr := checkSourceContext(repo, inputContext)
	contextEvidence["before_proofs"] = loadedContext
	if contextErr != nil {
		return fmt.Errorf("own source context drift after loaders: %w", contextErr)
	}
	inspected, _, err := docker(15*time.Second, "image", "inspect", image)
	if err != nil {
		return fmt.Errorf("pinned Gobra image is unavailable; no automatic pull: %w", err)
	}
	var images []imageInfo
	if err := json.Unmarshal(inspected, &images); err != nil {
		return err
	}
	if len(images) != 1 || !slices.Contains(images[0].RepoDigests, image) ||
		images[0].Config.Labels["org.opencontainers.image.revision"] != revision ||
		images[0].Config.Labels["org.opencontainers.image.source"] != "https://github.com/viperproject/gobra" {
		return errors.New("pinned Gobra image digest or source/revision labels do not match")
	}
	report["image_inspection"] = json.RawMessage(inspected)
	stub := []byte("package math\n\nconst MaxInt64 = " + actual.ConstantValue + "\n")
	if err := os.MkdirAll(filepath.Join(runDir, "stubs/math"), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(runDir, "stubs/math/math.gobra"), stub, 0644); err != nil {
		return err
	}
	report["math_header_sha256"] = digest(stub)
	if err := writeD1Headers(runDir, d1); err != nil {
		return err
	}
	var cases []caseResult
	for _, name := range []string{"positive", "guard-disabled", "record-count-positive", "record-count-extra-record"} {
		filename := "safecast.go"
		math := actual.Math
		var generated []byte
		var identity identity
		var err error
		if strings.HasPrefix(name, "record-count-") {
			filename, math = "records.go", nil
			generated, identity, err = annotateRecordCount(records.Source, records.ConstantValue, name == "record-count-extra-record")
		} else {
			generated, identity, err = annotate(actual.Source, name == "guard-disabled")
		}
		if err != nil {
			return err
		}
		if err := typecheckCopy(generated, math); err != nil {
			return fmt.Errorf("%s generated Go failed actual-import typecheck: %w", name, err)
		}
		if err := os.MkdirAll(filepath.Join(runDir, name), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(runDir, name, filename), generated, 0644); err != nil {
			return err
		}
		result, err := runCase(runDir, name, filename, images[0].ID, generated, identity)
		cases = append(cases, result)
		report["cases"] = cases
		if err != nil {
			return err
		}
	}

	var nativeCases []caseResult
	for _, name := range []string{"d1-parameters-positive", "d1-parameters-wrong-index"} {
		negative := name == "d1-parameters-wrong-index"
		generated, sourceIdentity, err := annotateD1(d1.Projection, negative)
		if err != nil {
			return err
		}
		if err = typecheckD1(generated, d1.Imports); err != nil {
			return fmt.Errorf("%s actual-import typecheck: %w", name, err)
		}
		directory := filepath.Join(runDir, name)
		if err = os.MkdirAll(directory, 0755); err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(directory, "parameters.go"), generated, 0644); err != nil {
			return err
		}
		result, err := runCase(runDir, name, "parameters.go", images[0].ID, generated, identity{PostconditionLine: sourceIdentity.PostconditionLine})
		result.D1Identity = &sourceIdentity
		result.Identity = nil
		cases = append(cases, result)
		report["cases"] = cases
		if err != nil {
			return err
		}
		compileCommand, err := compileD1Oracle(repo, runDir, name, generated)
		if err != nil {
			return err
		}
		report[name+"_native_compile_command"] = compileCommand
		native, output, err := runIsolated(runDir, name+"-native", images[0].ID, "/workspace/"+name+"-oracle", nil)
		native.Mode = "native concrete proof-control oracle; not application coverage"
		if err == nil {
			expectedCode, expectedNonce := 0, "000000000000000000000000000000000000000000000000"
			if negative {
				expectedCode, expectedNonce = 1, "000000000000000000000000000000000000000000000001"
			}
			native.Passed = native.ExitCode == expectedCode && strings.Contains(string(output), "nonce="+expectedNonce+" iv=00000000000000000000000000000000")
			if !native.Passed {
				err = fmt.Errorf("%s native frozen oracle did not produce required outcome", name)
			}
		}
		nativeCases = append(nativeCases, native)
		report["native_controls"] = nativeCases
		if err != nil {
			return err
		}
	}
	if err = runArithmetic(repo, runDir, images[0].ID, arithmetic, report, cases, nativeCases); err != nil {
		return err
	}
	if err = runPayload(repo, runDir, images[0].ID, payload, report); err != nil {
		return err
	}
	if err = runOffset(repo, runDir, images[0].ID, offset, report); err != nil {
		return err
	}
	if err = runMetadata(repo, runDir, images[0].ID, metadata, report); err != nil {
		return err
	}
	if err = runCorePolicy(repo, runDir, images[0].ID, corePolicy, report); err != nil {
		return err
	}
	finalContext, contextErr := checkSourceContext(repo, inputContext)
	contextEvidence["after_jobs"] = finalContext
	report["source_context_unchanged"] = contextErr == nil
	if contextErr != nil {
		return fmt.Errorf("own source context drift during verification: %w", contextErr)
	}
	unchanged := true
	for path, snapshot := range snapshots {
		current, err := os.ReadFile(filepath.Join(repo, path))
		if err != nil {
			return err
		}
		unchanged = unchanged && bytes.Equal(current, snapshot)
	}
	report["source_unchanged"] = unchanged
	if !unchanged {
		return errors.New("actual source changed during verification; generated proof does not validate current source")
	}
	report["passed"] = true
	return nil
}

func main() {
	repo := flag.String("repo", "../..", "Picocrypt NG repository root")
	flag.Parse()
	if err := run(*repo); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
