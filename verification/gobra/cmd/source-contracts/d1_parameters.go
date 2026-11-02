package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
)

const d1Relative = "src/internal/pcv3operation/internal/pcv3/d1_outer.go"
const d1ProfileRelative = "src/internal/pcv3operation/internal/pcv3credential/outer.go"
const binaryHeaderRelative = "verification/gobra/specs/encoding/binary/binary.gobra"
const credentialPath = "Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
const d1Prefix = "package pcv3\nimport (\"encoding/binary\"; \"" + credentialPath + "\")\n"
const d1Reviewed = d1Prefix + `
type d1OuterKeys struct {
 xChaCha20 [32]byte
 serpent [32]byte
 mac [32]byte
 xNoncePrefix [16]byte
 serpentPrefix [8]byte
}
type d1OuterCodec struct {
 keys d1OuterKeys
 profile pcv3credential.D1Profile
 closed bool
}
func (codec *d1OuterCodec) recordParameters(index uint64) ([24]byte, [16]byte) {
 var nonce [24]byte
 var serpentIV [16]byte
 copy(nonce[:16], codec.keys.xNoncePrefix[:])
 binary.BigEndian.PutUint64(nonce[16:], index)
 copy(serpentIV[:8], codec.keys.serpentPrefix[:])
 binary.BigEndian.PutUint64(serpentIV[8:], index<<16)
 return nonce, serpentIV
}
`
const d1NoncePost = "//@ ensures forall j int :: 0 <= j && j < 8 ==> integer(nonceOut[16+j]) == binary.Octet(integer(index), j)\n"
const d1BytePost = "//@ ensures nonceOut[23] == 0\n"
const d1Contract = "//@ requires codec != nil\n" +
	"//@ requires 0 <= index && index <= 18446744073709551615\n" +
	"//@ requires forall j int :: 0 <= j && j < 16 ==> acc(&codec.keys.xNoncePrefix[j])\n" +
	"//@ requires forall j int :: 0 <= j && j < 8 ==> acc(&codec.keys.serpentPrefix[j])\n" +
	"//@ ensures forall j int :: 0 <= j && j < 16 ==> acc(&codec.keys.xNoncePrefix[j])\n" +
	"//@ ensures forall j int :: 0 <= j && j < 8 ==> acc(&codec.keys.serpentPrefix[j])\n" +
	"//@ ensures forall j int :: 0 <= j && j < 16 ==> nonceOut[j] == old(codec.keys.xNoncePrefix[j])\n" +
	"//@ ensures forall j int :: 0 <= j && j < 8 ==> ivOut[j] == old(codec.keys.serpentPrefix[j])\n" + d1NoncePost +
	"//@ ensures forall j int :: 0 <= j && j < 8 ==> integer(ivOut[8+j]) == binary.Octet(integer(index<<16), j)\n"

var d1OwnedBodyComments = []string{" // @ addressable: nonce", " // @ addressable: serpentIV", " // @ with: perm(1/2)", " // @ with: perm(1/2)"}

type d1Target struct {
	Source     []byte
	Projection []byte
	Imports    actualImporter
	Snapshots  map[string][]byte
	Header     []byte
}

type d1Identity struct {
	DeclarationsIdentical bool     `json:"receiver_full_structs_signature_body_ast_identical"`
	BodyRecovered         bool     `json:"body_recovered_after_erasing_four_owned_comments"`
	ControlBodyRecovered  bool     `json:"body_recovered_after_erasing_four_owned_comments_and_undoing_control,omitempty"`
	BodyBytesIdentical    bool     `json:"body_bytes_identical"`
	OriginalBody          string   `json:"original_body_sha256"`
	GeneratedBody         string   `json:"generated_body_sha256"`
	OwnedBodyComments     []string `json:"owned_body_comments"`
	OwnedResultComments   int      `json:"owned_result_name_comments_outside_body"`
	NegativeMutation      string   `json:"negative_mutation,omitempty"`
	PostconditionLine     int      `json:"postcondition_line,omitempty"`
}

// Positions and comments are excluded; receiver, fields and executable nodes remain.
func structuralAST(node ast.Node) []byte {
	var out bytes.Buffer
	_ = ast.Fprint(&out, token.NewFileSet(), node, func(name string, value reflect.Value) bool {
		return value.Type() != reflect.TypeFor[token.Pos]() && name != "Doc" && name != "Comment" && name != "Comments" && name != "Obj" && name != "Scope" && name != "Unresolved"
	})
	return out.Bytes()
}

func d1Declarations(source []byte) (*token.FileSet, []*ast.GenDecl, *ast.FuncDecl, error) {
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "parameters.go", source, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, nil, nil, err
	}
	var groups []*ast.GenDecl
	var method *ast.FuncDecl
	for _, declaration := range file.Decls {
		switch d := declaration.(type) {
		case *ast.GenDecl:
			if d.Tok == token.TYPE {
				for _, specification := range d.Specs {
					spec := specification.(*ast.TypeSpec)
					if spec.Name.Name == "d1OuterKeys" || spec.Name.Name == "d1OuterCodec" {
						if spec.Assign != token.NoPos || spec.TypeParams != nil {
							return nil, nil, nil, errors.New("D1 structs must retain reviewed non-generic defined types")
						}
						if len(d.Specs) != 1 {
							return nil, nil, nil, errors.New("D1 structs need separate full declarations")
						}
						groups = append(groups, d)
					}
				}
			}
		case *ast.FuncDecl:
			if d.Name.Name == "recordParameters" {
				method = d
			}
		}
	}
	if len(groups) != 2 || method == nil {
		return nil, nil, nil, errors.New("D1 full structs or method missing")
	}
	return set, groups, method, nil
}

func d1Body(source []byte, set *token.FileSet, fn *ast.FuncDecl) []byte {
	file := set.File(fn.Pos())
	return source[file.Offset(fn.Body.Pos()):file.Offset(fn.Body.End())]
}

func reviewD1Shape(source []byte) error {
	if sourceAnnotationPattern.Match(source) {
		return errors.New("D1 source contains verifier input markers")
	}
	_, groups, fn, err := d1Declarations(source)
	if err != nil {
		return err
	}
	_, expected, method, err := d1Declarations([]byte(d1Reviewed))
	if err != nil {
		return err
	}
	if !bytes.Equal(structuralAST(fn), structuralAST(method)) ||
		!bytes.Equal(structuralAST(groups[0]), structuralAST(expected[0])) || !bytes.Equal(structuralAST(groups[1]), structuralAST(expected[1])) {
		return errors.New("D1 source is outside the reviewed constructor: full structs, receiver, fixed slices, copy, PutUint64 and index<<16 only")
	}
	return nil
}

func loadD1(repo, cache string) (d1Target, error) {
	var result d1Target
	pkg, source, err := loadSource(repo, cache, d1Relative, "./internal/pcv3operation/internal/pcv3")
	if err != nil {
		return result, err
	}
	if err = reviewD1Shape(source); err != nil {
		return result, err
	}
	set, groups, fn, err := d1Declarations(source)
	if err != nil {
		return result, err
	}
	allowed := map[types.Object]bool{}
	for _, name := range []string{"byte", "uint64", "bool", "copy"} {
		allowed[types.Universe.Lookup(name)] = true
	}
	keys := pkg.Types.Scope().Lookup("d1OuterKeys")
	codec := pkg.Types.Scope().Lookup("d1OuterCodec")
	for _, object := range []types.Object{keys, codec} {
		if object == nil {
			return result, errors.New("D1 named type missing")
		}
		allowed[object] = true
		structure, ok := object.Type().Underlying().(*types.Struct)
		if !ok {
			return result, errors.New("D1 type is not a struct")
		}
		for n := 0; n < structure.NumFields(); n++ {
			allowed[structure.Field(n)] = true
		}
	}
	binary := pkg.Imports["encoding/binary"]
	credential := pkg.Imports[credentialPath]
	if binary == nil || credential == nil {
		return result, errors.New("D1 actual imports missing")
	}
	endian := binary.Types.Scope().Lookup("BigEndian")
	if endian == nil {
		return result, errors.New("standard BigEndian missing")
	}
	put, _, _ := types.LookupFieldOrMethod(endian.Type(), true, binary.Types, "PutUint64")
	if put == nil {
		return result, errors.New("standard PutUint64 missing")
	}
	allowed[endian], allowed[put] = true, true
	profile := credential.Types.Scope().Lookup("D1Profile")
	if profile == nil || !types.Identical(profile.Type().Underlying(), types.Typ[types.Uint16]) {
		return result, errors.New("actual D1Profile underlying type changed")
	}
	allowed[profile] = true
	path := filepath.Join(repo, d1Relative)
	inProjection := func(position token.Pos) bool {
		physical := pkg.Fset.PositionFor(position, false)
		if physical.Filename != path {
			return false
		}
		selected := []ast.Node{groups[0], groups[1], fn}
		for _, node := range selected {
			file := set.File(node.Pos())
			if file.Offset(node.Pos()) <= physical.Offset && physical.Offset < file.Offset(node.End()) {
				return true
			}
		}
		return false
	}
	for id, object := range pkg.TypesInfo.Defs {
		if inProjection(id.Pos()) {
			switch id.Name {
			case "codec", "index", "nonce", "serpentIV":
				allowed[object] = true
			}
		}
	}
	for id, object := range pkg.TypesInfo.Uses {
		if !inProjection(id.Pos()) {
			continue
		}
		if name, ok := object.(*types.PkgName); ok && (name.Imported() == binary.Types || name.Imported() == credential.Types) {
			allowed[object] = true
		}
		if !allowed[object] {
			return result, fmt.Errorf("D1 unreviewed actual binding %q", id.Name)
		}
	}
	var projection bytes.Buffer
	projection.WriteString(d1Prefix)
	file := set.File(fn.Pos())
	for _, group := range groups {
		projection.Write(source[file.Offset(group.Pos()):file.Offset(group.End())])
		projection.WriteByte('\n')
	}
	projection.Write(source[file.Offset(fn.Pos()):file.Offset(fn.End())])
	projection.WriteByte('\n')
	result = d1Target{Source: source, Projection: projection.Bytes(), Imports: actualImporter{"encoding/binary": binary.Types, credentialPath: credential.Types}, Snapshots: map[string][]byte{d1Relative: source}}
	for _, relative := range []string{d1ProfileRelative, binaryHeaderRelative} {
		content, err := os.ReadFile(filepath.Join(repo, relative))
		if err != nil {
			return result, err
		}
		result.Snapshots[relative] = content
	}
	profileSource := result.Snapshots[d1ProfileRelative]
	profileSet := token.NewFileSet()
	profileFile, err := parser.ParseFile(profileSet, "outer.go", profileSource, 0)
	if err != nil {
		return result, err
	}
	found := false
	for _, d := range profileFile.Decls {
		if group, ok := d.(*ast.GenDecl); ok && group.Tok == token.TYPE {
			for _, s := range group.Specs {
				spec := s.(*ast.TypeSpec)
				if spec.Name.Name == "D1Profile" {
					underlying, ok := spec.Type.(*ast.Ident)
					found = ok && underlying.Name == "uint16" && spec.Assign == token.NoPos && spec.TypeParams == nil && filepath.Clean(credential.Fset.PositionFor(profile.Pos(), false).Filename) == filepath.Join(repo, d1ProfileRelative)
				}
			}
		}
	}
	if !found || sourceAnnotationPattern.Match(profileSource) {
		return result, errors.New("D1Profile type declaration needs review")
	}
	result.Header = result.Snapshots[binaryHeaderRelative]
	return result, nil
}

type actualImporter map[string]*types.Package

func (imports actualImporter) Import(path string) (*types.Package, error) {
	if actual := imports[path]; actual != nil {
		return actual, nil
	}
	return nil, fmt.Errorf("unreviewed generated import %q", path)
}
func typecheckD1(source []byte, imports actualImporter) error {
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "parameters.go", source, parser.ParseComments)
	if err != nil {
		return err
	}
	config := types.Config{GoVersion: "go1.27", Importer: imports}
	_, err = config.Check("Picocrypt-NG/internal/pcv3operation/internal/noncefixture", set, []*ast.File{file}, nil)
	return err
}

func annotateD1(source []byte, negative bool) ([]byte, d1Identity, error) {
	var result d1Identity
	if err := reviewD1Shape(source); err != nil {
		return nil, result, err
	}
	set, groups, fn, err := d1Declarations(source)
	if err != nil {
		return nil, result, err
	}
	file := set.File(fn.Pos())
	type insertion struct {
		offset int
		text   string
	}
	additions := []insertion{
		{file.Offset(fn.Pos()), d1Contract},
		{file.Offset(fn.Type.Results.List[0].Pos()), "/*@ nonceOut @*/ "},
		{file.Offset(fn.Type.Results.List[1].Pos()), "/*@ ivOut @*/ "},
	}
	for i, statement := range []ast.Stmt{fn.Body.List[0], fn.Body.List[1], fn.Body.List[2], fn.Body.List[4]} {
		additions = append(additions, insertion{file.Offset(statement.End()), d1OwnedBodyComments[i]})
	}
	generated := slices.Clone(source)
	slices.SortFunc(additions, func(a, b insertion) int { return b.offset - a.offset })
	for _, addition := range additions {
		generated = append(generated[:addition.offset], append([]byte(addition.text), generated[addition.offset:]...)...)
	}
	generatedSet, generatedGroups, generatedFn, err := d1Declarations(generated)
	if err != nil {
		return nil, result, err
	}
	originalBody := d1Body(source, set, fn)
	generatedBody := d1Body(generated, generatedSet, generatedFn)
	recovered := slices.Clone(generatedBody)
	for _, comment := range d1OwnedBodyComments {
		if !bytes.Contains(recovered, []byte(comment)) {
			return nil, result, errors.New("owned D1 body annotation missing")
		}
		recovered = bytes.Replace(recovered, []byte(comment), nil, 1)
	}
	result = d1Identity{DeclarationsIdentical: bytes.Equal(structuralAST(fn), structuralAST(generatedFn)) && bytes.Equal(structuralAST(groups[0]), structuralAST(generatedGroups[0])) && bytes.Equal(structuralAST(groups[1]), structuralAST(generatedGroups[1])), BodyRecovered: bytes.Equal(originalBody, recovered), BodyBytesIdentical: bytes.Equal(originalBody, generatedBody), OriginalBody: digest(originalBody), GeneratedBody: digest(generatedBody), OwnedBodyComments: slices.Clone(d1OwnedBodyComments), OwnedResultComments: 2}
	if !result.DeclarationsIdentical || !result.BodyRecovered || result.BodyBytesIdentical {
		return nil, result, errors.New("D1 owned comments failed executable identity or exact body recovery")
	}
	if negative {
		before := []byte("binary.BigEndian.PutUint64(nonce[16:], index)")
		if bytes.Count(generated, before) != 1 {
			return nil, result, errors.New("D1 nonce control site changed")
		}
		generated = bytes.Replace(generated, before, []byte("binary.BigEndian.PutUint64(nonce[16:], index + 1)"), 1)
		generated = bytes.Replace(generated, []byte(d1NoncePost), []byte(d1BytePost), 1)
		generated = bytes.Replace(generated, []byte("//@ requires codec != nil\n"), []byte("//@ requires codec != nil\n//@ requires index == 0\n"), 1)
		negativeSet, _, negativeFn, err := d1Declarations(generated)
		if err != nil {
			return nil, result, err
		}
		body := d1Body(generated, negativeSet, negativeFn)
		restored := bytes.Replace(body, []byte("binary.BigEndian.PutUint64(nonce[16:], index + 1)"), before, 1)
		for _, comment := range d1OwnedBodyComments {
			restored = bytes.Replace(restored, []byte(comment), nil, 1)
		}
		if !bytes.Equal(restored, originalBody) {
			return nil, result, errors.New("D1 control changed more than its reviewed nonce index argument")
		}
		result.BodyRecovered = false
		result.ControlBodyRecovered = true
		result.DeclarationsIdentical = false
		result.GeneratedBody = digest(body)
		result.NegativeMutation = "nonce PutUint64 argument index -> index + 1; control-only index=0 and nonceOut[23]=0 consequence"
		result.PostconditionLine = bytes.Count(generated[:bytes.Index(generated, []byte(d1BytePost))], []byte("\n")) + 1
	}
	return generated, result, nil
}

func d1Rejected(code int, log string, line int) bool {
	lower := strings.ToLower(log)
	return code == 1 && strings.Contains(log, "Gobra found 1 error.") && strings.Contains(log, fmt.Sprintf("</workspace/d1-parameters-wrong-index/parameters.go:%d:9> Postcondition might not hold.", line)) && strings.Contains(log, "Assertion nonceOut[23] == 0 might not hold.") && !strings.Contains(lower, "timeout") && !strings.Contains(lower, "outofmemory") && !strings.Contains(lower, "integer overflow")
}

func writeD1Headers(runDir string, target d1Target) error {
	for relative, source := range map[string][]byte{"stubs/encoding/binary/binary.gobra": target.Header, "stubs/" + credentialPath + "/credential.gobra": []byte("package pcv3credential\ntype D1Profile uint16\n")} {
		path := filepath.Join(runDir, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(path, source, 0644); err != nil {
			return err
		}
	}
	return nil
}

// The frozen all-zero fixture is a control oracle, not a second encoder.
const d1Oracle = `package main
import ("fmt"; "os")
func main() {
 codec := &d1OuterCodec{}
 nonce, iv := codec.recordParameters(0)
 fmt.Printf("nonce=%x iv=%x nonce23=%d\n",nonce,iv,nonce[23])
 if nonce != ([24]byte{}) || iv != ([16]byte{}) { os.Exit(1) }
}
`

func compileD1Oracle(repo, runDir, name string, source []byte) ([]string, error) {
	module := []byte("module Picocrypt-NG/internal/pcv3operation/internal/noncefixture\n\ngo 1.27.3\nrequire Picocrypt-NG v0.0.0\nreplace Picocrypt-NG => " + strconv.Quote(filepath.Join(repo, "src")) + "\n")
	sum, err := os.ReadFile(filepath.Join(repo, "src/go.sum"))
	if err != nil {
		return nil, err
	}
	return compileOracle(repo, runDir, name, "parameters.go", source, []byte(d1Oracle), module, sum)
}

func compileOracle(repo, runDir, name, filename string, source, oracle, module, sum []byte) ([]string, error) {
	directory := filepath.Join(runDir, name+"-native")
	if err := os.MkdirAll(directory, 0755); err != nil {
		return nil, err
	}
	for file, content := range map[string][]byte{"go.mod": module, filename: bytes.Replace(source, []byte("package pcv3"), []byte("package main"), 1), "main.go": oracle, "go.sum": sum} {
		if err := os.WriteFile(filepath.Join(directory, file), content, 0644); err != nil {
			return nil, err
		}
	}

	output := filepath.Join(runDir, name+"-oracle")
	args := []string{"build", "-mod=mod", "-o", output, "."}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", args...)
	command.Dir = directory
	command.Env = append(os.Environ(), "GOPACKAGESDRIVER=off", "GOFLAGS=", "GOWORK=off", "GOENV=off", "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOPROXY=off", "GOSUMDB=off", "GOMAXPROCS=2", "GOCACHE="+filepath.Join(repo, "verification/gobra/_build/go-cache"))
	log, err := command.CombinedOutput()
	if writeErr := os.WriteFile(filepath.Join(runDir, name+"-native-build.log"), log, 0644); writeErr != nil {
		return nil, writeErr
	}
	if err != nil {
		return nil, fmt.Errorf("native control compile: %w: %s", err, log)
	}
	return append([]string{"go"}, args...), nil
}
