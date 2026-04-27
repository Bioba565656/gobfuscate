package main

import (
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"math/rand"
	"os"
	"strconv"
	"time"
)

func main() {
	in := flag.String("in", "", "fichier .go d'entrée")
	out := flag.String("out", "", "fichier .go de sortie")
	seed := flag.Int64("seed", 0, "seed optionnelle pour rendre l'obfuscation reproductible")
	flag.Parse()

	if *in == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: go run gobfuscate.go -in input.go -out output.go [-seed 123]")
		os.Exit(2)
	}

	s := *seed
	if s == 0 {
		s = time.Now().UnixNano()
	}
	rng := rand.New(rand.NewSource(s))

	if err := obfuscateFile(*in, *out, rng); err != nil {
		fmt.Fprintf(os.Stderr, "erreur: %v\n", err)
		os.Exit(1)
	}
}

func obfuscateFile(input, output string, rng *rand.Rand) error {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, input, nil, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	info := &types.Info{
		Defs:  make(map[*ast.Ident]types.Object),
		Uses:  make(map[*ast.Ident]types.Object),
		Types: make(map[ast.Expr]types.TypeAndValue),
	}
	cfg := &types.Config{Importer: importer.Default(), Error: func(error) {}}
	pkgName := file.Name.Name
	if pkgName == "" {
		pkgName = "main"
	}
	_, _ = cfg.Check(pkgName, fset, []*ast.File{file}, info)

	renameByObj := collectObjectRenames(file, info, rng)
	applyObjectRenames(file, info, renameByObj)

	parents := buildParents(file)
	decoderName := "__gobfDec_" + randomHex(rng, 4)
	stringChanged := obfuscateStrings(file, parents, decoderName, rng)
	obfuscateFunctionBodies(file, rng)

	if stringChanged {
		hexIdent := ensureHexImport(file)
		ensureDecoderHelper(file, decoderName, hexIdent)
	}

	outFile, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer outFile.Close()

	if err := format.Node(outFile, fset, file); err != nil {
		return fmt.Errorf("format output: %w", err)
	}
	return nil
}

func collectObjectRenames(file *ast.File, info *types.Info, rng *rand.Rand) map[types.Object]string {
	renameByObj := map[types.Object]string{}

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Recv == nil {
			if obj, ok := info.Defs[fn.Name].(*types.Func); ok {
				name := fn.Name.Name
				if name != "main" && name != "init" && !ast.IsExported(name) {
					renameByObj[obj] = "_f" + randomHex(rng, 6)
				}
			}
		}

		ast.Inspect(fn, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			obj := info.Defs[id]
			if obj == nil {
				return true
			}
			if id.Name == "_" {
				return true
			}
			v, ok := obj.(*types.Var)
			if !ok {
				return true
			}
			if v.Pkg() == nil {
				renameByObj[obj] = "_v" + randomHex(rng, 6)
			}
			return true
		})
	}

	return renameByObj
}

func applyObjectRenames(file *ast.File, info *types.Info, renameByObj map[types.Object]string) {
	ast.Inspect(file, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		if obj := info.Defs[id]; obj != nil {
			if newName, ok := renameByObj[obj]; ok {
				id.Name = newName
			}
			return true
		}
		if obj := info.Uses[id]; obj != nil {
			if newName, ok := renameByObj[obj]; ok {
				id.Name = newName
			}
		}
		return true
	})
}

func obfuscateStrings(file *ast.File, parents map[ast.Node]ast.Node, decoderName string, rng *rand.Rand) bool {
	changed := false

	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if shouldSkipStringLiteral(n, parents) {
			return true
		}

		value, err := strconv.Unquote(lit.Value)
		if err != nil || value == "" {
			return true
		}

		k := byte(rng.Intn(255) + 1)
		buf := make([]byte, len(value))
		for i := range buf {
			buf[i] = value[i] ^ k
		}

		hexLit := &ast.BasicLit{Kind: token.STRING, Value: strconv.Quote(hex.EncodeToString(buf))}
		keyLit := &ast.BasicLit{Kind: token.INT, Value: strconv.Itoa(int(k))}
		call := &ast.CallExpr{Fun: ast.NewIdent(decoderName), Args: []ast.Expr{hexLit, keyLit}}

		if replaceExprInParent(lit, call, parents) {
			changed = true
		}
		return true
	})

	return changed
}

func shouldSkipStringLiteral(n ast.Node, parents map[ast.Node]ast.Node) bool {
	p := parents[n]
	switch pp := p.(type) {
	case *ast.ImportSpec:
		return true
	case *ast.Field:
		if pp.Tag == n {
			return true
		}
	case *ast.CaseClause:
		return true
	}

	for cur := n; cur != nil; cur = parents[cur] {
		if at, ok := parents[cur].(*ast.ArrayType); ok && at.Len == cur {
			return true
		}
		if vs, ok := parents[cur].(*ast.ValueSpec); ok {
			if gd, ok := parents[vs].(*ast.GenDecl); ok && gd.Tok == token.CONST {
				return true
			}
		}
	}
	return false
}

func replaceExprInParent(old ast.Expr, newExpr ast.Expr, parents map[ast.Node]ast.Node) bool {
	p := parents[old]
	switch pp := p.(type) {
	case *ast.AssignStmt:
		for i, e := range pp.Rhs {
			if e == old {
				pp.Rhs[i] = newExpr
				return true
			}
		}
	case *ast.BinaryExpr:
		if pp.X == old {
			pp.X = newExpr
			return true
		}
		if pp.Y == old {
			pp.Y = newExpr
			return true
		}
	case *ast.CallExpr:
		for i, e := range pp.Args {
			if e == old {
				pp.Args[i] = newExpr
				return true
			}
		}
	case *ast.ReturnStmt:
		for i, e := range pp.Results {
			if e == old {
				pp.Results[i] = newExpr
				return true
			}
		}
	case *ast.ExprStmt:
		if pp.X == old {
			pp.X = newExpr
			return true
		}
	case *ast.IfStmt:
		if pp.Cond == old {
			pp.Cond = newExpr
			return true
		}
	case *ast.ValueSpec:
		for i, e := range pp.Values {
			if e == old {
				pp.Values[i] = newExpr
				return true
			}
		}
	case *ast.CompositeLit:
		for i, e := range pp.Elts {
			if ee, ok := e.(ast.Expr); ok && ee == old {
				pp.Elts[i] = newExpr
				return true
			}
		}
	case *ast.KeyValueExpr:
		if pp.Key == old {
			pp.Key = newExpr
			return true
		}
		if pp.Value == old {
			pp.Value = newExpr
			return true
		}
	case *ast.IndexExpr:
		if pp.Index == old {
			pp.Index = newExpr
			return true
		}
	case *ast.SliceExpr:
		if pp.Low == old {
			pp.Low = newExpr
			return true
		}
		if pp.High == old {
			pp.High = newExpr
			return true
		}
		if pp.Max == old {
			pp.Max = newExpr
			return true
		}
	case *ast.UnaryExpr:
		if pp.X == old {
			pp.X = newExpr
			return true
		}
	case *ast.ParenExpr:
		if pp.X == old {
			pp.X = newExpr
			return true
		}
	case *ast.ArrayType:
		if pp.Len == old {
			pp.Len = newExpr
			return true
		}
	case *ast.MapType:
		if pp.Key == old {
			pp.Key = newExpr
			return true
		}
		if pp.Value == old {
			pp.Value = newExpr
			return true
		}
	}
	return false
}

func obfuscateFunctionBodies(file *ast.File, rng *rand.Rand) {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}

		tmp := "_g" + randomHex(rng, 5)
		a := rng.Intn(9000) + 1000
		b := rng.Intn(9000) + 1000

		noise := []ast.Stmt{
			&ast.AssignStmt{Lhs: []ast.Expr{ast.NewIdent(tmp)}, Tok: token.DEFINE, Rhs: []ast.Expr{&ast.BinaryExpr{X: &ast.BasicLit{Kind: token.INT, Value: strconv.Itoa(a)}, Op: token.XOR, Y: &ast.BasicLit{Kind: token.INT, Value: strconv.Itoa(b)}}}},
			&ast.IfStmt{
				Cond: &ast.BinaryExpr{
					X: &ast.BinaryExpr{
						X:  &ast.BinaryExpr{X: ast.NewIdent(tmp), Op: token.MUL, Y: &ast.ParenExpr{X: &ast.BinaryExpr{X: ast.NewIdent(tmp), Op: token.ADD, Y: &ast.BasicLit{Kind: token.INT, Value: "1"}}}},
						Op: token.REM,
						Y:  &ast.BasicLit{Kind: token.INT, Value: "2"},
					},
					Op: token.NEQ,
					Y:  &ast.BasicLit{Kind: token.INT, Value: "0"},
				},
				Body: &ast.BlockStmt{List: []ast.Stmt{
					&ast.ExprStmt{X: &ast.CallExpr{Fun: ast.NewIdent("panic"), Args: []ast.Expr{&ast.BasicLit{Kind: token.STRING, Value: strconv.Quote("gobf unreachable")}}}},
				}},
			},
		}
		fn.Body.List = append(noise, fn.Body.List...)
	}
}

func ensureHexImport(file *ast.File) string {
	const path = "encoding/hex"
	for _, im := range file.Imports {
		if im.Path != nil && im.Path.Value == strconv.Quote(path) {
			if im.Name == nil {
				return "hex"
			}
			if im.Name.Name != "_" && im.Name.Name != "." {
				return im.Name.Name
			}
			break
		}
	}

	newSpec := &ast.ImportSpec{Path: &ast.BasicLit{Kind: token.STRING, Value: strconv.Quote(path)}}
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.IMPORT {
			continue
		}
		gd.Specs = append(gd.Specs, newSpec)
		file.Imports = append(file.Imports, newSpec)
		return "hex"
	}

	gd := &ast.GenDecl{Tok: token.IMPORT, Specs: []ast.Spec{newSpec}}
	file.Decls = append([]ast.Decl{gd}, file.Decls...)
	file.Imports = append(file.Imports, newSpec)
	return "hex"
}

func ensureDecoderHelper(file *ast.File, name, hexIdent string) {
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return
		}
	}

	helper := &ast.FuncDecl{
		Name: ast.NewIdent(name),
		Type: &ast.FuncType{
			Params: &ast.FieldList{List: []*ast.Field{
				{Names: []*ast.Ident{ast.NewIdent("enc")}, Type: ast.NewIdent("string")},
				{Names: []*ast.Ident{ast.NewIdent("key")}, Type: ast.NewIdent("byte")},
			}},
			Results: &ast.FieldList{List: []*ast.Field{{Type: ast.NewIdent("string")}}},
		},
		Body: &ast.BlockStmt{List: []ast.Stmt{
			&ast.AssignStmt{Lhs: []ast.Expr{ast.NewIdent("b"), ast.NewIdent("err")}, Tok: token.DEFINE, Rhs: []ast.Expr{&ast.CallExpr{Fun: &ast.SelectorExpr{X: ast.NewIdent(hexIdent), Sel: ast.NewIdent("DecodeString")}, Args: []ast.Expr{ast.NewIdent("enc")}}}},
			&ast.IfStmt{Cond: &ast.BinaryExpr{X: ast.NewIdent("err"), Op: token.NEQ, Y: ast.NewIdent("nil")}, Body: &ast.BlockStmt{List: []ast.Stmt{&ast.ReturnStmt{Results: []ast.Expr{&ast.BasicLit{Kind: token.STRING, Value: strconv.Quote("")}}}}}},
			&ast.RangeStmt{Key: ast.NewIdent("i"), Tok: token.DEFINE, X: ast.NewIdent("b"), Body: &ast.BlockStmt{List: []ast.Stmt{&ast.AssignStmt{Lhs: []ast.Expr{&ast.IndexExpr{X: ast.NewIdent("b"), Index: ast.NewIdent("i")}}, Tok: token.XOR_ASSIGN, Rhs: []ast.Expr{ast.NewIdent("key")}}}}},
			&ast.ReturnStmt{Results: []ast.Expr{&ast.CallExpr{Fun: ast.NewIdent("string"), Args: []ast.Expr{ast.NewIdent("b")}}}},
		}},
	}

	file.Decls = append(file.Decls, helper)
}

func buildParents(root ast.Node) map[ast.Node]ast.Node {
	parents := map[ast.Node]ast.Node{}
	var stack []ast.Node
	ast.Inspect(root, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if len(stack) > 0 {
			parents[n] = stack[len(stack)-1]
		}
		stack = append(stack, n)
		return true
	})
	return parents
}

func randomHex(rng *rand.Rand, nBytes int) string {
	buf := make([]byte, nBytes)
	for i := range buf {
		buf[i] = byte(rng.Intn(256))
	}
	h := sha1.Sum(buf)
	return hex.EncodeToString(h[:nBytes])
}
