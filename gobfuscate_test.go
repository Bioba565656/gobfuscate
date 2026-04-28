package main

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"math/rand"
	"testing"
)

func TestCollectObjectRenamesSkipsMethods(t *testing.T) {
	src := `package p

type I interface{ F() }

type T struct{}

func (T) F() {}

func helper() {}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "input.go", src, 0)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	info := &types.Info{
		Defs:  make(map[*ast.Ident]types.Object),
		Uses:  make(map[*ast.Ident]types.Object),
		Types: make(map[ast.Expr]types.TypeAndValue),
	}
	cfg := &types.Config{Importer: importer.Default(), Error: func(error) {}}
	if _, err := cfg.Check("p", fset, []*ast.File{file}, info); err != nil {
		t.Fatalf("type-check failed: %v", err)
	}

	rng := rand.New(rand.NewSource(1))
	renameByObj, renameByFuncName := collectObjectRenames(file, info, rng)

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		obj, ok := info.Defs[fn.Name].(*types.Func)
		if !ok {
			t.Fatalf("missing function object for %s", fn.Name.Name)
		}
		_, renamed := renameByObj[obj]
		switch fn.Name.Name {
		case "F":
			if !fnHasRecv(fn) {
				t.Fatalf("test setup broken: F expected to be a method")
			}
			if renamed {
				t.Fatalf("method %s should not be renamed", fn.Name.Name)
			}
		case "helper":
			if !renamed {
				t.Fatalf("free function %s should be renamed", fn.Name.Name)
			}
			if _, ok := renameByFuncName[fn.Name.Name]; !ok {
				t.Fatalf("fallback rename missing for function %s", fn.Name.Name)
			}
		}
	}
}

func fnHasRecv(fn *ast.FuncDecl) bool {
	return fn.Recv != nil && len(fn.Recv.List) > 0
}
