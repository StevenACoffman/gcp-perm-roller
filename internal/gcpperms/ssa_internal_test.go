package gcpperms

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// fakeSDK is a stand-in Google Cloud package. Its import path makes isSDK
// treat it as SDK code; building it in memory keeps these tests fast.
const fakeSDK = `package fake

type Client struct{}

func New() *Client               { return &Client{} }
func (c *Client) Get() error     { return nil }
func (c *Client) Other() error   { return nil }
func (c *Client) Closure() func() { return func() {} }

type Iface interface{ M() }

// Anon has an anonymous interface type.
var Anon interface{ N() }

type Gen[T any] struct{}

func (Gen[T]) Do()  {}
func Generic[T any]() {}
`

// fakeApp is first-party code using fakeSDK in each way the analyzer must
// recognize.
const fakeApp = `package app

import "cloud.google.com/go/fake"

func Use(c *fake.Client, i fake.Iface) {
	_ = fake.New()
	sink(c.Get)              // bound method value
	sink((*fake.Client).Get) // method expression thunk
	sink(fake.Iface.M)       // interface method thunk
	sink(fake.Anon.N)        // anonymous interface method value
	sink(error.Error)        // universe method thunk
	fake.Generic[int]()
	fake.Gen[string]{}.Do()
	func() { _ = c.Get() }()
}

func Gen[T any](c *fake.Client) {
	func() { _ = c.Get() }()
}

var Instance = Gen[int]

func sink(any) {}
`

// fakeCmd is a first-party binary. It converts wrapper to an interface but
// only ever calls Used, so Unused, and its call to Client.Other, are
// reachable only if reflection could call wrapper's methods.
const fakeCmd = `package main

import "cloud.google.com/go/fake"

type wrapper struct{ c *fake.Client }

func (w wrapper) Used() error   { return w.c.Get() }
func (w wrapper) Unused() error { return w.c.Other() }

type user interface{ Used() error }

func main() {
	var u user = wrapper{c: fake.New()}
	_ = u.Used()
}
`

// fakeCached calls the SDK only from fetch, which it reaches only through
// cache: like a memoizing wrapper, cache calls its argument by reflection,
// which VTA does not follow.
const fakeCached = `package main

import (
	"reflect"

	"cloud.google.com/go/fake"
)

func cache[T any](f T) T {
	v := reflect.ValueOf(f)
	return reflect.MakeFunc(v.Type(), func(args []reflect.Value) []reflect.Value {
		return v.Call(args)
	}).Interface().(T)
}

func fetch() error { return fake.New().Get() }

var cachedFetch = cache(fetch)

func main() { _ = cachedFetch() }
`

// fakeConv converts functions and methods in ways funcValue must see
// through, and has a method named like a function, which wrapperKey must not
// confuse with it.
const fakeConv = `package conv

type F func() error

type T struct{}

func (T) cache(f func() error) {}

func cache(f func() error) {}

func g() error { return nil }

func Use() {
	sink(F(g))
	T{}.cache(g)
	cache(g)
}

func sink(any) {}
`

// mapImporter resolves the in-memory packages in pkgs, and every other
// import through fallback.
type mapImporter struct {
	fallback types.Importer
	pkgs     map[string]*types.Package
}

// buildFake type-checks and builds fakeSDK, fakeApp, and fakeCmd as SSA.
func buildFake(t *testing.T) (*ssa.Program, *ssa.Package, *ssa.Package) {
	t.Helper()
	prog, sdk, app, _ := buildFakeWithCmd(t)
	return prog, sdk, app
}

func buildFakeWithCmd(t *testing.T) (*ssa.Program, *ssa.Package, *ssa.Package, *ssa.Package) {
	t.Helper()
	prog, pkgs := buildSSA(t,
		[2]string{"cloud.google.com/go/fake", fakeSDK},
		[2]string{"example.com/app", fakeApp},
		[2]string{"example.com/cmd", fakeCmd},
	)
	return prog, pkgs[0], pkgs[1], pkgs[2]
}

// buildSSA type-checks and builds each package, given as its import path
// and source, in order, so later ones may import earlier ones.
func buildSSA(t *testing.T, srcs ...[2]string) (*ssa.Program, []*ssa.Package) {
	t.Helper()
	fset := token.NewFileSet()
	prog := ssa.NewProgram(fset, ssa.InstantiateGenerics)
	imp := &mapImporter{fallback: importer.Default(), pkgs: make(map[string]*types.Package)}
	build := func(path, src string) *ssa.Package {
		f, err := parser.ParseFile(fset, path+".go", src, 0)
		ok(t, err)
		info := &types.Info{
			Types:        make(map[ast.Expr]types.TypeAndValue),
			Defs:         make(map[*ast.Ident]types.Object),
			Uses:         make(map[*ast.Ident]types.Object),
			Implicits:    make(map[ast.Node]types.Object),
			Instances:    make(map[*ast.Ident]types.Instance),
			Scopes:       make(map[ast.Node]*types.Scope),
			Selections:   make(map[*ast.SelectorExpr]*types.Selection),
			FileVersions: make(map[*ast.File]string),
		}
		pkg, err := (&types.Config{Importer: imp}).Check(path, fset, []*ast.File{f}, info)
		ok(t, err)
		imp.pkgs[path] = pkg
		for _, dep := range pkg.Imports() {
			if prog.Package(dep) == nil {
				prog.CreatePackage(dep, nil, nil, true)
			}
		}
		return prog.CreatePackage(pkg, []*ast.File{f}, info, false)
	}
	pkgs := make([]*ssa.Package, len(srcs))
	for i, src := range srcs {
		pkgs[i] = build(src[0], src[1])
	}
	prog.Build()
	return prog, pkgs
}

func (m *mapImporter) Import(path string) (*types.Package, error) {
	if p, ok := m.pkgs[path]; ok {
		return p, nil
	}
	return m.fallback.Import(path)
}

// operands returns the API names apiName gives the functions referenced in
// fn and its closures, and the number it rejects.
func operands(fn *ssa.Function) (names []string, rejected int) {
	fns := append([]*ssa.Function{fn}, fn.AnonFuncs...)
	for _, f := range fns {
		for _, b := range f.Blocks {
			for _, instr := range b.Instrs {
				for _, op := range instr.Operands(nil) {
					callee, isFn := (*op).(*ssa.Function)
					if !isFn {
						continue
					}
					if name, found := apiName(callee); found {
						names = append(names, name)
					} else {
						rejected++
					}
				}
			}
		}
	}
	return names, rejected
}

func TestAPIName(t *testing.T) {
	_, sdk, app := buildFake(t)
	const p = "cloud.google.com/go/fake."
	names, _ := operands(app.Func("Use"))
	equals(t, names, []string{
		p + "New",
		p + "Client.Get", // $bound wrapper
		p + "Client.Get", // $thunk wrapper
		p + "Iface.M",
		// fake.Anon.N and error.Error are rejected.
		p + "Generic", // instance, named by its origin
		p + "Gen.Do",  // method of an instantiated type
		p + "Client.Get",
	})

	tests := map[string]struct {
		fn *ssa.Function
	}{
		"closure in SDK code": {
			fn: sdk.Prog.FuncValue(lookupMethod(t, sdk, "Client", "Closure")).AnonFuncs[0],
		},
		"first-party function":        {fn: app.Func("Use")},
		"first-party closure":         {fn: app.Func("Use").AnonFuncs[0]},
		"anonymous interface method":  {fn: findOperand(t, app.Func("Use"), "N")},
		"universe error.Error method": {fn: findOperand(t, app.Func("Use"), "Error")},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got, found := apiName(tc.fn); found {
				t.Fatalf("apiName(%s) = %q, want no API name", tc.fn, got)
			}
		})
	}
}

func lookupMethod(t *testing.T, pkg *ssa.Package, typ, method string) *types.Func {
	t.Helper()
	obj, _, _ := types.LookupFieldOrMethod(
		types.NewPointer(pkg.Pkg.Scope().Lookup(typ).Type()), true, pkg.Pkg, method)
	f, isFunc := obj.(*types.Func)
	if !isFunc {
		t.Fatalf("no method %s.%s", typ, method)
	}
	return f
}

// findOperand returns the function referenced in fn whose object is named name.
func findOperand(t *testing.T, fn *ssa.Function, name string) *ssa.Function {
	t.Helper()
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			for _, op := range instr.Operands(nil) {
				if f, isFn := (*op).(*ssa.Function); isFn && f.Object() != nil &&
					f.Object().Name() == name {
					return f
				}
			}
		}
	}
	t.Fatalf("%s references no function named %s", fn, name)
	return nil
}

func TestPkgPath(t *testing.T) {
	prog, sdk, app := buildFake(t)
	instance := findOperand(t, app.Func("init"), "Gen") // Gen[int]
	tests := map[string]struct {
		fn   *ssa.Function
		want string
	}{
		"declared function": {fn: app.Func("Use"), want: "example.com/app"},
		"closure": {
			fn:   app.Func("Use").AnonFuncs[0],
			want: "example.com/app",
		},
		"package initializer": {fn: app.Func("init"), want: "example.com/app"},
		"generic instance":    {fn: instance, want: "example.com/app"},
		"closure in a generic instance": {
			fn:   instance.AnonFuncs[0],
			want: "example.com/app",
		},
		"SDK method": {
			fn:   prog.FuncValue(lookupMethod(t, sdk, "Client", "Get")),
			want: "cloud.google.com/go/fake",
		},
		"synthetic wrapper has no owner": {
			fn:   findOperand(t, app.Func("Use"), "Get"),
			want: "",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			equals(t, pkgPath(tc.fn), tc.want)
		})
	}
}

func TestSite(t *testing.T) {
	prog, _, app := buildFake(t)
	a := analyzer{prog: prog, root: "/elsewhere"}
	use := app.Func("Use")
	// Instructions without a position fall back to their function's.
	equals(t, a.site(token.NoPos, use), Site{File: "example.com/app.go", Line: 5})
}

func TestBinaryAlgorithms(t *testing.T) {
	prog, _, _, cmd := buildFakeWithCmd(t)
	const p = "cloud.google.com/go/fake."
	tests := map[string]struct {
		algo Algorithm
		want []string
	}{
		// spec: RTA assumes reflection may call every exported method of a
		// type converted to an interface, so it reaches Unused.
		"RTA reports methods only reflection could call": {
			algo: RTA,
			want: []string{p + "Client.Get", p + "Client.Other", p + "New"},
		},
		// spec: VTA follows only the calls that are made.
		"VTA reports only the methods that are called": {
			algo: VTA,
			want: []string{p + "Client.Get", p + "New"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			a := analyzer{
				prog:       prog,
				firstParty: map[string]bool{"example.com/cmd": true},
				algo:       tc.algo,
			}
			bin := a.binary(cmd)
			equals(t, bin.Package, "example.com/cmd")
			var got []string
			for _, c := range bin.Calls {
				got = append(got, c.API)
			}
			equals(t, got, tc.want)
		})
	}
}

func TestBinaryWrappers(t *testing.T) {
	prog, pkgs := buildSSA(t,
		[2]string{"cloud.google.com/go/fake", fakeSDK},
		[2]string{"example.com/cached", fakeCached},
	)
	const p = "cloud.google.com/go/fake."
	tests := map[string]struct {
		algo     Algorithm
		wrappers []Wrapper
		want     []string
	}{
		// spec: VTA does not follow cache's reflective call, so it misses
		// what fetch calls.
		"VTA misses calls made by reflection": {algo: VTA},
		// spec: naming cache as a wrapper makes the functions passed to it
		// count as called.
		"VTA with the wrapper named": {
			algo:     VTA,
			wrappers: []Wrapper{{Function: "example.com/cached.cache"}},
			want:     []string{p + "Client.Get", p + "New"},
		},
		"VTA with the wrapper's parameter": {
			algo:     VTA,
			wrappers: []Wrapper{{Function: "example.com/cached.cache", Params: []int{0}}},
			want:     []string{p + "Client.Get", p + "New"},
		},
		// spec: only the listed parameters' functions count as called.
		"VTA with another parameter": {
			algo:     VTA,
			wrappers: []Wrapper{{Function: "example.com/cached.cache", Params: []int{1}}},
		},
		"another function named does nothing": {
			algo: VTA,
			wrappers: []Wrapper{
				{Function: "example.com/cached.fetch"}, {Function: "example.com/other.cache"},
			},
		},
		// spec: RTA already assumes address-taken functions are called.
		"RTA needs no wrappers": {algo: RTA, want: []string{p + "Client.Get", p + "New"}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			a := analyzer{
				prog:       prog,
				firstParty: map[string]bool{"example.com/cached": true},
				algo:       tc.algo,
				wrappers:   tc.wrappers,
			}
			var got []string
			for _, c := range a.binary(pkgs[1]).Calls {
				got = append(got, c.API)
			}
			equals(t, got, tc.want)
		})
	}
}

func TestWrapperKey(t *testing.T) {
	// fakeApp instantiates fake.Generic.
	prog, pkgs := buildSSA(t,
		[2]string{"cloud.google.com/go/fake", fakeSDK},
		[2]string{"example.com/app", fakeApp},
		[2]string{"example.com/conv", fakeConv},
	)
	sdk, conv := pkgs[0], pkgs[2]
	var generic *ssa.Function
	for fn := range ssautil.AllFunctions(prog) {
		if fn.Origin() == sdk.Func("Generic") {
			generic = fn
		}
	}
	if generic == nil {
		t.Fatal("no instance of fake.Generic")
	}
	method := prog.FuncValue(lookupMethod(t, conv, "T", "cache"))
	tests := map[string]struct {
		fn   *ssa.Function
		want string
	}{
		"a named function": {fn: conv.Func("cache"), want: "example.com/conv.cache"},
		"an instance of a generic function": {
			fn: generic, want: "cloud.google.com/go/fake.Generic",
		},
		// spec: a method is never a wrapper, even one named like it.
		"a method with the wrapper's name": {fn: method},
		"no function":                      {},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			equals(t, wrapperKey(tc.fn), tc.want)
		})
	}
	// spec: a synthetic function, which belongs to no package, is no wrapper
	// and does not stop the search.
	for fn := range ssautil.AllFunctions(prog) {
		if fn.Pkg == nil && fn.Origin() == nil {
			equals(t, wrapperKey(fn), "")
			return
		}
	}
	t.Fatal("no synthetic function in the program")
}

func TestFuncValue(t *testing.T) {
	_, _, app := buildFake(t)
	use := app.Func("Use")
	var closures, bound int
	for _, b := range use.Blocks {
		for _, instr := range b.Instrs {
			v, ok := instr.(ssa.Value)
			if !ok {
				continue
			}
			fn := funcValue(v)
			switch v.(type) {
			case *ssa.MakeClosure:
				// spec: a closure or bound method value refers to its function.
				if fn == nil {
					t.Errorf("no function for %s", v.Name())
				}
				closures++
			case *ssa.MakeInterface:
				if fn != nil {
					bound++
				}
			}
		}
	}
	if closures == 0 || bound == 0 {
		t.Fatalf("closures %d, functions through interfaces %d; want both", closures, bound)
	}
	// spec: other values refer to no function.
	equals(t, funcValue(ssa.NewConst(nil, types.Typ[types.Int])) == nil, true)

	// spec: a function converted to a named function type, then to an
	// interface, still refers to the function.
	_, pkgs := buildSSA(t,
		[2]string{"cloud.google.com/go/fake", fakeSDK},
		[2]string{"example.com/conv", fakeConv},
	)
	conv := pkgs[1]
	var found bool
	for _, b := range conv.Func("Use").Blocks {
		for _, instr := range b.Instrs {
			if mi, ok := instr.(*ssa.MakeInterface); ok {
				if _, converted := mi.X.(*ssa.ChangeType); converted {
					equals(t, funcValue(mi), conv.Func("g"))
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("no converted function in conv.Use")
	}
}

func TestReachableFrom(t *testing.T) {
	_, _, _, cmd := buildFakeWithCmd(t)
	main, init := cmd.Func("main"), cmd.Func("init")
	g, _ := buildCallGraph([]*ssa.Function{main, init}, VTA, nil)
	got := reachableFrom(g, []*ssa.Function{main, init})
	// spec: roots are reachable even with no edges, and so is everything
	// main calls, transitively.
	for _, fn := range []*ssa.Function{main, init} {
		if !got[fn] {
			t.Errorf("root %s not reachable", fn)
		}
	}
	names := make(map[string]bool)
	for fn := range got {
		names[fn.String()] = true
	}
	for _, want := range []string{
		"(example.com/cmd.wrapper).Used",
		"(*cloud.google.com/go/fake.Client).Get",
	} {
		if !names[want] {
			t.Errorf("%s not reachable from main; got %v", want, names)
		}
	}
	if names["(example.com/cmd.wrapper).Unused"] {
		t.Errorf("Unused is reachable, but nothing calls it")
	}
}
