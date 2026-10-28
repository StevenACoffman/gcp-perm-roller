package gcpperms

import (
	"encoding/json"
	"fmt"
	"go/token"
	"go/types"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// Wrapper is a function that calls the functions passed to it in a way VTA
// cannot follow, such as by reflection. Under VTA, a call to a wrapper
// counts as calling each function passed in its Params.
type Wrapper struct {
	// Function is the wrapper, as "importpath.Func".
	Function string `json:"function"`
	// Params are the indexes of the parameters whose functions the wrapper
	// calls. Empty means every function argument.
	Params []int `json:"params,omitempty"`
	// Site is where the wrapper is declared.
	Site *Site `json:"site,omitempty"`
	// Calls is how many calls to the wrapper FindWrappers saw.
	Calls int `json:"calls,omitempty"`
	// Reason says how the wrapper calls the functions passed to it.
	Reason string `json:"reason,omitempty"`
}

// WrapperFile is the JSON form of a list of wrappers, as FindWrappers'
// results are saved and LoadWrappers reads them.
type WrapperFile struct {
	Wrappers []Wrapper `json:"wrappers"`
}

// reflectSummary is what a function calls by reflection.
type reflectSummary struct {
	// values are the indexes of reflect.Value parameters the function
	// calls, with how.
	values map[int]string
	// funcs are the indexes of parameters the function makes a
	// reflect.Value of and calls, with how: it is a wrapper of these.
	funcs map[int]string
}

// calledValue is a reflect.Value a call calls, and how.
type calledValue struct {
	value ssa.Value
	how   string
}

// FindWrappers loads cfg.Patterns and returns the functions in them that
// call a function passed as a parameter by reflection: each passes the
// parameter to reflect.ValueOf and, in its own body or a closure it
// creates, calls reflect.Value.Call or CallSlice, or reflect.MakeFunc.
// Wrappers that keep the function in a field or variable before calling it
// are not found; add those to the saved list by hand.
//
// Only the packages the patterns name are loaded from source, so finding
// wrappers in a large module costs far less than analyzing it. cfg.Dir,
// Patterns, and Tags are used.
func FindWrappers(cfg *Config) ([]Wrapper, error) {
	const op = "gcpperms.FindWrappers"
	root, err := filepath.Abs(cfg.Dir)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	pkgs, err := packages.Load(&packages.Config{
		Mode:       packages.LoadSyntax,
		Dir:        cfg.Dir,
		BuildFlags: []string{"-tags=" + strings.Join(cfg.Tags, ",")},
	}, cfg.Patterns...)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	var healthy []*packages.Package
	for _, p := range pkgs {
		if len(p.Errors) == 0 && p.Types != nil {
			healthy = append(healthy, p)
		}
	}
	// Generic functions keep their one generic body, so a wrapper is found
	// once however many instances of it the code uses.
	prog, ssaPkgs := ssautil.Packages(healthy, 0)
	prog.Build()
	return findWrappers(ssaPkgs, root), nil
}

// findWrappers returns the wrappers declared in pkgs, sorted by name, with
// the number of calls to each from pkgs.
func findWrappers(pkgs []*ssa.Package, root string) []Wrapper {
	funcs := declaredFuncs(pkgs)
	sums := summarize(funcs)
	byName := make(map[string]*Wrapper)
	for _, fn := range funcs {
		name := wrapperKey(fn)
		sum := sums[fn]
		if name == "" || len(sum.funcs) == 0 {
			continue
		}
		site := site(fn.Prog.Fset, fn.Pos(), root)
		byName[name] = &Wrapper{
			Function: name,
			Params:   slices.Sorted(maps.Keys(sum.funcs)),
			Site:     &site,
			Reason:   sum.reason(),
		}
	}
	for _, fn := range funcs {
		countWrapperCalls(fn, byName)
	}
	out := make([]Wrapper, 0, len(byName))
	for _, w := range byName {
		out = append(out, *w)
	}
	slices.SortFunc(out, func(a, b Wrapper) int { return strings.Compare(a.Function, b.Function) })
	return out
}

// declaredFuncs returns the functions and methods declared in pkgs, not
// closures or instances, in a stable order.
func declaredFuncs(pkgs []*ssa.Package) []*ssa.Function {
	in := make(map[*ssa.Package]bool, len(pkgs))
	var prog *ssa.Program
	for _, sp := range pkgs {
		if sp != nil {
			in[sp], prog = true, sp.Prog
		}
	}
	if prog == nil {
		return nil
	}
	var funcs []*ssa.Function
	for fn := range ssautil.AllFunctions(prog) {
		if fn.Parent() == nil && in[fn.Pkg] && fn.Origin() == nil {
			funcs = append(funcs, fn)
		}
	}
	slices.SortFunc(
		funcs,
		func(a, b *ssa.Function) int { return strings.Compare(a.String(), b.String()) },
	)
	return funcs
}

// countWrapperCalls counts fn's calls, and its closures', to the wrappers
// in byName.
func countWrapperCalls(fn *ssa.Function, byName map[string]*Wrapper) {
	for _, f := range withClosures(fn) {
		for _, b := range f.Blocks {
			for _, instr := range b.Instrs {
				if call, ok := instr.(ssa.CallInstruction); ok {
					if w := byName[wrapperKey(call.Common().StaticCallee())]; w != nil {
						w.Calls++
					}
				}
			}
		}
	}
}

// reason describes how the wrapper calls its function parameters.
func (s *reflectSummary) reason() string {
	var hows []string
	for _, i := range slices.Sorted(maps.Keys(s.funcs)) {
		if h := s.funcs[i]; !slices.Contains(hows, h) {
			hows = append(hows, h)
		}
	}
	return fmt.Sprintf("passes parameter %s to reflect.ValueOf and calls it %s",
		joinInts(slices.Sorted(maps.Keys(s.funcs))), strings.Join(hows, " and "))
}

// summarize finds what each of funcs calls by reflection. A function calls
// a reflect.Value it calls Call or CallSlice on, or passes to a function
// that calls it; summaries are recomputed until none grows, so calls
// through helpers at any depth are found.
func summarize(funcs []*ssa.Function) map[*ssa.Function]*reflectSummary {
	sums := make(map[*ssa.Function]*reflectSummary, len(funcs))
	for _, fn := range funcs {
		sums[fn] = &reflectSummary{values: map[int]string{}, funcs: map[int]string{}}
	}
	for changed := true; changed; {
		changed = false
		for _, fn := range funcs {
			changed = summarizeOnce(fn, sums) || changed
		}
	}
	return sums
}

// summarizeOnce adds to fn's summary what its calls, and its closures',
// show, and reports whether the summary grew.
func summarizeOnce(fn *ssa.Function, sums map[*ssa.Function]*reflectSummary) bool {
	sum := sums[fn]
	grew := false
	for _, f := range withClosures(fn) {
		for _, b := range f.Blocks {
			for _, instr := range b.Instrs {
				var called []calledValue
				switch x := instr.(type) {
				case ssa.CallInstruction:
					called = calledValues(x, sums)
				case *ssa.MakeClosure:
					called = boundCall(x)
				}
				for _, c := range called {
					grew = sum.add(fn, c.value, c.how) || grew
				}
			}
		}
	}
	return grew
}

// calledValues returns the reflect.Values that call calls: the receiver of
// reflect.Value.Call or CallSlice, or the arguments a summarized callee
// calls.
func calledValues(call ssa.CallInstruction, sums map[*ssa.Function]*reflectSummary) []calledValue {
	common := call.Common()
	callee := common.StaticCallee()
	for _, name := range []string{"Value.Call", "Value.CallSlice"} {
		if isReflect(callee, name) && len(common.Args) > 0 {
			how := "with reflect." + name
			if makeFuncIn(call.Parent()) {
				how += ", in a function built with reflect.MakeFunc"
			}
			return []calledValue{{common.Args[0], how}}
		}
	}
	if callee == nil {
		return nil
	}
	origin := callee
	if o := callee.Origin(); o != nil {
		origin = o
	}
	sum := sums[origin]
	if sum == nil {
		return nil
	}
	var out []calledValue
	for _, j := range slices.Sorted(maps.Keys(sum.values)) {
		if j < len(common.Args) {
			out = append(out, calledValue{common.Args[j], "through " + origin.Name()})
		}
	}
	return out
}

// boundCall returns the reflect.Value whose Call or CallSlice method mc
// binds as a method value, as in next := v.Call, which calls v when next is
// called.
func boundCall(mc *ssa.MakeClosure) []calledValue {
	fn, ok := mc.Fn.(*ssa.Function)
	if !ok || len(mc.Bindings) != 1 {
		return nil
	}
	for _, name := range []string{"Value.Call", "Value.CallSlice"} {
		if isReflect(fn, name) {
			return []calledValue{{mc.Bindings[0], "with reflect." + name + " as a method value"}}
		}
	}
	return nil
}

// makeFuncIn reports whether fn, a closure, or a closure enclosing it, is
// passed to reflect.MakeFunc by the function that creates it.
func makeFuncIn(fn *ssa.Function) bool {
	for f := fn; f.Parent() != nil; f = f.Parent() {
		if passedToMakeFunc(f) {
			return true
		}
	}
	return false
}

// passedToMakeFunc reports whether the closure fn is an argument of a call
// to reflect.MakeFunc in the function that creates it.
func passedToMakeFunc(fn *ssa.Function) bool {
	for _, b := range fn.Parent().Blocks {
		for _, instr := range b.Instrs {
			c, ok := instr.(*ssa.Call)
			if !ok || !isReflect(c.Common().StaticCallee(), "MakeFunc") {
				continue
			}
			if slices.ContainsFunc(c.Call.Args, func(arg ssa.Value) bool {
				mc, ok := arg.(*ssa.MakeClosure)
				return ok && mc.Fn == fn
			}) {
				return true
			}
		}
	}
	return false
}

// add records that fn calls the reflect.Value v, made from one of fn's
// parameters or being one, and reports whether that is new.
func (s *reflectSummary) add(fn *ssa.Function, v ssa.Value, how string) bool {
	grew := false
	for _, src := range sources(v) {
		if i := paramOf(fn, src); i >= 0 {
			grew = record(s.values, i, how) || grew
			continue
		}
		for _, arg := range valueOfArgs(src) {
			if i := paramOf(fn, arg); i >= 0 {
				grew = record(s.funcs, i, how) || grew
			}
		}
	}
	return grew
}

// record sets m[i] to how unless m has i, and reports whether it did.
func record(m map[int]string, i int, how string) bool {
	if _, ok := m[i]; ok {
		return false
	}
	m[i] = how
	return true
}

// valueOfArgs returns what v may have been made from when v is a call of
// reflect.ValueOf, and nothing otherwise.
func valueOfArgs(v ssa.Value) []ssa.Value {
	call, ok := v.(*ssa.Call)
	if !ok || !isReflect(call.Common().StaticCallee(), "ValueOf") || len(call.Call.Args) != 1 {
		return nil
	}
	return sources(call.Call.Args[0])
}

// paramOf is the index of the parameter of fn that v is, or -1.
func paramOf(fn *ssa.Function, v ssa.Value) int {
	if p, ok := v.(*ssa.Parameter); ok && p.Parent() == fn {
		return slices.Index(fn.Params, p)
	}
	return -1
}

// sources returns the values v may come from, seen through conversions, the
// variables a closure captures, and loads of local variables.
func sources(v ssa.Value) []ssa.Value {
	var out []ssa.Value
	seen := make(map[ssa.Value]bool)
	stack := []ssa.Value{v}
	for len(stack) > 0 {
		v := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if v == nil || seen[v] {
			continue
		}
		seen[v] = true
		if from, ok := comesFrom(v); ok {
			stack = append(stack, from...)
		} else {
			out = append(out, v)
		}
	}
	return out
}

// comesFrom returns the values v is taken from, and false when v is a
// source itself.
func comesFrom(v ssa.Value) ([]ssa.Value, bool) {
	switch x := v.(type) {
	case *ssa.MakeInterface:
		return []ssa.Value{x.X}, true
	case *ssa.ChangeType:
		return []ssa.Value{x.X}, true
	case *ssa.Phi:
		return x.Edges, true
	case *ssa.FreeVar:
		return closureBindings(x), true
	case *ssa.UnOp:
		if x.Op == token.MUL {
			return storedTo(x.X), true
		}
	}
	return nil, false
}

// closureBindings returns the values bound to the free variable fv where
// its closure is created.
func closureBindings(fv *ssa.FreeVar) []ssa.Value {
	closure := fv.Parent()
	parent := closure.Parent()
	i := slices.Index(closure.FreeVars, fv)
	if parent == nil || i < 0 {
		return nil
	}
	var out []ssa.Value
	for _, b := range parent.Blocks {
		for _, instr := range b.Instrs {
			if mc, ok := instr.(*ssa.MakeClosure); ok && mc.Fn == closure {
				out = append(out, mc.Bindings[i])
			}
		}
	}
	return out
}

// storedTo returns the values stored to the variable that ptr points to,
// when ptr is a local variable or one captured from the enclosing function.
func storedTo(ptr ssa.Value) []ssa.Value {
	var allocs []ssa.Value
	for _, p := range sources(ptr) {
		if a, ok := p.(*ssa.Alloc); ok {
			allocs = append(allocs, a)
		}
	}
	var out []ssa.Value
	for _, a := range allocs {
		for _, ref := range *a.Referrers() {
			if st, ok := ref.(*ssa.Store); ok && st.Addr == a {
				out = append(out, st.Val)
			}
		}
	}
	return out
}

// withClosures returns fn and the closures it creates, transitively.
func withClosures(fn *ssa.Function) []*ssa.Function {
	out := []*ssa.Function{fn}
	for i := 0; i < len(out); i++ {
		out = append(out, out[i].AnonFuncs...)
	}
	return out
}

// isReflect reports whether fn is the function or method name ("Func" or
// "Type.Method") of package reflect.
func isReflect(fn *ssa.Function, name string) bool {
	if fn == nil {
		return false
	}
	obj, ok := fn.Object().(*types.Func)
	if !ok || obj.Pkg() == nil || obj.Pkg().Path() != "reflect" {
		return false
	}
	got := obj.Name()
	if named, ok := receiverNamed(obj); ok {
		got = named.Obj().Name() + "." + got
	}
	return got == name
}

// receiverNamed returns the named type of obj's receiver, if it has one.
func receiverNamed(obj *types.Func) (*types.Named, bool) {
	recv := obj.Signature().Recv()
	if recv == nil {
		return nil, false
	}
	t := recv.Type()
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	return named, ok
}

func joinInts(ns []int) string {
	s := make([]string, len(ns))
	for i, n := range ns {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ", ")
}

// LoadWrappers reads wrappers saved as a WrapperFile.
func LoadWrappers(path string) ([]Wrapper, error) {
	var f WrapperFile
	if err := readJSONFile(path, &f); err != nil {
		return nil, errors.Wrap(err, "gcpperms.LoadWrappers")
	}
	for _, w := range f.Wrappers {
		if w.Function == "" {
			return nil, errors.Errorf("gcpperms.LoadWrappers: %s: a wrapper has no function", path)
		}
	}
	return f.Wrappers, nil
}

// WriteWrappers writes wrappers to w as an indented WrapperFile.
func WriteWrappers(w io.Writer, wrappers []Wrapper) error {
	if wrappers == nil {
		wrappers = []Wrapper{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return errors.Wrap(enc.Encode(WrapperFile{Wrappers: wrappers}), "gcpperms.WriteWrappers")
}
