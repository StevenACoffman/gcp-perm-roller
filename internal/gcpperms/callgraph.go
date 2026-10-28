package gcpperms

import (
	"slices"

	"github.com/cockroachdb/errors"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/ssa"
)

const (
	// VTA refines the RTA call graph with Variable Type Analysis, which
	// tracks the types that flow to each dynamic call site, then recomputes
	// reachability over the refined graph. Unlike RTA, it does not assume
	// that reflection may call every exported method of a type converted
	// to an interface, so wrapper methods a program never calls drop out.
	// It is the default.
	VTA Algorithm = "vta"
	// RTA uses Rapid Type Analysis alone. It is several times faster, but
	// it assumes reflection may call any exported method of a type that is
	// converted to an interface, and any address-taken function, so it
	// reports calls that only such reflection could make.
	RTA Algorithm = "rta"
)

// Algorithm selects how call graphs, and so reachability, are computed.
type Algorithm string

// ParseAlgorithm returns the algorithm named s. The empty string means VTA.
func ParseAlgorithm(s string) (Algorithm, error) {
	switch a := Algorithm(s); a {
	case "":
		return VTA, nil
	case VTA, RTA:
		return a, nil
	default:
		return "", errors.Errorf("unknown call graph algorithm %q (want vta or rta)", s)
	}
}

// buildCallGraph returns the call graph of the program rooted at roots and
// the set of functions reachable from them.
//
// RTA always runs first: its reachable functions are the code VTA analyzes,
// and its call graph is VTA's initial graph. VTA only removes edges from
// the initial graph, so its result is never less precise than RTA's.
//
// wrappers are functions that call their function arguments in a way VTA
// cannot follow, such as by reflection. Each call to one gains an edge from
// the caller to every function passed in the wrapper's Params. RTA already
// assumes such calls, so wrappers matter only to VTA.
func buildCallGraph(
	roots []*ssa.Function,
	algo Algorithm,
	wrappers []Wrapper,
) (*callgraph.Graph, map[*ssa.Function]bool) {
	res := rta.Analyze(roots, true)
	funcs := make(map[*ssa.Function]bool, len(res.Reachable))
	for fn := range res.Reachable {
		funcs[fn] = true
	}
	if algo == RTA {
		return res.CallGraph, funcs
	}
	g := vta.CallGraph(funcs, res.CallGraph)
	addWrapperEdges(g, funcs, wrappers)
	return g, reachableFrom(g, roots)
}

// addWrapperEdges adds to g, for each call in funcs to one of wrappers, an
// edge from the caller to each function value passed in the wrapper's
// Params, or in any argument when it lists none.
func addWrapperEdges(g *callgraph.Graph, funcs map[*ssa.Function]bool, wrappers []Wrapper) {
	byName := make(map[string]*Wrapper, len(wrappers))
	for i := range wrappers {
		byName[wrappers[i].Function] = &wrappers[i]
	}
	for fn := range funcs {
		for _, site := range wrapperCalls(fn, byName) {
			w := byName[wrapperKey(site.Common().StaticCallee())]
			for _, callee := range passedFuncs(site, w) {
				callgraph.AddEdge(g.CreateNode(fn), site, g.CreateNode(callee))
			}
		}
	}
}

// passedFuncs returns the functions site passes to the wrapper w in its
// Params, or in any argument when it lists none.
func passedFuncs(site ssa.CallInstruction, w *Wrapper) []*ssa.Function {
	var out []*ssa.Function
	for i, arg := range site.Common().Args {
		if len(w.Params) > 0 && !slices.Contains(w.Params, i) {
			continue
		}
		if callee := funcValue(arg); callee != nil {
			out = append(out, callee)
		}
	}
	return out
}

// wrapperCalls returns fn's calls to one of the wrappers in byName.
func wrapperCalls(fn *ssa.Function, byName map[string]*Wrapper) []ssa.CallInstruction {
	var out []ssa.CallInstruction
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			if site, ok := instr.(ssa.CallInstruction); ok &&
				byName[wrapperKey(site.Common().StaticCallee())] != nil {
				out = append(out, site)
			}
		}
	}
	return out
}

// wrapperKey is the name a wrapper would be listed under for fn: its
// "importpath.Func", or that of the generic function it instantiates. A
// method, a synthetic function, or nil has none, and is never a wrapper.
func wrapperKey(fn *ssa.Function) string {
	if fn == nil {
		return ""
	}
	if o := fn.Origin(); o != nil {
		fn = o
	}
	if fn.Pkg == nil || fn.Signature.Recv() != nil {
		return ""
	}
	return fn.Pkg.Pkg.Path() + "." + fn.Name()
}

// funcValue returns the function a value passed as an argument refers to:
// a function, a closure or bound method value, or either converted to an
// interface. It returns nil for any other value.
func funcValue(v ssa.Value) *ssa.Function {
	for {
		switch x := v.(type) {
		case *ssa.Function:
			return x
		case *ssa.MakeClosure:
			fn, _ := x.Fn.(*ssa.Function)
			return fn
		case *ssa.MakeInterface:
			v = x.X
		case *ssa.ChangeType:
			v = x.X
		default:
			return nil
		}
	}
}

// reachableFrom returns the functions reachable from roots along the edges
// of g, roots included.
func reachableFrom(g *callgraph.Graph, roots []*ssa.Function) map[*ssa.Function]bool {
	seen := make(map[*ssa.Function]bool)
	stack := append([]*ssa.Function(nil), roots...)
	for len(stack) > 0 {
		fn := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[fn] {
			continue
		}
		seen[fn] = true
		if node := g.Nodes[fn]; node != nil {
			for _, e := range node.Out {
				stack = append(stack, e.Callee.Func)
			}
		}
	}
	return seen
}
