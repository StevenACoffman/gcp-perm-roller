// Package gcpperms finds the Google Cloud API calls each program in a Go
// workspace can actually make, and maps them to the IAM permissions the
// program's service account needs.
//
// The analysis is whole-program and static:
//
//  1. Load every package matched by the patterns (tests excluded) and build
//     SSA for the whole program, dependencies included.
//  2. For each main package, build a call graph from main and init and find
//     the functions reachable at runtime. By default the graph comes from
//     Variable Type Analysis (VTA) seeded with Rapid Type Analysis (RTA); see
//     Algorithm.
//  3. In each reachable first-party function (one that belongs to a workspace
//     module), record every Google Cloud SDK function it calls or takes the
//     value of, plus the SDK methods reached through first-party interfaces
//     (for example a wrapper interface whose implementation is
//     *datastore.Client).
//  4. Look each SDK entry point up in the permission table (see table.go).
//     Entry points with no rule are reported as unmapped so the table can be
//     extended.
//
// Calls are recorded at the boundary between first-party code and the SDK,
// so the table describes public SDK functions rather than internal RPC
// stubs. Because call graph analysis over-approximates dynamic calls, the
// result is an upper bound on what a binary can do, not a trace of what it
// did.
package gcpperms

import (
	"cmp"
	"go/token"
	"go/types"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/cockroachdb/errors"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// Site is a source location in first-party code that calls into the SDK.
type Site struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

// Call is one SDK entry point a program reaches, with what it requires.
type Call struct {
	// API is the entry point, e.g. "cloud.google.com/go/datastore.Client.Get".
	API string `json:"api"`
	// Mapped is false when no rule in the table matches API.
	Mapped      bool     `json:"mapped"`
	Permissions []string `json:"permissions,omitempty"`
	Conditional []string `json:"conditional,omitempty"`
	Note        string   `json:"note,omitempty"`
	Sites       []Site   `json:"sites"`
}

// Binary is the analysis result for one main package.
type Binary struct {
	Package string `json:"package"`
	// Calls lists every reached SDK entry point that requires something:
	// a permission, a conditional permission, a note, or a missing rule.
	Calls []Call `json:"calls"`
	// PredefinedRoles are the least-privilege predefined roles for the
	// binary, when they were requested.
	PredefinedRoles *RoleSelection `json:"predefinedRoles,omitempty"`
}

// Result is the outcome of analyzing a set of packages.
type Result struct {
	Binaries []Binary `json:"binaries"`
	// Skipped lists main packages that could not be analyzed because they
	// or their dependencies failed to type-check.
	Skipped []string `json:"skipped,omitempty"`
	// Errors holds the load and type errors encountered.
	Errors []string `json:"errors,omitempty"`
}

// Config controls Analyze.
type Config struct {
	// Dir is the directory patterns are resolved in; usually the workspace root.
	Dir string
	// Patterns are package patterns as accepted by go list.
	Patterns []string
	// Tags are extra build tags.
	Tags []string
	// Algorithm builds the call graphs. The zero value means VTA.
	Algorithm Algorithm
	// Parallelism is how many binaries are analyzed at once. Zero or less
	// means DefaultParallelism.
	Parallelism int
	// Wrappers are functions that call the functions passed to them in a
	// way VTA cannot follow, such as by reflection; FindWrappers finds
	// them. Under VTA a call to one counts as calling each function passed
	// in its Params. RTA needs none.
	Wrappers []Wrapper
}

// analyzer finds the SDK calls of binaries in one built program.
type analyzer struct {
	prog       *ssa.Program
	firstParty map[string]bool
	root       string
	algo       Algorithm
	wrappers   []Wrapper
}

// sdkPrefixes identifies Google Cloud client libraries by import path.
func sdkPrefixes() []string {
	return []string{
		"cloud.google.com/go/",
		"google.golang.org/api/",
		"github.com/GoogleCloudPlatform/opentelemetry-operations-go/",
		"golang.org/x/oauth2/google",
	}
}

// wrapperPrefixes are third-party packages treated as first-party code
// because they only adapt SDK clients to interfaces. Calls from their
// adapters into the SDK are attributed to the program that uses them.
func wrapperPrefixes() []string {
	return []string{
		"github.com/googleapis/google-cloud-go-testing/",
	}
}

func isSDK(pkgPath string) bool {
	return hasAnyPrefix(pkgPath, sdkPrefixes())
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// Permissions returns the sorted union of required permissions.
func (b Binary) Permissions() []string {
	return collect(b.Calls, func(c Call) []string { return c.Permissions })
}

// ConditionalPermissions returns the sorted union of permissions that are
// needed only on some code paths, minus those that are always required.
func (b Binary) ConditionalPermissions() []string {
	required := make(map[string]bool)
	for _, p := range b.Permissions() {
		required[p] = true
	}
	var out []string
	for _, p := range collect(b.Calls, func(c Call) []string { return c.Conditional }) {
		if !required[p] {
			out = append(out, p)
		}
	}
	return out
}

// Services returns the sorted Google APIs the binary calls.
func (b Binary) Services() []string {
	return collect(b.Calls, func(c Call) []string {
		if s := serviceFor(c.API); s != "" {
			return []string{s}
		}
		return nil
	})
}

// Unmapped returns the calls that no table rule matches.
func (b Binary) Unmapped() []Call {
	var out []Call
	for _, c := range b.Calls {
		if !c.Mapped {
			out = append(out, c)
		}
	}
	return out
}

func collect(calls []Call, f func(Call) []string) []string {
	set := make(map[string]struct{})
	for _, c := range calls {
		for _, s := range f(c) {
			set[s] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Union merges every binary into one named name.
func (r Result) Union(name string) Binary {
	byAPI := make(map[string]*Call)
	for _, b := range r.Binaries {
		for _, c := range b.Calls {
			if m, ok := byAPI[c.API]; ok {
				m.Sites = append(m.Sites, c.Sites...)
				continue
			}
			c.Sites = append([]Site(nil), c.Sites...)
			byAPI[c.API] = &c
		}
	}
	u := Binary{Package: name}
	for _, c := range byAPI {
		c.Sites = dedupSites(c.Sites)
		u.Calls = append(u.Calls, *c)
	}
	slices.SortFunc(u.Calls, compareCalls)
	return u
}

// DefaultParallelism is GOMAXPROCS capped at 4. Each VTA run builds large
// type propagation graphs, so more workers contend for memory: on a 10-core
// machine a 20-module workspace took 121s with 4 workers and 144s
// with 10.
func DefaultParallelism() int {
	return min(runtime.GOMAXPROCS(0), 4)
}

// workerCount is the number of binaries to analyze at once for a
// Config.Parallelism of p.
func workerCount(p int) int {
	if p <= 0 {
		return DefaultParallelism()
	}
	return p
}

// Analyze loads cfg.Patterns and reports the SDK calls reachable from each
// main package they contain.
func Analyze(cfg *Config) (Result, error) {
	const op = "gcpperms.Analyze"
	algo, err := ParseAlgorithm(string(cfg.Algorithm))
	if err != nil {
		return Result{}, errors.Wrap(err, op)
	}
	root, err := filepath.Abs(cfg.Dir)
	if err != nil {
		return Result{}, errors.Wrap(err, op)
	}
	pcfg := &packages.Config{
		Mode:       packages.LoadAllSyntax | packages.NeedModule,
		Dir:        cfg.Dir,
		BuildFlags: []string{"-tags=" + strings.Join(cfg.Tags, ",")},
	}
	pkgs, err := packages.Load(pcfg, cfg.Patterns...)
	if err != nil {
		return Result{}, errors.Wrap(err, op)
	}

	var res Result
	firstParty, broken := classify(pkgs, &res)
	mains := healthyMains(pkgs, broken, &res)
	// Build SSA only for the healthy part of the program; ill-typed
	// packages cannot be translated.
	prog, ssaPkgs := ssautil.AllPackages(mains, ssa.InstantiateGenerics)
	prog.Build()

	a := analyzer{
		prog: prog, firstParty: firstParty, root: root, algo: algo, wrappers: cfg.Wrappers,
	}
	res.Binaries = a.binaries(ssaPkgs, workerCount(cfg.Parallelism))
	sort.Strings(res.Skipped)
	return res, nil
}

// classify walks pkgs and their dependencies. It returns the import paths
// of first-party packages, and the packages that have errors or depend on
// one, and records every load and type error in res.
func classify(
	pkgs []*packages.Package,
	res *Result,
) (firstParty map[string]bool, broken map[*packages.Package]bool) {
	firstParty = make(map[string]bool)
	broken = make(map[*packages.Package]bool)
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if (p.Module != nil && p.Module.Main) || hasAnyPrefix(p.PkgPath, wrapperPrefixes()) {
			firstParty[p.PkgPath] = true
		}
		for _, e := range p.Errors {
			res.Errors = append(res.Errors, e.Error())
		}
		broken[p] = len(p.Errors) > 0
		for _, imp := range p.Imports {
			if broken[imp] {
				broken[p] = true
			}
		}
	})
	return firstParty, broken
}

// healthyMains returns the main packages in pkgs that can be analyzed, and
// records the rest in res.Skipped.
func healthyMains(
	pkgs []*packages.Package,
	broken map[*packages.Package]bool,
	res *Result,
) []*packages.Package {
	var mains []*packages.Package
	for _, p := range pkgs {
		switch {
		case p.Name != "main":
		case broken[p]:
			res.Skipped = append(res.Skipped, p.PkgPath)
		default:
			mains = append(mains, p)
		}
	}
	return mains
}

// binaries analyzes each main package, at most workers at a time, sorted
// by package path. Every package in ssaPkgs type-checked, so none is nil.
// The built program is read-only apart from its own locked caches, so
// binaries can be analyzed concurrently.
func (a analyzer) binaries(ssaPkgs []*ssa.Package, workers int) []Binary {
	bins := make([]Binary, len(ssaPkgs))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, sp := range ssaPkgs {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			bins[i] = a.binary(sp)
		})
	}
	wg.Wait()
	slices.SortFunc(
		bins,
		func(a, b Binary) int { return strings.Compare(a.Package, b.Package) },
	)
	return bins
}

func (a analyzer) binary(mainPkg *ssa.Package) Binary {
	var roots []*ssa.Function
	for _, name := range []string{"main", "init"} {
		if f := mainPkg.Func(name); f != nil {
			roots = append(roots, f)
		}
	}
	graph, reachable := buildCallGraph(roots, a.algo, a.wrappers)

	sites := make(map[string][]Site)
	for fn := range reachable {
		if a.firstParty[pkgPath(fn)] {
			a.recordCalls(sites, fn, graph.Nodes[fn])
		}
	}
	return Binary{Package: mainPkg.Pkg.Path(), Calls: calls(sites)}
}

// recordCalls adds to sites the SDK entry points fn calls or takes the
// value of, and those it reaches through first-party interfaces along the
// call graph edges of node. A function with no outgoing edges may have no
// node.
func (a analyzer) recordCalls(sites map[string][]Site, fn *ssa.Function, node *callgraph.Node) {
	callees := make(map[ssa.CallInstruction][]*ssa.Function)
	if node != nil {
		for _, e := range node.Out {
			callees[e.Site] = append(callees[e.Site], e.Callee.Func)
		}
	}
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			for _, callee := range a.sdkCallees(instr, callees) {
				if api, ok := apiName(callee); ok {
					sites[api] = append(sites[api], a.site(instr.Pos(), fn))
				}
			}
		}
	}
}

// sdkCallees returns the functions instr may call or takes the value of
// that could be SDK entry points. callees holds the call graph's targets
// for each call site.
func (a analyzer) sdkCallees(
	instr ssa.Instruction,
	callees map[ssa.CallInstruction][]*ssa.Function,
) []*ssa.Function {
	var out []*ssa.Function
	// Static calls, closures, and function or method values all appear as
	// *ssa.Function operands.
	for _, op := range instr.Operands(nil) {
		if f, ok := (*op).(*ssa.Function); ok {
			out = append(out, f)
		}
	}
	// Calls through stdlib or third-party interfaces (error, io.Closer,
	// proto.Message, ...) match so many SDK types that following them only
	// adds noise; the operations that need permissions are reached by name
	// elsewhere.
	if call, ok := instr.(ssa.CallInstruction); ok &&
		a.firstPartyInterface(call.Common().Value.Type()) {
		out = append(out, callees[call]...)
	}
	return out
}

// calls looks up each entry point in sites, sorted by API, leaving out
// those whose rule requires nothing.
func calls(sites map[string][]Site) []Call {
	var out []Call
	for api, ss := range sites {
		r, ok := lookup(api)
		if ok && r.noop() {
			continue
		}
		out = append(out, Call{
			API:         api,
			Mapped:      ok,
			Permissions: r.Perms,
			Conditional: r.Maybe,
			Note:        r.Note,
			Sites:       dedupSites(ss),
		})
	}
	slices.SortFunc(out, compareCalls)
	return out
}

// firstPartyInterface reports whether t is an interface type declared in
// first-party code. A call's value has such a type only for interface
// method calls; static calls and calls through function values do not.
func (a analyzer) firstPartyInterface(t types.Type) bool {
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || !types.IsInterface(named) || named.Obj().Pkg() == nil {
		return false
	}
	return a.firstParty[named.Obj().Pkg().Path()]
}

func (a analyzer) site(pos token.Pos, fn *ssa.Function) Site {
	if !pos.IsValid() {
		pos = fn.Pos()
	}
	return site(a.prog.Fset, pos, a.root)
}

// site is the position pos, with its file relative to root when it is
// under root.
func site(fset *token.FileSet, pos token.Pos, root string) Site {
	p := fset.Position(pos)
	file := p.Filename
	if rel, err := filepath.Rel(root, file); err == nil && !strings.HasPrefix(rel, "..") {
		file = rel
	}
	return Site{File: file, Line: p.Line}
}

// compareCalls orders calls by API. slices.SortFunc passes elements by value.
//
//nolint:gocritic // hugeParam: the signature is fixed by slices.SortFunc.
func compareCalls(a, b Call) int { return strings.Compare(a.API, b.API) }

// dedupSites sorts ss by file and line and removes duplicates, in place.
func dedupSites(ss []Site) []Site {
	slices.SortFunc(ss, func(a, b Site) int {
		return cmp.Or(strings.Compare(a.File, b.File), cmp.Compare(a.Line, b.Line))
	})
	return slices.Compact(ss)
}

// pkgPath returns the import path of the package whose code fn is. SSA
// gives closures their enclosing package, but generic instances have none,
// so they are resolved through their origin. Synthetic wrappers belong to
// no package: they only forward to a method that is analyzed on its own.
func pkgPath(fn *ssa.Function) string {
	if o := fn.Origin(); o != nil {
		fn = o
	}
	if fn.Pkg == nil {
		return ""
	}
	return fn.Pkg.Pkg.Path()
}

// apiName names an exported SDK function or method as "pkg.Func" or
// "pkg.Type.Method". It reports false for anything else, including
// closures and unexported SDK internals.
func apiName(fn *ssa.Function) (string, bool) {
	// Object is the declared function even for $bound and $thunk wrappers
	// and generic instantiations. It is nil for closures and has no package
	// for error.Error. First-party code can only name exported SDK
	// functions, so unexported ones are never seen here.
	obj, ok := fn.Object().(*types.Func)
	if !ok || obj.Pkg() == nil || !isSDK(obj.Pkg().Path()) {
		return "", false
	}
	name := obj.Name()
	if recv := obj.Signature().Recv(); recv != nil {
		t := recv.Type()
		if p, ok := t.(*types.Pointer); ok {
			t = p.Elem()
		}
		named, ok := types.Unalias(t).(*types.Named)
		if !ok {
			return "", false
		}
		name = named.Obj().Name() + "." + name
	}
	return obj.Pkg().Path() + "." + name, true
}
