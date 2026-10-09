package verifytable

import (
	"context"
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"io"
	"os/exec"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

var (
	// grpcMethodRE matches a gRPC full method name constant.
	grpcMethodRE = regexp.MustCompile(
		`^/([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)\.([A-Z]\w*)/([A-Z]\w*)$`,
	)
	// restPkgRE matches a generated REST client package.
	restPkgRE    = regexp.MustCompile(`^google\.golang\.org/api/([a-z0-9]+)/(v[0-9a-z]+)$`)
	restClientRE = regexp.MustCompile(`^(\w+)RESTClient$`)
)

// RPC is one remote method an entry point can invoke.
type RPC struct {
	// Kind is "grpc" or "rest".
	Kind string
	// GRPC is the full method, e.g. google.datastore.v1.Datastore.Lookup.
	GRPC string
	// API and Version identify a REST API, e.g. bigquery v2; CallType is
	// the generated call type, e.g. JobsInsertCall.
	API, Version, CallType string
}

type program struct {
	// debugEntry names an entry point whose trace is printed to debugOut.
	debugEntry  string
	debugOut    io.Writer
	prog        *ssa.Program
	graph       *callgraph.Graph
	firstParty  map[string]bool
	descriptors map[string]*serviceInfo // by full service name
}

type serviceInfo struct {
	name    string // service name, e.g. AlloyDBAdmin
	goPkg   string // Go package of the generated messages
	host    string
	methods map[string]*descriptorpb.MethodDescriptorProto
	pkg     string // proto package, e.g. google.datastore.v1
}

func (r RPC) String() string {
	if r.Kind == "grpc" {
		return r.GRPC
	}
	return fmt.Sprintf("%s/%s.%s", r.API, r.Version, r.CallType)
}

// isSDK reports whether a package path belongs to a Google Cloud SDK. The
// RPC trace walks only through these packages.
func isSDK(path string) bool {
	for _, p := range []string{
		"cloud.google.com/go/",
		"google.golang.org/api/",
		// Older clients, such as the profiler's, call gRPC stubs generated
		// into genproto rather than their own apiv* packages.
		"google.golang.org/genproto/",
		"github.com/GoogleCloudPlatform/opentelemetry-operations-go/",
	} {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// loadProgram loads every module of the workspace, builds SSA, and computes
// one RTA-seeded VTA call graph rooted at every main and init.
func loadProgram(
	ctx context.Context,
	workspace string,
	patterns []string,
	algo string,
	stderr io.Writer,
) (*program, error) {
	if len(patterns) == 0 {
		var err error
		if patterns, err = modulePatterns(ctx, workspace, stderr); err != nil {
			return nil, err
		}
	}
	pkgs, err := packages.Load(&packages.Config{
		Context: ctx,
		Mode:    packages.LoadAllSyntax | packages.NeedModule,
		Dir:     workspace,
	}, patterns...)
	if err != nil {
		return nil, fmt.Errorf("loading the workspace: %w", err)
	}
	p := &program{firstParty: make(map[string]bool)}
	mains := p.mainPackages(pkgs, stderr)
	prog, ssaPkgs := ssautil.AllPackages(mains, ssa.InstantiateGenerics)
	prog.Build()
	p.prog = prog
	p.graph = callGraph(ssaPkgs, algo)
	p.descriptors = loadDescriptors(prog)
	addSyntaxDescriptors(p.descriptors, pkgs)
	return p, nil
}

// modulePatterns returns "<module path>/..." for every module of the workspace.
func modulePatterns(ctx context.Context, workspace string, stderr io.Writer) ([]string, error) {
	// Module paths, not directories: "..." skips directories whose names
	// start with "_".
	cmd := exec.CommandContext(ctx, "go", "list", "-m", "-f", "{{.Path}}")
	cmd.Dir = workspace
	cmd.Stderr = stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list -m: %w", err)
	}
	var patterns []string
	for d := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		patterns = append(patterns, d+"/...")
	}
	return patterns, nil
}

// mainPackages records the first-party packages among pkgs and their
// dependencies, and returns the main packages that type-check, warning
// about the others.
func (p *program) mainPackages(pkgs []*packages.Package, stderr io.Writer) []*packages.Package {
	broken := make(map[*packages.Package]bool)
	packages.Visit(pkgs, nil, func(pk *packages.Package) {
		if (pk.Module != nil && pk.Module.Main) ||
			strings.HasPrefix(
				pk.PkgPath,
				"github.com/googleapis/google-cloud-go-testing/",
			) {
			p.firstParty[pk.PkgPath] = true
		}
		broken[pk] = len(pk.Errors) > 0 || anyBroken(pk.Imports, broken)
	})
	var mains []*packages.Package
	for _, pk := range pkgs {
		switch {
		case pk.Name != "main":
		case broken[pk]:
			_, _ = fmt.Fprintf(stderr, "warning: skipping %s: type errors\n", pk.PkgPath)
		default:
			mains = append(mains, pk)
		}
	}
	return mains
}

// anyBroken reports whether one of imports is broken.
func anyBroken(imports map[string]*packages.Package, broken map[*packages.Package]bool) bool {
	for _, imp := range imports {
		if broken[imp] {
			return true
		}
	}
	return false
}

// callGraph builds the VTA call graph rooted at every main and init, seeded
// with the functions RTA finds reachable.
func callGraph(ssaPkgs []*ssa.Package, algo string) *callgraph.Graph {
	var roots []*ssa.Function
	for _, sp := range ssaPkgs {
		for _, name := range []string{"main", "init"} {
			if f := sp.Func(name); f != nil {
				roots = append(roots, f)
			}
		}
	}
	res := rta.Analyze(roots, true)
	if algo == "rta" {
		return res.CallGraph
	}
	funcs := make(map[*ssa.Function]bool, len(res.Reachable))
	for f := range res.Reachable {
		funcs[f] = true
	}
	return vta.CallGraph(funcs, res.CallGraph)
}

func pkgOf(fn *ssa.Function) string {
	if o := fn.Origin(); o != nil {
		fn = o
	}
	if fn.Pkg != nil {
		return fn.Pkg.Pkg.Path()
	}
	if obj := fn.Object(); obj != nil && obj.Pkg() != nil {
		return obj.Pkg().Path()
	}
	return ""
}

// entryName names an exported SDK function as "pkg.Func" or "pkg.Type.Method".
func entryName(fn *ssa.Function) (string, bool) {
	obj, ok := fn.Object().(*types.Func)
	if !ok || obj.Pkg() == nil || !isSDK(obj.Pkg().Path()) || !obj.Exported() {
		return "", false
	}
	name := obj.Name()
	if recv := obj.Signature().Recv(); recv != nil {
		t := recv.Type()
		if ptr, ok := t.(*types.Pointer); ok {
			t = ptr.Elem()
		}
		named, ok := types.Unalias(t).(*types.Named)
		if !ok {
			return "", false
		}
		name = named.Obj().Name() + "." + name
	}
	return obj.Pkg().Path() + "." + name, true
}

// entryPoints returns the SDK functions first-party code calls or takes
// the value of, by name, each with the SSA functions behind the name.
func (p *program) entryPoints() map[string][]*ssa.Function {
	out := make(map[string][]*ssa.Function)
	add := func(fn *ssa.Function) {
		if name, ok := entryName(fn); ok {
			out[name] = appendUnique(out[name], fn)
		}
	}
	for fn, node := range p.graph.Nodes {
		if fn == nil || !p.firstParty[pkgOf(fn)] {
			continue
		}
		for _, e := range node.Out {
			add(e.Callee.Func)
		}
		for _, v := range operands(fn) {
			if f, ok := v.(*ssa.Function); ok {
				add(f)
			}
		}
	}
	return out
}

// operands returns the operands of every instruction in fn.
func operands(fn *ssa.Function) []ssa.Value {
	var out []ssa.Value
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			for _, op := range instr.Operands(nil) {
				out = append(out, *op)
			}
		}
	}
	return out
}

func appendUnique(fns []*ssa.Function, fn *ssa.Function) []*ssa.Function {
	if slices.Contains(fns, fn) {
		return fns
	}
	return append(fns, fn)
}

// rpcs returns the remote methods reachable from the entry functions
// without leaving SDK code.
//
// Only static and interface call edges are followed. Calls through function
// values are not: retry helpers such as gax.Invoke call a function value,
// and VTA, which is not context-sensitive, resolves that call to every
// closure passed to the helper anywhere in the program. Instead, closures
// and method values created along the way are followed directly.
func (p *program) rpcs(entries []*ssa.Function) []RPC {
	debug := p.debugging(entries)
	seen := make(map[*ssa.Function]bool)
	stack := append([]*ssa.Function(nil), entries...)
	found := make(map[RPC]bool)
	for len(stack) > 0 {
		fn := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[fn] {
			continue
		}
		seen[fn] = true
		if debug {
			_, _ = fmt.Fprintf(p.debugOut, "visit %s\n", fn)
		}
		// Synthetic wrappers ($bound, $thunk) have no package; walk them.
		if pkg := pkgOf(fn); pkg != "" && !isSDK(pkg) {
			continue
		}
		for _, rpc := range p.sentBy(fn) {
			found[rpc] = true
		}
		stack = append(stack, p.successors(fn)...)
	}
	out := make([]RPC, 0, len(found))
	for r := range found {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// deferredSenders returns the methods that send the RPCs of the entry point
// api when api only builds the value that sends them, and something the
// trace cannot follow calls its methods later.
func (p *program) deferredSenders(api string) []*ssa.Function {
	// The OpenTelemetry SDK calls the exporter New returns, through its
	// sdkmetric.Exporter interface, from a periodic reader.
	senders := map[string][2]string{
		"github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric.New": {
			"github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric",
			"metricExporter",
		},
	}
	t, ok := senders[api]
	if !ok {
		return nil
	}
	return p.methodsOf(t[0], t[1])
}

// methodsOf returns the methods of the named type, and of a pointer to it,
// in the package with the given path.
func (p *program) methodsOf(pkgPath, typeName string) []*ssa.Function {
	sp := p.prog.ImportedPackage(pkgPath)
	if sp == nil {
		return nil
	}
	tn, ok := sp.Pkg.Scope().Lookup(typeName).(*types.TypeName)
	if !ok {
		return nil
	}
	var out []*ssa.Function
	ms := p.prog.MethodSets.MethodSet(types.NewPointer(tn.Type()))
	for i := range ms.Len() {
		if fn := p.prog.MethodValue(ms.At(i)); fn != nil {
			out = append(out, fn)
		}
	}
	return out
}

// debugging reports whether one of entries is the entry point to trace.
func (p *program) debugging(entries []*ssa.Function) bool {
	if p.debugEntry == "" {
		return false
	}
	return slices.ContainsFunc(entries, func(e *ssa.Function) bool {
		name, _ := entryName(e)
		return name == p.debugEntry
	})
}

// sentBy returns the RPCs fn sends itself: as a REST call's Do, as a gapic
// REST transport method, or by naming a gRPC method constant.
func (p *program) sentBy(fn *ssa.Function) []RPC {
	var out []RPC
	if rpc, ok := restCall(fn); ok {
		out = append(out, rpc)
	}
	if rpc, ok := p.gapicRESTCall(fn); ok {
		out = append(out, rpc)
	}
	for _, v := range operands(fn) {
		c, ok := v.(*ssa.Const)
		if !ok || c.Value == nil || c.Value.Kind() != constant.String {
			continue
		}
		if m := grpcMethodRE.FindStringSubmatch(constant.StringVal(c.Value)); m != nil {
			out = append(out, RPC{Kind: "grpc", GRPC: m[1] + "." + m[2] + "." + m[3]})
		}
	}
	return out
}

// successors returns the functions the trace continues to from fn: the
// closures and method values it creates, then its static and interface
// callees.
func (p *program) successors(fn *ssa.Function) []*ssa.Function {
	var out []*ssa.Function
	for _, v := range operands(fn) {
		if f, ok := v.(*ssa.Function); ok {
			out = append(out, f)
		}
	}
	node := p.graph.Nodes[fn]
	if node == nil {
		return out
	}
	for _, e := range node.Out {
		if cc := e.Site.Common(); cc.StaticCallee() != nil || cc.IsInvoke() {
			out = append(out, e.Callee.Func)
		}
	}
	return out
}

// receiverNamed returns the named type of obj's receiver, through a
// pointer.
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

// restCall reports whether fn is the Do or Download method of a generated
// REST client call type, which sends exactly one REST request: Download
// sends the call's request for the media itself (alt=media), as storage's
// JSON-API readers do.
func restCall(fn *ssa.Function) (RPC, bool) {
	obj, ok := fn.Object().(*types.Func)
	if !ok || obj.Name() != "Do" && obj.Name() != "Download" || obj.Pkg() == nil {
		return RPC{}, false
	}
	m := restPkgRE.FindStringSubmatch(obj.Pkg().Path())
	if m == nil {
		return RPC{}, false
	}
	named, ok := receiverNamed(obj)
	if !ok || !strings.HasSuffix(named.Obj().Name(), "Call") {
		return RPC{}, false
	}
	return RPC{Kind: "rest", API: m[1], Version: m[2], CallType: named.Obj().Name()}, true
}

// loadDescriptors decodes the file descriptors embedded in generated
// protobuf packages (file_*_rawDesc string constants) and indexes their
// services, so each gRPC method's HTTP binding and host can be looked up.
func loadDescriptors(prog *ssa.Program) map[string]*serviceInfo {
	out := make(map[string]*serviceInfo)
	for _, sp := range prog.AllPackages() {
		scope := sp.Pkg.Scope()
		for _, name := range scope.Names() {
			fd, ok := fileDescriptor(scope, name)
			if !ok {
				continue
			}
			for _, svc := range fd.GetService() {
				out[fd.GetPackage()+"."+svc.GetName()] = newServiceInfo(fd, svc)
			}
		}
	}
	return out
}

// addSyntaxDescriptors adds the services of descriptors that older protobuf
// generators wrote as a byte slice literal, var file_*_rawDesc = []byte{...},
// which only the package's syntax holds. Services already found are kept.
func addSyntaxDescriptors(out map[string]*serviceInfo, pkgs []*packages.Package) {
	packages.Visit(pkgs, nil, func(pk *packages.Package) {
		for _, f := range pk.Syntax {
			for _, fd := range syntaxDescriptors(f) {
				for _, svc := range fd.GetService() {
					key := fd.GetPackage() + "." + svc.GetName()
					if out[key] == nil {
						out[key] = newServiceInfo(fd, svc)
					}
				}
			}
		}
	})
}

// syntaxDescriptors decodes the file_*_rawDesc byte slice literals in f.
func syntaxDescriptors(f *ast.File) []*descriptorpb.FileDescriptorProto {
	var out []*descriptorpb.FileDescriptorProto
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			if fd, ok := rawDescVar(spec); ok {
				out = append(out, fd)
			}
		}
	}
	return out
}

// rawDescVar decodes spec if it declares one file_*_rawDesc variable as a
// byte slice literal.
func rawDescVar(spec ast.Spec) (*descriptorpb.FileDescriptorProto, bool) {
	vs, ok := spec.(*ast.ValueSpec)
	if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
		return nil, false
	}
	name := vs.Names[0].Name
	if !strings.HasPrefix(name, "file_") || !strings.HasSuffix(name, "_rawDesc") {
		return nil, false
	}
	raw, ok := byteLiteral(vs.Values[0])
	if !ok {
		return nil, false
	}
	var fd descriptorpb.FileDescriptorProto
	if proto.Unmarshal(raw, &fd) != nil {
		return nil, false
	}
	return &fd, true
}

// byteLiteral returns the bytes of a []byte{...} literal of integer
// constants.
func byteLiteral(e ast.Expr) ([]byte, bool) {
	lit, ok := e.(*ast.CompositeLit)
	if !ok {
		return nil, false
	}
	out := make([]byte, 0, len(lit.Elts))
	for _, elt := range lit.Elts {
		b, ok := elt.(*ast.BasicLit)
		if !ok || b.Kind != token.INT {
			return nil, false
		}
		v, err := strconv.ParseUint(b.Value, 0, 8)
		if err != nil {
			return nil, false
		}
		out = append(out, byte(v))
	}
	return out, true
}

// fileDescriptor decodes the file descriptor in the scope's constant name,
// if it is a file_*_rawDesc string constant.
func fileDescriptor(scope *types.Scope, name string) (*descriptorpb.FileDescriptorProto, bool) {
	if !strings.HasPrefix(name, "file_") || !strings.HasSuffix(name, "_rawDesc") {
		return nil, false
	}
	c, ok := scope.Lookup(name).(*types.Const)
	if !ok || c.Val().Kind() != constant.String {
		return nil, false
	}
	var fd descriptorpb.FileDescriptorProto
	if err := proto.Unmarshal([]byte(constant.StringVal(c.Val())), &fd); err != nil {
		return nil, false
	}
	return &fd, true
}

// newServiceInfo indexes a service of a file descriptor.
func newServiceInfo(
	fd *descriptorpb.FileDescriptorProto,
	svc *descriptorpb.ServiceDescriptorProto,
) *serviceInfo {
	goPkg, _, _ := strings.Cut(fd.GetOptions().GetGoPackage(), ";")
	info := &serviceInfo{
		name:    svc.GetName(),
		goPkg:   goPkg,
		pkg:     fd.GetPackage(),
		methods: make(map[string]*descriptorpb.MethodDescriptorProto),
	}
	if svc.GetOptions() != nil {
		info.host, _ = proto.GetExtension(svc.GetOptions(), annotations.E_DefaultHost).(string)
	}
	for _, m := range svc.GetMethod() {
		info.methods[m.GetName()] = m
	}
	return info
}

// httpRule returns the HTTP verb and path template of a gRPC method, plus
// its host and the API version from the proto package.
func (p *program) httpRule(grpc string) (verb, tmpl, host, version string, err error) {
	i := strings.LastIndex(grpc, ".")
	svc, method := grpc[:i], grpc[i+1:]
	info, ok := p.descriptors[svc]
	if !ok {
		return "", "", "", "", fmt.Errorf("no descriptor for service %s", svc)
	}
	m, ok := info.methods[method]
	if !ok {
		return "", "", "", "", fmt.Errorf("service %s has no method %s", svc, method)
	}
	rule, _ := proto.GetExtension(m.GetOptions(), annotations.E_Http).(*annotations.HttpRule)
	if rule == nil {
		return "", "", "", "", fmt.Errorf("%s has no HTTP binding", grpc)
	}
	switch pat := rule.GetPattern().(type) {
	case *annotations.HttpRule_Get:
		verb, tmpl = "GET", pat.Get
	case *annotations.HttpRule_Post:
		verb, tmpl = "POST", pat.Post
	case *annotations.HttpRule_Put:
		verb, tmpl = "PUT", pat.Put
	case *annotations.HttpRule_Patch:
		verb, tmpl = "PATCH", pat.Patch
	case *annotations.HttpRule_Delete:
		verb, tmpl = "DELETE", pat.Delete
	default:
		return "", "", "", "", fmt.Errorf("%s has an unsupported HTTP binding", grpc)
	}
	parts := strings.Split(info.pkg, ".")
	return verb, tmpl, info.host, parts[len(parts)-1], nil
}

// sdkTypes returns the named SDK types in fn's receiver, its parameters
// (including the parameters of callback parameters), and its results. in
// includes the receiver.
func sdkTypes(fn *ssa.Function) (recv, in, out map[string]bool) {
	recv, in, out = make(map[string]bool), make(map[string]bool), make(map[string]bool)
	obj, ok := fn.Object().(*types.Func)
	if !ok {
		return recv, in, out
	}
	sig := obj.Signature()
	if sig.Recv() != nil {
		addSDKType(sig.Recv().Type(), recv, in)
	}
	for v := range sig.Params().Variables() {
		addSDKType(v.Type(), in)
		// A callback's parameters are handed to the caller's code, as
		// RunInTransaction hands its function a *Transaction it commits.
		if cb, ok := v.Type().Underlying().(*types.Signature); ok {
			for cv := range cb.Params().Variables() {
				addSDKType(cv.Type(), in)
			}
		}
	}
	for v := range sig.Results().Variables() {
		addSDKType(v.Type(), out)
	}
	return recv, in, out
}

// addSDKType adds the SDK type t names, through pointers and slices, to
// each of sets.
func addSDKType(t types.Type, sets ...map[string]bool) {
	for {
		switch u := t.(type) {
		case *types.Pointer:
			t = u.Elem()
			continue
		case *types.Slice:
			t = u.Elem()
			continue
		}
		break
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj().Pkg() == nil || !isSDK(named.Obj().Pkg().Path()) {
		return
	}
	for _, set := range sets {
		set[named.Obj().Pkg().Path()+"."+named.Obj().Name()] = true
	}
}

// gapicRESTCall reports whether fn is a method of a generated gapic REST
// transport, such as (*alloyDBAdminRESTClient).GenerateClientCertificate,
// which sends the same method as the gRPC transport but over HTTP and
// without a method-name constant. The service is identified by the
// transport's type name and the client package its messages belong to.
func (p *program) gapicRESTCall(fn *ssa.Function) (RPC, bool) {
	obj, ok := fn.Object().(*types.Func)
	if !ok || !obj.Exported() || obj.Pkg() == nil {
		return RPC{}, false
	}
	named, ok := receiverNamed(obj)
	if !ok {
		return RPC{}, false
	}
	m := restClientRE.FindStringSubmatch(named.Obj().Name())
	if m == nil {
		return RPC{}, false
	}
	for full, info := range p.descriptors {
		if strings.EqualFold(info.name, m[1]) &&
			strings.HasPrefix(info.goPkg, obj.Pkg().Path()+"/") {
			if _, ok := info.methods[obj.Name()]; ok {
				return RPC{Kind: "grpc", GRPC: full + "." + obj.Name()}, true
			}
		}
	}
	return RPC{}, false
}
