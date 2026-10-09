package gcpperms

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

var errWrite = errors.New("write failed")

// failingWriter fails after accepting limit bytes.
type failingWriter struct{ limit int }

// fataler is the part of testing.TB the helpers need. *rapid.T provides it
// but not all of testing.TB.
type fataler interface {
	Helper()
	Fatalf(format string, args ...any)
}

func TestLookup(t *testing.T) {
	tests := map[string]struct {
		api       string
		wantFound bool
		wantPerms []string
		wantNoop  bool
	}{
		"exact method": {
			api:       "cloud.google.com/go/datastore.Client.Get",
			wantFound: true,
			wantPerms: []string{"datastore.entities.get"},
		},
		"glob method": {
			api:       "cloud.google.com/go/datastore.Client.PutMulti",
			wantFound: true,
			wantPerms: []string{
				"datastore.entities.create",
				"datastore.entities.update",
			},
		},
		"specific rule wins over package catch-all": {
			api:       "cloud.google.com/go/pubsub/v2.Publisher.Publish",
			wantFound: true,
			wantPerms: []string{"pubsub.topics.publish"},
		},
		"package catch-all is a no-op": {
			api:       "cloud.google.com/go/datastore.NameKey",
			wantFound: true,
			wantNoop:  true,
		},
		"package path glob": {
			api:       "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/trace.Exporter.Shutdown",
			wantFound: true,
			wantNoop:  true,
		},
		"versioned package is not confused with its parent": {
			api:       "cloud.google.com/go/pubsub/v2/apiv1.TopicAdminClient.GetTopic",
			wantFound: true,
			wantPerms: []string{"pubsub.topics.get"},
		},
		"unknown package": {
			api: "cloud.google.com/go/spanner.Client.Single",
		},
		"unknown method in package without catch-all": {
			api: "cloud.google.com/go/secretmanager/apiv1.Client.DestroySecretVersion",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r, found := lookup(tc.api)
			equals(t, found, tc.wantFound)
			equals(t, r.Perms, tc.wantPerms)
			if found {
				equals(t, r.noop(), tc.wantNoop)
			}
		})
	}
}

func TestShortAPI(t *testing.T) {
	tests := map[string]struct {
		api  string
		want string
	}{
		"unversioned": {
			api:  "cloud.google.com/go/datastore.Client.Get",
			want: "datastore.Client.Get",
		},
		"one version element": {
			api:  "cloud.google.com/go/secretmanager/apiv1.Client.AccessSecretVersion",
			want: "secretmanager/apiv1.Client.AccessSecretVersion",
		},
		"two version elements": {
			api:  "cloud.google.com/go/pubsub/v2/apiv1.TopicAdminClient.GetTopic",
			want: "pubsub/v2/apiv1.TopicAdminClient.GetTopic",
		},
		"beta version": {
			api:  "google.golang.org/api/dataflow/v1b3.ProjectsLocationsJobsGetCall.Do",
			want: "dataflow/v1b3.ProjectsLocationsJobsGetCall.Do",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			equals(t, shortAPI(tc.api), tc.want)
		})
	}
}

// TestRulePatternsAreValid catches malformed globs, which path.Match would
// otherwise silently treat as non-matching.
func TestRulePatternsAreValid(t *testing.T) {
	for _, r := range rules {
		pkg, name := splitAPI(r.Pattern)
		if pkg == "" {
			t.Errorf("rule %q has no package", r.Pattern)
		}
		if name == "" && !strings.Contains(pkg, "*") {
			t.Errorf("rule %q has no name", r.Pattern)
		}
		if len(r.Maybe) > 0 && r.Note == "" {
			t.Errorf(
				"rule %q has conditional permissions but no note explaining when",
				r.Pattern,
			)
		}
	}
}

// siteOf returns the site of the fixture line marked "// site: marker".
func siteOf(t *testing.T, file, marker string) Site {
	t.Helper()
	data, err := os.ReadFile(file)
	ok(t, err)
	for i, line := range strings.Split(string(data), "\n") {
		if strings.HasSuffix(line, "// site: "+marker) {
			return Site{File: file, Line: i + 1}
		}
	}
	t.Fatalf("no line in %s is marked %q", file, marker)
	return Site{}
}

func TestAnalyzeWrappers(t *testing.T) {
	if testing.Short() {
		t.Skip("loads and type-checks the Google Cloud SDK")
	}
	const fixture = "github.com/StevenACoffman/gcp-perm-roller/internal/gcpperms/testdata/cached"
	res, err := Analyze(&Config{
		Dir:      ".",
		Patterns: []string{"./testdata/cached"},
		Wrappers: []string{fixture + ".cache"},
	})
	ok(t, err)
	equals(t, len(res.Binaries), 1)
	var apis []string
	for _, c := range res.Binaries[0].Calls {
		apis = append(apis, c.API)
	}
	// spec: naming the wrapper makes the call behind it visible to VTA.
	equals(t, apis, []string{"cloud.google.com/go/datastore.Client.Get"})
}

func TestAnalyze(t *testing.T) {
	if testing.Short() {
		t.Skip("loads and type-checks the Google Cloud SDK")
	}
	const fixture = "github.com/StevenACoffman/gcp-perm-roller/internal/gcpperms/testdata/"
	// One load covers every fixture. Patterns are deliberately out of
	// order to check that results are sorted.
	res, err := Analyze(&Config{
		Dir: ".",
		Patterns: []string{
			// A library first: only main packages are binaries.
			"./testdata/brokenlib",
			"./testdata/brokendep",
			"./testdata/broken",
			"./testdata/app",
			"./testdata/adapter",
		},
		Tags: []string{"gcppermstest"},
		// One worker for two binaries: the second waits on the first, so
		// a worker that never releases its slot hangs the test.
		Parallelism: 1,
	})
	ok(t, err)

	t.Run("type errors skip the binary", func(t *testing.T) {
		// A main with its own type error, and one whose dependency has one.
		equals(t, res.Skipped, []string{fixture + "broken", fixture + "brokendep"})
		if len(res.Errors) < 2 {
			t.Fatalf("want an error from each broken package, got %q", res.Errors)
		}
		for _, want := range []string{"broken/main.go", "brokenlib/lib.go"} {
			if !slices.ContainsFunc(
				res.Errors,
				func(e string) bool { return strings.Contains(e, want) },
			) {
				t.Errorf("no error reported for %s in %q", want, res.Errors)
			}
		}
	})

	var pkgs []string
	for _, b := range res.Binaries {
		pkgs = append(pkgs, b.Package)
	}
	equals(t, pkgs, []string{fixture + "adapter", fixture + "app"})

	t.Run("wrapper adapters count as first-party", func(t *testing.T) {
		// VTA reports only the adapter method the program calls; RTA would
		// report all of them (see TestBinaryAlgorithms).
		calls := res.Binaries[0].Calls
		equals(t, len(calls), 1)
		equals(t, calls[0].API, "cloud.google.com/go/datastore.Client.AllocateIDs")
		equals(t, calls[0].Permissions, []string{"datastore.entities.allocateIds"})
		// The call is in the adapter, outside the analyzed directory, so
		// its site keeps the absolute path.
		equals(t, len(calls[0].Sites), 1)
		if f := calls[0].Sites[0].File; !filepath.IsAbs(f) ||
			!strings.HasSuffix(f, "dsiface/adapters.go") {
			t.Fatalf(
				"adapter call site = %q, want an absolute path to dsiface/adapters.go",
				f,
			)
		}
	})

	app := res.Binaries[1]
	const main = "testdata/app/main.go"
	sites := make(map[string][]Site)
	var apis []string
	for _, c := range app.Calls {
		sites[c.API] = c.Sites
		apis = append(apis, c.API)
	}
	if !strictlySorted(apis) {
		t.Fatalf("calls not sorted by API: %q", apis)
	}
	equals(t, sites, map[string][]Site{
		// Built only with the gcppermstest tag.
		"cloud.google.com/go/datastore.Client.DeleteMulti": {
			siteOf(t, "testdata/app/tagged.go", "tagged"),
		},
		// Through a first-party interface.
		"cloud.google.com/go/datastore.Client.Get": {siteOf(t, main, "via-interface")},
		// In an instance of a generic function.
		"cloud.google.com/go/datastore.Client.GetAll": {siteOf(t, main, "generic")},
		// From a package initializer.
		"cloud.google.com/go/datastore.Client.GetMulti": {
			siteOf(t, main, "package-init"),
		},
		"cloud.google.com/go/datastore.Client.NewTransaction": {
			{File: main, Line: siteOf(t, main, "tx-method-value").Line - 1},
		},
		// As method values; the call through getFunc adds no site.
		"cloud.google.com/go/datastore.Client.Put": {
			siteOf(t, main, "method-value"),
		},
		"cloud.google.com/go/datastore.Transaction.Get": {
			siteOf(t, main, "tx-method-value"),
		},
		"cloud.google.com/go/storage.ObjectHandle.NewWriter": {
			siteOf(t, main, "writer"),
		},
		"cloud.google.com/go/secretmanager/apiv1.Client.AccessSecretVersion": {
			siteOf(t, main, "access"),
		},
		"cloud.google.com/go/secretmanager/apiv1.Client.DestroySecretVersion": {
			siteOf(t, main, "unmapped"),
		},
		// Not Count (through a non-first-party interface) and not Delete
		// (unreachable).
	})
	equals(t, app.Permissions(), []string{
		"datastore.databases.get",
		"datastore.entities.create",
		"datastore.entities.delete",
		"datastore.entities.get",
		"datastore.entities.list",
		"datastore.entities.update",
		"secretmanager.versions.access",
		"storage.objects.create",
	})
	equals(
		t,
		app.ConditionalPermissions(),
		[]string{"storage.objects.delete", "storage.objects.get"},
	)
	equals(t, app.Services(), []string{
		"datastore.googleapis.com",
		"secretmanager.googleapis.com",
		"storage.googleapis.com",
	})
	writerRule, _ := lookup("cloud.google.com/go/storage.ObjectHandle.NewWriter")
	notes := make(map[string]string)
	for _, c := range app.Calls {
		if c.Note != "" {
			notes[c.API] = c.Note
		}
	}
	equals(t, notes, map[string]string{
		"cloud.google.com/go/datastore.Client.GetAll":        "keys-only queries need only datastore.entities.list",
		"cloud.google.com/go/storage.ObjectHandle.NewWriter": writerRule.Note,
	})

	unmapped := app.Unmapped()
	equals(t, len(unmapped), 1)
	equals(
		t,
		unmapped[0].API,
		"cloud.google.com/go/secretmanager/apiv1.Client.DestroySecretVersion",
	)
}

func TestParseAlgorithm(t *testing.T) {
	tests := map[string]struct {
		in      string
		want    Algorithm
		wantErr bool
	}{
		"empty means the default": {in: "", want: VTA},
		"vta":                     {in: "vta", want: VTA},
		"rta":                     {in: "rta", want: RTA},
		"unknown":                 {in: "cha", wantErr: true},
		"case matters":            {in: "VTA", wantErr: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := ParseAlgorithm(tc.in)
			equals(t, err != nil, tc.wantErr)
			equals(t, got, tc.want)
		})
	}
}

func TestAnalyzeRejectsUnknownAlgorithm(t *testing.T) {
	// The algorithm is checked before anything is loaded.
	_, err := Analyze(&Config{Dir: "testdata/does-not-exist", Algorithm: "cha"})
	if err == nil || !strings.Contains(err.Error(), `"cha"`) {
		t.Fatalf("Analyze with algorithm cha returned %v", err)
	}
}

func TestDefaultParallelism(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(0))
	tests := map[string]struct{ procs, want int }{
		"capped at 4": {procs: 10, want: 4},
		"exactly 4":   {procs: 4, want: 4},
		"fewer CPUs":  {procs: 2, want: 2},
		"one CPU":     {procs: 1, want: 1},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			runtime.GOMAXPROCS(tc.procs)
			equals(t, DefaultParallelism(), tc.want)
			// spec: asking does not change GOMAXPROCS.
			equals(t, runtime.GOMAXPROCS(0), tc.procs)
		})
	}
}

func TestWorkerCount(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(8))
	tests := map[string]struct{ p, want int }{
		"zero means the default":     {p: 0, want: 4},
		"negative means the default": {p: -3, want: 4},
		"one is honored":             {p: 1, want: 1},
		"more than the default":      {p: 9, want: 9},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			equals(t, workerCount(tc.p), tc.want)
		})
	}
}

func TestAnalyzeLoadError(t *testing.T) {
	_, err := Analyze(&Config{Dir: "testdata/does-not-exist", Patterns: []string{"."}})
	if err == nil {
		t.Fatal("Analyze in a missing directory succeeded")
	}
}

// Generators for property tests. They produce strings shaped like the
// "importpath.Name" API identifiers the analyzer builds in apiName.

// genIdent draws a Go identifier.
func genIdent() *rapid.Generator[string] {
	return rapid.StringMatching(`[A-Za-z_][A-Za-z0-9_]*`)
}

// genPathElem draws an import path element after the domain: no dots or
// slashes, and often a version element such as v2 or apiv1 so shortAPI's
// trimming is exercised.
func genPathElem() *rapid.Generator[string] {
	return rapid.OneOf(
		rapid.StringMatching(`[a-z0-9_-]+`),
		rapid.SampledFrom(
			[]string{"v1", "v2", "apiv1", "apiv2", "v1b3", "v1alpha", "v2beta1"},
		),
	)
}

// genImportPath draws a module-style import path: a dotted domain followed
// by at least one element, like cloud.google.com/go/datastore.
func genImportPath() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		domain := rapid.StringMatching(`[a-z]+(\.[a-z]+)+`).Draw(t, "domain")
		elems := rapid.SliceOfN(genPathElem(), 1, -1).Draw(t, "elems")
		return domain + "/" + strings.Join(elems, "/")
	})
}

// genName draws a function name or a Type.Method pair.
func genName() *rapid.Generator[string] {
	return rapid.OneOf(
		genIdent(),
		rapid.Custom(func(t *rapid.T) string {
			return genIdent().Draw(t, "type") + "." + genIdent().Draw(t, "method")
		}),
	)
}

func genAPI() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		return genImportPath().Draw(t, "pkg") + "." + genName().Draw(t, "name")
	})
}

// genPerm draws permissions from a small pool so that calls share
// permissions; overlap is what collect's de-duplication must handle.
func genPerm() *rapid.Generator[string] {
	return rapid.SampledFrom([]string{
		"datastore.entities.get", "datastore.entities.list", "pubsub.topics.publish",
		"storage.objects.create", "storage.objects.delete", "iam.serviceAccounts.signBlob",
	})
}

func genSite() *rapid.Generator[Site] {
	return rapid.Custom(func(t *rapid.T) Site {
		return Site{
			// A small file pool forces equal files, so sorting by line matters.
			File: rapid.SampledFrom([]string{"a.go", "b.go", "dir/c.go"}).
				Draw(t, "file"),
			Line: rapid.Int().Draw(t, "line"),
		}
	})
}

func genCall() *rapid.Generator[Call] {
	return rapid.Custom(func(t *rapid.T) Call {
		return Call{
			API:         genAPI().Draw(t, "api"),
			Mapped:      rapid.Bool().Draw(t, "mapped"),
			Permissions: rapid.SliceOf(genPerm()).Draw(t, "perms"),
			Conditional: rapid.SliceOf(genPerm()).Draw(t, "maybe"),
			Sites:       rapid.SliceOf(genSite()).Draw(t, "sites"),
		}
	})
}

// genBinaries draws binaries whose calls agree on everything but call sites
// for a given API, as they do in real results: the rule fields come from
// the table, so two binaries calling the same API get the same fields.
func genBinaries(t *rapid.T) []Binary {
	pool := rapid.SliceOfDistinct(genCall(), func(c Call) string { return c.API }).
		Draw(t, "pool")
	n := rapid.IntRange(0, 5).Draw(t, "binaries")
	bins := make([]Binary, n)
	for i := range bins {
		bins[i].Package = fmt.Sprintf("example.com/bin%d", i)
		if len(pool) == 0 {
			continue
		}
		picks := rapid.SliceOfDistinct(rapid.IntRange(0, len(pool)-1), rapid.ID[int]).
			Draw(t, "picks")
		for _, p := range picks {
			c := pool[p]
			c.Sites = rapid.SliceOf(genSite()).Draw(t, "sites")
			bins[i].Calls = append(bins[i].Calls, c)
		}
	}
	return bins
}

func set(ss ...[]string) map[string]bool {
	m := make(map[string]bool)
	for _, s := range ss {
		for _, x := range s {
			m[x] = true
		}
	}
	return m
}

func strictlySorted(ss []string) bool {
	for i := 1; i < len(ss); i++ {
		if ss[i-1] >= ss[i] {
			return false
		}
	}
	return true
}

func TestSplitAPIRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pkg := genImportPath().Draw(t, "pkg")
		name := genName().Draw(t, "name")
		// spec: splitAPI inverts the "importpath.Name" join done by apiName.
		gotPkg, gotName := splitAPI(pkg + "." + name)
		if gotPkg != pkg || gotName != name {
			t.Fatalf("splitAPI(%q) = (%q, %q), want (%q, %q)",
				pkg+"."+name, gotPkg, gotName, pkg, name)
		}
	})
}

// checkSplitAPIReassembles holds for every string, not just well-formed
// APIs, so it doubles as a fuzz property.
func checkSplitAPIReassembles(t fataler, api string) {
	pkg, name := splitAPI(api)
	// spec: the package is everything before the first dot of the last path
	// element; with no such dot the whole string is the package.
	if name == "" && pkg != api && pkg+"." != api {
		t.Fatalf(
			"splitAPI(%q) = (%q, %q): empty name must leave the input whole",
			api,
			pkg,
			name,
		)
	}
	if name != "" && pkg+"."+name != api {
		t.Fatalf("splitAPI(%q) = (%q, %q) does not reassemble", api, pkg, name)
	}
	if last := pkg[strings.LastIndex(pkg, "/")+1:]; strings.Contains(last, ".") && name != "" {
		t.Fatalf("splitAPI(%q): package %q has a dot in its last element", api, pkg)
	}
}

func TestSplitAPIReassembles(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		checkSplitAPIReassembles(t, rapid.String().Draw(t, "api"))
	})
}

func TestShortAPIIdempotent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		api := genAPI().Draw(t, "api")
		once := shortAPI(api)
		// spec: the short form already ends at its last unversioned element,
		// so shortening it again changes nothing.
		if twice := shortAPI(once); twice != once {
			t.Fatalf("shortAPI(%q) = %q, but shortAPI(%q) = %q", api, once, once, twice)
		}
	})
}

func TestShortAPIKeepsLastUnversionedElement(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pkg := genImportPath().Draw(t, "pkg")
		name := genName().Draw(t, "name")
		short := shortAPI(pkg + "." + name)

		shortPkg, ok := strings.CutSuffix(short, "."+name)
		if !ok {
			t.Fatalf("shortAPI(%q) = %q lost the name", pkg+"."+name, short)
		}
		// spec: the short package is a trailing run of whole path elements:
		// one unversioned element followed only by version elements.
		if pkg != shortPkg && !strings.HasSuffix(pkg, "/"+shortPkg) {
			t.Fatalf("shortAPI kept %q, which is not a suffix of %q", shortPkg, pkg)
		}
		elems := strings.Split(shortPkg, "/")
		if versionRE.MatchString(elems[0]) {
			t.Fatalf(
				"shortAPI(%q) = %q starts at a version element",
				pkg+"."+name,
				short,
			)
		}
		for _, e := range elems[1:] {
			if !versionRE.MatchString(e) {
				t.Fatalf(
					"shortAPI(%q) = %q keeps unversioned element %q after the first",
					pkg+"."+name,
					short,
					e,
				)
			}
		}
	})
}

func TestLookupUnknownPackageNotFound(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// spec: every rule is anchored to a Google Cloud package, so an API
		// in an unrelated package never matches.
		api := "example.com/" + genPathElem().Draw(t, "elem") +
			"." + genName().Draw(t, "name")
		if r, found := lookup(api); found {
			t.Fatalf("lookup(%q) matched rule %q", api, r.Pattern)
		}
	})
}

// instantiate turns a rule pattern into a concrete API it matches by
// replacing each glob star with fill.
func instantiate(pattern, fill string) string {
	pkg, name := splitAPI(pattern)
	if strings.HasSuffix(pkg, "*") {
		return strings.TrimSuffix(pkg, "*") + "x." + fill
	}
	return pkg + "." + strings.ReplaceAll(name, "*", fill)
}

func ruleIndex(pattern string) int {
	for i, r := range rules {
		if r.Pattern == pattern {
			return i
		}
	}
	return -1
}

func TestLookupFirstMatchWins(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		i := rapid.IntRange(0, len(rules)-1).Draw(t, "rule")
		api := instantiate(rules[i].Pattern, genIdent().Draw(t, "fill"))
		got, found := lookup(api)
		// spec: rule i matches api, and lookup returns the first matching
		// rule, so it finds rule i or one declared before it.
		if !found {
			t.Fatalf(
				"lookup(%q) found nothing, but rule %q matches it",
				api,
				rules[i].Pattern,
			)
		}
		if j := ruleIndex(got.Pattern); j > i {
			t.Fatalf("lookup(%q) = rule %d %q, but earlier rule %d %q matches",
				api, j, got.Pattern, i, rules[i].Pattern)
		}
	})
}

// TestNoRuleIsShadowed checks that every rule is reachable: some API
// matches it before any earlier rule. A shadowed rule is dead table data.
func TestNoRuleIsShadowed(t *testing.T) {
	for i, r := range rules {
		api := instantiate(r.Pattern, "Zz")
		got, _ := lookup(api)
		if j := ruleIndex(got.Pattern); j != i {
			t.Errorf(
				"rule %d %q is shadowed by rule %d %q (for %q)",
				i,
				r.Pattern,
				j,
				got.Pattern,
				api,
			)
		}
	}
}

func TestPermissionsAreSortedUnion(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		b := Binary{Calls: rapid.SliceOf(genCall()).Draw(t, "calls")}
		got := b.Permissions()
		var all [][]string
		for _, c := range b.Calls {
			all = append(all, c.Permissions)
		}
		// spec: "the sorted union of required permissions".
		if !strictlySorted(got) {
			t.Fatalf("Permissions() = %q is not sorted and distinct", got)
		}
		if !reflect.DeepEqual(set(got), set(all...)) {
			t.Fatalf("Permissions() = %q, want the union of %q", got, all)
		}
	})
}

func TestConditionalPermissionsPartitionTheRest(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		b := Binary{Calls: rapid.SliceOf(genCall()).Draw(t, "calls")}
		req, cond := b.Permissions(), b.ConditionalPermissions()
		var all [][]string
		for _, c := range b.Calls {
			all = append(all, c.Permissions, c.Conditional)
		}
		// spec: conditional permissions are the sorted union of Conditional
		// "minus those that are always required".
		if !strictlySorted(cond) {
			t.Fatalf("ConditionalPermissions() = %q is not sorted and distinct", cond)
		}
		reqSet := set(req)
		for _, p := range cond {
			if reqSet[p] {
				t.Fatalf("%q is both required and conditional", p)
			}
		}
		if !reflect.DeepEqual(set(req, cond), set(all...)) {
			t.Fatalf(
				"required %q + conditional %q != all permissions %q",
				req,
				cond,
				all,
			)
		}
	})
}

func TestUnmappedSelectsUnmappedCallsInOrder(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		b := Binary{Calls: rapid.SliceOf(genCall()).Draw(t, "calls")}
		var want []Call
		for _, c := range b.Calls {
			if !c.Mapped {
				want = append(want, c)
			}
		}
		equals(t, b.Unmapped(), want)
	})
}

func TestServicesAreSortedKnownServices(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Prefix some APIs with a real SDK package so services are found.
		calls := rapid.SliceOf(rapid.Custom(func(t *rapid.T) Call {
			c := genCall().Draw(t, "call")
			if rapid.Bool().Draw(t, "sdk") {
				s := rapid.SampledFrom(services()).Draw(t, "service")
				c.API = s.prefix + "." + genName().Draw(t, "name")
			}
			return c
		})).Draw(t, "calls")
		got := Binary{Calls: calls}.Services()
		want := make(map[string]bool)
		for _, c := range calls {
			for _, s := range services() {
				if strings.HasPrefix(c.API, s.prefix) {
					want[s.service] = true
					break
				}
			}
		}
		if !strictlySorted(got) || !reflect.DeepEqual(set(got), want) {
			t.Fatalf("Services() = %q, want sorted %v", got, want)
		}
	})
}

func siteLess(a, b Site) bool {
	if a.File != b.File {
		return a.File < b.File
	}
	return a.Line < b.Line
}

func TestDedupSitesSortsAndRemovesDuplicates(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		in := rapid.SliceOf(genSite()).Draw(t, "sites")
		want := make(map[Site]bool)
		for _, s := range in {
			want[s] = true
		}
		got := dedupSites(append([]Site(nil), in...))
		// spec: sorted by file then line, each site once, nothing lost.
		for i := 1; i < len(got); i++ {
			if !siteLess(got[i-1], got[i]) {
				t.Fatalf("dedupSites(%v) = %v is not strictly sorted", in, got)
			}
		}
		gotSet := make(map[Site]bool)
		for _, s := range got {
			gotSet[s] = true
		}
		if !reflect.DeepEqual(gotSet, want) && len(in) > 0 {
			t.Fatalf("dedupSites(%v) = %v changed the set of sites", in, got)
		}
	})
}

func TestUnionIgnoresBinaryOrder(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		bins := genBinaries(t)
		shuffled := rapid.Permutation(bins).Draw(t, "shuffled")
		// spec: a union is a set operation, so input order cannot matter.
		equals(t, Result{Binaries: shuffled}.Union("u"), Result{Binaries: bins}.Union("u"))
	})
}

func TestUnionMergesEveryBinary(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		bins := genBinaries(t)
		u := Result{Binaries: bins}.Union("all")
		equals(t, u.Package, "all")

		var perms, cond, svcs [][]string
		sites := make(map[string]map[Site]bool)
		for _, b := range bins {
			perms = append(perms, b.Permissions())
			cond = append(cond, b.Permissions(), b.ConditionalPermissions())
			svcs = append(svcs, b.Services())
			for _, c := range b.Calls {
				if sites[c.API] == nil {
					sites[c.API] = make(map[Site]bool)
				}
				for _, s := range c.Sites {
					sites[c.API][s] = true
				}
			}
		}
		// spec: the union binary needs exactly what the binaries together need.
		if !reflect.DeepEqual(set(u.Permissions()), set(perms...)) {
			t.Fatalf("union permissions %q, want %q", u.Permissions(), perms)
		}
		if !reflect.DeepEqual(
			set(u.Permissions(), u.ConditionalPermissions()),
			set(cond...),
		) {
			t.Fatalf(
				"union conditional permissions %q, want %q",
				u.ConditionalPermissions(),
				cond,
			)
		}
		if !reflect.DeepEqual(set(u.Services()), set(svcs...)) {
			t.Fatalf("union services %q, want %q", u.Services(), svcs)
		}
		// spec: each API appears once, sorted, with every binary's sites.
		equals(t, len(u.Calls), len(sites))
		for i, c := range u.Calls {
			if i > 0 && u.Calls[i-1].API >= c.API {
				t.Fatalf(
					"union calls not sorted by API: %q then %q",
					u.Calls[i-1].API,
					c.API,
				)
			}
			got := make(map[Site]bool)
			for _, s := range c.Sites {
				got[s] = true
			}
			if len(got) != len(c.Sites) ||
				(len(got) > 0 && !reflect.DeepEqual(got, sites[c.API])) ||
				(len(got) == 0 && len(sites[c.API]) > 0) {
				t.Fatalf(
					"union sites for %q = %v, want each of %v once",
					c.API,
					c.Sites,
					sites[c.API],
				)
			}
		}
	})
}

func TestUnionDoesNotModifyInput(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		bins := genBinaries(t)
		before, err := json.Marshal(bins)
		ok(t, err)
		_ = Result{Binaries: bins}.Union("u")
		after, err := json.Marshal(bins)
		ok(t, err)
		// spec: Union returns a merged copy; the per-binary results are
		// printed after it in -union mode's JSON output.
		equals(t, string(after), string(before))
	})
}

func TestWriteJSONRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		res := Result{
			Binaries: genBinaries(t),
			Skipped:  rapid.SliceOf(genImportPath()).Draw(t, "skipped"),
			Errors:   rapid.SliceOf(rapid.String()).Draw(t, "errors"),
		}
		var buf bytes.Buffer
		ok(t, WriteJSON(&buf, res))
		var got Result
		ok(t, json.Unmarshal(buf.Bytes(), &got))
		// spec: JSON output carries the whole result. Empty and nil slices
		// are indistinguishable in it, so compare re-encoded forms.
		want, err := json.Marshal(res)
		ok(t, err)
		again, err := json.Marshal(got)
		ok(t, err)
		equals(t, string(again), string(want))
	})
}

func TestWriteRolesListsEachPermissionOnce(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		bins := genBinaries(t)
		var buf bytes.Buffer
		ok(t, WriteRoles(&buf, bins))

		var docs []string
		if out := buf.String(); out != "" {
			docs = strings.Split(out, "---\n")
		}
		var want []Binary
		for _, b := range bins {
			if len(b.Permissions())+len(b.ConditionalPermissions()) > 0 {
				want = append(want, b)
			}
		}
		// spec: one role document per binary that needs any permission.
		equals(t, len(docs), len(want))
		for i, b := range want {
			_, list, found := strings.Cut(docs[i], "includedPermissions:\n")
			if !found || !strings.Contains(docs[i], b.Package) {
				t.Fatalf(
					"document %d is not the role for %s:\n%s",
					i,
					b.Package,
					docs[i],
				)
			}
			var got []string
			for line := range strings.SplitSeq(strings.TrimSpace(list), "\n") {
				p, isCond := strings.CutSuffix(
					strings.TrimPrefix(line, "- "),
					" # conditional",
				)
				if isCond != slices.Contains(b.ConditionalPermissions(), p) {
					t.Fatalf(
						"%s: %q conditional marker = %v",
						b.Package,
						p,
						isCond,
					)
				}
				got = append(got, p)
			}
			// spec: every required and conditional permission, sorted, once.
			wantPerms := append(b.Permissions(), b.ConditionalPermissions()...)
			slices.Sort(wantPerms)
			equals(t, got, wantPerms)
		}
	})
}

func TestWriteTextReportsEveryBinary(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		bins := genBinaries(t)
		verbose := rapid.Bool().Draw(t, "verbose")
		var buf bytes.Buffer
		ok(t, WriteText(&buf, bins, verbose))
		out := buf.String()
		for _, b := range bins {
			// spec: each binary gets a section, and empty ones say so.
			header := "== " + b.Package + "\n"
			if !strings.Contains(out, header) {
				t.Fatalf("no section for %s in:\n%s", b.Package, out)
			}
			_, rest, _ := strings.Cut(out, header)
			section := header + rest
			if len(b.Calls) == 0 &&
				!strings.HasPrefix(
					section,
					header+"  no Google Cloud API calls\n",
				) {
				t.Fatalf("empty %s not reported as such:\n%s", b.Package, section)
			}
			for _, p := range b.Permissions() {
				if !strings.Contains(section, "    "+p+" ") {
					t.Fatalf(
						"permission %q missing from %s section:\n%s",
						p,
						b.Package,
						section,
					)
				}
			}
			for _, c := range b.Unmapped() {
				if !strings.Contains(section, "    "+c.API+"\n") {
					t.Fatalf(
						"unmapped %q missing from %s section",
						c.API,
						b.Package,
					)
				}
			}
		}
	})
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if len(p) > w.limit {
		return 0, errWrite
	}
	w.limit -= len(p)
	return len(p), nil
}

func TestWritersReportWriteErrors(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		bins := genBinaries(t)
		var full bytes.Buffer
		ok(t, WriteText(&full, bins, true))
		if full.Len() == 0 {
			t.Skip("nothing to write")
		}
		// spec: a write failure at any point is returned, not swallowed.
		limit := rapid.IntRange(0, full.Len()-1).Draw(t, "limit")
		if err := WriteText(
			&failingWriter{limit: limit},
			bins,
			true,
		); !errors.Is(
			err,
			errWrite,
		) {
			t.Fatalf(
				"WriteText with a writer failing after %d bytes returned %v",
				limit,
				err,
			)
		}
	})
}

func ok(t fataler, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func equals[T any](t fataler, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestRuleNoop(t *testing.T) {
	tests := map[string]struct {
		r    rule
		want bool
	}{
		"nothing":               {r: rule{Pattern: "p"}, want: true},
		"permissions":           {r: rule{Perms: []string{"a.b.c"}}},
		"conditional only":      {r: rule{Maybe: []string{"a.b.c"}}},
		"a note only (not IAM)": {r: rule{Note: "needs an OAuth scope"}},
		"everything": {
			r: rule{Perms: []string{"a.b.c"}, Maybe: []string{"a.b.d"}, Note: "n"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			equals(t, tc.r.noop(), tc.want)
		})
	}
}

func TestSplitAPIEdges(t *testing.T) {
	tests := map[string]struct{ in, pkg, name string }{
		"method":                         {in: "a.com/b.T.M", pkg: "a.com/b", name: "T.M"},
		"last element starts with a dot": {in: "a.com/.F", pkg: "a.com/", name: "F"},
		"no dot after the last slash":    {in: "a.com/b", pkg: "a.com/b"},
		"no slash":                       {in: "pkg.F", pkg: "pkg", name: "F"},
		"leading dot, no slash":          {in: ".F", pkg: "", name: "F"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			pkg, n := splitAPI(tc.in)
			equals(t, pkg, tc.pkg)
			equals(t, n, tc.name)
		})
	}
}
