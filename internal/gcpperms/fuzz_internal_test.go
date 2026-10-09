package gcpperms

import (
	"path"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// The string fuzz targets feed arbitrary bytes to the API-name helpers. The
// analyzer only builds API names from type-checked identifiers, but the
// helpers must still behave on anything: a panic in them aborts a whole
// workspace analysis.
//
// Run one with, for example:
//
//	go test -run='^$' -fuzz=FuzzSplitAPI -fuzztime=30s ./analyzers/gcpperms/

// apiSeeds are real API names plus inputs at the edges of splitAPI's
// slash-then-dot parsing.
var apiSeeds = []string{
	"cloud.google.com/go/datastore.Client.Get",
	"cloud.google.com/go/pubsub/v2/apiv1.TopicAdminClient.GetTopic",
	"google.golang.org/api/dataflow/v1b3.ProjectsLocationsJobsGetCall.Do",
	"github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/trace.New",
	"golang.org/x/oauth2/google.FindDefaultCredentials",
	"",
	".",
	"/",
	"a/",
	"a/.",
	"/.b",
	"a.b/c",
	"a.b/c.",
	"a/b.c.d",
	"*",
	"a/*",
	"a/b.[",
	"a/v1.v2",
	"apiv1/v2.X",
	"\xff/\x00.\x80",
}

func FuzzSplitAPI(f *testing.F) {
	for _, s := range apiSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, api string) {
		checkSplitAPIReassembles(t, api)
	})
}

func FuzzShortAPI(f *testing.F) {
	for _, s := range apiSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, api string) {
		pkg, name := splitAPI(api)
		short := shortAPI(api)
		// spec: the name is kept whole after the shortened package.
		shortPkg, ok := strings.CutSuffix(short, "."+name)
		if !ok {
			t.Fatalf("shortAPI(%q) = %q lost the name %q", api, short, name)
		}
		// spec: the shortened package is a trailing run of path elements.
		if shortPkg != pkg && !strings.HasSuffix(pkg, "/"+shortPkg) {
			t.Fatalf(
				"shortAPI(%q) kept %q, which is not a suffix of %q",
				api,
				shortPkg,
				pkg,
			)
		}
	})
}

func FuzzLookup(f *testing.F) {
	for _, s := range apiSeeds {
		f.Add(s)
	}
	for _, r := range rules {
		f.Add(instantiate(r.Pattern, "Zz"))
	}
	f.Fuzz(func(t *testing.T, api string) {
		r, found := lookup(api)
		if !found {
			if r.Pattern != "" {
				t.Fatalf(
					"lookup(%q) found nothing but returned rule %q",
					api,
					r.Pattern,
				)
			}
			return
		}
		// spec: a found rule is anchored to the API's package (exactly, or
		// by a trailing package-path glob) and its name glob matches.
		pkg, name := splitAPI(api)
		rpkg, rname := splitAPI(r.Pattern)
		if prefix, isGlob := strings.CutSuffix(rpkg, "*"); isGlob {
			if !strings.HasPrefix(pkg, prefix) {
				t.Fatalf(
					"lookup(%q) = %q, outside the rule's package glob",
					api,
					r.Pattern,
				)
			}
		} else if rpkg != pkg {
			t.Fatalf("lookup(%q) = %q, a rule for another package", api, r.Pattern)
		}
		if matched, _ := path.Match(rname, name); !matched && rname != "" {
			t.Fatalf(
				"lookup(%q) = %q, whose name glob does not match %q",
				api,
				r.Pattern,
				name,
			)
		}
		// spec: a returned rule comes from the table.
		if j := ruleIndex(r.Pattern); j < 0 {
			t.Fatalf(
				"lookup(%q) returned %q, which is not in the table",
				api,
				r.Pattern,
			)
		}
	})
}

// The structured fuzz targets reuse the rapid properties with Go's
// coverage-guided fuzzer as the source of randomness, so the fuzzer can
// steer generated results toward new code paths.

func FuzzUnionMergesEveryBinary(f *testing.F) {
	f.Fuzz(rapid.MakeFuzz(func(t *rapid.T) {
		bins := genBinaries(t)
		u := Result{Binaries: bins}.Union("all")
		want := make(map[string]bool)
		for _, b := range bins {
			for _, p := range b.Permissions() {
				want[p] = true
			}
		}
		if got := set(u.Permissions()); len(got) != len(want) {
			t.Fatalf("union permissions %q, want %v", u.Permissions(), want)
		}
	}))
}

func FuzzWriteRoles(f *testing.F) {
	f.Fuzz(rapid.MakeFuzz(func(t *rapid.T) {
		bins := genBinaries(t)
		var buf strings.Builder
		ok(t, WriteRoles(&buf, bins))
		// spec: every role document lists its permissions under
		// includedPermissions, which gcloud requires.
		for doc := range strings.SplitSeq(buf.String(), "---\n") {
			if doc != "" && !strings.Contains(doc, "\nincludedPermissions:\n- ") {
				t.Fatalf("role document without permissions:\n%s", doc)
			}
		}
	}))
}

func FuzzSelectRolesIsOptimal(f *testing.F) {
	f.Fuzz(rapid.MakeFuzz(func(t *rapid.T) {
		need, roles := genRoleProblem(t)
		want, _ := bruteForce(need, roles)
		// spec: the chosen roles cost no more than any covering set.
		equals(t, selectionCost(SelectRoles(need, roles, RoleFilter{})), want)
	}))
}
