package verifytable

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/golden/report.md from this run")

// roundTripFunc is an http.RoundTripper made of a function.
type roundTripFunc func(*http.Request) (*http.Response, error)

// offline is an HTTP client that fails every request, so a test that needs
// a page its cache lacks fails instead of downloading it.
func offline() *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("offline: no page cached for " + r.URL.String())
	})}
}

// RoundTrip calls f.
func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// recordedCache unpacks testdata/pages.json.gz, the documentation pages the
// fixture run reads, into a cache directory. The pages were recorded from
// docs.cloud.google.com with scripts, styles, and navigation removed.
func recordedCache(t *testing.T) string {
	t.Helper()
	f, err := os.Open("testdata/pages.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var pages map[string]json.RawMessage
	if err := json.NewDecoder(zr).Decode(&pages); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, p := range pages {
		if err := os.WriteFile(filepath.Join(dir, name), p, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// fixtureOptions checks the frozen copy of the table in testdata against
// the analyzer's test programs, which call the Datastore, Storage, and
// Secret Manager SDKs.
func fixtureOptions(t *testing.T) *Options {
	t.Helper()
	return &Options{
		Workspace: "../..",
		Patterns: []string{
			"./internal/gcpperms/testdata/app",
			"./internal/gcpperms/testdata/adapter",
		},
		Table:      "testdata/table.go",
		IAMDataset: "testdata/iam-dataset",
		Cache:      recordedCache(t),
		client:     offline(),
	}
}

func TestRunMatchesGolden(t *testing.T) {
	if testing.Short() {
		t.Skip("loads and type-checks the Google Cloud SDK")
	}
	var out bytes.Buffer
	if err := Run(context.Background(), fixtureOptions(t), &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	const golden = "testdata/golden/report.md"
	if *update {
		if err := os.WriteFile(golden, out.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != string(want) {
		t.Fatalf("report differs from %s (rerun with -update to accept):\n%s", golden, got)
	}
}

func TestRunStrict(t *testing.T) {
	if testing.Short() {
		t.Skip("loads and type-checks the Google Cloud SDK")
	}
	opts := fixtureOptions(t)
	opts.Table = "testdata/strict-table.go"
	opts.IAMDataset = ""
	var out bytes.Buffer
	if err := Run(context.Background(), opts, &out, io.Discard); err != nil {
		t.Fatalf("without --strict, problems are only reported: %v", err)
	}
	// spec: the unknown permission is reported, and the documentation
	// contradicts the rule.
	for _, want := range []string{
		"- NOT FOUND `datastore.entities.bogus`",
		"0 of 1 permissions found in the IAM reference.",
		"## Mismatches (1)",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, out.String())
		}
	}
	opts.Strict = true
	err := Run(context.Background(), opts, io.Discard, io.Discard)
	if err == nil || err.Error() != "2 problems found" {
		t.Fatalf("got %v, want 2 problems found", err)
	}
}

func TestRunErrors(t *testing.T) {
	tests := map[string]func(*Options){
		"a missing table": func(o *Options) { o.Table = "testdata/nope.go" },
		"a missing iam-dataset": func(o *Options) {
			o.IAMDataset = "testdata/nope"
		},
		// spec: with nothing cached and no network, fetching fails.
		"a page not cached": func(o *Options) { o.Cache = t.TempDir() },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			opts := &Options{
				Workspace: "../..",
				Table:     "testdata/table.go",
				Cache:     t.TempDir(),
				client:    offline(),
			}
			change(opts)
			if err := Run(context.Background(), opts, io.Discard, io.Discard); err == nil {
				t.Fatal("succeeded")
			}
		})
	}
}
