// Package verifytable checks gcpperms' permission table (table.go) against
// Google's public documentation, independently of the analyzer.
//
// Check 1 confirms every permission the table grants is listed in the IAM
// roles and permissions reference. Check 2 traces each SDK entry point the
// workspace calls to the RPCs it sends, finds each RPC's REST reference page
// through its HTTP binding and the API's discovery document, and compares
// the permissions the page states with the table's rule.
//
// It shares no code with gcpperms: the table is parsed from source (embedded
// as [gcpperms.TableSource] unless another file is given), and the call graph
// and documentation lookups are built here. It only reads public
// documentation; it needs no Google Cloud credentials.
//
// With Options.IAMDataset pointing at a clone of
// github.com/iann0036/iam-dataset, the report adds that dataset's
// method-to-permission map as a second opinion, checks permission names
// against its role data too, and uses its lists of reference and
// access-control pages for APIs not covered here.
package verifytable

import (
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/StevenACoffman/gcp-perm-roller/internal/gcpperms"
)

// Options configures [Run].
type Options struct {
	// Workspace is the directory whose binaries are traced: a go.work
	// workspace root or a module.
	Workspace string
	// Patterns are the packages, resolved in Workspace, whose main packages
	// are traced. Empty traces every module of the workspace.
	Patterns []string
	// Algorithm is the call graph algorithm: "vta" (the default when
	// empty), or "rta", which also follows calls VTA cannot resolve, such
	// as those through reflection.
	Algorithm string
	// Table is the table.go file to check. Empty checks the table built
	// into this program.
	Table string
	// Cache is the directory fetched documentation is cached in. Empty
	// means a directory in the user cache directory.
	Cache string
	// Debug names an entry point whose RPC trace is printed to stderr.
	Debug string
	// Strict makes Run return an error when any check finds a problem.
	Strict bool
	// IAMDataset is an optional clone of github.com/iann0036/iam-dataset,
	// used as a second opinion.
	IAMDataset string
	// client fetches documentation; nil means a client with a timeout.
	// Tests set one that fails, so a page missing from their cache is an
	// error rather than a download.
	client *http.Client
}

// errWriter writes formatted text until the first error, which it keeps.
type errWriter struct {
	w   io.Writer
	err error
}

// Run checks the table and writes a Markdown report to stdout. Progress
// goes to stderr.
func Run(ctx context.Context, opts *Options, stdout, stderr io.Writer) error {
	f, dataset, err := newFetcher(ctx, opts.Cache, opts.IAMDataset, opts.client)
	if err != nil {
		return err
	}
	rules, err := loadRules(opts.Table)
	if err != nil {
		return err
	}
	w := &errWriter{w: stdout}
	problems, err := checkPermissionNames(w, f, rules, dataset)
	if err != nil {
		return err
	}
	mismatches, err := checkMethodDocs(ctx, w, f, opts, rules, dataset, stderr)
	if err != nil {
		return err
	}
	problems += mismatches
	if w.err != nil {
		return w.err
	}
	if opts.Strict && problems > 0 {
		return fmt.Errorf("%d problems found", problems)
	}
	return nil
}

// newFetcher returns a fetcher caching in cache, or in the user cache
// directory when it is empty, and the iam-dataset clone in datasetDir when
// one is given.
func newFetcher(
	ctx context.Context,
	cache, datasetDir string,
	client *http.Client,
) (*fetcher, *iamDataset, error) {
	if cache == "" {
		dir, err := os.UserCacheDir()
		if err != nil {
			return nil, nil, fmt.Errorf("finding the user cache directory: %w", err)
		}
		cache = filepath.Join(dir, "gcpperms-verifytable")
	}
	if err := os.MkdirAll(cache, 0o755); err != nil {
		return nil, nil, fmt.Errorf("creating the cache directory: %w", err)
	}
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	f := &fetcher{ctx: ctx, dir: cache, client: client}
	if datasetDir == "" {
		return f, nil, nil
	}
	dataset, err := loadIAMDataset(datasetDir)
	if err != nil {
		return nil, nil, err
	}
	f.extraRefs, f.extraAccess = dataset.restURLs, dataset.accessPages
	return f, dataset, nil
}

// loadRules parses the table in file, or the built-in one when file is
// empty.
func loadRules(file string) ([]tableRule, error) {
	if file == "" {
		return parseTable("table.go", gcpperms.TableSource)
	}
	return parseTable(file, nil)
}

// checkPermissionNames runs check 1: every permission in the table exists.
// It returns the number of problems found.
func checkPermissionNames(
	w *errWriter,
	f *fetcher,
	rules []tableRule,
	dataset *iamDataset,
) (int, error) {
	w.printf("# Check 1: permission names\n\n")
	known, noPage, err := f.knownPermissions(prefixes(rules))
	if err != nil {
		return 0, err
	}
	names, total := checkNames(rules, known)
	for _, n := range names {
		if n.Canonical == "" {
			w.printf("- NOT FOUND `%s` (table.go lines %v)\n", n.Permission, n.Lines)
		} else {
			w.printf(
				"- CASE `%s` is listed as `%s` (lines %v)\n",
				n.Permission,
				n.Canonical,
				n.Lines,
			)
		}
	}
	for _, pre := range noPage {
		w.printf("- NO REFERENCE PAGE for prefix `%s`\n", pre)
	}
	missing := countMissing(names)
	w.printf("\n%d of %d permissions found in the IAM reference.\n", total-missing, total)
	if dataset != nil {
		writeDatasetNames(w, rules, dataset, total)
	}
	w.printf("\n")
	return missing + len(noPage), nil
}

// writeDatasetNames checks permission names against the dataset's role
// data, which comes from the IAM roles API: a second and independent list.
func writeDatasetNames(w *errWriter, rules []tableRule, dataset *iamDataset, total int) {
	roleNames, _ := checkNames(rules, dataset.roles)
	for _, n := range roleNames {
		if n.Canonical == "" {
			w.printf(
				"- NOT IN ANY PREDEFINED ROLE (iam-dataset) `%s` (lines %v)\n",
				n.Permission,
				n.Lines,
			)
		} else {
			w.printf(
				"- CASE `%s` is `%s` in predefined roles (iam-dataset)\n",
				n.Permission,
				n.Canonical,
			)
		}
	}
	w.printf(
		"%d of %d permissions found in iam-dataset's predefined roles.\n",
		total-countMissing(roleNames),
		total,
	)
}

// checkMethodDocs runs check 2: traced RPCs against their documentation.
// It returns the number of mismatches.
func checkMethodDocs(
	ctx context.Context,
	w *errWriter,
	f *fetcher,
	opts *Options,
	rules []tableRule,
	dataset *iamDataset,
	stderr io.Writer,
) (int, error) {
	w.printf("# Check 2: SDK entry points against method documentation\n\n")
	_, _ = fmt.Fprintln(stderr, "loading workspace and building call graph...")
	p, err := loadProgram(ctx, opts.Workspace, opts.Patterns, opts.Algorithm, stderr)
	if err != nil {
		return 0, err
	}
	p.debugEntry, p.debugOut = opts.Debug, stderr
	es, exercised := entriesFor(p, rules)
	evaluated := evaluate(es, cachedDocs(f, p))
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("checking method documentation: %w", err)
	}
	mismatches := writeFindings(w, evaluated)
	if dataset != nil {
		writeSecondOpinion(w, dataset, evaluated)
	}
	w.printf("## Rules with permissions not exercised by any workspace binary\n\n")
	for i := range rules {
		if r := &rules[i]; !exercised[i] && !r.noop() {
			w.printf("- line %d `%s`\n", r.Line, r.Pattern)
		}
	}
	return mismatches, nil
}

// entriesFor returns an entry for each SDK entry point the program calls
// that a rule matches, in name order, and the indexes of the rules matched.
func entriesFor(p *program, rules []tableRule) ([]*entry, map[int]bool) {
	entries := p.entryPoints()
	apis := make([]string, 0, len(entries))
	for api := range entries {
		apis = append(apis, api)
	}
	sort.Strings(apis)

	var es []*entry
	exercised := make(map[int]bool)
	for _, api := range apis {
		i := match(rules, api)
		if i < 0 {
			continue // gcpperms reports these as unmapped
		}
		exercised[i] = true
		recv, in, out := make(map[string]bool), make(map[string]bool), make(map[string]bool)
		for _, fn := range entries[api] {
			frecv, fin, fout := sdkTypes(fn)
			maps.Copy(recv, frecv)
			maps.Copy(in, fin)
			maps.Copy(out, fout)
		}
		fns := slices.Concat(entries[api], p.deferredSenders(api))
		es = append(es, newEntry(api, &rules[i], p.rpcs(fns), recv, in, out))
	}
	return es, exercised
}

// cachedDocs returns a document function for evaluate that looks each RPC
// up once.
func cachedDocs(f *fetcher, p *program) func(*RPC) (methodDoc, error) {
	docs := make(map[RPC]methodDoc)
	docErr := make(map[RPC]error)
	return func(rpc *RPC) (methodDoc, error) {
		if _, done := docs[*rpc]; !done && docErr[*rpc] == nil {
			if d, err := f.documentRPC(p, rpc); err != nil {
				docErr[*rpc] = err
			} else {
				docs[*rpc] = d
			}
		}
		return docs[*rpc], docErr[*rpc]
	}
}

// writeFindings writes a section for each status, and returns the number
// of mismatches.
func writeFindings(w *errWriter, evaluated []finding) int {
	byStatus := make(map[Status][]*finding)
	for i := range evaluated {
		x := &evaluated[i]
		byStatus[x.status] = append(byStatus[x.status], x)
	}
	for _, sec := range []struct {
		status Status
		title  string
	}{
		{Mismatch, "Mismatches"},
		{Accepted, "Accepted (differences kept deliberately)"},
		{Unverified, "Unverified"},
		{NotIAM, "Not IAM (rule grants nothing, by design)"},
		{Confirmed, "Confirmed"},
	} {
		fs := byStatus[sec.status]
		w.printf("## %s (%d)\n\n", sec.title, len(fs))
		for _, x := range fs {
			writeFinding(w, x)
		}
		w.printf("\n")
	}
	return len(byStatus[Mismatch])
}

// writeFinding writes one finding as a list item.
func writeFinding(w *errWriter, x *finding) {
	switch x.status {
	case Mismatch:
		w.printf(
			"- `%s`: missing %v, extra %v\n  %s\n",
			x.api,
			x.missing,
			x.extra,
			x.detail,
		)
	case Accepted:
		w.printf(
			"- `%s`: %s\n    accepted: %s\n",
			x.api,
			x.detail,
			strings.Join(x.accepted, "\n    accepted: "),
		)
	default:
		w.printf("- `%s`: %s\n", x.api, x.detail)
	}
}

// writeSecondOpinion lists where iam-dataset's method map disagrees with
// the table, or covers a method the documentation does not.
func writeSecondOpinion(w *errWriter, dataset *iamDataset, evaluated []finding) {
	w.printf("## Second opinion: iam-dataset\n\n")
	w.printf(
		"Where iam-dataset's method map disagrees with the table, or covers a method the documentation does not.\n\n",
	)
	for i := range evaluated {
		x := &evaluated[i]
		if x.deferred || len(x.methods) == 0 {
			continue
		}
		lines, datasetOnly, ruleOnly, _ := dataset.opinion(x.methods, x.granted)
		undocumented := x.status == Unverified || len(x.accepted) > 0
		if len(datasetOnly)+len(ruleOnly) == 0 &&
			(!undocumented || len(lines) == 0) {
			continue
		}
		w.printf(
			"- `%s`: dataset only %v, table only %v\n    %s\n",
			x.api,
			datasetOnly,
			ruleOnly,
			strings.Join(lines, "\n    "),
		)
	}
	w.printf("\n")
}

func countMissing(ns []nameFinding) int {
	n := 0
	for _, x := range ns {
		if x.Canonical == "" {
			n++
		}
	}
	return n
}

func (e *errWriter) printf(format string, args ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, args...)
}
