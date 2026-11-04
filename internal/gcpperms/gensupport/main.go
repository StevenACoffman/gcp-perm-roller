// Command gensupport writes two tables of Google's permission support pages
// into the current directory; `go generate` runs it in internal/gcpperms.
//
//   - support_levels.go: the permissions Google's list of support levels for
//     permissions in custom roles marks TESTING or NOT_SUPPORTED.
//   - deny_names.go: the IAM v2 name, as deny policies write permissions, of
//     each permission whose v2 name does not follow from its v1 name.
//
// Only exceptions are written, and the files carry no date, so regenerating
// them changes them only when Google's pages change what they say.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/format"
	"html"
	"io"
	"maps"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strings"
)

const (
	// supportURL is Google's list of every permission and its support level
	// in custom roles.
	supportURL = "https://docs.cloud.google.com/iam/docs/custom-roles-permissions-support"
	// denyURL is Google's list of the permissions deny policies can deny,
	// by their v2 names.
	denyURL = "https://docs.cloud.google.com/iam/docs/deny-permissions-support"
)

// minSupportRows and minDenyNames are fewer entries than the pages have
// ever had (14,279 and 9,188 in November 2026). A page parsing to fewer has
// changed its layout, and writing what parsed would silently drop entries.
const (
	minSupportRows = 10000
	minDenyNames   = 5000
)

// entryPattern matches the lines of the generated files that hold an
// entry, each a quoted permission indented by one tab.
const entryPattern = `^\t"`

var (
	// rowRE matches one row of the support page's table: a permission and
	// its level.
	rowRE = regexp.MustCompile(
		`<td class="column1-class">\s*<code[^>]*>([^<]+)</code>\s*</td>\s*` +
			`<td class="column2-class">\s*<code[^>]*>([^<]+)</code>\s*</td>`,
	)
	// v2NameRE matches one permission on the deny page, such as
	// <code>iam.googleapis.com/roles.delete</code>. Permission groups, with
	// a "*", are left out: they name no single permission.
	v2NameRE = regexp.MustCompile(
		`<code[^>]*>([a-z0-9.-]+\.googleapis\.com)/([A-Za-z0-9]+\.[A-Za-z0-9]+)</code>`,
	)
)

// denyIndex is what parseDenyNames matches v2 names against.
type denyIndex struct {
	v1       map[string]string   // the support page's permissions
	services map[string][]string // "resource.verb" -> the v1 services that have it
	listed   map[string]bool     // the deny page's v2 names
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	files, err := generate(ctx, http.DefaultClient, supportURL, denyURL)
	stop()
	for _, name := range slices.Sorted(maps.Keys(files)) {
		if err != nil {
			break
		}
		err = os.WriteFile(name, files[name], 0o644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gensupport:", err)
		os.Exit(1)
	}
}

// generate fetches the support page at supportURL and the deny page at
// denyURL, and returns the source of each file it writes, by name. It
// returns no files unless both pages parse.
func generate(
	ctx context.Context,
	client *http.Client,
	supportURL, denyURL string,
) (map[string][]byte, error) {
	page, err := fetch(ctx, client, supportURL)
	if err != nil {
		return nil, err
	}
	levels, err := parseLevels(page)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", supportURL, err)
	}
	page, err = fetch(ctx, client, denyURL)
	if err != nil {
		return nil, err
	}
	names, err := parseDenyNames(page, levels)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", denyURL, err)
	}

	levelSrc, err := renderLevels(levels)
	if err != nil {
		return nil, err
	}
	nameSrc, err := renderDenyNames(names)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{"support_levels.go": levelSrc, "deny_names.go": nameSrc}, nil
}

// fetch returns the body of the page at url.
func fetch(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	body, readErr := io.ReadAll(resp.Body)
	if err := errors.Join(readErr, resp.Body.Close()); err != nil {
		return nil, fmt.Errorf("reading %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: %s", url, resp.Status)
	}
	return body, nil
}

// parseLevels returns the level of every permission the support page
// lists. It fails when the page lists fewer than minSupportRows
// permissions, a permission twice with different levels, or a level it
// does not know.
func parseLevels(page []byte) (map[string]string, error) {
	rows := rowRE.FindAllSubmatch(page, -1)
	if len(rows) < minSupportRows {
		return nil, fmt.Errorf(
			"found %d permissions, expected at least %d", len(rows), minSupportRows,
		)
	}
	levels := make(map[string]string, len(rows))
	for _, row := range rows {
		perm := strings.TrimSpace(html.UnescapeString(string(row[1])))
		level := strings.TrimSpace(html.UnescapeString(string(row[2])))
		if levelConst(level) == "" {
			return nil, fmt.Errorf("%s: unknown support level %q", perm, level)
		}
		if prev, ok := levels[perm]; ok && prev != level {
			return nil, fmt.Errorf("%s is listed as both %s and %s", perm, prev, level)
		}
		levels[perm] = level
	}
	return levels, nil
}

// parseDenyNames returns the v2 name of each permission in v1 (keyed by v1
// name) whose v2 name, as the deny page lists it, is not the v1 name's
// service with ".googleapis.com" and a "/": resourcemanager.projects.delete
// is cloudresourcemanager.googleapis.com/projects.delete.
//
// A v2 name whose service's first label, followed by its resource and verb,
// is no v1 permission belongs to the v1 permission with the same resource
// and verb whose service the label contains. When none does, it belongs to
// the only v1 permission with that resource and verb, unless the page lists
// that permission's own default v2 name: Secret Manager's
// secretmanager.googleapis.com/backups.restore, which the support page does
// not list yet, is not bigtable.backups.restore's. A v2 name that matches
// no single v1 permission, or a v1 permission two v2 names match, is left
// out: no deny rule can be matched to it with certainty.
func parseDenyNames(page []byte, v1 map[string]string) (map[string]string, error) {
	found := v2NameRE.FindAllSubmatch(page, -1)
	if len(found) < minDenyNames {
		return nil, fmt.Errorf(
			"found %d permissions, expected at least %d", len(found), minDenyNames,
		)
	}
	ix := denyIndex{
		v1:       v1,
		services: make(map[string][]string),
		listed:   make(map[string]bool, len(found)),
	}
	for perm := range v1 {
		service, rest, _ := strings.Cut(perm, ".")
		ix.services[rest] = append(ix.services[rest], service)
	}
	for _, m := range found {
		ix.listed[string(m[1])+"/"+string(m[2])] = true
	}
	names := make(map[string]string)
	ambiguous := make(map[string]bool)
	for _, m := range found {
		name := string(m[1]) + "/" + string(m[2])
		perm, ok := ix.owner(string(m[1]), string(m[2]))
		if !ok {
			continue
		}
		if prev, dup := names[perm]; dup && prev != name {
			ambiguous[perm] = true
		}
		names[perm] = name
	}
	maps.DeleteFunc(names, func(perm, _ string) bool { return ambiguous[perm] })
	return names, nil
}

// owner returns the v1 permission the v2 name fqdn/rest is an exception
// for, or false when it is the default name of its own v1 permission or
// matches no single v1 permission.
func (ix *denyIndex) owner(fqdn, rest string) (string, bool) {
	label, _, _ := strings.Cut(fqdn, ".")
	if _, ok := ix.v1[label+"."+rest]; ok {
		return "", false
	}
	candidates := ix.services[rest]
	contained := slices.DeleteFunc(slices.Clone(candidates), func(s string) bool {
		return !strings.Contains(label, s)
	})
	switch {
	case len(contained) == 1:
		return contained[0] + "." + rest, true
	// contained is within candidates, so here the label contains no
	// candidate's service.
	case len(candidates) == 1 && !ix.listed[candidates[0]+".googleapis.com/"+rest]:
		return candidates[0] + "." + rest, true
	}
	return "", false
}

// renderLevels returns support_levels.go: the levels that are not
// SUPPORTED, as customRoleSupport.
func renderLevels(levels map[string]string) ([]byte, error) {
	var b bytes.Buffer
	writeHeader(&b, supportURL)
	b.WriteString("// customRoleSupport is the support level in custom roles of each\n")
	b.WriteString("// permission that is not SUPPORTED. CustomRoleSupport reads it.\n")
	b.WriteString("var customRoleSupport = map[string]SupportLevel{\n")
	for _, perm := range slices.Sorted(maps.Keys(levels)) {
		if levels[perm] != "SUPPORTED" {
			fmt.Fprintf(&b, "\t%q: %s,\n", perm, levelConst(levels[perm]))
		}
	}
	b.WriteString("}\n")
	return formatted(b.Bytes())
}

// renderDenyNames returns deny_names.go: names, as denyNames.
func renderDenyNames(names map[string]string) ([]byte, error) {
	var b bytes.Buffer
	writeHeader(&b, denyURL)
	b.WriteString("// denyNames is the v2 name of each permission whose v2 name is not its\n")
	b.WriteString("// v1 name's service, \".googleapis.com/\", and the rest. V2Name reads it.\n")
	b.WriteString("var denyNames = map[string]string{\n")
	for _, perm := range slices.Sorted(maps.Keys(names)) {
		fmt.Fprintf(&b, "\t%q: %q,\n", perm, names[perm])
	}
	b.WriteString("}\n")
	return formatted(b.Bytes())
}

// writeHeader writes the generated-code line naming url, the annotation
// that keeps mutago from mutating the entries, and the package clause. The
// entries are data copied from Google's page: no test could catch a mutant
// that blanks one without restating the page.
func writeHeader(b *bytes.Buffer, url string) {
	fmt.Fprintf(b, "// Code generated by gensupport from %s; DO NOT EDIT.\n\n", url)
	b.WriteString("// mutator-disable-regexp " + entryPattern + " *\n\n")
	b.WriteString("package gcpperms\n\n")
}

// formatted returns src gofmt'd.
func formatted(src []byte) ([]byte, error) {
	out, err := format.Source(src)
	if err != nil {
		return nil, fmt.Errorf("formatting the generated source: %w", err)
	}
	return out, nil
}

// levelConst names the gcpperms constant for a level the page uses, or
// returns "" for a level it does not know.
func levelConst(level string) string {
	switch level {
	case "SUPPORTED":
		return "Supported"
	case "TESTING":
		return "Testing"
	case "NOT_SUPPORTED":
		return "NotSupported"
	}
	return ""
}
