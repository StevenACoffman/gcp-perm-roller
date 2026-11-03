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
// is no v1 permission belongs to the one v1 permission with the same
// resource and verb; when several have it, to the one whose service the
// label contains. A v2 name that matches no single v1 permission is left
// out: no deny rule can be matched to it.
func parseDenyNames(page []byte, v1 map[string]string) (map[string]string, error) {
	found := v2NameRE.FindAllSubmatch(page, -1)
	if len(found) < minDenyNames {
		return nil, fmt.Errorf(
			"found %d permissions, expected at least %d", len(found), minDenyNames,
		)
	}
	services := make(map[string][]string) // "resource.verb" -> v1 services
	for perm := range v1 {
		service, rest, _ := strings.Cut(perm, ".")
		services[rest] = append(services[rest], service)
	}
	names := make(map[string]string)
	for _, m := range found {
		fqdn, rest := string(m[1]), string(m[2])
		label, _, _ := strings.Cut(fqdn, ".")
		if _, ok := v1[label+"."+rest]; ok {
			continue
		}
		candidates := services[rest]
		if len(candidates) > 1 {
			candidates = slices.DeleteFunc(slices.Clone(candidates), func(s string) bool {
				return !strings.Contains(label, s)
			})
		}
		if len(candidates) == 1 {
			names[candidates[0]+"."+rest] = fqdn + "/" + rest
		}
	}
	return names, nil
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

// writeHeader writes the generated-code line naming url, and the package
// clause.
func writeHeader(b *bytes.Buffer, url string) {
	fmt.Fprintf(b, "// Code generated by gensupport from %s; DO NOT EDIT.\n\n", url)
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
