package verifytable

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
)

// politeDelay is how long get waits after each request, to be polite to the
// docs site.
const politeDelay = 200 * time.Millisecond

var (
	tagRE   = regexp.MustCompile(`(?s)<script.*?</script>|<style.*?</style>|<[^>]+>`)
	spaceRE = regexp.MustCompile(`\s+`)
	permRE  = regexp.MustCompile(`\b[a-z][a-zA-Z0-9]*\.[a-zA-Z0-9]+\.[a-zA-Z0-9]+\b`)

	tmplVarRE = regexp.MustCompile(`\{[^}=]+=([^}]+)\}`)
	anyVarRE  = regexp.MustCompile(`\{[^}]+\}`)

	markerRE = regexp.MustCompile(
		`(?i)(requires the following IAM permissions?|IAM Permissions|Required permissions|must have the|Requires the )`,
	)
	// iamHeadingRE starts a page's IAM section, as on BigQuery and Cloud
	// Storage reference pages.
	iamHeadingRE = regexp.MustCompile(
		`<h[23][^>]*\bid="(?:iam-permissions|required-permissions)"`,
	)
	sectionEndRE = regexp.MustCompile(`<h[23][\s>]|</section>`)
	// conditionalRE marks a sentence that makes a permission depend on the
	// request: "Requires X to cancel a job", "must also have X", "If ...".
	conditionalRE = regexp.MustCompile(
		`(?i)\b(?:if|when|whether|depending|also|additional|additionally|optional|optionally)\b|` +
			`permissions?\s+to\s+(?:cancel|update|delete|create|return|set|change|modify|read|write|list|get|run|access)\b|` +
			`^to\s+\w+`,
	)
	sentenceEndRE = regexp.MustCompile(`\.\s+`)

	rowRE  = regexp.MustCompile(`(?s)<tr[^>]*>(.*?)</tr>`)
	cellRE = regexp.MustCompile(`(?s)<t[dh][^>]*>(.*?)</t[dh]>`)

	gaVersionRE  = regexp.MustCompile(`^v\d+`)
	codeRE       = regexp.MustCompile(`(?s)<code[^>]*>(.*?)</code>`)
	customVerbRE = regexp.MustCompile(`:([a-zA-Z]+)$`)
)

// fetcher downloads public documentation with an on-disk cache, so a rerun
// does not refetch and every source can be inspected afterwards.
type fetcher struct {
	ctx    context.Context
	dir    string
	client *http.Client
	// extraRefs and extraAccess add reference roots and access-control
	// pages for APIs the built-in tables do not cover, keyed by API name.
	extraRefs   map[string]string
	extraAccess map[string]string
	// referenceRoot is where the IAM roles and permissions reference is
	// served; empty means docs.cloud.google.com.
	referenceRoot string
}

// page is a fetched page, as cached on disk.
type page struct {
	URL    string `json:"URL"` // final URL after redirects
	Status int    `json:"Status"`
	Body   string `json:"Body"`
}

type discoveryDoc struct {
	Name              string                       `json:"name"`
	Version           string                       `json:"version"`
	DocumentationLink string                       `json:"documentationLink"`
	ServicePath       string                       `json:"servicePath"`
	Resources         map[string]discoveryResource `json:"resources"`
	Methods           map[string]discoveryMethod   `json:"methods"`
}

type discoveryResource struct {
	Resources map[string]discoveryResource `json:"resources"`
	Methods   map[string]discoveryMethod   `json:"methods"`
}

type discoveryMethod struct {
	ID         string `json:"id"`
	HTTPMethod string `json:"httpMethod"`
	Path       string `json:"path"`
	FlatPath   string `json:"flatPath"`
}

// methodDoc is what the documentation says a method requires.
type methodDoc struct {
	Method   string   // discovery id
	Source   string   // URL the permissions came from
	Required []string // permissions stated as required
	// Mentioned are other permissions named alongside, such as ones needed
	// only for some requests, or the variants of a qualified table row.
	Mentioned []string
}

func (f *fetcher) get(url string) (page, error) {
	sum := sha256.Sum256([]byte(url))
	file := filepath.Join(f.dir, hex.EncodeToString(sum[:])+".json")
	if data, err := os.ReadFile(file); err == nil {
		var p page
		if json.Unmarshal(data, &p) == nil {
			return p, nil
		}
	}
	p, err := f.fetch(url)
	if err != nil {
		return page{}, err
	}
	if data, err := json.Marshal(p); err == nil {
		_ = os.WriteFile(file, data, 0o644)
	}
	return p, f.pause()
}

// fetch downloads url, following redirects.
func (f *fetcher) fetch(url string) (page, error) {
	req, err := http.NewRequestWithContext(f.ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return page{}, fmt.Errorf("fetching %s: %w", url, err)
	}
	req.Header.Set("User-Agent", "gcpperms-verifytable (documentation check)")
	resp, err := f.client.Do(req)
	if err != nil {
		return page{}, fmt.Errorf("fetching documentation: %w", err)
	}
	body, readErr := io.ReadAll(resp.Body)
	if err := errors.Join(readErr, resp.Body.Close()); err != nil {
		return page{}, fmt.Errorf("reading %s: %w", url, err)
	}
	return page{URL: resp.Request.URL.String(), Status: resp.StatusCode, Body: string(body)}, nil
}

// pause waits politeDelay after a request, or until the run is canceled.
func (f *fetcher) pause() error {
	t := time.NewTimer(politeDelay)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-f.ctx.Done():
		return fmt.Errorf("fetching documentation: %w", context.Cause(f.ctx))
	}
}

func text(htmlBody string) string {
	return spaceRE.ReplaceAllString(
		html.UnescapeString(tagRE.ReplaceAllString(htmlBody, " ")),
		" ",
	)
}

// perms returns the permission-shaped tokens in s, skipping host names.
func perms(s string) []string {
	var out []string
	for _, tok := range permRE.FindAllString(s, -1) {
		parts := strings.Split(tok, ".")
		if strings.Contains(tok, "googleapis") || strings.Contains(tok, "google.") ||
			parts[2] == "com" || parts[2] == "html" || unicode.IsUpper(rune(parts[0][0])) {
			continue
		}
		out = append(out, tok)
	}
	return out
}

// --- Check 1: permission names ---

// referenceSlug is the roles-and-permissions reference page for a
// permission prefix, which is the prefix unless the page is named
// differently.
func referenceSlug(prefix string) string {
	if prefix == "datastore" {
		return "firestore"
	}
	return prefix
}

// knownPermissions returns every permission listed on the IAM roles and
// permissions reference pages for the given prefixes, lowercased, plus the
// prefixes that have no reference page.
func (f *fetcher) knownPermissions(prefixes []string) (map[string]string, []string, error) {
	known := make(map[string]string)
	var missing []string
	root := f.referenceRoot
	if root == "" {
		root = "https://docs.cloud.google.com"
	}
	for _, prefix := range prefixes {
		p, err := f.get(root + "/iam/docs/roles-permissions/" + referenceSlug(prefix))
		if err != nil {
			return nil, nil, err
		}
		if p.Status != http.StatusOK {
			missing = append(missing, prefix)
			continue
		}
		for _, tok := range permRE.FindAllString(p.Body, -1) {
			known[strings.ToLower(tok)] = tok
		}
	}
	return known, missing, nil
}

// --- Check 2: method documentation ---

func (d *discoveryDoc) allMethods() []discoveryMethod {
	var out []discoveryMethod
	var walk func(map[string]discoveryResource)
	walk = func(rs map[string]discoveryResource) {
		for _, r := range rs {
			for _, m := range r.Methods {
				out = append(out, m)
			}
			walk(r.Resources)
		}
	}
	for _, m := range d.Methods {
		out = append(out, m)
	}
	walk(d.Resources)
	return out
}

func (f *fetcher) discovery(url string) (*discoveryDoc, error) {
	p, err := f.get(url)
	if err != nil {
		return nil, err
	}
	if p.Status != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, p.Status)
	}
	var d discoveryDoc
	if err := json.Unmarshal([]byte(p.Body), &d); err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	return &d, nil
}

// normPath reduces a google.api.http template or a discovery path to a
// comparable form in which every variable segment is "*".
func normPath(p string) string {
	p = strings.TrimPrefix(p, "/")
	p = tmplVarRE.ReplaceAllString(p, "$1")
	p = anyVarRE.ReplaceAllString(p, "*")
	return strings.ReplaceAll(p, "**", "*")
}

// methodFor finds the discovery method with the given verb and template.
func (d *discoveryDoc) methodFor(verb, tmpl string) (discoveryMethod, bool) {
	want := normPath(tmpl)
	for _, m := range d.allMethods() {
		p := m.FlatPath
		if p == "" {
			p = m.Path
		}
		if m.HTTPMethod == verb && normPath(d.ServicePath+p) == want {
			return m, true
		}
	}
	return discoveryMethod{}, false
}

// methodForCall finds the discovery method a generated REST call type sends.
func (d *discoveryDoc) methodForCall(callType string) (discoveryMethod, bool) {
	for _, m := range d.allMethods() {
		parts := strings.Split(m.ID, ".")[1:]
		var name strings.Builder
		for _, p := range parts {
			name.WriteString(strings.ToUpper(p[:1]) + p[1:])
		}
		if name.String()+"Call" == callType {
			return m, true
		}
	}
	return discoveryMethod{}, false
}

// referenceBase is the REST reference root of an API whose discovery
// documentationLink does not lead to its reference pages. Pages are
// {base}/{version}/{resource path}/{method}.
func referenceBase(api string) (string, bool) {
	const root = "https://docs.cloud.google.com/"
	switch api {
	case "artifactregistry":
		return root + "artifact-registry/docs/reference/rest", true
	case "cloudprofiler":
		// Like Trace: .../reference/v2/rest/v2/projects.profiles/create.
		return root + "profiler/docs/reference/v2/rest", true
	case "cloudtrace":
		// Trace keeps each API version's pages under its own reference
		// root: .../reference/v2/rest/v2/projects.traces/batchWrite.
		return root + "trace/docs/reference/v2/rest", true
	case "datastore":
		return root + "datastore/docs/reference/data/rest", true
	case "monitoring":
		return root + "monitoring/api/ref_v3/rest", true
	case "iamcredentials":
		return root + "iam/docs/reference/credentials/rest", true
	case "storage":
		return root + "storage/docs/json_api", true
	default:
		return "", false
	}
}

// referencePage finds the REST reference page for a discovery method.
func (f *fetcher) referencePage(d *discoveryDoc, m discoveryMethod) (page, error) {
	parts := strings.Split(m.ID, ".")
	method := parts[len(parts)-1]
	res := strings.Join(parts[1:len(parts)-1], ".")
	base, ok := referenceBase(d.Name)
	if !ok {
		base, ok = f.extraRefs[d.Name]
	}
	if !ok {
		link := strings.TrimSuffix(strings.TrimSuffix(d.DocumentationLink, "/"), "/docs")
		link = strings.Replace(link, "://cloud.google.com/", "://docs.cloud.google.com/", 1)
		base = link + "/docs/reference/rest"
	}
	u := base + "/" + d.Version + "/" + res + "/" + method
	p, err := f.get(u)
	if err != nil {
		return page{}, err
	}
	if p.Status != http.StatusOK || !strings.Contains(p.Body, method) {
		return page{}, fmt.Errorf(
			"no reference page for %s at %s (HTTP %d)",
			m.ID,
			u,
			p.Status,
		)
	}
	return p, nil
}

// iamBlocks returns the parts of a reference page that state permissions:
// the IAM section under its heading, and each parameter description that
// says "Authorization requires the following IAM permission", with the list
// that follows it. It returns nil for pages with neither.
func iamBlocks(body string) []string {
	blocks, sections := iamSections(body)
	return append(blocks, statementBlocks(body, sections)...)
}

// iamSections returns the IAM sections of a page, each from the end of its
// heading to the next heading or section end, and their byte ranges.
func iamSections(body string) (blocks []string, sections [][2]int) {
	for _, loc := range iamHeadingRE.FindAllStringIndex(body, -1) {
		start := loc[1]
		// Skip the heading itself, then stop at the next heading or section end.
		if i := strings.Index(body[start:], "</h"); i >= 0 {
			start += i + 3
		}
		end := len(body)
		if e := sectionEndRE.FindStringIndex(body[start:]); e != nil {
			end = start + e[0]
		}
		blocks = append(blocks, body[start:end])
		sections = append(sections, [2]int{start, end})
	}
	return blocks, sections
}

// statementBlocks returns each paragraph that says "following IAM
// permission", with the list that follows it, except those inside one of
// sections, which were read with the section.
func statementBlocks(body string, sections [][2]int) []string {
	inSection := func(at int) bool {
		for _, r := range sections {
			if at >= r[0] && at < r[1] {
				return true
			}
		}
		return false
	}
	var blocks []string
	for i := 0; ; {
		j := strings.Index(body[i:], "following IAM permission")
		if j < 0 {
			return blocks
		}
		at := i + j
		start, end, ok := statementAt(body, at)
		if !ok {
			return blocks
		}
		if !inSection(at) {
			blocks = append(blocks, body[start:end])
		}
		i = end
	}
}

// statementAt returns the byte range of the paragraph containing the
// statement at index at, extended over a list that directly follows it. It
// reports false when the paragraph does not end.
func statementAt(body string, at int) (start, end int, ok bool) {
	start = strings.LastIndex(body[:at], "<p")
	if start < 0 {
		start = at
	}
	end = strings.Index(body[at:], "</p>")
	if end < 0 {
		return 0, 0, false
	}
	end += at + len("</p>")
	// A list of permissions often follows the paragraph.
	if after := strings.TrimLeft(body[end:], " \n\t"); strings.HasPrefix(after, "<ul") {
		if k := strings.Index(after, "</ul>"); k >= 0 {
			end = len(body) - len(after) + k + len("</ul>")
		}
	}
	return start, end, true
}

// sentences splits text at sentence ends. Permission names contain dots
// but no spaces after them, so they stay whole.
func sentences(t string) []string {
	var out []string
	last := 0
	for _, loc := range sentenceEndRE.FindAllStringIndex(t, -1) {
		if loc[1] < len(t) && unicode.IsUpper(rune(t[loc[1]])) {
			out = append(out, t[last:loc[0]+1])
			last = loc[1]
		}
	}
	return append(out, t[last:])
}

// pagePermissions extracts what a reference page says a method requires.
// Permissions in a sentence that makes them depend on the request are only
// mentioned; the rest are required. It reads the page's IAM statements when
// it has them, and otherwise every sentence that looks like one.
func pagePermissions(body string) (required, mentioned []string) {
	blocks := iamBlocks(body)
	structured := len(blocks) > 0
	if !structured {
		blocks = []string{body}
	}
	for _, b := range blocks {
		// List items read as a comma-separated continuation of the
		// sentence that introduces them.
		t := text(strings.ReplaceAll(b, "</li>", ", </li>"))
		for _, s := range sentences(t) {
			if !structured && !markerRE.MatchString(s) {
				continue
			}
			ps := perms(s)
			mentioned = appendNew(mentioned, ps...)
			if !conditionalRE.MatchString(s) {
				required = appendNew(required, ps...)
			}
		}
	}
	return required, mentioned
}

// accessControlPage is the page documenting per-method permissions in a
// table for an API whose reference pages do not state them.
func accessControlPage(api string) (string, bool) {
	switch api {
	case "datastore":
		return "https://docs.cloud.google.com/datastore/docs/access/iam", true
	case "pubsub":
		return "https://docs.cloud.google.com/pubsub/docs/access-control", true
	default:
		return "", false
	}
}

// tablePermissions looks the method up in an access-control page's tables.
// The method is the first cell's code element; text after it, as in
// "commit for an insert", qualifies the row. An unqualified row gives
// required permissions; a qualified row gives a variant, which is only
// mentioned, since which variant applies depends on the request.
func tablePermissions(body string, names []string) (required, mentioned []string, found bool) {
	for _, row := range rowRE.FindAllStringSubmatch(body, -1) {
		cells := cellRE.FindAllStringSubmatch(row[1], -1)
		if len(cells) < 2 {
			continue
		}
		head, qualified := rowMethod(cells[0][1])
		var rest strings.Builder
		for _, c := range cells[1:] {
			rest.WriteString(" " + text(c[1]))
		}
		ps := perms(rest.String())
		// A row counts once for each name it matches.
		for _, n := range names {
			if !strings.EqualFold(head, n) {
				continue
			}
			found = true
			if !qualified {
				required = append(required, ps...)
			}
			mentioned = append(mentioned, ps...)
		}
	}
	return required, mentioned, found
}

// rowMethod returns the lowercased method a table row's first cell names,
// and whether text after it qualifies the row.
func rowMethod(first string) (head string, qualified bool) {
	head = first
	if c := codeRE.FindStringSubmatch(first); c != nil {
		head = c[1]
	}
	head = strings.ToLower(strings.TrimSpace(text(head)))
	whole := strings.TrimSpace(text(first))
	qualified = whole != strings.TrimSpace(text(head)) && !strings.EqualFold(whole, head)
	return head, qualified
}

// documentRPC returns what the documentation says rpc requires.
func (f *fetcher) documentRPC(p *program, rpc *RPC) (methodDoc, error) {
	d, m, api, err := f.findMethod(p, rpc)
	if err != nil {
		// A gRPC-only API has no discovery method, but may have an RPC
		// reference page.
		if doc, ok := f.rpcReferenceDoc(rpc); ok {
			return doc, nil
		}
		// Name the method even when it cannot be documented, so other
		// sources can be consulted for it.
		return methodDoc{Method: m.ID}, err
	}

	doc := methodDoc{Method: m.ID}
	pg, pageErr := f.referencePage(d, m)
	if pageErr == nil {
		doc.Source = pg.URL
		doc.Required, doc.Mentioned = pagePermissions(pg.Body)
	}
	if len(doc.Required)+len(doc.Mentioned) == 0 {
		if err := f.accessControlDoc(&doc, api, rpc, m); err != nil {
			return doc, err
		}
	}
	if len(doc.Required)+len(doc.Mentioned) == 0 {
		if pageErr != nil {
			return doc, fmt.Errorf("%s (%s): %w", rpc, m.ID, pageErr)
		}
		return doc, fmt.Errorf("%s (%s): %s states no permission", rpc, m.ID, pg.URL)
	}
	return doc, nil
}

// findMethod finds the discovery method an RPC is, and the API it belongs to.
func (f *fetcher) findMethod(p *program, rpc *RPC) (*discoveryDoc, discoveryMethod, string, error) {
	if rpc.Kind == "grpc" {
		return f.grpcMethod(p, rpc)
	}
	d, m, err := f.restMethod(rpc)
	return d, m, rpc.API, err
}

// rpcReferencePage is the RPC reference page of a gRPC-only API, one with no
// discovery document to map its methods to REST reference pages.
func rpcReferencePage(protoPkg string) (string, bool) {
	switch protoPkg {
	case "google.cloud.bigquery.storage.v1":
		return "https://docs.cloud.google.com/bigquery/docs/reference/storage/rpc/" + protoPkg, true
	default:
		return "", false
	}
}

// rpcReferenceDoc documents a gRPC method from its API's RPC reference page,
// for APIs rpcReferencePage lists.
func (f *fetcher) rpcReferenceDoc(rpc *RPC) (methodDoc, bool) {
	parts := strings.Split(rpc.GRPC, ".")
	if len(parts) < 3 {
		return methodDoc{}, false
	}
	method := parts[len(parts)-1]
	url, ok := rpcReferencePage(strings.Join(parts[:len(parts)-2], "."))
	if !ok {
		return methodDoc{}, false
	}
	pg, err := f.get(url)
	if err != nil || pg.Status != http.StatusOK {
		return methodDoc{}, false
	}
	required := rpcPermissions(text(pg.Body), method)
	if len(required) == 0 {
		return methodDoc{}, false
	}
	return methodDoc{Method: rpc.GRPC, Source: url, Required: required}, true
}

// rpcPermissions returns the permissions an RPC reference page's text
// requires for method: those its request message's fields state
// ("Authorization requires the following IAM permission ... : perm").
func rpcPermissions(t, method string) []string {
	heading := method + "Request Request message for " + method
	start := strings.Index(t, heading)
	if start < 0 {
		return nil
	}
	section := t[start+len(heading):]
	if end := strings.Index(section, " Request message for "); end >= 0 {
		// The next message starts with its name, just before this.
		section = section[:strings.LastIndex(section[:end], " ")+1]
	}
	if end := strings.Index(section, "Response message for "); end >= 0 {
		section = section[:end]
	}
	var out []string
	const lead = "Authorization requires the following IAM permission"
	for _, part := range strings.Split(section, lead)[1:] {
		// The permission is the first one after each statement.
		if ps := perms(part); len(ps) > 0 {
			out = appendNew(out, ps[0])
		}
	}
	return out
}

// grpcMethod finds the documented discovery method a gRPC method is bound
// to, and the API it belongs to. When none is found, the method returned
// carries only a guessed ID.
func (f *fetcher) grpcMethod(p *program, rpc *RPC) (*discoveryDoc, discoveryMethod, string, error) {
	verb, tmpl, host, version, err := p.httpRule(rpc.GRPC)
	if err != nil {
		return nil, discoveryMethod{}, "", err
	}
	if host == "" {
		return nil, discoveryMethod{}, "", fmt.Errorf(
			"%s: service has no default host",
			rpc.GRPC,
		)
	}
	api := strings.Split(host, ".")[0]
	// Pre-GA versions (v1alpha, v1beta) often have no reference pages;
	// fall back to the GA version of the same method, which documents
	// the same permission.
	versions := []string{version}
	if ga := gaVersionRE.FindString(version); ga != version {
		versions = append(versions, ga)
	}
	var lastErr error
	for _, v := range versions {
		t := strings.Replace(tmpl, "/"+version+"/", "/"+v+"/", 1)
		d, m, err := f.boundMethod(rpc, host, verb, t, v)
		if err == nil {
			return d, m, api, nil
		}
		lastErr = err
	}
	return nil, discoveryMethod{ID: guessMethodID(api, tmpl)}, api, lastErr
}

// boundMethod finds the discovery method of API version v with the given
// verb and path template, provided it has a reference page.
func (f *fetcher) boundMethod(
	rpc *RPC,
	host, verb, tmpl, v string,
) (*discoveryDoc, discoveryMethod, error) {
	d, err := f.discovery("https://" + host + "/$discovery/rest?version=" + v)
	if err != nil {
		return nil, discoveryMethod{}, err
	}
	m, ok := d.methodFor(verb, tmpl)
	if !ok {
		return nil, discoveryMethod{}, fmt.Errorf(
			"%s: no discovery method for %s %s",
			rpc.GRPC,
			verb,
			tmpl,
		)
	}
	if _, err := f.referencePage(d, m); err != nil {
		return nil, discoveryMethod{}, err
	}
	return d, m, nil
}

// restMethod finds the discovery method a generated REST call sends.
func (f *fetcher) restMethod(rpc *RPC) (*discoveryDoc, discoveryMethod, error) {
	d, err := f.discovery(
		"https://www.googleapis.com/discovery/v1/apis/" + rpc.API + "/" + rpc.Version + "/rest",
	)
	if err != nil {
		return nil, discoveryMethod{}, err
	}
	m, ok := d.methodForCall(rpc.CallType)
	if !ok {
		return nil, discoveryMethod{}, fmt.Errorf("%s: no discovery method for call type", rpc)
	}
	return d, m, nil
}

// accessControlDoc fills doc from the API's access-control page, if it has
// one that lists the method.
func (f *fetcher) accessControlDoc(doc *methodDoc, api string, rpc *RPC, m discoveryMethod) error {
	u, ok := accessControlPage(api)
	if !ok {
		u, ok = f.extraAccess[api]
	}
	if !ok {
		return nil
	}
	pg, err := f.get(u)
	if err != nil {
		return err
	}
	// Tables name methods by their last segment ("lookup") or by their
	// resource path ("projects.topics.publish").
	parts := strings.Split(m.ID, ".")
	var names []string
	for i := 1; i < len(parts); i++ {
		names = append(names, strings.Join(parts[i:], "."))
	}
	if rpc.Kind == "grpc" {
		names = append(names, rpc.GRPC[strings.LastIndex(rpc.GRPC, ".")+1:])
	}
	if req, men, found := tablePermissions(pg.Body, names); found {
		doc.Source, doc.Required, doc.Mentioned = u, req, men
	}
	return nil
}

// guessMethodID names the REST method a custom-verb HTTP binding would have
// in a discovery document: the API, the collection names in the path, and
// the verb, as in alloydb.projects.locations.clusters.generateClientCertificate
// for POST /v1alpha/{parent=projects/*/locations/*/clusters/*}:generateClientCertificate.
// It returns "" for standard methods, whose names cannot be read off the path.
func guessMethodID(api, tmpl string) string {
	m := customVerbRE.FindStringSubmatch(tmpl)
	if m == nil {
		return ""
	}
	parts := []string{api}
	for i, seg := range strings.Split(normPath(strings.TrimSuffix(tmpl, m[0])), "/") {
		if i == 0 || seg == "*" || seg == "" {
			continue // the version, and variable segments
		}
		parts = append(parts, seg)
	}
	return strings.Join(append(parts, m[1]), ".")
}

// appendNew appends the elements of add that list does not contain yet.
func appendNew(list []string, add ...string) []string {
	for _, a := range add {
		if !slices.Contains(list, a) {
			list = append(list, a)
		}
	}
	return list
}
