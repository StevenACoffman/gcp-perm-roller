package verifytable

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// iamDataset is a second opinion from a local clone of
// github.com/iann0036/iam-dataset, whose gcp/ directory maps REST
// discovery methods to permissions and lists every role's permissions.
//
// Its method map is cumulative and partly hand-written, so it is reported
// alongside the documentation, never instead of it. Each permission carries
// the methodologies that found it: "restcrawlv1" and "restcrawliamblockv1"
// come from crawling the same reference pages, possibly an older version
// of them, "fuzzv1" from calling the API, and "manual" from a person.
type iamDataset struct {
	methods map[string][]datasetPerm // REST method id -> permissions
	// restURLs and accessPages are per-API reference roots and
	// access-control pages, keyed by API name.
	restURLs    map[string]string
	accessPages map[string]string
	// roles maps lowercased permission names, from every predefined role,
	// to their canonical spelling.
	roles map[string]string
}

type datasetPerm struct {
	Name          string          `json:"name"`
	Methodologies []string        `json:"discoveryMethodologies"`
	Condition     json.RawMessage `json:"condition,omitempty"`
}

func (p datasetPerm) String() string {
	s := p.Name + " (" + strings.Join(p.Methodologies, ", ")
	if len(p.Condition) > 0 {
		s += "; only if " + string(p.Condition)
	}
	return s + ")"
}

// loadIAMDataset reads gcp/map.json and gcp/role_permissions.json from dir.
func loadIAMDataset(dir string) (*iamDataset, error) {
	var m struct {
		API map[string]struct {
			RestURL              string `json:"restUrl"`
			SourceURL            string `json:"sourceUrl"`
			SourceURLAuthoritive bool   `json:"sourceUrlAuthoritive"`
			Methods              map[string]struct {
				Permissions []datasetPerm `json:"permissions"`
			} `json:"methods"`
		} `json:"api"`
	}
	if err := readJSON(filepath.Join(dir, "gcp", "map.json"), &m); err != nil {
		return nil, err
	}
	var roles map[string]json.RawMessage
	if err := readJSON(filepath.Join(dir, "gcp", "role_permissions.json"), &roles); err != nil {
		return nil, err
	}
	d := &iamDataset{
		methods:     make(map[string][]datasetPerm),
		restURLs:    make(map[string]string),
		accessPages: make(map[string]string),
		roles:       make(map[string]string, len(roles)),
	}
	for api, a := range m.API {
		if a.RestURL != "" {
			d.restURLs[api] = docsHost(a.RestURL)
		}
		if a.SourceURL != "" && a.SourceURLAuthoritive {
			d.accessPages[api] = docsHost(a.SourceURL)
		}
		for id, meth := range a.Methods {
			d.methods[id] = meth.Permissions
		}
	}
	for p := range roles {
		d.roles[strings.ToLower(p)] = p
	}
	return d, nil
}

func readJSON(file string, v any) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("reading iam-dataset: %w", err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parsing %s: %w", file, err)
	}
	return nil
}

// docsHost moves a cloud.google.com documentation URL to the host it
// redirects to.
func docsHost(u string) string {
	return strings.Replace(
		strings.TrimSuffix(u, "/"),
		"://cloud.google.com/",
		"://docs.cloud.google.com/",
		1,
	)
}

// opinion returns the dataset's permissions for the methods, and those
// that disagree with granted: listed by the dataset but not granted, and
// granted but listed for none of the methods. Methods it has no entry for
// are returned as unknown.
func (d *iamDataset) opinion(
	methods []string,
	granted []string,
) (lines, datasetOnly, ruleOnly, unknown []string) {
	lines, listed, unknown := d.listed(methods)
	if len(lines) == 0 {
		return lines, nil, nil, unknown
	}
	grant := lowerSet(granted)
	for p := range listed {
		if !grant[p] {
			datasetOnly = append(datasetOnly, p)
		}
	}
	for p := range grant {
		if !listed[p] {
			ruleOnly = append(ruleOnly, p)
		}
	}
	sort.Strings(datasetOnly)
	sort.Strings(ruleOnly)
	return lines, datasetOnly, ruleOnly, unknown
}

// listed returns a line for each method the dataset has permissions for,
// the lowercased permissions it lists unconditionally, and the methods it
// has no entry for.
func (d *iamDataset) listed(
	methods []string,
) (lines []string, listed map[string]bool, unknown []string) {
	listed = make(map[string]bool)
	for _, id := range methods {
		perms, ok := d.methods[id]
		if !ok || len(perms) == 0 {
			unknown = append(unknown, id)
			continue
		}
		var ps []string
		for _, p := range perms {
			ps = append(ps, p.String())
			// Permissions that apply only to some requests are listed but
			// never counted as missing.
			if len(p.Condition) == 0 {
				listed[strings.ToLower(p.Name)] = true
			}
		}
		lines = append(lines, id+": "+strings.Join(ps, ", "))
	}
	return lines, listed, unknown
}
