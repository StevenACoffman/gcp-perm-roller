package gcpperms

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/cockroachdb/errors"
)

// analysisEntry is one result `gcloud asset analyze-iam-policy` prints: a
// binding of a policy attached to a resource, and the identities it grants
// access to, groups expanded with --expand-groups. The command lists a
// binding once per access control list it matches, so a binding can come
// more than once.
type analysisEntry struct {
	Policy struct {
		AttachedResource string  `json:"attachedResource"`
		Binding          Binding `json:"binding"`
	} `json:"policy"`
	ACLs []struct {
		Identities []struct {
			Name string `json:"name"`
		} `json:"identities"`
	} `json:"ACLs"`
}

// isAnalysis reports whether values, a file's JSON values, are what
// analyze-iam-policy prints: results with the resource their policy is
// attached to.
func isAnalysis(values []json.RawMessage) bool {
	if len(values) == 0 {
		return false
	}
	var e analysisEntry
	return json.Unmarshal(values[0], &e) == nil && e.Policy.AttachedResource != ""
}

// analysisBindings returns the bindings analyze-iam-policy's results
// values grant, each once, with the identities the analysis expanded its
// members to in Identities. The analysis must be of one project, run with
// --full-resource-name naming it, so that its bindings are the project's
// and its ancestors', as get-ancestors-iam-policy's are.
func analysisBindings(values []json.RawMessage) ([]Binding, error) {
	var (
		bindings []Binding
		project  string
	)
	for _, v := range values {
		var e analysisEntry
		if err := json.Unmarshal(v, &e); err != nil {
			return nil, errors.Wrap(err, "reading an analysis result")
		}
		b, err := e.binding()
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(b.Resource, "projects/") {
			if project != "" && project != b.Resource {
				return nil, errors.Errorf(
					"the analysis covers %s and %s; analyze one project, with "+
						"--full-resource-name=//cloudresourcemanager.googleapis.com/projects/ID",
					project, b.Resource,
				)
			}
			project, b.Resource = b.Resource, ""
		}
		bindings = mergeBinding(bindings, &b)
	}
	return bindings, nil
}

// binding returns e's binding, with the identities of all its access
// control lists, and the resource its policy is attached to as a relative
// name, such as "folders/123".
func (e *analysisEntry) binding() (Binding, error) {
	attached := e.Policy.AttachedResource
	if attached == "" {
		return Binding{}, errors.New(
			"a result has no attached resource; only the main analysis is read, " +
				"so run analyze-iam-policy without --analyze-service-account-impersonation",
		)
	}
	b := e.Policy.Binding
	b.Resource = strings.TrimPrefix(attached, "//cloudresourcemanager.googleapis.com/")
	for _, acl := range e.ACLs {
		for _, id := range acl.Identities {
			b.Identities = append(b.Identities, id.Name)
		}
	}
	return b, nil
}

// mergeBinding returns bindings with b added, or with b's identities added
// to the binding of the same resource, role, and condition.
func mergeBinding(bindings []Binding, b *Binding) []Binding {
	i := slices.IndexFunc(bindings, func(o Binding) bool {
		return o.Resource == b.Resource && o.Role == b.Role &&
			sameCondition(o.Condition, b.Condition)
	})
	if i < 0 {
		nb := *b
		nb.Identities = slices.Compact(slices.Sorted(slices.Values(b.Identities)))
		return append(bindings, nb)
	}
	out := slices.Clone(bindings)
	out[i].Identities = slices.Compact(slices.Sorted(slices.Values(
		slices.Concat(out[i].Identities, b.Identities),
	)))
	return out
}
