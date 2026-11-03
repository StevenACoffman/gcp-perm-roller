package gcpperms

import (
	"bytes"
	"cmp"
	"encoding/json"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"sigs.k8s.io/yaml"
)

const (
	// Unconditional bindings always apply.
	Unconditional ConditionState = "unconditional"
	// Conditional bindings apply only when their condition holds, which
	// depends on the request, so they may apply.
	Conditional ConditionState = "conditional"
	// Expired bindings had a time limit that has passed, so they never
	// apply again.
	Expired ConditionState = "expired"
)

// expiryRE matches the condition the Cloud Console writes for temporary
// access, `request.time < timestamp("2026-07-01T07:00:00.000Z")`, capturing
// the comparison and the time.
var expiryRE = regexp.MustCompile(`^request\.time\s*(<=?)\s*timestamp\(\s*"([^"]+)"\s*\)$`)

// ConditionState says whether the role a member holds through a binding
// applies.
type ConditionState string

// Policy is the IAM allow policy a member's roles are read from: one
// resource's, as `gcloud projects get-iam-policy` prints it, or a project's
// together with its folders' and organization's, as
// `gcloud projects get-ancestors-iam-policy` prints them. Fields this tool
// does not use, such as auditConfigs and etag, are ignored.
type Policy struct {
	Bindings []Binding `json:"bindings"`
	// DenyPolicies is the number of deny policies read with the allow
	// policies (get-ancestors-iam-policy --include-deny). They are counted
	// so a report can say they exist; they are not applied.
	DenyPolicies int `json:"-"`
	// DenyRules are the rules of those deny policies, which ApplyDenials
	// applies.
	DenyRules []DenyRule `json:"-"`
	// raw is the policy as read, for Propose to change; nil unless it is
	// one resource's policy.
	raw map[string]any
}

// Binding grants one role to its members, under a condition when it has
// one.
type Binding struct {
	Role      string     `json:"role"`
	Members   []string   `json:"members"`
	Condition *Condition `json:"condition,omitempty"`
	// Resource is the folder or organization the binding is inherited
	// from, such as "folders/123"; empty for a binding on the project, or
	// on the one resource a policy was read for.
	Resource string `json:"-"`
	// Identities are who the binding grants its role to, its groups
	// expanded, when it was read from analyze-iam-policy output.
	Identities []string `json:"-"`
}

// ancestorEntry is one policy get-ancestors-iam-policy prints: an allow
// policy, or with --include-deny a deny policy, of the project or one of
// its ancestors.
type ancestorEntry struct {
	Type   string          `json:"type"`
	ID     string          `json:"id"`
	Policy json.RawMessage `json:"policy"`
}

// policyDocument is an allow policy or, when Kind says so or it has Rules,
// an IAM v2 deny policy.
type policyDocument struct {
	Bindings    []Binding `json:"bindings"`
	Kind        string    `json:"kind"`
	Name        string    `json:"name"`
	DisplayName string    `json:"displayName"`
	Rules       []struct {
		DenyRule *DenyRule `json:"denyRule"`
	} `json:"rules"`
}

// Condition is an IAM condition: a CEL expression that must hold for the
// binding to apply.
type Condition struct {
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Expression  string `json:"expression"`
}

// HeldBinding is a role a member holds through one binding, and whether it
// applies.
type HeldBinding struct {
	Role      string         `json:"role"`
	Condition *Condition     `json:"condition,omitempty"`
	State     ConditionState `json:"state"`
	// Resource is where the binding is inherited from, as in Binding.
	Resource string `json:"resource,omitempty"`
	// Through are the groups in the binding that the member holds the role
	// through, when an analysis says it does but the binding does not name
	// it.
	Through []string `json:"through,omitempty"`
}

// MemberAccess is what one member holds in a policy: its bindings, the
// permissions they grant, and the predefined roles that grant those.
type MemberAccess struct {
	Member   string        `json:"member"`
	Bindings []HeldBinding `json:"bindings"`
	// Permissions are granted by the member's unconditional bindings.
	Permissions []string `json:"permissions"`
	// ConditionalPermissions are granted only by conditional bindings.
	ConditionalPermissions []string `json:"conditionalPermissions,omitempty"`
	// DenyPolicies and Denials are set by Policy.ApplyDenials: how many
	// deny policies there are, and how they deny or may deny the member's
	// permissions. Permissions certainly denied are not in Permissions or
	// ConditionalPermissions.
	DenyPolicies int      `json:"denyPolicies,omitempty"`
	Denials      []Denial `json:"denials,omitempty"`
	// PredefinedRoles is set by the caller, from SelectRoles.
	PredefinedRoles *RoleSelection `json:"predefinedRoles,omitempty"`
}

// ParsePolicy parses what `gcloud projects get-iam-policy` or
// `gcloud projects get-ancestors-iam-policy` prints, in YAML (gcloud's
// default) or JSON (--format=json, which is YAML too); it tells them apart
// itself. Ancestors' bindings come after the project's, each marked with
// the resource it is inherited from. Deny policies are counted, not read.
func ParsePolicy(data []byte) (Policy, error) {
	const op = "gcpperms.ParsePolicy"
	values, err := jsonValues(data)
	if err != nil {
		return Policy{}, errors.Wrap(err, op)
	}
	if isAnalysis(values) {
		bindings, err := analysisBindings(values)
		if err != nil {
			return Policy{}, errors.Wrap(err, op)
		}
		return Policy{Bindings: bindings}, nil
	}
	entries, err := policyEntries(values)
	if err != nil {
		return Policy{}, errors.Wrap(err, op)
	}
	p, err := entriesPolicy(entries)
	if err != nil {
		return Policy{}, errors.Wrap(err, op)
	}
	return p, nil
}

// entriesPolicy returns the policy entries make up: their bindings, marked
// with where they are inherited from, and their deny rules. One resource's
// policy is also kept as read, for Propose.
func entriesPolicy(entries []ancestorEntry) (Policy, error) {
	var p Policy
	for _, e := range entries {
		resource, err := e.resource()
		if err != nil {
			return Policy{}, err
		}
		if err := p.add(e.Policy, resource); err != nil {
			if e.Type != "" {
				err = errors.Wrapf(err, "%s %s", e.Type, e.ID)
			}
			return Policy{}, err
		}
	}
	if len(entries) == 1 && entries[0].Type == "" {
		if err := json.Unmarshal(entries[0].Policy, &p.raw); err != nil {
			return Policy{}, errors.Wrap(err, "reading a policy")
		}
	}
	return p, nil
}

// MemberBindings returns the bindings of p that name member, in policy
// order, or that an analysis says grant it their role through a group.
// member is written as in a policy, "user:x@example.com"; a bare email,
// with no type, matches a member of any type with that email. Members
// whose principal was deleted ("deleted:user:…") never match.
//
// A binding whose condition only limits time, as the Cloud Console's
// temporary access does, is Expired once now reaches the limit and
// Unconditional before it. Any other condition is Conditional.
func (p Policy) MemberBindings(member string, now time.Time) []HeldBinding {
	var out []HeldBinding
	is := func(m string) bool { return isMember(m, member) }
	for _, b := range p.Bindings {
		direct := slices.ContainsFunc(b.Members, is)
		if !direct && !slices.ContainsFunc(b.Identities, is) {
			continue
		}
		var through []string
		if !direct {
			// The groups the analysis expanded to identities are the ones
			// the member may be in; a group it did not expand is not.
			through = slices.DeleteFunc(slices.Clone(b.Members), func(m string) bool {
				return !strings.HasPrefix(m, "group:") || !slices.Contains(b.Identities, m)
			})
		}
		out = append(out, HeldBinding{
			Role:      b.Role,
			Condition: b.Condition,
			State:     conditionState(b.Condition, now),
			Resource:  b.Resource,
			Through:   through,
		})
	}
	return out
}

// NewMemberAccess returns what member holds through bindings, with the
// permissions of each binding's role taken from roles. It also returns the
// roles of applicable bindings that roles does not define, sorted; while
// any are missing, the permissions are incomplete. Expired bindings grant
// nothing.
func NewMemberAccess(
	member string,
	bindings []HeldBinding,
	roles []Role,
) (access MemberAccess, missing []string) {
	byName := make(map[string]*Role, len(roles))
	for i := range roles {
		byName[roles[i].Name] = &roles[i]
	}
	always, sometimes := map[string]bool{}, map[string]bool{}
	for _, b := range bindings {
		if b.State == Expired {
			continue
		}
		r := byName[b.Role]
		if r == nil {
			missing = append(missing, b.Role)
			continue
		}
		// A state other than Unconditional, even an unknown one, may not
		// apply, so it never makes a permission unconditional.
		granted := sometimes
		if b.State == Unconditional {
			granted = always
		}
		for _, perm := range r.Permissions {
			granted[perm] = true
		}
	}
	for perm := range always {
		delete(sometimes, perm)
	}
	return MemberAccess{
		Member:                 member,
		Bindings:               bindings,
		Permissions:            slices.Sorted(maps.Keys(always)),
		ConditionalPermissions: slices.Sorted(maps.Keys(sometimes)),
	}, slices.Compact(slices.Sorted(slices.Values(missing)))
}

// Required returns the permissions a role selection for a must grant:
// those a holds unconditionally and, with includeConditional, those it
// holds under conditions too. Covered returns the bindings they come from.
func (a *MemberAccess) Required(includeConditional bool) []string {
	if !includeConditional {
		return a.Permissions
	}
	return append(slices.Clone(a.Permissions), a.ConditionalPermissions...)
}

// Covered returns the bindings a role selection made for
// Required(includeConditional) stands in for: those that apply
// unconditionally and, with includeConditional, those under conditions
// too. Expired bindings grant nothing, so they are never covered.
func (a *MemberAccess) Covered(includeConditional bool) []HeldBinding {
	var out []HeldBinding
	for _, b := range a.Bindings {
		if b.State == Unconditional || (includeConditional && b.State == Conditional) {
			out = append(out, b)
		}
	}
	return out
}

// Name returns c's title, or its expression when it has none.
func (c *Condition) Name() string {
	if c.Title != "" {
		return c.Title
	}
	return c.Expression
}

// add appends the bindings of the allow policy doc, inherited from
// resource, to p, or counts doc if it is a deny policy.
func (p *Policy) add(doc []byte, resource string) error {
	var d policyDocument
	if err := json.Unmarshal(doc, &d); err != nil {
		return errors.Wrap(err, "reading a policy")
	}
	if d.Kind == "DenyPolicy" || len(d.Rules) > 0 {
		p.DenyPolicies++
		// A deny policy's name ends in its ID, which names it well enough.
		name := cmp.Or(d.DisplayName, path.Base(d.Name))
		for _, r := range d.Rules {
			if r.DenyRule != nil {
				rule := *r.DenyRule
				rule.Policy = name
				p.DenyRules = append(p.DenyRules, rule)
			}
		}
		return nil
	}
	for _, b := range d.Bindings {
		b.Resource = resource
		p.Bindings = append(p.Bindings, b)
	}
	return nil
}

// resource names where e's bindings are inherited from: empty for the
// project itself, or for one resource's policy, which has no Type;
// "folders/ID" or "organizations/ID" for an ancestor.
func (e ancestorEntry) resource() (string, error) {
	switch e.Type {
	case "", "project":
		return "", nil
	case "folder":
		return "folders/" + e.ID, nil
	case "organization":
		return "organizations/" + e.ID, nil
	}
	return "", errors.Errorf("unknown ancestor type %q of %s", e.Type, e.ID)
}

// policyEntries returns the policies in values, the JSON values of a YAML
// or JSON file, as get-ancestors-iam-policy entries. That command prints a
// list of them (--format=json) or one YAML document per entry; a file
// holding one resource's policy becomes an entry with no Type, and must
// hold nothing else.
func policyEntries(values []json.RawMessage) ([]ancestorEntry, error) {
	entries := make([]ancestorEntry, 0, len(values))
	for _, v := range values {
		var e ancestorEntry
		if err := json.Unmarshal(v, &e); err != nil {
			return nil, errors.Wrap(err, "reading a policy")
		}
		if e.Type == "" || e.Policy == nil {
			e = ancestorEntry{Policy: v}
		}
		entries = append(entries, e)
	}
	if len(entries) > 1 && slices.ContainsFunc(entries, func(e ancestorEntry) bool {
		return e.Type == ""
	}) {
		return nil, errors.New(
			"the file holds more than one policy, and is not get-ancestors-iam-policy output",
		)
	}
	return entries, nil
}

// jsonValues returns the values in data, YAML or JSON, as JSON: one per
// YAML document, and one per element of a document that is a list, as
// gcloud prints a list with --format=json. Empty documents have none.
func jsonValues(data []byte) ([]json.RawMessage, error) {
	var values []json.RawMessage
	for _, doc := range yamlDocuments(data) {
		js, err := yaml.YAMLToJSON(doc)
		if err != nil {
			return nil, errors.Wrap(err, "reading YAML")
		}
		js = bytes.TrimSpace(js)
		switch {
		case len(js) == 0 || string(js) == "null":
			continue
		case js[0] == '[':
			var list []json.RawMessage
			if err := json.Unmarshal(js, &list); err != nil {
				return nil, errors.Wrap(err, "reading a list")
			}
			values = append(values, list...)
		default:
			values = append(values, js)
		}
	}
	return values, nil
}

// yamlDocuments splits data at YAML's document separators, lines that are
// "---", as gcloud prints between the items of a list. A YAML scalar
// cannot hold such a line, so splitting needs no parsing.
func yamlDocuments(data []byte) [][]byte {
	var (
		docs [][]byte
		cur  []byte
	)
	for line := range bytes.Lines(data) {
		if string(bytes.TrimRight(line, " \t\r\n")) == "---" {
			docs = append(docs, cur)
			cur = nil
			continue
		}
		cur = append(cur, line...)
	}
	return append(docs, cur)
}

// isMember reports whether the policy member m is member, or has the bare
// email member.
func isMember(m, member string) bool {
	if strings.HasPrefix(m, "deleted:") {
		return false
	}
	if strings.Contains(member, ":") {
		return strings.EqualFold(m, member)
	}
	_, id, _ := strings.Cut(m, ":")
	return strings.EqualFold(id, member)
}

// conditionState is the state of a binding with condition c at now.
func conditionState(c *Condition, now time.Time) ConditionState {
	if c == nil {
		return Unconditional
	}
	m := expiryRE.FindStringSubmatch(strings.TrimSpace(c.Expression))
	if m == nil {
		return Conditional
	}
	limit, err := time.Parse(time.RFC3339, m[2])
	if err != nil {
		return Conditional
	}
	// "<" stops applying at the limit; "<=" just after it.
	if now.After(limit) || (m[1] == "<" && now.Equal(limit)) {
		return Expired
	}
	return Unconditional
}
