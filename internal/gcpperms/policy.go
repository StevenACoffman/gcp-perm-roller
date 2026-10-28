package gcpperms

import (
	"maps"
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

// Policy is an IAM allow policy, as `gcloud projects get-iam-policy`
// prints it. Fields this tool does not use, such as auditConfigs and etag,
// are ignored.
type Policy struct {
	Bindings []Binding `json:"bindings"`
}

// Binding grants one role to its members, under a condition when it has
// one.
type Binding struct {
	Role      string     `json:"role"`
	Members   []string   `json:"members"`
	Condition *Condition `json:"condition,omitempty"`
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
	// PredefinedRoles is set by the caller, from SelectRoles.
	PredefinedRoles *RoleSelection `json:"predefinedRoles,omitempty"`
}

// ParsePolicy parses a policy printed as YAML (gcloud's default) or as
// JSON (--format=json), which is YAML too.
func ParsePolicy(data []byte) (Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return Policy{}, errors.Wrap(err, "gcpperms.ParsePolicy")
	}
	return p, nil
}

// MemberBindings returns the bindings of p that name member, in policy
// order. member is written as in a policy, "user:x@example.com"; a bare
// email, with no type, matches a member of any type with that email.
// Members whose principal was deleted ("deleted:user:…") never match.
//
// A binding whose condition only limits time, as the Cloud Console's
// temporary access does, is Expired once now reaches the limit and
// Unconditional before it. Any other condition is Conditional.
func (p Policy) MemberBindings(member string, now time.Time) []HeldBinding {
	var out []HeldBinding
	for _, b := range p.Bindings {
		if !slices.ContainsFunc(b.Members, func(m string) bool { return isMember(m, member) }) {
			continue
		}
		out = append(out, HeldBinding{
			Role:      b.Role,
			Condition: b.Condition,
			State:     conditionState(b.Condition, now),
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
