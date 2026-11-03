package gcpperms

import (
	"cmp"
	"slices"
	"strings"
)

const (
	// noMatch: the principal is not the member.
	noMatch principalMatch = iota
	// mayMatch: the principal is a set, such as a group or a domain, that
	// the policy cannot say whether the member is in.
	mayMatch
	// sureMatch: the principal is the member, or everyone.
	sureMatch
)

// DenyRule is one rule of an IAM deny policy: the principals it denies the
// permissions to, less its exceptions, when its condition holds.
// Permissions are IAM v2 names (see V2Name), possibly with a "*" for the
// resource or the verb; principals are v2 identifiers, such as
// principal://goog/subject/ada@example.com.
type DenyRule struct {
	// Policy names the deny policy the rule is in: its display name, or its
	// ID when it has none.
	Policy               string     `json:"-"`
	DeniedPrincipals     []string   `json:"deniedPrincipals"`
	ExceptionPrincipals  []string   `json:"exceptionPrincipals,omitempty"`
	DeniedPermissions    []string   `json:"deniedPermissions"`
	ExceptionPermissions []string   `json:"exceptionPermissions,omitempty"`
	DenialCondition      *Condition `json:"denialCondition,omitempty"`
}

// Denial is a deny rule's effect on a permission a member holds.
type Denial struct {
	Permission string `json:"permission"`
	// Policy names the deny policy of the rule.
	Policy string `json:"policy"`
	// Certain is set when the rule denies the permission whatever the
	// request. Otherwise the rule may deny it, for Reason.
	Certain bool   `json:"certain"`
	Reason  string `json:"reason,omitempty"`
}

// principalMatch is how surely a deny rule's principal is a member.
type principalMatch int

// ApplyDenials returns access with p's deny rules applied, leaving access
// itself as it was: permissions a rule certainly denies are taken out of
// its permissions, and each permission a
// rule denies or may deny gets a Denial, the most certain one, sorted by
// permission. It also records how many deny policies p has.
//
// A rule may deny a permission, rather than certainly deny it, when it has
// a condition (which can only test resource tags, which a policy does not
// show), names a set of principals the member may be in, such as a group,
// or makes an exception for such a set.
func (p Policy) ApplyDenials(access *MemberAccess) MemberAccess {
	a := *access
	a.DenyPolicies = p.DenyPolicies
	held := slices.Concat(a.Permissions, a.ConditionalPermissions)
	var denials []Denial
	for _, perm := range held {
		if d, ok := denial(perm, a.Member, p.DenyRules); ok {
			denials = append(denials, d)
		}
	}
	slices.SortFunc(
		denials,
		func(x, y Denial) int { return cmp.Compare(x.Permission, y.Permission) },
	)
	denied := func(perm string) bool {
		i, found := slices.BinarySearchFunc(denials, perm, func(d Denial, p string) int {
			return cmp.Compare(d.Permission, p)
		})
		return found && denials[i].Certain
	}
	a.Permissions = slices.DeleteFunc(slices.Clone(a.Permissions), denied)
	a.ConditionalPermissions = slices.DeleteFunc(slices.Clone(a.ConditionalPermissions), denied)
	a.Denials = denials
	return a
}

// V2Name returns the IAM v2 name of the v1 permission perm, as deny
// policies write permissions: its service's domain, a "/", and the rest,
// so iam.roles.delete is iam.googleapis.com/roles.delete. A few services'
// domains are not their v1 name (resourcemanager.projects.delete is
// cloudresourcemanager.googleapis.com/projects.delete); deny_names.go,
// generated from Google's list of permissions deny policies support, has
// those.
func V2Name(perm string) string {
	if name, ok := denyNames[perm]; ok {
		return name
	}
	service, rest, _ := strings.Cut(perm, ".")
	return service + ".googleapis.com/" + rest
}

// denial returns the most certain effect rules have on member's perm, and
// whether any rule has one.
func denial(perm, member string, rules []DenyRule) (Denial, bool) {
	v2 := V2Name(perm)
	var best Denial
	var found bool
	for _, r := range rules {
		reasons, applies := r.effect(v2, member)
		if !applies {
			continue
		}
		d := Denial{
			Permission: perm,
			Policy:     r.Policy,
			Certain:    len(reasons) == 0,
			Reason:     strings.Join(reasons, "; "),
		}
		if d.Certain {
			return d, true
		}
		if !found {
			best, found = d, true
		}
	}
	return best, found
}

// effect reports whether r denies, or may deny, member the v2 permission
// v2, and why it only may: no reasons means r certainly denies it.
func (r *DenyRule) effect(v2, member string) (reasons []string, applies bool) {
	if !matchesAny(r.DeniedPermissions, v2) || matchesAny(r.ExceptionPermissions, v2) {
		return nil, false
	}
	switch bestMatch(r.DeniedPrincipals, member) {
	case noMatch:
		return nil, false
	case mayMatch:
		reasons = append(reasons, "denied to a set of principals the member may be in")
	case sureMatch:
	}
	switch bestMatch(r.ExceptionPrincipals, member) {
	case sureMatch:
		return nil, false
	case mayMatch:
		reasons = append(reasons, "except for a set of principals the member may be in")
	case noMatch:
	}
	if r.DenialCondition != nil {
		reasons = append(reasons, "only when "+r.DenialCondition.Name()+" holds")
	}
	return reasons, true
}

// matchesAny reports whether any of patterns matches the v2 permission
// name v2. A pattern is a v2 name, or a permission group with "*" for the
// resource, the verb, or both.
func matchesAny(patterns []string, v2 string) bool {
	service, rest, _ := strings.Cut(v2, "/")
	resource, verb, _ := strings.Cut(rest, ".")
	return slices.ContainsFunc(patterns, func(pattern string) bool {
		pService, pRest, _ := strings.Cut(pattern, "/")
		pResource, pVerb, _ := strings.Cut(pRest, ".")
		return strings.EqualFold(pService, service) &&
			(pResource == "*" || strings.EqualFold(pResource, resource)) &&
			(pVerb == "*" || strings.EqualFold(pVerb, verb))
	})
}

// bestMatch returns how surely any of the deny rule principals is member,
// a member as an allow policy writes it ("user:ada@example.com"), or a
// bare email.
func bestMatch(principals []string, member string) principalMatch {
	best := noMatch
	for _, p := range principals {
		best = max(best, matchPrincipal(p, member))
	}
	return best
}

// matchPrincipal returns how surely the v2 principal identifier principal
// is member.
func matchPrincipal(principal, member string) principalMatch {
	if principal == "principalSet://goog/public:all" {
		return sureMatch
	}
	kind := principalKind(principal)
	if kind == "" {
		// A set this cannot resolve, such as a domain or a workforce pool,
		// may hold anyone; any other principal is the member only if it is
		// written the same way, as a workforce identity can be in an allow
		// policy.
		if strings.HasPrefix(principal, "principalSet://") {
			return mayMatch
		}
		if strings.EqualFold(principal, member) {
			return sureMatch
		}
		return noMatch
	}
	email := principal[strings.LastIndex(principal, "/")+1:]
	if isMember(kind+":"+email, member) {
		return sureMatch
	}
	if kind == "group" {
		// Users, service accounts, and groups can all be in a group.
		return mayMatch
	}
	return noMatch
}

// principalKind returns the allow-policy member type ("user",
// "serviceAccount", or "group") of the v2 principal identifier principal,
// whose email ends it, or "" for any other identifier.
func principalKind(principal string) string {
	switch {
	case strings.HasPrefix(principal, "principal://goog/subject/"):
		return "user"
	case strings.HasPrefix(principal, "principal://iam.googleapis.com/projects/") &&
		strings.Contains(principal, "/serviceAccounts/"):
		return "serviceAccount"
	case strings.HasPrefix(principal, "principalSet://goog/group/"):
		return "group"
	}
	return ""
}
