package gcpperms

import (
	"bytes"
	"maps"
	"slices"
	"strings"

	"github.com/cockroachdb/errors"
)

// Propose returns p, as JSON, with member's replaced bindings swapped for
// unconditional grants of roles: member is removed from each binding in
// replaced (a binding left with no members is dropped) and added to each of
// roles. Every other binding and field, such as etag and auditConfigs, is
// kept as it was, so the result can be given to
// `gcloud iam simulator replay-recent-access` to see what the change
// would deny.
//
// member must have its type ("user:…"), since the new bindings name it.
// Only one resource's policy can be proposed: an ancestor's bindings are
// not in the project's policy.
func (p Policy) Propose(member string, roles []string, replaced []HeldBinding) ([]byte, error) {
	const op = "gcpperms.Policy.Propose"
	if p.raw == nil {
		return nil, errors.Errorf(
			"%s: only one resource's policy can be proposed, not get-ancestors-iam-policy output",
			op,
		)
	}
	if !strings.Contains(member, ":") {
		return nil, errors.Errorf("%s: member %q has no type, as in user:%s", op, member, member)
	}
	raw, _ := p.raw["bindings"].([]any)
	bindings := make([]any, 0, len(raw)+len(roles))
	// p.Bindings was parsed from raw, so the two are in the same order.
	for i, b := range p.Bindings {
		replace := slices.ContainsFunc(replaced, func(h HeldBinding) bool {
			return h.Role == b.Role && sameCondition(h.Condition, b.Condition)
		})
		if !replace {
			bindings = append(bindings, raw[i])
			continue
		}
		members := slices.DeleteFunc(slices.Clone(b.Members), func(m string) bool {
			return isMember(m, member)
		})
		if len(members) > 0 {
			bindings = append(bindings, withMembers(raw[i], members))
		}
	}
	for _, role := range roles {
		bindings = grant(bindings, role, member)
	}
	doc := maps.Clone(p.raw)
	doc["bindings"] = bindings
	var out bytes.Buffer
	if err := WriteJSON(&out, doc); err != nil {
		return nil, errors.Wrap(err, op)
	}
	return out.Bytes(), nil
}

// grant returns bindings with member granted role unconditionally: added
// to role's unconditional binding, or to a new one if role has none.
func grant(bindings []any, role, member string) []any {
	for i, rb := range bindings {
		b, ok := rb.(map[string]any)
		if !ok || b["role"] != role || b["condition"] != nil {
			continue
		}
		members := rawMembers(b)
		if slices.ContainsFunc(members, func(m string) bool { return isMember(m, member) }) {
			return bindings
		}
		out := slices.Clone(bindings)
		out[i] = withMembers(b, append(members, member))
		return out
	}
	return append(bindings, map[string]any{"role": role, "members": []any{member}})
}

// withMembers returns a copy of the raw binding rb with members.
func withMembers(rb any, members []string) map[string]any {
	b, _ := rb.(map[string]any)
	out := maps.Clone(b)
	list := make([]any, len(members))
	for i, m := range members {
		list[i] = m
	}
	out["members"] = list
	return out
}

// rawMembers returns the members of the raw binding b.
func rawMembers(b map[string]any) []string {
	list, _ := b["members"].([]any)
	members := make([]string, 0, len(list))
	for _, m := range list {
		if s, ok := m.(string); ok {
			members = append(members, s)
		}
	}
	return members
}

// sameCondition reports whether a and b are the same condition, or both
// absent.
func sameCondition(a, b *Condition) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
