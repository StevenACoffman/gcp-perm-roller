package gcpperms

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// policyNow is a time after the fixture's past expiry and before its
// future one.
var policyNow = time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)

func readPolicy(t *testing.T, name string) Policy {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "policy", name))
	ok(t, err)
	p, err := ParsePolicy(data)
	ok(t, err)
	return p
}

func TestParsePolicy(t *testing.T) {
	yamlPolicy := readPolicy(t, "policy.yaml")
	// spec: gcloud's YAML and its --format=json output parse the same.
	equals(t, readPolicy(t, "policy.json"), yamlPolicy)
	equals(t, len(yamlPolicy.Bindings), 6)
	equals(t, yamlPolicy.Bindings[2].Condition, &Condition{
		Title:       "Temp access 90 days",
		Description: "Assigned 4.1.2026",
		Expression:  `request.time < timestamp("2026-07-01T07:00:00.000Z")`,
	})

	for name, data := range map[string]string{
		"not YAML":          "bindings: [",
		"bindings not list": "bindings: 3",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePolicy([]byte(data)); err == nil {
				t.Fatal("parsed a bad policy")
			}
		})
	}
}

func TestMemberBindings(t *testing.T) {
	p := readPolicy(t, "policy.yaml")
	held := func(role string, state ConditionState) HeldBinding {
		for _, b := range p.Bindings {
			if b.Role == role {
				return HeldBinding{Role: role, Condition: b.Condition, State: state}
			}
		}
		t.Fatalf("no binding for %s", role)
		return HeldBinding{}
	}
	ada := []HeldBinding{
		held("roles/datastore.user", Unconditional),
		held("projects/demo/roles/CustomRole1", Unconditional),
		held("roles/pubsub.publisher", Expired),
		held("roles/secretmanager.secretAccessor", Unconditional),
		held("roles/storage.objectViewer", Conditional),
	}
	tests := map[string]struct {
		member string
		want   []HeldBinding
	}{
		"a user":               {member: "user:ada@example.com", want: ada},
		"case does not matter": {member: "user:Ada@Example.com", want: ada},
		// spec: a bare email matches any member type with that email.
		"a bare email": {member: "ada@example.com", want: ada},
		"a group": {
			member: "group:eng@example.com",
			want:   []HeldBinding{held("roles/datastore.user", Unconditional)},
		},
		"a service account": {
			member: "serviceAccount:app@demo.iam.gserviceaccount.com",
			want:   []HeldBinding{held("roles/owner", Unconditional)},
		},
		// spec: the type must match when given; a deleted principal never
		// matches, so ada does not hold roles/owner.
		"another type":  {member: "serviceAccount:ada@example.com"},
		"nobody":        {member: "user:bob@example.com"},
		"a prefix only": {member: "user:ada"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			equals(t, p.MemberBindings(tc.member, policyNow), tc.want)
		})
	}
}

func TestConditionState(t *testing.T) {
	limit := time.Date(2026, 7, 1, 7, 0, 0, 0, time.UTC)
	tests := map[string]struct {
		cond *Condition
		now  time.Time
		want ConditionState
	}{
		"no condition": {now: limit, want: Unconditional},
		"before the limit": {
			cond: &Condition{Expression: `request.time < timestamp("2026-07-01T07:00:00Z")`},
			now:  limit.Add(-time.Second),
			want: Unconditional,
		},
		// spec: "<" stops applying at the limit, "<=" only after it.
		"at the limit": {
			cond: &Condition{Expression: `request.time < timestamp("2026-07-01T07:00:00Z")`},
			now:  limit,
			want: Expired,
		},
		"at the limit, inclusive": {
			cond: &Condition{Expression: `request.time <= timestamp("2026-07-01T07:00:00Z")`},
			now:  limit,
			want: Unconditional,
		},
		"after the limit, inclusive": {
			cond: &Condition{Expression: `request.time<=timestamp( "2026-07-01T07:00:00Z" )`},
			now:  limit.Add(time.Second),
			want: Expired,
		},
		"surrounding space": {
			cond: &Condition{Expression: "  request.time < timestamp(\"2026-07-01T07:00:00Z\")\n"},
			now:  limit,
			want: Expired,
		},
		// spec: anything more than a time limit depends on the request.
		"a time limit and more": {
			cond: &Condition{
				Expression: `request.time < timestamp("2026-07-01T07:00:00Z") && ` +
					`resource.type == "storage.googleapis.com/Bucket"`,
			},
			now:  limit,
			want: Conditional,
		},
		"a start time": {
			cond: &Condition{Expression: `request.time > timestamp("2026-07-01T07:00:00Z")`},
			now:  limit,
			want: Conditional,
		},
		"a bad time": {
			cond: &Condition{Expression: `request.time < timestamp("July 1")`},
			now:  limit,
			want: Conditional,
		},
		"a resource condition": {
			cond: &Condition{Expression: `resource.name.startsWith("x")`},
			now:  limit,
			want: Conditional,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			equals(t, conditionState(tc.cond, tc.now), tc.want)
		})
	}
}

func TestNewMemberAccess(t *testing.T) {
	roles := []Role{
		{Name: "roles/a", Permissions: []string{"a.x.get", "shared.x.get"}},
		{Name: "roles/b", Permissions: []string{"b.x.get", "shared.x.get"}},
		{Name: "roles/c", Permissions: []string{"c.x.get"}},
	}
	tests := map[string]struct {
		bindings    []HeldBinding
		wantPerms   []string
		wantCond    []string
		wantMissing []string
	}{
		"nothing": {},
		"one role": {
			bindings:  []HeldBinding{{Role: "roles/a", State: Unconditional}},
			wantPerms: []string{"a.x.get", "shared.x.get"},
		},
		// spec: a permission also granted unconditionally is not
		// conditional.
		"conditional beside unconditional": {
			bindings: []HeldBinding{
				{Role: "roles/a", State: Unconditional},
				{Role: "roles/b", State: Conditional},
			},
			wantPerms: []string{"a.x.get", "shared.x.get"},
			wantCond:  []string{"b.x.get"},
		},
		// spec: an unknown state, such as the zero value, may not apply.
		"unknown state": {
			bindings: []HeldBinding{{Role: "roles/c"}},
			wantCond: []string{"c.x.get"},
		},
		// spec: an expired binding grants nothing, and its role need not
		// be defined.
		"expired": {
			bindings: []HeldBinding{
				{Role: "roles/c", State: Expired},
				{Role: "projects/p/roles/gone", State: Expired},
			},
		},
		// spec: every undefined role is reported once, sorted.
		"missing roles": {
			bindings: []HeldBinding{
				{Role: "projects/p/roles/z", State: Unconditional},
				{Role: "roles/a", State: Unconditional},
				{Role: "projects/p/roles/y", State: Conditional},
				{Role: "projects/p/roles/z", State: Conditional},
			},
			wantPerms:   []string{"a.x.get", "shared.x.get"},
			wantMissing: []string{"projects/p/roles/y", "projects/p/roles/z"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			access, missing := NewMemberAccess("user:x", tc.bindings, roles)
			equals(t, access, MemberAccess{
				Member:                 "user:x",
				Bindings:               tc.bindings,
				Permissions:            tc.wantPerms,
				ConditionalPermissions: tc.wantCond,
			})
			equals(t, missing, tc.wantMissing)
		})
	}
}
