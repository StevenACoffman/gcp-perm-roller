package gcpperms

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/golden/proposed.json from this run")

func TestRequiredAndCovered(t *testing.T) {
	access := goldenMemberAccess(t)
	// The checks below mean something only with permissions of both kinds.
	if len(access.Permissions) == 0 || len(access.ConditionalPermissions) == 0 {
		t.Fatalf("the fixture grants %v, and %v under conditions",
			access.Permissions, access.ConditionalPermissions)
	}
	roles := func(bs []HeldBinding) []string {
		var out []string
		for _, b := range bs {
			out = append(out, b.Role)
		}
		return out
	}
	// spec: the required permissions add the conditional ones only when
	// asked, as the covered bindings add the conditional bindings.
	equals(t, access.Required(false), access.Permissions)
	equals(t, access.Required(true), append(
		slices.Clone(access.Permissions), access.ConditionalPermissions...,
	))
	// spec: unconditional and temporary bindings are covered; conditional
	// ones only when asked; expired ones never.
	equals(t, roles(access.Covered(false)), []string{
		"roles/datastore.user",
		"projects/demo/roles/CustomRole1",
		"roles/secretmanager.secretAccessor",
	})
	equals(t, roles(access.Covered(true)), []string{
		"roles/datastore.user",
		"projects/demo/roles/CustomRole1",
		"roles/secretmanager.secretAccessor",
		"roles/storage.objectViewer",
	})
}

func TestPropose(t *testing.T) {
	const ada = "user:ada@example.com"
	p := readPolicy(t, "policy.yaml")
	access, _ := NewMemberAccess(ada, p.MemberBindings(ada, policyNow), nil)
	got, err := p.Propose(
		ada,
		[]string{"roles/datastore.user", "roles/pubsub.viewer"},
		access.Covered(false),
	)
	ok(t, err)
	// spec: ada keeps the datastore.user binding she shares with the group,
	// loses the custom role and the temporary grant, gains pubsub.viewer, and
	// keeps the expired and conditional bindings; auditConfigs, etag, and
	// version stay.
	golden := filepath.Join("testdata", "golden", "proposed.json")
	if *update {
		ok(t, os.WriteFile(golden, got, 0o600))
	}
	want, err := os.ReadFile(golden)
	ok(t, err)
	if !bytes.Equal(got, want) {
		t.Fatalf("proposed policy differs from %s:\n%s", golden, got)
	}
	// spec: proposing leaves p as it was, so a second proposal is the same.
	again, err := p.Propose(
		ada,
		[]string{"roles/datastore.user", "roles/pubsub.viewer"},
		access.Covered(false),
	)
	ok(t, err)
	equals(t, string(again), string(got))
	// spec: the proposal is a policy this package reads back.
	back, err := ParsePolicy(got)
	ok(t, err)
	equals(t, len(back.MemberBindings(ada, policyNow)), 4)
}

func TestProposeRefuses(t *testing.T) {
	ancestors := readPolicy(t, "ancestors.yaml")
	single := readPolicy(t, "policy.yaml")
	tests := map[string]struct {
		p      Policy
		member string
		want   string
	}{
		"ancestors": {
			p:      ancestors,
			member: "user:ada@example.com",
			want:   "only one resource's policy",
		},
		// spec: a single ancestor entry is still not one resource's
		// policy as gcloud's set-iam-policy reads it.
		"one ancestor entry": {
			p: func() Policy {
				p, err := ParsePolicy([]byte("type: project\nid: demo\npolicy:\n  bindings: []\n"))
				ok(t, err)
				return p
			}(),
			member: "user:ada@example.com",
			want:   "only one resource's policy",
		},
		"bare email": {
			p:      single,
			member: "ada@example.com",
			want:   `member "ada@example.com" has no type`,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := tc.p.Propose(tc.member, []string{"roles/viewer"}, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func TestProposeBindings(t *testing.T) {
	const ada = "user:ada@example.com"
	logs := `{"title": "Logs", "expression": "resource.name.startsWith(\"logs\")"}`
	tests := map[string]struct {
		policy   string
		roles    []string
		replaced []HeldBinding
		want     string
	}{
		"a policy with fewer bindings than roles": {
			policy: `{"bindings": [{"role": "roles/viewer", "members": ["user:bob@example.com"]}]}`,
			roles:  []string{"roles/pubsub.viewer", "roles/storage.objectViewer"},
			want: `{"bindings": [
				{"role": "roles/viewer", "members": ["user:bob@example.com"]},
				{"role": "roles/pubsub.viewer", "members": ["user:ada@example.com"]},
				{"role": "roles/storage.objectViewer", "members": ["user:ada@example.com"]}
			]}`,
		},
		// spec: a binding left with no members is dropped.
		"the member's own binding is dropped": {
			policy: `{"bindings": [
				{"role": "roles/owner", "members": ["user:ada@example.com"]},
				{"role": "roles/viewer", "members": ["user:ada@example.com"]}
			]}`,
			replaced: []HeldBinding{{Role: "roles/owner"}},
			// spec: the member's binding of another role is kept.
			want: `{"bindings": [{"role": "roles/viewer", "members": ["user:ada@example.com"]}]}`,
		},
		// spec: only the binding with the replaced role and condition loses
		// the member.
		"a binding of the role under another condition is kept": {
			policy: `{"bindings": [
				{"role": "roles/storage.objectViewer", "members": ["user:ada@example.com"],
				 "condition": ` + logs + `},
				{"role": "roles/storage.objectViewer", "members": ["user:ada@example.com", "user:bob@example.com"]}
			]}`,
			replaced: []HeldBinding{{Role: "roles/storage.objectViewer"}},
			want: `{"bindings": [
				{"role": "roles/storage.objectViewer", "members": ["user:ada@example.com"],
				 "condition": ` + logs + `},
				{"role": "roles/storage.objectViewer", "members": ["user:bob@example.com"]}
			]}`,
		},
		"a conditional binding is replaced only under its condition": {
			policy: `{"bindings": [
				{"role": "roles/storage.objectViewer", "members": ["user:ada@example.com"]},
				{"role": "roles/storage.objectViewer", "members": ["user:ada@example.com"],
				 "condition": ` + logs + `}
			]}`,
			replaced: []HeldBinding{
				{
					Role: "roles/storage.objectViewer",
					Condition: &Condition{
						Title:      "Logs",
						Expression: `resource.name.startsWith("logs")`,
					},
				},
			},
			want: `{"bindings": [
				{"role": "roles/storage.objectViewer", "members": ["user:ada@example.com"]}
			]}`,
		},
		// spec: a role is granted in its unconditional binding, wherever it
		// is, and only once.
		"granted in the role's later unconditional binding": {
			policy: `{"bindings": [
				{"role": "roles/viewer", "members": ["user:bob@example.com"]},
				{"role": "roles/pubsub.viewer", "members": ["user:bob@example.com"], "condition": ` + logs + `},
				{"role": "roles/pubsub.viewer", "members": ["user:bob@example.com"]}
			]}`,
			roles: []string{"roles/pubsub.viewer"},
			want: `{"bindings": [
				{"role": "roles/viewer", "members": ["user:bob@example.com"]},
				{"role": "roles/pubsub.viewer", "members": ["user:bob@example.com"], "condition": ` + logs + `},
				{"role": "roles/pubsub.viewer", "members": ["user:bob@example.com", "user:ada@example.com"]}
			]}`,
		},
		"already granted": {
			policy: `{"bindings": [{"role": "roles/viewer", "members": ["user:ada@example.com"]}]}`,
			roles:  []string{"roles/viewer"},
			want:   `{"bindings": [{"role": "roles/viewer", "members": ["user:ada@example.com"]}]}`,
		},
		"a role held only under a condition gets a binding of its own": {
			policy: `{"bindings": [{"role": "roles/viewer", "members": ["user:bob@example.com"], "condition": ` + logs + `}]}`,
			roles:  []string{"roles/viewer"},
			want: `{"bindings": [
				{"role": "roles/viewer", "members": ["user:bob@example.com"], "condition": ` + logs + `},
				{"role": "roles/viewer", "members": ["user:ada@example.com"]}
			]}`,
		},
	}
	// canonical returns the JSON value s with its keys sorted and no space.
	canonical := func(t *testing.T, s []byte) string {
		t.Helper()
		var v any
		ok(t, json.Unmarshal(s, &v))
		out, err := json.Marshal(v)
		ok(t, err)
		return string(out)
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p, err := ParsePolicy([]byte(tc.policy))
			ok(t, err)
			got, err := p.Propose(ada, tc.roles, tc.replaced)
			ok(t, err)
			equals(t, canonical(t, got), canonical(t, []byte(tc.want)))
		})
	}
}
