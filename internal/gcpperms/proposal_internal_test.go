package gcpperms

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/golden/proposed.json from this run")

func TestRequiredAndCovered(t *testing.T) {
	p := readPolicy(t, "policy.yaml")
	access, _ := NewMemberAccess(
		"user:ada@example.com",
		p.MemberBindings("user:ada@example.com", policyNow),
		nil,
	)
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
