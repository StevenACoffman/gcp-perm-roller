package gcpperms

import (
	"strings"
	"testing"
)

func TestParsePolicyAnalysis(t *testing.T) {
	p := readPolicy(t, "analysis.yaml")
	// spec: gcloud's YAML documents and its --format=json list parse the
	// same.
	equals(t, readPolicy(t, "analysis.json"), p)
	logs := &Condition{
		Title:      "Logs bucket only",
		Expression: `resource.name.startsWith("projects/_/buckets/logs")`,
	}
	// spec: each binding comes once, with the identities of all its
	// results; the project's bindings have no resource, the folder's say it.
	equals(t, p, Policy{Bindings: []Binding{
		{
			Role:       "roles/datastore.user",
			Members:    []string{"group:eng@example.com"},
			Identities: []string{"group:eng@example.com", "user:ada@example.com"},
		},
		{
			Role:       "roles/pubsub.publisher",
			Members:    []string{"user:ada@example.com"},
			Identities: []string{"user:ada@example.com"},
		},
		{
			Role:       "roles/storage.objectViewer",
			Members:    []string{"group:eng@example.com", "group:ops@example.com"},
			Condition:  logs,
			Resource:   "folders/123456789012",
			Identities: []string{"group:eng@example.com", "user:ada@example.com"},
		},
	}})

	// spec: a grant through a group says which of the binding's groups.
	equals(t, p.MemberBindings("user:ada@example.com", policyNow), []HeldBinding{
		{
			Role:    "roles/datastore.user",
			State:   Unconditional,
			Through: []string{"group:eng@example.com"},
		},
		{Role: "roles/pubsub.publisher", State: Unconditional},
		{
			Role:      "roles/storage.objectViewer",
			Condition: logs,
			State:     Conditional,
			Resource:  "folders/123456789012",
			Through:   []string{"group:eng@example.com"},
		},
	})
	// spec: the analysis cannot be proposed, having no policy to change.
	if _, err := p.Propose("user:ada@example.com", nil, nil); err == nil {
		t.Fatal("proposed a policy from an analysis")
	}
}

func TestParsePolicyAnalysisErrors(t *testing.T) {
	result := func(resource string) string {
		return `{"policy": {"attachedResource": "` + resource +
			`", "binding": {"role": "roles/viewer", "members": ["user:a@b.c"]}}, "ACLs": []}`
	}
	tests := map[string]struct {
		data, want string
	}{
		"two projects": {
			data: "[" + result("//cloudresourcemanager.googleapis.com/projects/1") + "," +
				result("//cloudresourcemanager.googleapis.com/projects/2") + "]",
			want: "the analysis covers projects/1 and projects/2",
		},
		"an impersonation analysis": {
			data: "[" + result("//cloudresourcemanager.googleapis.com/projects/1") +
				`, {"Service Account Impersonation Analysis Query": {}}]`,
			want: "only the main analysis is read",
		},
		"a bad result": {
			data: "[" + result("//cloudresourcemanager.googleapis.com/projects/1") +
				`, {"policy": {"attachedResource": 3}}]`,
			want: "reading an analysis result",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParsePolicy([]byte(tc.data))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}
}
