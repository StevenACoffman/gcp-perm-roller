package gcpperms

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// flakyWriter fails its nth write only, and records every write.
type flakyWriter struct {
	n      int
	writes int
}

// goldenBinaries exercises every part of the reports: several APIs needing
// one permission, a conditional permission that is also required elsewhere
// (so it is not conditional), notes, unmapped calls, call sites, a binary
// needing nothing, one making no calls, and one calling no known API.
func goldenBinaries() []Binary {
	return []Binary{
		{Package: "example.com/one", Calls: []Call{
			{
				API:         "cloud.google.com/go/datastore.Client.Get",
				Mapped:      true,
				Permissions: []string{"datastore.entities.get"},
				Sites: []Site{
					{File: "one/main.go", Line: 10},
					{File: "one/main.go", Line: 20},
				},
			},
			{
				API:    "cloud.google.com/go/datastore.Client.Run",
				Mapped: true,
				Permissions: []string{
					"datastore.entities.get",
					"datastore.entities.list",
				},
				Note:  "keys-only queries need only datastore.entities.list",
				Sites: []Site{{File: "one/query.go", Line: 5}},
			},
			{
				API:         "cloud.google.com/go/storage.ObjectHandle.NewWriter",
				Mapped:      true,
				Permissions: []string{"storage.objects.create"},
				Conditional: []string{
					"storage.objects.delete",
					"datastore.entities.get",
				},
				Note:  "storage.objects.delete is needed to overwrite an existing object",
				Sites: []Site{{File: "one/upload.go", Line: 7}},
			},
			{
				API: "cloud.google.com/go/spanner.Client.Single",
				Sites: []Site{
					{File: "one/db.go", Line: 3},
					{File: "one/db.go", Line: 9},
				},
			},
		}},
		{Package: "example.com/notes", Calls: []Call{
			{
				API:    "google.golang.org/api/sheets/v4.SpreadsheetsGetCall.Do",
				Mapped: true,
				Note:   "not IAM: needs an OAuth scope",
				Sites:  []Site{{File: "notes/sheet.go", Line: 1}},
			},
		}},
		{Package: "example.com/empty"},
		// No recognized API, and an unmapped call sorted before a mapped
		// one, which verbose call sites must still list.
		{Package: "example.com/mixed", Calls: []Call{
			{
				API:   "cloud.google.com/go/bigtable.Client.Open",
				Sites: []Site{{File: "mixed/main.go", Line: 2}},
			},
			{
				API: "golang.org/x/oauth2/google.Exchange", Mapped: true,
				Note:  "needs an OAuth client",
				Sites: []Site{{File: "mixed/main.go", Line: 8}},
			},
		}},
		{Package: "example.com/two", Calls: []Call{
			{
				API:         "cloud.google.com/go/pubsub/v2.Publisher.Publish",
				Mapped:      true,
				Permissions: []string{"pubsub.topics.publish"},
				Sites:       []Site{{File: "two/main.go", Line: 4}},
			},
		}},
	}
}

// goldenMemberAccess is what user:ada@example.com holds in the fixture
// policy, with the predefined roles that grant it.
func goldenMemberAccess(t *testing.T) *MemberAccess {
	t.Helper()
	roles := []Role{
		{
			Name: "roles/datastore.user", Title: "Cloud Datastore User", Stage: "GA",
			Permissions: []string{"datastore.entities.get", "datastore.entities.list"},
		},
		{
			Name: "roles/datastore.viewer", Title: "Cloud Datastore Viewer", Stage: "GA",
			Permissions: []string{"datastore.entities.get"},
		},
		{
			Name: "projects/demo/roles/CustomRole1", Title: "Reader", Stage: "GA",
			Permissions: []string{"datastore.entities.get", "pubsub.topics.get"},
		},
		{
			Name: "roles/pubsub.viewer", Title: "Pub/Sub Viewer", Stage: "GA",
			Permissions: []string{"pubsub.topics.get", "pubsub.topics.list"},
		},
		{
			Name: "roles/pubsub.publisher", Title: "Pub/Sub Publisher", Stage: "GA",
			Permissions: []string{"pubsub.topics.publish"},
		},
		{
			Name: "roles/secretmanager.secretAccessor", Title: "Secret Accessor", Stage: "GA",
			Permissions: []string{"secretmanager.versions.access"},
		},
		{
			Name: "roles/storage.objectViewer", Title: "Storage Object Viewer", Stage: "GA",
			Permissions: []string{"storage.objects.get", "storage.objects.list"},
		},
	}
	const member = "user:ada@example.com"
	access, missing := NewMemberAccess(
		member, readPolicy(t, "policy.yaml").MemberBindings(member, policyNow), roles)
	equals(t, len(missing), 0)
	sel := SelectRoles(access.Permissions, roles, RoleFilter{})
	access.PredefinedRoles = &sel
	return &access
}

// TestReportsMatchGolden pins the exact report layouts. Update the files
// in testdata/golden deliberately when a layout changes.
func TestReportsMatchGolden(t *testing.T) {
	tests := map[string]struct {
		golden string
		write  func(io.Writer) error
	}{
		"text": {golden: "text.txt", write: func(w io.Writer) error {
			return WriteText(w, goldenBinaries(), false)
		}},
		"text, verbose": {golden: "text-verbose.txt", write: func(w io.Writer) error {
			return WriteText(w, goldenBinaries(), true)
		}},
		"roles": {golden: "roles.yaml", write: func(w io.Writer) error {
			return WriteRoles(w, goldenBinaries())
		}},
		"member": {golden: "member.txt", write: func(w io.Writer) error {
			return WriteMemberAccess(w, goldenMemberAccess(t))
		}},
		"member, json": {golden: "member.json", write: func(w io.Writer) error {
			return WriteJSON(w, goldenMemberAccess(t))
		}},
		"json": {golden: "result.json", write: func(w io.Writer) error {
			return WriteJSON(
				w,
				Result{
					Binaries: goldenBinaries()[:1],
					Skipped:  []string{"example.com/broken"},
				},
			)
		}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			want, err := os.ReadFile(filepath.Join("testdata", "golden", tc.golden))
			ok(t, err)
			var buf bytes.Buffer
			ok(t, tc.write(&buf))
			if got := buf.String(); got != string(want) {
				t.Fatalf(
					"output differs from %s:\n--- got\n%s\n--- want\n%s",
					tc.golden,
					got,
					want,
				)
			}
		})
	}
}

func (w *flakyWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.n {
		return 0, errWrite
	}
	return len(p), nil
}

func TestWritersStopAtTheFirstError(t *testing.T) {
	writers := map[string]func(io.Writer) error{
		"text":  func(w io.Writer) error { return WriteText(w, goldenBinaries(), true) },
		"roles": func(w io.Writer) error { return WriteRoles(w, goldenBinaries()) },
		"member": func(w io.Writer) error {
			return WriteMemberAccess(w, goldenMemberAccess(t))
		},
	}
	for name, write := range writers {
		t.Run(name, func(t *testing.T) {
			// spec: the error is returned even though later writes would
			// succeed, and nothing more is written after it.
			w := &flakyWriter{n: 2}
			if err := write(w); !errors.Is(err, errWrite) {
				t.Fatalf("got %v, want the write error", err)
			}
			equals(t, w.writes, 2)
		})
	}
}

func TestWritePredefinedRolesSections(t *testing.T) {
	grant := RoleGrant{Role: "roles/x.user", Title: "X User", Size: 2, Covers: []string{"x.a.get"}}
	tests := map[string]struct {
		sel       *RoleSelection
		roles     bool // a "Predefined roles" section
		uncovered bool // a custom-role section
		nothing   bool // "no permissions required"
	}{
		"no selection":    {nothing: true},
		"empty selection": {sel: &RoleSelection{}, nothing: true},
		"grants only":     {sel: &RoleSelection{Grants: []RoleGrant{grant}}, roles: true},
		"uncovered only": {
			sel:       &RoleSelection{Uncovered: []string{"y.b.get"}},
			uncovered: true,
		},
		"one grant, one missing": {
			sel:       &RoleSelection{Grants: []RoleGrant{grant}, Uncovered: []string{"y.b.get"}},
			roles:     true,
			uncovered: true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			ok(
				t,
				WritePredefinedRoles(
					&buf,
					[]Binary{{Package: "example.com/x", PredefinedRoles: tc.sel}},
				),
			)
			out := buf.String()
			equals(t, strings.Contains(out, "Predefined roles"), tc.roles)
			equals(t, strings.Contains(out, "use a custom role"), tc.uncovered)
			equals(t, strings.Contains(out, "no permissions required"), tc.nothing)
		})
	}
}

func TestWriteMemberAccessNotesAndDenials(t *testing.T) {
	bindings := []HeldBinding{
		{
			Role:    "roles/datastore.user",
			State:   Unconditional,
			Through: []string{"group:eng@example.com", "group:ops@example.com"},
		},
		{Role: "roles/pubsub.viewer", State: Unconditional, Resource: "organizations/1"},
		{
			Role:      "roles/storage.objectViewer",
			Condition: &Condition{Expression: `resource.name.startsWith("logs")`},
			State:     Conditional,
			Resource:  "folders/2",
			Through:   []string{"group:eng@example.com"},
		},
	}
	denials := []Denial{
		{Permission: "datastore.entities.delete", Policy: "No deletes", Certain: true},
		{Permission: "datastore.entities.get", Policy: "prod", Reason: "only when Prod holds"},
		{Permission: "pubsub.topics.get", Policy: "No reads", Certain: true},
		{Permission: "storage.objects.get", Policy: "groups"},
	}
	const holds = `== user:ada@example.com
  Holds:
    roles/datastore.user                          through group:eng@example.com, group:ops@example.com
    roles/pubsub.viewer                           inherited from organizations/1
    roles/storage.objectViewer                    conditional: resource.name.startsWith("logs"); through group:eng@example.com; inherited from folders/2
  1 permissions
`
	tests := map[string]struct {
		denyPolicies int
		// denials, when set, are the denials instead of all of them.
		denials []Denial
		want    string
	}{
		// spec: each binding notes its condition, the groups it is held
		// through, and where it is inherited from; denials are listed in
		// order under whether they are certain, each with its policy and
		// any reason.
		"deny policies": {
			denyPolicies: 3,
			want: holds + `  3 deny policies
  Denied, so not counted:
    datastore.entities.delete                     by No deletes
    pubsub.topics.get                             by No reads
  Possibly denied, still counted:
    datastore.entities.get                        by prod, only when Prod holds
    storage.objects.get                           by groups
  no permissions required
`,
		},
		// spec: a list with no denials is left out, and one with a single
		// denial is written.
		"only certain denials": {
			denyPolicies: 1,
			denials:      denials[:1],
			want: holds + `  1 deny policies
  Denied, so not counted:
    datastore.entities.delete                     by No deletes
  no permissions required
`,
		},
		// spec: with no deny policies, nothing is said about them.
		"no deny policies": {want: holds + "  no permissions required\n"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ds := denials
			if tc.denials != nil {
				ds = tc.denials
			}
			var buf bytes.Buffer
			ok(t, WriteMemberAccess(&buf, &MemberAccess{
				Member:       "user:ada@example.com",
				Bindings:     bindings,
				Permissions:  []string{"datastore.entities.get"},
				DenyPolicies: tc.denyPolicies,
				Denials:      ds,
			}))
			equals(t, buf.String(), tc.want)
		})
	}
}
