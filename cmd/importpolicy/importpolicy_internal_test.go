package importpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"

	"github.com/StevenACoffman/gcp-perm-roller/cmd/root"
	"github.com/StevenACoffman/gcp-perm-roller/internal/gcpperms"
)

// flagLineRE matches a flag's line in help output: its names and value type.
var flagLineRE = regexp.MustCompile(`^\s+((?:\S+, )?--\S+(?: [A-Z]+)?)\s{2,}`)

func ok(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func equals[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

// runImport runs the import command with args, reading roles saved in
// testdata, and returns what it wrote to stdout.
func runImport(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	r := root.New(strings.NewReader(""), &out, io.Discard)
	New(r)
	err := r.Command.ParseAndRun(context.Background(), append([]string{
		"import",
		"--policy=" + filepath.Join("testdata", "policy.yaml"),
		"--roles=" + filepath.Join("testdata", "roles.json"),
		"--custom-roles=" + filepath.Join("testdata", "custom"),
	}, args...))
	return out.String(), err
}

func TestImport(t *testing.T) {
	out, err := runImport(t, "--member=user:ada@example.com")
	ok(t, err)
	// spec: the expired binding grants nothing; the conditional one is
	// reported but not covered; the custom role's permissions are.
	equals(t, out, `== user:ada@example.com
  Holds:
    roles/datastore.user
    projects/demo/roles/CustomRole1
    roles/pubsub.publisher                        expired: Expired long ago
    roles/storage.objectViewer                    conditional: Logs bucket only
  3 permissions, and 2 more under conditions
  Predefined roles (1 permissions beyond those required):
    roles/datastore.user                          Cloud Datastore User, 2 permissions
      for datastore.entities.get, datastore.entities.list
    roles/pubsub.viewer                           Pub/Sub Viewer, 2 permissions
      for pubsub.topics.get
`)
}

func TestImportAncestors(t *testing.T) {
	out, err := runImport(t,
		"--policy="+filepath.Join("testdata", "ancestors.yaml"),
		"--member=user:ada@example.com")
	ok(t, err)
	// spec: grants inherited from the folder and the organization count,
	// and say where they come from; the deny policy is reported, not
	// applied.
	equals(t, out, `== user:ada@example.com
  Holds:
    roles/datastore.user
    roles/storage.objectViewer                    conditional: Logs bucket only; inherited from folders/123456789012
    roles/pubsub.viewer                           inherited from organizations/987654321098
  4 permissions, and 2 more under conditions
  Deny policies not applied: 1 (permissions they deny are still counted)
  Predefined roles (0 permissions beyond those required):
    roles/datastore.user                          Cloud Datastore User, 2 permissions
      for datastore.entities.get, datastore.entities.list
    roles/pubsub.viewer                           Pub/Sub Viewer, 2 permissions
      for pubsub.topics.get, pubsub.topics.list
`)
}

func TestImportProposedPolicy(t *testing.T) {
	proposed := filepath.Join(t.TempDir(), "proposed.json")
	var out, errOut bytes.Buffer
	r := root.New(strings.NewReader(""), &out, &errOut)
	New(r)
	err := r.Command.ParseAndRun(context.Background(), []string{
		"import",
		"--policy=" + filepath.Join("testdata", "policy.yaml"),
		"--roles=" + filepath.Join("testdata", "roles.json"),
		"--custom-roles=" + filepath.Join("testdata", "custom"),
		"--member=user:ada@example.com",
		"--include-conditional",
		"--proposed-policy=" + proposed,
	})
	ok(t, err)
	data, err := os.ReadFile(proposed)
	ok(t, err)
	policy, err := gcpperms.ParsePolicy(data)
	ok(t, err)
	// spec: the member holds exactly the recommended roles, and the expired
	// binding, which grants nothing, is left alone.
	var held []string
	for _, b := range policy.MemberBindings("user:ada@example.com", time.Now()) {
		held = append(held, b.Role+" "+string(b.State))
	}
	equals(t, held, []string{
		"roles/datastore.user unconditional",
		"roles/pubsub.publisher expired",
		"roles/pubsub.viewer unconditional",
		"roles/storage.objectViewer unconditional",
	})
	// spec: dropping the condition is said, on stderr; stdout has only the
	// report.
	equals(t, errOut.String(),
		"import: the proposed policy drops the condition \"Logs bucket only\" of "+
			"roles/storage.objectViewer; its roles are granted without it\n")
	if !strings.HasPrefix(out.String(), "== user:ada@example.com\n") {
		t.Fatalf("stdout is not the report:\n%s", out.String())
	}

	// spec: a proposal needs one project's policy and a typed member.
	for name, args := range map[string][]string{
		"ancestors":  {"--policy=" + filepath.Join("testdata", "ancestors.yaml"), "--member=user:ada@example.com"},
		"bare email": {"--member=ada@example.com"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := runImport(t, append(args, "--proposed-policy="+proposed)...)
			if err == nil {
				t.Fatal("wrote a proposal it cannot make")
			}
		})
	}
}

func TestImportOptions(t *testing.T) {
	tests := map[string]struct {
		args  []string
		grant []string
	}{
		"a bare email": {
			args:  []string{"--member=ada@example.com"},
			grant: []string{"roles/datastore.user", "roles/pubsub.viewer"},
		},
		// spec: --include-conditional covers the conditional permissions.
		"conditional permissions": {
			args: []string{"--member=user:ada@example.com", "--include-conditional"},
			grant: []string{
				"roles/datastore.user", "roles/pubsub.viewer", "roles/storage.objectViewer",
			},
		},
		"a group": {
			args:  []string{"--member=group:eng@example.com"},
			grant: []string{"roles/datastore.user"},
		},
		// spec: a stage the roles do not have leaves the permissions
		// uncovered.
		"another stage": {
			args: []string{"--member=group:eng@example.com", "--role-stages=BETA"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			out, err := runImport(t, append(tc.args, "--format=json")...)
			ok(t, err)
			var got gcpperms.MemberAccess
			ok(t, json.Unmarshal([]byte(out), &got))
			var grants []string
			for _, g := range got.PredefinedRoles.Grants {
				grants = append(grants, g.Role)
			}
			equals(t, grants, tc.grant)
		})
	}
}

func TestImportErrors(t *testing.T) {
	badPolicy := filepath.Join(t.TempDir(), "bad.yaml")
	ok(t, os.WriteFile(badPolicy, []byte("bindings: ["), 0o600))
	tests := map[string]struct {
		args  []string
		usage bool
		want  string
	}{
		"no member": {usage: true, want: "import: --member is required"},
		"no policy": {
			args:  []string{"--policy", "", "--member=user:ada@example.com"},
			usage: true,
			want:  "import: --policy is required",
		},
		"a bad format": {
			args:  []string{"--member=user:ada@example.com", "--format=yaml"},
			usage: true,
			want:  `import: --format: "yaml" is not text or json`,
		},
		"arguments": {
			args:  []string{"--member=user:ada@example.com", "extra"},
			usage: true,
			want:  "import: unexpected arguments: extra",
		},
		"a missing policy": {
			args: []string{"--policy=testdata/nope.yaml", "--member=user:ada@example.com"},
			want: "import: reading the policy: ",
		},
		"a bad policy": {
			args: []string{"--policy=" + badPolicy, "--member=user:ada@example.com"},
			want: "import: " + badPolicy + ": gcpperms.ParsePolicy: ",
		},
		// spec: a member with no binding is reported, as a mistyped one
		// would be.
		"a member with no roles": {
			args: []string{"--member=user:eve@example.com"},
			want: "import: user:eve@example.com holds no role in testdata/policy.yaml",
		},
		"bad predefined roles": {
			args: []string{"--member=user:ada@example.com", "--roles=testdata/nope"},
			want: "import: loading predefined roles: ",
		},
		"bad custom roles": {
			args: []string{"--member=user:ada@example.com", "--custom-roles=testdata/nope"},
			want: "import: loading custom roles: ",
		},
		// spec: a custom role with no definition stops the import rather
		// than leaving its permissions out.
		"an undefined custom role": {
			args: []string{"--member=user:bob@example.com"},
			want: "import: no definition of projects/demo/roles/Undefined in " +
				"--custom-roles=testdata/custom",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := runImport(t, tc.args...)
			if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error starting %q", err, tc.want)
			}
			equals(t, errors.Is(err, root.ErrUsage), tc.usage)
		})
	}
}

func TestImportHelp(t *testing.T) {
	var out bytes.Buffer
	r := root.New(strings.NewReader(""), io.Discard, &out)
	New(r)
	err := r.Command.ParseAndRun(context.Background(), []string{"import", "--help"})
	if !errors.Is(err, ff.ErrHelp) {
		t.Fatalf("got %v, want ff.ErrHelp", err)
	}
	help := ffhelp.Command(r.Command.GetSelected()).String()
	for _, want := range []string{
		"import -- find the predefined roles that grant what a member holds in an IAM policy",
		"gcp-perm-roller import --policy=FILE --member=PRINCIPAL [FLAGS]",
		"gcloud projects get-iam-policy my-project > policy.yaml",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("help lacks %q:\n%s", want, help)
		}
	}
	var flags []string
	for _, line := range strings.Split(help, "\n") {
		if m := flagLineRE.FindStringSubmatch(line); m != nil {
			flags = append(flags, m[1])
		}
	}
	equals(t, flags, []string{
		"--policy STRING",
		"--member STRING",
		"--format STRING",
		"--roles STRING",
		"--custom-roles STRING",
		"--role-stages STRING",
		"--include-conditional",
		"--proposed-policy STRING",
	})
}
