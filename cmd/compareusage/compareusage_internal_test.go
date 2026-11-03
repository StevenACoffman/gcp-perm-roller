package compareusage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/StevenACoffman/gcp-perm-roller/cmd/root"
	"github.com/StevenACoffman/gcp-perm-roller/internal/gcpperms"
)

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

// runCompare runs the command with args on the files in testdata, and
// returns what it wrote to stdout.
func runCompare(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	r := root.New(strings.NewReader(""), &out, io.Discard)
	New(r)
	err := r.Command.ParseAndRun(context.Background(), append([]string{
		"compare-usage",
		"--from=" + filepath.Join("testdata", "result.json"),
		"--insights=" + filepath.Join("testdata", "insights.yaml"),
		"--roles=" + filepath.Join("testdata", "roles.json"),
		"--member=serviceAccount:app@demo.iam.gserviceaccount.com",
	}, args...))
	return out.String(), err
}

func TestCompareUsage(t *testing.T) {
	out, err := runCompare(t, "--format=json", "example.com/cmd/server")
	ok(t, err)
	var got gcpperms.Usage
	ok(t, json.Unmarshal([]byte(out), &got))
	// spec: only the named binary is compared; its conditional permission
	// is unused, the get is used, and the storage list was used though
	// analyze did not find it.
	equals(t, got.Packages, []string{"example.com/cmd/server"})
	equals(t, got.Used, []string{"datastore.entities.get"})
	equals(t, got.Unexpected, []string{"logging.logEntries.create", "storage.objects.list"})
	equals(t, got.Unobserved, []string{"datastore.entities.update"})
	equals(t, got.UnknownRoles, []string{"projects/demo/roles/Custom"})

	out, err = runCompare(t)
	ok(t, err)
	// spec: by default every binary is compared, as text.
	if !strings.HasPrefix(out, "== serviceAccount:app@demo.iam.gserviceaccount.com "+
		"(example.com/cmd/server, example.com/cmd/worker)\n") {
		t.Fatalf("report does not name both binaries:\n%s", out)
	}
}

func TestCompareUsageRequiresFlags(t *testing.T) {
	r := root.New(strings.NewReader(""), io.Discard, io.Discard)
	New(r)
	err := r.Command.ParseAndRun(context.Background(), []string{"compare-usage"})
	var usage *root.UsageError
	// spec: with no flags, the first required one is named.
	if !errors.As(err, &usage) || !strings.Contains(err.Error(), "--from is required") {
		t.Fatalf("got %v, want a usage error naming --from", err)
	}
}

func TestCompareUsageErrors(t *testing.T) {
	tests := map[string]struct {
		args  []string
		usage bool
		want  string
	}{
		"unknown binary": {
			args: []string{"example.com/cmd/nothing"}, usage: true,
			want: "no binary example.com/cmd/nothing in the results",
		},
		"missing insights": {
			args: []string{"--insights=" + filepath.Join("testdata", "none.yaml")},
			want: "reading the insights",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := runCompare(t, tc.args...)
			var usage *root.UsageError
			if err == nil || !strings.Contains(err.Error(), tc.want) ||
				errors.As(err, &usage) != tc.usage {
				t.Fatalf(
					"got %v, want an error containing %q (usage error: %v)",
					err,
					tc.want,
					tc.usage,
				)
			}
		})
	}
}
