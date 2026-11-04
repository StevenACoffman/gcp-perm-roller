package compareusage

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

	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"

	"github.com/StevenACoffman/gcp-perm-roller/cmd/root"
	"github.com/StevenACoffman/gcp-perm-roller/internal/gcpperms"
)

// flagLineRE matches a flag's line in help output: its names and value type.
var flagLineRE = regexp.MustCompile(`^\s+((?:\S+, )?--\S+(?: [A-Z]+)?)\s{2,}`)

// failingWriter fails every write.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

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
	tests := map[string]struct {
		args []string
		want string
	}{
		// spec: the first required flag missing is named.
		"no flags":    {want: "compare-usage: --from is required"},
		"no insights": {args: []string{"--from=x"}, want: "compare-usage: --insights is required"},
		"no member": {
			args: []string{"--from=x", "--insights=y"},
			want: "compare-usage: --member is required",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := root.New(strings.NewReader(""), io.Discard, io.Discard)
			New(r)
			err := r.Command.ParseAndRun(
				context.Background(), append([]string{"compare-usage"}, tc.args...),
			)
			var usage *root.UsageError
			if !errors.As(err, &usage) || err.Error() != tc.want {
				t.Fatalf("got %v, want the usage error %q", err, tc.want)
			}
		})
	}
}

func TestCompareUsageErrors(t *testing.T) {
	badInsights := filepath.Join(t.TempDir(), "insights.json")
	ok(t, os.WriteFile(badInsights, []byte(`[{"content": {}}]`), 0o600))
	tests := map[string]struct {
		args  []string
		usage bool
		want  string
	}{
		"unknown binary": {
			args: []string{"example.com/cmd/nothing"}, usage: true,
			want: "compare-usage: no binary example.com/cmd/nothing in the results",
		},
		"missing results": {
			args: []string{"--from=" + filepath.Join("testdata", "none.json")},
			want: "compare-usage: ",
		},
		"missing insights": {
			args: []string{"--insights=" + filepath.Join("testdata", "none.yaml")},
			want: "compare-usage: reading the insights",
		},
		"insights of another kind": {
			args: []string{"--insights=" + badInsights},
			want: "compare-usage: " + badInsights + ": ",
		},
		"missing roles": {
			args: []string{"--roles=" + filepath.Join("testdata", "none")},
			want: "compare-usage: loading predefined roles: ",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := runCompare(t, tc.args...)
			var usage *root.UsageError
			if err == nil || !strings.HasPrefix(err.Error(), tc.want) ||
				errors.As(err, &usage) != tc.usage {
				t.Fatalf(
					"got %v, want an error starting %q (usage error: %v)",
					err,
					tc.want,
					tc.usage,
				)
			}
		})
	}
}

func TestCompareUsageUnwritable(t *testing.T) {
	r := root.New(strings.NewReader(""), failingWriter{}, io.Discard)
	New(r)
	err := r.Command.ParseAndRun(context.Background(), []string{
		"compare-usage",
		"--from=" + filepath.Join("testdata", "result.json"),
		"--insights=" + filepath.Join("testdata", "insights.yaml"),
		"--roles=" + filepath.Join("testdata", "roles.json"),
		"--member=serviceAccount:app@demo.iam.gserviceaccount.com",
	})
	// spec: a report that cannot be written fails the run.
	if err == nil || err.Error() != "compare-usage: write failed" {
		t.Fatalf("got %v, want the write error", err)
	}
}

func TestCompareUsageHelp(t *testing.T) {
	var out bytes.Buffer
	r := root.New(strings.NewReader(""), io.Discard, &out)
	New(r)
	err := r.Command.ParseAndRun(context.Background(), []string{"compare-usage", "--help"})
	if !errors.Is(err, ff.ErrHelp) {
		t.Fatalf("got %v, want ff.ErrHelp", err)
	}
	help := ffhelp.Command(r.Command.GetSelected()).String()
	for _, want := range []string{
		"compare-usage -- compare the permissions analyze found with those the IAM recommender saw used",
		"gcp-perm-roller compare-usage --from=FILE --insights=FILE --member=PRINCIPAL [FLAGS] [PACKAGES...]",
		"Compare-usage reads results saved with analyze --format=json",
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
	// spec: the flags have no short names.
	equals(t, flags, []string{
		"--from STRING",
		"--insights STRING",
		"--member STRING",
		"--roles STRING",
		"--format STRING",
	})
}
