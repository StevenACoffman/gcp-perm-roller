package troubleshoot

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"io"
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

// runTroubleshoot runs the command with args on testdata/result.json,
// answering from states (CAN_ACCESS for a permission it lacks), and
// returns its stdout and the permissions asked about.
func runTroubleshoot(
	t *testing.T,
	states map[string]gcpperms.AccessState,
	args ...string,
) (out string, asked []string, err error) {
	t.Helper()
	var buf bytes.Buffer
	r := root.New(strings.NewReader(""), &buf, io.Discard)
	cfg := New(r)
	cfg.newTroubleshooter = func(context.Context) (gcpperms.Troubleshooter, error) {
		return func(_ context.Context, principal, resource, perm string) (gcpperms.Verdict, error) {
			asked = append(asked, principal+" "+resource+" "+perm)
			if s, found := states[perm]; found {
				return gcpperms.Verdict{State: s}, nil
			}
			return gcpperms.Verdict{State: gcpperms.CanAccess}, nil
		}, nil
	}
	err = r.Command.ParseAndRun(context.Background(), append([]string{
		"troubleshoot",
		"--from=" + filepath.Join("testdata", "result.json"),
		"--principal=app@demo.iam.gserviceaccount.com",
		"--resource=//cloudresourcemanager.googleapis.com/projects/demo",
	}, args...))
	return buf.String(), asked, err
}

func TestTroubleshoot(t *testing.T) {
	out, asked, err := runTroubleshoot(t,
		map[string]gcpperms.AccessState{"datastore.entities.update": gcpperms.CannotAccess},
		"--include-conditional", "example.com/cmd/server")
	ok(t, err)
	// spec: only the named binary is checked, its conditional permission
	// too, for the principal on the resource.
	const prefix = "app@demo.iam.gserviceaccount.com //cloudresourcemanager.googleapis.com/projects/demo "
	equals(
		t,
		asked,
		[]string{prefix + "datastore.entities.get", prefix + "datastore.entities.update"},
	)
	equals(t, out, `== example.com/cmd/server
  app@demo.iam.gserviceaccount.com on //cloudresourcemanager.googleapis.com/projects/demo
    CAN_ACCESS           datastore.entities.get
    CANNOT_ACCESS        datastore.entities.update (conditional)
  1 of 2 permissions held
`)

	// spec: with --strict, a permission the principal may lack fails the
	// run, after the report.
	_, _, err = runTroubleshoot(t,
		map[string]gcpperms.AccessState{"pubsub.topics.publish": gcpperms.UnknownInfo},
		"--strict")
	if err == nil || err.Error() != "troubleshoot: the principal may lack 1 permissions" {
		t.Fatalf("got %v, want the count of permissions it may lack", err)
	}
	// spec: without it, the run succeeds and checks every binary.
	_, asked, err = runTroubleshoot(t, nil)
	ok(t, err)
	equals(t, len(asked), 2)
}

func TestTroubleshootUsage(t *testing.T) {
	tests := map[string]struct {
		args []string
		want string
	}{
		"typed principal": {
			args: []string{"--principal=serviceAccount:app@demo.iam.gserviceaccount.com"},
			want: "--principal: give the email alone",
		},
		"relative resource": {
			args: []string{"--resource=projects/demo"},
			want: "is not a full resource name",
		},
		"unknown binary": {
			args: []string{"example.com/cmd/nothing"},
			want: "no binary example.com/cmd/nothing in the results",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, asked, err := runTroubleshoot(t, nil, tc.args...)
			var usage *root.UsageError
			if !errors.As(err, &usage) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want a usage error containing %q", err, tc.want)
			}
			// spec: a bad command line asks the troubleshooter nothing.
			equals(t, len(asked), 0)
		})
	}
}

func TestTroubleshootStrictCounts(t *testing.T) {
	tests := map[string]struct {
		states map[string]gcpperms.AccessState
		want   string // the error, or "" for none
	}{
		// spec: --strict counts every permission not certainly held.
		"two of three lacking": {
			states: map[string]gcpperms.AccessState{
				"datastore.entities.update": gcpperms.CannotAccess,
				"pubsub.topics.publish":     gcpperms.UnknownConditional,
			},
			want: "troubleshoot: the principal may lack 2 permissions",
		},
		// spec: with every permission held, --strict passes.
		"all held": {},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, err := runTroubleshoot(t, tc.states, "--strict", "--include-conditional")
			if tc.want == "" {
				ok(t, err)
				return
			}
			if err == nil || err.Error() != tc.want {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestTroubleshootJSON(t *testing.T) {
	out, _, err := runTroubleshoot(t, nil, "--format=json", "example.com/cmd/worker")
	ok(t, err)
	var got []gcpperms.BinaryAccess
	ok(t, json.Unmarshal([]byte(out), &got))
	// spec: --format=json writes the checks as data.
	equals(t, got, []gcpperms.BinaryAccess{{
		Package:   "example.com/cmd/worker",
		Principal: "app@demo.iam.gserviceaccount.com",
		Resource:  "//cloudresourcemanager.googleapis.com/projects/demo",
		Checks: []gcpperms.AccessCheck{{
			Permission: "pubsub.topics.publish",
			Verdict:    gcpperms.Verdict{State: gcpperms.CanAccess},
		}},
	}})
}

func TestTroubleshootRequiresFlags(t *testing.T) {
	tests := map[string]struct {
		args []string
		want string
	}{
		"no results":   {args: nil, want: "troubleshoot: --from is required"},
		"no principal": {args: []string{"--from=x"}, want: "troubleshoot: --principal is required"},
		"no resource": {
			args: []string{"--from=x", "--principal=app@demo.iam.gserviceaccount.com"},
			want: "troubleshoot: --resource is required",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := root.New(strings.NewReader(""), io.Discard, io.Discard)
			New(r)
			err := r.Command.ParseAndRun(
				context.Background(),
				append([]string{"troubleshoot"}, tc.args...),
			)
			var usage *root.UsageError
			if !errors.As(err, &usage) || err.Error() != tc.want {
				t.Fatalf("got %v, want the usage error %q", err, tc.want)
			}
		})
	}
}

func TestTroubleshootErrors(t *testing.T) {
	errAPI := errors.New("API down")
	tests := map[string]struct {
		from   string
		stdout io.Writer
		// newErr and checkErr, when set, are the errors of building the
		// troubleshooter and of using it.
		newErr, checkErr error
		want             string
	}{
		"unreadable results": {
			from: filepath.Join("testdata", "nope.json"),
			want: "troubleshoot: ",
		},
		"no troubleshooter": {newErr: errAPI, want: "troubleshoot: API down"},
		"a failed check":    {checkErr: errAPI, want: "troubleshoot: API down"},
		"an unwritable report": {
			stdout: failingWriter{},
			want:   "troubleshoot: write failed",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := root.New(
				strings.NewReader(""),
				cmp.Or[io.Writer](tc.stdout, io.Discard),
				io.Discard,
			)
			cfg := New(r)
			cfg.newTroubleshooter = func(context.Context) (gcpperms.Troubleshooter, error) {
				if tc.newErr != nil {
					return nil, tc.newErr
				}
				return func(context.Context, string, string, string) (gcpperms.Verdict, error) {
					return gcpperms.Verdict{State: gcpperms.CanAccess}, tc.checkErr
				}, nil
			}
			err := r.Command.ParseAndRun(context.Background(), []string{
				"troubleshoot",
				"--from=" + cmp.Or(tc.from, filepath.Join("testdata", "result.json")),
				"--principal=app@demo.iam.gserviceaccount.com",
				"--resource=//cloudresourcemanager.googleapis.com/projects/demo",
			})
			var usage *root.UsageError
			// spec: a failure past the command line is no usage error.
			if err == nil || errors.As(err, &usage) || !strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error starting %q", err, tc.want)
			}
			if tc.checkErr != nil && !errors.Is(err, tc.checkErr) {
				t.Fatalf("got %v, which does not wrap %v", err, tc.checkErr)
			}
		})
	}
}

func TestTroubleshootHelp(t *testing.T) {
	var out bytes.Buffer
	r := root.New(strings.NewReader(""), io.Discard, &out)
	New(r)
	err := r.Command.ParseAndRun(context.Background(), []string{"troubleshoot", "--help"})
	if !errors.Is(err, ff.ErrHelp) {
		t.Fatalf("got %v, want ff.ErrHelp", err)
	}
	help := ffhelp.Command(r.Command.GetSelected()).String()
	for _, want := range []string{
		"troubleshoot -- check that a principal holds the permissions analyze found",
		"gcp-perm-roller troubleshoot --from=FILE --principal=EMAIL --resource=NAME [FLAGS] [PACKAGES...]",
		"Troubleshoot reads results saved with analyze --format=json",
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
		"--principal STRING",
		"--resource STRING",
		"--format STRING",
		"--include-conditional",
		"--strict",
	})
}
