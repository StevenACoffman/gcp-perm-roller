package troubleshoot

import (
	"bytes"
	"context"
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
