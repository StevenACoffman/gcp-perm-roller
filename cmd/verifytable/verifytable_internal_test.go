package verifytable

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"

	"github.com/StevenACoffman/gcp-perm-roller/cmd/root"
	"github.com/StevenACoffman/gcp-perm-roller/internal/verifytable"
)

// flagLineRE matches a flag's line in help output: its names and value type.
var flagLineRE = regexp.MustCompile(`^\s+((?:\S+, )?--\S+(?: [A-Z]+)?)\s{2,}`)

// ctxKey marks the context a test passes to the command.
type ctxKey struct{}

func equals[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestVerifyTableOptions(t *testing.T) {
	tests := map[string]struct {
		args []string
		want verifytable.Options
	}{
		"defaults": {
			want: verifytable.Options{Workspace: ".", Patterns: []string{}, Algorithm: "vta"},
		},
		"every flag, and packages": {
			args: []string{
				"-C", "/ws", "--table=t.go", "--cache=/c", "--debug=x.Y", "--strict",
				"--iam-dataset=/d", "--algo=rta", "./cmd/...", "./other",
			},
			want: verifytable.Options{
				Workspace: "/ws", Patterns: []string{"./cmd/...", "./other"}, Table: "t.go",
				Cache: "/c", Debug: "x.Y", Strict: true, IAMDataset: "/d", Algorithm: "rta",
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			r := root.New(strings.NewReader(""), &out, io.Discard)
			cfg := New(r)
			var got *verifytable.Options
			cfg.run = func(_ context.Context, o *verifytable.Options, stdout, _ io.Writer) error {
				got = o
				_, err := io.WriteString(stdout, "report")
				return err
			}
			err := r.Command.ParseAndRun(context.Background(),
				append([]string{"verify-table"}, tc.args...))
			if err != nil {
				t.Fatal(err)
			}
			equals(t, *got, tc.want)
			// spec: the report goes to the command's stdout.
			equals(t, out.String(), "report")
		})
	}
}

func TestVerifyTableErrors(t *testing.T) {
	r := root.New(strings.NewReader(""), io.Discard, io.Discard)
	cfg := New(r)
	cfg.run = func(context.Context, *verifytable.Options, io.Writer, io.Writer) error {
		return errors.New("3 problems found")
	}
	err := r.Command.ParseAndRun(context.Background(), []string{"verify-table"})
	// spec: a failed check is reported under the command's name, and is not a
	// usage error.
	if err == nil || err.Error() != "verify-table: 3 problems found" {
		t.Fatalf("got %v", err)
	}
	equals(t, errors.Is(err, root.ErrUsage), false)
}

func TestVerifyTableHelp(t *testing.T) {
	var out bytes.Buffer
	r := root.New(strings.NewReader(""), io.Discard, &out)
	New(r)
	err := r.Command.ParseAndRun(context.Background(), []string{"verify-table", "--help"})
	if !errors.Is(err, ff.ErrHelp) {
		t.Fatalf("got %v, want ff.ErrHelp", err)
	}
	help := ffhelp.Command(r.Command.GetSelected()).String()
	for _, want := range []string{
		"verify-table -- check the permission table against Google's public documentation",
		"gcp-perm-roller verify-table [FLAGS] [PACKAGES...]",
		"Verify-table checks the rules",
		"--iam-dataset",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("help lacks %q:\n%s", want, help)
		}
	}
}

func TestVerifyTableRun(t *testing.T) {
	// spec: New runs the real check unless a test replaces it.
	r := root.New(strings.NewReader(""), io.Discard, io.Discard)
	equals(t, reflect.ValueOf(New(r).run).Pointer(), reflect.ValueOf(verifytable.Run).Pointer())

	r = root.New(strings.NewReader(""), io.Discard, io.Discard)
	cfg := New(r)
	failed := errors.New("3 problems found")
	var got context.Context
	cfg.run = func(ctx context.Context, _ *verifytable.Options, _, _ io.Writer) error {
		got = ctx
		return failed
	}
	ctx := context.WithValue(context.Background(), ctxKey{}, "mine")
	err := r.Command.ParseAndRun(ctx, []string{"verify-table"})
	// spec: the check runs with the command's context, and its error stays
	// inspectable.
	equals(t, got.Value(ctxKey{}), any("mine"))
	equals(t, errors.Is(err, failed), true)
}

func TestVerifyTableFlags(t *testing.T) {
	r := root.New(strings.NewReader(""), io.Discard, io.Discard)
	New(r)
	_ = r.Command.ParseAndRun(context.Background(), []string{"verify-table", "--help"})
	help := ffhelp.Command(r.Command.GetSelected()).String()
	var got []string
	for _, line := range strings.Split(help, "\n") {
		if m := flagLineRE.FindStringSubmatch(line); m != nil {
			got = append(got, m[1])
		}
	}
	// spec: each flag, in order, with its short form only where it has one.
	equals(t, got, []string{
		"-C, --dir STRING",
		"--table STRING",
		"--cache STRING",
		"--debug STRING",
		"--strict",
		"--algo STRING",
		"--iam-dataset STRING",
	})
}
