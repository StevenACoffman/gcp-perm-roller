package wrappers

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

// runWrappers runs the wrappers command with args and returns what it
// wrote to stdout and stderr.
func runWrappers(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut bytes.Buffer
	r := root.New(strings.NewReader(""), &out, &errOut)
	New(r)
	err = r.Command.ParseAndRun(context.Background(), append([]string{"wrappers"}, args...))
	return out.String(), errOut.String(), err
}

// writeModule writes a module with one wrapper, called once, to a directory
// whose name starts with "_", and returns the directory.
func writeModule(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "_tool")
	ok(t, os.MkdirAll(filepath.Join(dir, "memo"), 0o750))
	ok(t, os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module example.com/_tool\n\ngo 1.24\n"), 0o600))
	ok(t, os.WriteFile(filepath.Join(dir, "memo", "memo.go"), []byte(`package memo

import "reflect"

func Call(f any) { reflect.ValueOf(f).Call(nil) }

func use() { Call(func() {}) }
`), 0o600))
	return dir
}

func TestWrappers(t *testing.T) {
	dir := writeModule(t)
	want := []gcpperms.Wrapper{{
		Function: "example.com/_tool/memo.Call",
		Params:   []int{0},
		Site:     &gcpperms.Site{File: "memo/memo.go", Line: 5},
		Calls:    1,
		Reason:   "passes parameter 0 to reflect.ValueOf and calls it with reflect.Value.Call",
	}}
	for name, args := range map[string][]string{
		"every module, by default": {"-C", dir},
		"a pattern":                {"-C", dir, "./memo"},
	} {
		t.Run(name, func(t *testing.T) {
			out, errOut, err := runWrappers(t, args...)
			ok(t, err)
			var got gcpperms.WrapperFile
			ok(t, json.Unmarshal([]byte(out), &got))
			equals(t, got.Wrappers, want)
			equals(t, errOut, "found 1 wrappers\n")
		})
	}

	// spec: --out writes the file analyze --wrapper-file reads.
	file := filepath.Join(t.TempDir(), "wrappers.json")
	out, _, err := runWrappers(t, "-C", dir, "--out="+file)
	ok(t, err)
	equals(t, out, "")
	got, err := gcpperms.LoadWrappers(file)
	ok(t, err)
	equals(t, got, want)
}

func TestWrappersErrors(t *testing.T) {
	dir := writeModule(t)
	for name, args := range map[string][]string{
		"a missing directory":      {"-C", filepath.Join(dir, "nope")},
		"an output file not saved": {"-C", dir, "--out=" + filepath.Join(dir, "nope", "w.json")},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := runWrappers(t, args...)
			if err == nil || !strings.HasPrefix(err.Error(), "wrappers: ") {
				t.Fatalf("got %v, want an error from the wrappers command", err)
			}
		})
	}
	_, _, err := runWrappers(t, "-C", dir, "--out="+filepath.Join(dir, "nope", "w.json"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("got %v, want the cause kept", err)
	}
}

func TestWrappersHelp(t *testing.T) {
	var out bytes.Buffer
	r := root.New(strings.NewReader(""), io.Discard, &out)
	New(r)
	err := r.Command.ParseAndRun(context.Background(), []string{"wrappers", "--help"})
	if !errors.Is(err, ff.ErrHelp) {
		t.Fatalf("got %v, want ff.ErrHelp", err)
	}
	help := ffhelp.Command(r.Command.GetSelected()).String()
	for _, want := range []string{
		"wrappers -- find functions that call the functions passed to them by reflection",
		"gcp-perm-roller wrappers [FLAGS] [PACKAGES...]",
		"analyze --wrapper-file",
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
	equals(t, flags, []string{"-C, --dir STRING", "--out STRING", "--tags STRING"})
}
