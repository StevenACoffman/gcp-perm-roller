package analyze

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
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

func TestPackageDir(t *testing.T) {
	mods := map[string]string{
		"example.com/ws/billing-api": "/ws/billing-api",
		"example.com/ws/billing":     "/ws/billing",
		"example.com/other/ledger":   "/ws/ledger",
		"example.com/outside":        "/elsewhere/outside",
	}
	tests := map[string]struct {
		pkg  string
		want string
	}{
		"module root": {
			pkg:  "example.com/ws/billing-api",
			want: "billing-api",
		},
		"nested package": {
			pkg:  "example.com/ws/billing-api/cmd/worker",
			want: "billing-api/cmd/worker",
		},
		"longest module prefix wins": {pkg: "example.com/ws/billing/x", want: "billing/x"},
		"prefix only at path boundary": {
			pkg:  "example.com/ws/billingx",
			want: "example.com/ws/billingx",
		},
		"module path unlike its dir": {pkg: "example.com/other/ledger", want: "ledger"},
		"module outside root": {
			pkg:  "example.com/outside/x",
			want: "example.com/outside/x",
		},
		"no module": {pkg: "nowhere.org/x", want: "nowhere.org/x"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			equals(t, packageDir(tc.pkg, mods, "/ws"), tc.want)
		})
	}
}

func TestRemoveStale(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"kept.txt":     generatedPrefix + " -outdir x; DO NOT EDIT.\n",
		"stale.txt":    generatedPrefix + " -outdir x; DO NOT EDIT.\n",
		"README.md":    "# Hand-written\n",
		"notes.txt":    "not generated\n",
		"sub/deep.txt": generatedPrefix + "\n",
	}
	for name, body := range files {
		ok(t, os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755))
		ok(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644))
	}
	ok(t, removeStale(dir, map[string]bool{"kept.txt": true}))
	var left []string
	ok(t, filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(dir, path)
			left = append(left, filepath.ToSlash(rel))
		}
		return err
	}))
	slices.Sort(left)
	// Only top-level generated files not rewritten are removed.
	equals(t, left, []string{"README.md", "kept.txt", "notes.txt", "sub/deep.txt"})
}

// runAnalyze runs the analyze command with args and returns what it wrote.
func runAnalyze(t *testing.T, args ...string) (stdout string, err error) {
	t.Helper()
	var out, errOut bytes.Buffer
	r := root.New(strings.NewReader(""), &out, &errOut)
	New(r)
	err = r.Command.ParseAndRun(context.Background(), append([]string{"analyze"}, args...))
	return out.String(), err
}

func TestAnalyzeFrom(t *testing.T) {
	const one, two, roles = "testdata/one.json", "testdata/two.json", "testdata/roles.json"
	tests := map[string]struct {
		args    []string
		want    []string // substrings of the output, in order
		without []string // substrings that must not appear
	}{
		"text, one binary per section": {
			args: []string{"--from=" + one},
			want: []string{
				"== example.com/one/cmd/a", "datastore.entities.get",
				"Conditional permissions:", "storage.objects.delete",
				"== example.com/one/cmd/idle", "no Google Cloud API calls",
			},
			without: []string{"a/main.go:10"},
		},
		"text with call sites": {
			args: []string{"--from=" + one, "-v"},
			want: []string{"Call sites:", "a/main.go:10", "a/upload.go:7"},
		},
		"two files merged into one custom role": {
			args: []string{"--from=" + one, "--from=" + two, "--union", "--format=role"},
			want: []string{
				"title: all binaries",
				"- datastore.entities.get\n",
				"- pubsub.topics.publish\n",
				"- storage.objects.create\n",
				"- storage.objects.delete # conditional",
			},
			without: []string{"example.com/one/cmd/a", "---"},
		},
		"two files, a role per binary": {
			args: []string{"--from=" + one, "--from=" + two, "--format=role"},
			want: []string{"for example.com/one/cmd/a", "---", "for example.org/two"},
		},
		"predefined roles for required permissions": {
			args: []string{"--from=" + one, "--format=predefined", "--roles=" + roles},
			want: []string{
				"roles/datastore.viewer", "roles/storage.objectCreator",
				"no permissions required",
			},
			without: []string{"roles/storage.objectUser"},
		},
		"predefined roles with conditional permissions": {
			args: []string{
				"--from=" + one, "--format=predefined", "--roles=" + roles,
				"--include-conditional",
			},
			want:    []string{"roles/datastore.viewer", "roles/storage.objectUser"},
			without: []string{"roles/storage.objectCreator"},
		},
		"GA roles only by default": {
			args:    []string{"--from=" + two, "--format=predefined", "--roles=" + roles},
			want:    []string{"use a custom role", "pubsub.topics.publish"},
			without: []string{"roles/pubsub.publisher"},
		},
		"other launch stages when asked": {
			args: []string{
				"--from=" + two, "--format=predefined", "--roles=" + roles,
				"--role-stages=GA", "--role-stages=BETA",
			},
			want:    []string{"roles/pubsub.publisher"},
			without: []string{"use a custom role"},
		},
		"json with roles": {
			args: []string{"--from=" + one, "--format=json", "--roles=" + roles},
			want: []string{`"predefinedRoles"`, `"roles/datastore.viewer"`, `"skipped"`},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			out, err := runAnalyze(t, tc.args...)
			ok(t, err)
			rest := out
			for _, w := range tc.want {
				i := strings.Index(rest, w)
				if i < 0 {
					t.Fatalf("output lacks %q after the earlier matches:\n%s", w, out)
				}
				rest = rest[i+len(w):]
			}
			for _, w := range tc.without {
				if strings.Contains(out, w) {
					t.Fatalf("output has %q:\n%s", w, out)
				}
			}
		})
	}
}

func TestAnalyzeFromJSONRoundTrips(t *testing.T) {
	out, err := runAnalyze(
		t,
		"--from=testdata/one.json",
		"--from=testdata/two.json",
		"--format=json",
	)
	ok(t, err)
	var got gcpperms.Result
	ok(t, json.Unmarshal([]byte(out), &got))
	want, err := loadResults([]string{"testdata/one.json", "testdata/two.json"})
	ok(t, err)
	// spec: saved results are read back as written, in file order.
	equals(t, got, want)
	equals(t, len(got.Binaries), 3)
	equals(t, got.Skipped, []string{"example.com/one/cmd/broken"})
}

func TestAnalyzeStrict(t *testing.T) {
	tests := map[string]struct {
		args    []string
		wantErr string
	}{
		"every call mapped":         {args: []string{"--from=testdata/one.json", "--strict"}},
		"an unmapped call, ignored": {args: []string{"--from=testdata/two.json"}},
		"an unmapped call, strict": {
			args:    []string{"--from=testdata/two.json", "--strict"},
			wantErr: "analyze: 1 SDK calls have no permission rule",
		},
		"unmapped calls of every binary": {
			args: []string{
				"--from=testdata/two.json", "--from=testdata/two.json", "--strict",
			},
			wantErr: "analyze: 2 SDK calls have no permission rule",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := runAnalyze(t, tc.args...)
			if tc.wantErr == "" {
				ok(t, err)
				return
			}
			if err == nil || err.Error() != tc.wantErr {
				t.Fatalf("got %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestAnalyzeFromErrors(t *testing.T) {
	tests := map[string]struct {
		args  []string
		usage bool
		want  string
	}{
		"packages as well": {
			args: []string{"--from=testdata/one.json", "./..."}, usage: true,
			want: "--from reads saved results, so it takes no packages",
		},
		"a missing file": {args: []string{"--from=testdata/nope.json"}, want: "nope.json"},
		"a file not JSON": {
			args: []string{"--from=testdata/bad.json"},
			want: "parsing testdata/bad.json",
		},
		"unreadable roles": {
			args: []string{"--from=testdata/one.json", "--roles=testdata/nope"},
			want: "loading predefined roles",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := runAnalyze(t, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
			equals(t, errors.Is(err, root.ErrUsage), tc.usage)
		})
	}
}

func TestAnalyzeOutDir(t *testing.T) {
	tests := map[string]struct {
		args  []string
		files map[string]string // file name -> its first line, or "" for JSON
	}{
		"predefined roles, one file per binary needing permissions": {
			args: []string{"--format=predefined", "--roles=testdata/roles.json"},
			files: map[string]string{
				"example.com-one-cmd-a.txt": "# Code generated by gcp-perm-roller analyze " +
					"--format=predefined --roles=testdata/roles.json; DO NOT EDIT.",
			},
		},
		"custom roles": {
			args: []string{"--format=role"},
			files: map[string]string{
				"example.com-one-cmd-a.yaml": "# Code generated by gcp-perm-roller analyze --format=role; DO NOT EDIT.",
			},
		},
		"JSON, which has no header": {
			args:  []string{"--format=json"},
			files: map[string]string{"example.com-one-cmd-a.json": ""},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			// A generated file from an earlier run, a legacy one, and a
			// hand-written one.
			ok(t, os.WriteFile(filepath.Join(dir, "gone.txt"), []byte(generatedPrefix+"\n"), 0o600))
			ok(t, os.WriteFile(filepath.Join(dir, "old.txt"), []byte(legacyPrefix+"\n"), 0o600))
			ok(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Notes\n"), 0o600))
			_, err := runAnalyze(
				t,
				append([]string{"--from=testdata/one.json", "--outdir=" + dir}, tc.args...)...)
			ok(t, err)
			entries, err := os.ReadDir(dir)
			ok(t, err)
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			want := []string{"README.md"}
			for f := range tc.files {
				want = append(want, f)
			}
			slices.Sort(want)
			// spec: generated files this run did not write are removed; the
			// binary needing nothing gets no file.
			equals(t, names, want)
			for f, first := range tc.files {
				data, err := os.ReadFile(filepath.Join(dir, f))
				ok(t, err)
				line, _, _ := strings.Cut(string(data), "\n")
				if first == "" {
					equals(t, strings.HasPrefix(line, "{"), true)
					continue
				}
				equals(t, line, first)
			}
		})
	}
}

func TestCommandLine(t *testing.T) {
	cfg := Config{
		Format: "predefined", Roles: "api", RoleStages: []string{"GA", "BETA"},
		WithConditional: true, Union: true, Verbose: true, Tags: []string{"a", "b"},
		Algo: "rta", Wrappers: []string{"example.com/x.Cache"}, WrapperFiles: []string{"w.json"},
		Dir: "/somewhere", OutDir: "/elsewhere", From: []string{"x.json"},
	}
	// spec: every option that changes the content, and none that says where
	// it was made or written.
	equals(t, cfg.commandLine(), "gcp-perm-roller analyze --format=predefined --roles=api "+
		"--role-stages=GA --role-stages=BETA --include-conditional --union --verbose "+
		"--tags=a --tags=b --algo=rta --wrapper=example.com/x.Cache --wrapper-file=w.json")
	equals(t, (&Config{Format: "text", Algo: "vta"}).commandLine(),
		"gcp-perm-roller analyze --format=text")
}

func TestExtension(t *testing.T) {
	for format, want := range map[string]string{
		"json": ".json", "role": ".yaml", "predefined": ".txt", "text": ".txt",
	} {
		equals(t, extension(format), want)
	}
}

func TestWriteUnknownFormat(t *testing.T) {
	if err := write(io.Discard, "xml", gcpperms.Result{}, false); err == nil {
		t.Fatal("wrote an unknown format")
	}
}

func TestAnalyzeHelp(t *testing.T) {
	var out bytes.Buffer
	r := root.New(strings.NewReader(""), io.Discard, &out)
	New(r)
	err := r.Command.ParseAndRun(context.Background(), []string{"analyze", "--help"})
	if !errors.Is(err, ff.ErrHelp) {
		t.Fatalf("got %v, want ff.ErrHelp", err)
	}
	help := ffhelp.Command(r.Command.GetSelected()).String()
	for _, want := range []string{
		"analyze -- list the GCP permissions and roles each binary in a workspace needs",
		"gcp-perm-roller analyze [FLAGS] [PACKAGES...]",
		"Analyze builds a whole-program call graph",
		"--from=one.json --from=two.json --union",
		"--wrapper", "--wrapper-file", "--from",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("help lacks %q:\n%s", want, help)
		}
	}
}

func TestAnalyzeErrorsWrap(t *testing.T) {
	for name, args := range map[string][]string{
		"a missing results file": {"--from=testdata/nope.json"},
		"missing saved roles":    {"--from=testdata/one.json", "--roles=testdata/nope"},
		"a missing directory":    {"-C", "testdata/nope"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := runAnalyze(t, args...)
			// spec: the cause stays inspectable through the command's error.
			if !errors.Is(err, fs.ErrNotExist) && !strings.Contains(fmt.Sprint(err), "go list -m") {
				t.Fatalf("got %v, want a wrapped cause", err)
			}
		})
	}
	_, err := runAnalyze(t, "--from=testdata/bad.json")
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) {
		t.Fatalf("got %v, want a wrapped *json.SyntaxError", err)
	}
}

// writeModule writes a one-binary module, with no Google Cloud calls, to a
// directory whose name starts with "_", and returns the directory.
func writeModule(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "_tool")
	ok(t, os.MkdirAll(filepath.Join(dir, "cmd", "x"), 0o750))
	ok(t, os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module example.com/_tool\n\ngo 1.24\n"), 0o600))
	ok(t, os.WriteFile(filepath.Join(dir, "cmd", "x", "main.go"),
		[]byte("package main\n\nfunc main() {}\n"), 0o600))
	return dir
}

func TestAnalyzePackages(t *testing.T) {
	dir := writeModule(t)
	for name, args := range map[string][]string{
		"every module, by default": {"-C", dir},
		"a pattern":                {"-C", dir, "./cmd/..."},
		"with RTA":                 {"-C", dir, "--algo=rta", "./cmd/x"},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := runAnalyze(t, args...)
			ok(t, err)
			equals(t, out, "== example.com/_tool/cmd/x\n  no Google Cloud API calls\n")
		})
	}
	// spec: a wrapper file that cannot be read stops the analysis.
	_, err := runAnalyze(t, "-C", dir, "--wrapper-file=testdata/nope.json")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("got %v, want a missing wrapper file reported", err)
	}
	// spec: wrappers from a file and from --wrapper are both used.
	wfile := filepath.Join(t.TempDir(), "w.json")
	ok(
		t,
		os.WriteFile(wfile, []byte(`{"wrappers": [{"function": "example.com/_tool/x.F"}]}`), 0o600),
	)
	cfg := &Config{Wrappers: []string{"example.com/y.G"}, WrapperFiles: []string{wfile}}
	ws, err := cfg.wrappers()
	ok(t, err)
	equals(
		t,
		ws,
		[]gcpperms.Wrapper{{Function: "example.com/y.G"}, {Function: "example.com/_tool/x.F"}},
	)

	// spec: patterns that match no binary are an error, not an empty report.
	_, err = runAnalyze(t, "-C", dir, "./nope/...")
	if err == nil || !strings.Contains(err.Error(), "analyze: no main packages match ./nope/...") {
		t.Fatalf("got %v, want an error naming the pattern", err)
	}
}

func TestAnalyzeFlags(t *testing.T) {
	r := root.New(strings.NewReader(""), io.Discard, io.Discard)
	New(r)
	_ = r.Command.ParseAndRun(context.Background(), []string{"analyze", "--help"})
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
		"--format STRING",
		"--roles STRING",
		"--role-stages STRING",
		"--include-conditional",
		"--outdir STRING",
		"--union",
		"-v, --verbose",
		"--strict",
		"--tags STRING",
		"-j, --jobs INT",
		"--algo STRING",
		"--wrapper STRING",
		"--wrapper-file STRING",
		"--from STRING",
	})
}
