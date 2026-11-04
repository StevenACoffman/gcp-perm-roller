package gcpperms

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadResults(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		ok(t, os.WriteFile(path, []byte(data), 0o600))
		return path
	}
	one := write(
		"one.json",
		`{"binaries": [{"package": "example.com/a"}], "skipped": ["example.com/x"],
		"errors": ["example.com/e1: boom"]}`,
	)
	two := write(
		"two.json",
		`{"binaries": [{"package": "example.com/b"}, {"package": "example.com/c"}],
		"skipped": ["example.com/y"], "errors": ["example.com/e2: bang"]}`,
	)
	got, err := LoadResults([]string{one, two})
	ok(t, err)
	// spec: binaries, skipped packages, and errors are kept in file order.
	var pkgs []string
	for _, b := range got.Binaries {
		pkgs = append(pkgs, b.Package)
	}
	equals(t, pkgs, []string{"example.com/a", "example.com/b", "example.com/c"})
	equals(t, got.Skipped, []string{"example.com/x", "example.com/y"})
	equals(t, got.Errors, []string{"example.com/e1: boom", "example.com/e2: bang"})

	bad := write("bad.json", "not JSON")
	for name, tc := range map[string]struct {
		files []string
		want  string
	}{
		"a missing file": {
			files: []string{one, filepath.Join(dir, "nope.json")},
			want:  "gcpperms.LoadResults: open ",
		},
		"a file not JSON": {
			files: []string{bad},
			want:  "gcpperms.LoadResults: parsing " + bad + ": ",
		},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := LoadResults(tc.files)
			if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error starting %q", err, tc.want)
			}
			// spec: a failed load returns no partial result.
			equals(t, len(res.Binaries), 0)
		})
	}
}

func TestSelectBinaries(t *testing.T) {
	bins := []Binary{
		{Package: "example.com/a"},
		{Package: "example.com/b"},
		{Package: "example.com/c"},
	}
	tests := map[string]struct {
		packages []string
		want     []string
		wantErr  string
	}{
		"every binary by default": {
			want: []string{"example.com/a", "example.com/b", "example.com/c"},
		},
		// spec: the binaries named, in the order named.
		"named, in order": {
			packages: []string{"example.com/c", "example.com/a"},
			want:     []string{"example.com/c", "example.com/a"},
		},
		"an unknown package": {
			packages: []string{"example.com/a", "example.com/z"},
			wantErr:  "no binary example.com/z in the results",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := SelectBinaries(bins, tc.packages)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("got %v, want %q", err, tc.wantErr)
				}
				equals(t, len(got), 0)
				return
			}
			ok(t, err)
			var pkgs []string
			for _, b := range got {
				pkgs = append(pkgs, b.Package)
			}
			equals(t, pkgs, tc.want)
		})
	}
}
