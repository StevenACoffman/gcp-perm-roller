package verifytable

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/StevenACoffman/gcp-perm-roller/internal/gcpperms"
)

const tableSource = `package gcpperms

var shared = []string{"a.b.get", "a.b.list"}

var note = "a shared note"

var rules = []rule{
	{Pattern: "example.com/x.Client.Get", Perms: []string{"a.b.get"}},
	{
		Pattern: "example.com/x.Client.Run*",
		Perms:   shared,
		Maybe:   []string{"a.b.delete"},
		Note:    "first " + "second " + "third",
	},
	{Pattern: "example.com/x.Client.Note", Note: note},
	{Pattern: "example.com/x.*"},
	{Pattern: "example.com/glob/*"},
}
`

func TestParseTable(t *testing.T) {
	file := filepath.Join(t.TempDir(), "table.go")
	ok(t, os.WriteFile(file, []byte(tableSource), 0o644))
	rules, err := parseTable(file, nil)
	ok(t, err)
	equals(t, rules, []tableRule{
		{Pattern: "example.com/x.Client.Get", Perms: []string{"a.b.get"}, Line: 8},
		{
			Pattern: "example.com/x.Client.Run*",
			Perms:   []string{"a.b.get", "a.b.list"},
			Maybe:   []string{"a.b.delete"},
			Note:    "first second third",
			Line:    9,
		},
		{Pattern: "example.com/x.Client.Note", Note: "a shared note", Line: 15},
		{Pattern: "example.com/x.*", Line: 16},
		{Pattern: "example.com/glob/*", Line: 17},
	})
}

func TestParseTableErrors(t *testing.T) {
	tests := map[string]string{
		"syntax error":        "package x\nvar rules = ",
		"no rules":            "package x\nvar other = []int{1}",
		"rules not a literal": "package x\nvar rules = f()",
		"rule not a literal":  "package x\nvar rules = []rule{r}",
		"unkeyed field":       "package x\nvar rules = []rule{{\"p\"}}",
		"pattern not string":  "package x\nvar rules = []rule{{Pattern: 1}}",
		"perms not a slice":   "package x\nvar rules = []rule{{Perms: \"p\"}}",
		"perm not a string":   "package x\nvar rules = []rule{{Perms: []string{x}}}",
		"note not a string":   "package x\nvar rules = []rule{{Note: 1 - 2}}",
		"bad concatenation":   "package x\nvar rules = []rule{{Note: \"a\" + 1}}",
		"maybe not a slice":   "package x\nvar rules = []rule{{Maybe: 3}}",
	}
	for name, src := range tests {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "table.go")
			ok(t, os.WriteFile(file, []byte(src), 0o644))
			if _, err := parseTable(file, nil); err == nil {
				t.Fatal("parseTable succeeded")
			}
		})
	}
}

// TestParseRealTable keeps the parser in step with gcpperms' table.
func TestParseRealTable(t *testing.T) {
	rules, err := parseTable("table.go", gcpperms.TableSource)
	ok(t, err)
	if len(rules) < 100 {
		t.Fatalf("parsed only %d rules", len(rules))
	}
	for _, r := range rules {
		if r.Pattern == "" {
			t.Fatalf("rule at line %d has no pattern", r.Line)
		}
	}
}

func TestMatch(t *testing.T) {
	rules := []tableRule{
		{Pattern: "example.com/x.Client.Get"},
		{Pattern: "example.com/x.Client.Run*"},
		{Pattern: "example.com/x.*"},
		{Pattern: "example.com/glob/*"},
	}
	tests := map[string]struct {
		api  string
		want int
	}{
		"exact":                 {api: "example.com/x.Client.Get", want: 0},
		"name glob":             {api: "example.com/x.Client.RunQuery", want: 1},
		"first match wins":      {api: "example.com/x.Client.Close", want: 2},
		"package glob":          {api: "example.com/glob/deep/pkg.F", want: 3},
		"other package":         {api: "example.com/y.Client.Get", want: -1},
		"parent of a glob root": {api: "example.com/glob.F", want: -1},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			equals(t, match(rules, tc.api), tc.want)
		})
	}
}

func TestSplitAPI(t *testing.T) {
	tests := map[string]struct{ in, pkg, name string }{
		"method": {
			in:   "cloud.google.com/go/datastore.Client.Get",
			pkg:  "cloud.google.com/go/datastore",
			name: "Client.Get",
		},
		"function":      {in: "a/b.F", pkg: "a/b", name: "F"},
		"no name":       {in: "a/b", pkg: "a/b"},
		"dotted domain": {in: "a.b/c", pkg: "a.b/c"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			pkg, n := splitAPI(tc.in)
			equals(t, pkg, tc.pkg)
			equals(t, n, tc.name)
		})
	}
}
