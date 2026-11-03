package gcpperms

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const appSA = "serviceAccount:app@demo.iam.gserviceaccount.com"

func readInsights(t *testing.T, name string) []Insight {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	ok(t, err)
	insights, err := ParseInsights(data)
	ok(t, err)
	return insights
}

func TestParseInsights(t *testing.T) {
	got := readInsights(t, "insights.yaml")
	// spec: gcloud's YAML and its --format=json output parse the same.
	equals(t, readInsights(t, "insights.json"), got)
	equals(t, got[1], Insight{
		Member:    appSA,
		Role:      "roles/storage.objectViewer",
		Exercised: []string{"storage.objects.list"},
		Observed:  30 * 24 * time.Hour,
	})

	for name, tc := range map[string]struct{ data, want string }{
		"not an IAM insight": {data: `[{"content": {"recommendation": "x"}}]`, want: "names no member and role"},
		"bad period": {
			data: `[{"observationPeriod": "a while", "content": {"member": "user:a@b.c", "role": "roles/viewer"}}]`,
			want: "observation period",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseInsights([]byte(tc.data))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func TestCompareUsage(t *testing.T) {
	roles := []Role{
		{
			Name:        "roles/datastore.user",
			Permissions: []string{"datastore.entities.get", "datastore.entities.update"},
		},
		{
			Name:        "roles/storage.objectViewer",
			Permissions: []string{"storage.objects.get", "storage.objects.list"},
		},
	}
	bins := []Binary{
		{Package: "example.com/cmd/server", Calls: []Call{{
			API:         "x",
			Permissions: []string{"datastore.entities.get", "storage.objects.get"},
			Conditional: []string{"datastore.entities.update"},
		}}},
		{
			Package: "example.com/cmd/worker",
			Calls:   []Call{{API: "y", Permissions: []string{"secretmanager.versions.access"}}},
		},
	}
	got := CompareUsage(bins, appSA, readInsights(t, "insights.yaml"), roles)
	// spec: another member's insight is not counted; a permission used but
	// not found is unexpected; one found and held by an insight's role but
	// not used is unused; one no insight's role holds has no usage data; an
	// insight's role with no definition is named.
	equals(t, got, Usage{
		Member:       appSA,
		Packages:     []string{"example.com/cmd/server", "example.com/cmd/worker"},
		Insights:     3,
		ObservedDays: 90,
		Unexpected:   []string{"logging.logEntries.create", "storage.objects.list"},
		Used:         []string{"datastore.entities.get"},
		Unused:       []string{"datastore.entities.update", "storage.objects.get"},
		Unobserved:   []string{"secretmanager.versions.access"},
		Conditional:  []string{"datastore.entities.update"},
		UnknownRoles: []string{"projects/demo/roles/Custom"},
	})

	var buf bytes.Buffer
	ok(t, WriteUsage(&buf, &got))
	equals(
		t,
		buf.String(),
		`== serviceAccount:app@demo.iam.gserviceaccount.com (example.com/cmd/server, example.com/cmd/worker)
  3 insights, observing up to 90 days
  Used, but not found by analyze (a missing rule, a call analyze cannot follow, or another program running as this member):
    logging.logEntries.create
    storage.objects.list
  Found by analyze, but not used:
    datastore.entities.update (conditional)
    storage.objects.get
  Found by analyze, with no usage data (no insight covers a role holding them):
    secretmanager.versions.access
  Roles with insights but no definition: projects/demo/roles/Custom
  1 of 4 permissions found by analyze were used
`,
	)

	// spec: with no insights about the member, the report says so.
	none := CompareUsage(bins, "user:nobody@example.com", readInsights(t, "insights.yaml"), roles)
	buf.Reset()
	ok(t, WriteUsage(&buf, &none))
	if !strings.Contains(buf.String(), "no insights about this member") {
		t.Fatalf("report lacks the no-insights line:\n%s", buf.String())
	}
}
