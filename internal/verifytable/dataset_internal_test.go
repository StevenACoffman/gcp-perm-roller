package verifytable

import "testing"

func TestLoadIAMDataset(t *testing.T) {
	d, err := loadIAMDataset("testdata/iam-dataset")
	ok(t, err)
	equals(
		t,
		d.restURLs,
		map[string]string{
			"bigquery": "https://docs.cloud.google.com/bigquery/docs/reference/rest",
		},
	)
	// Only authoritative access-control pages are used.
	equals(
		t,
		d.accessPages,
		map[string]string{
			"pubsub": "https://docs.cloud.google.com/pubsub/docs/access-control",
		},
	)
	equals(t, len(d.methods), 3)
	equals(
		t,
		d.roles["artifactregistry.dockerimages.list"],
		"artifactregistry.dockerimages.list",
	)
	equals(t, len(d.roles), 3)

	if _, err := loadIAMDataset("testdata/does-not-exist"); err == nil {
		t.Fatal("loading a missing dataset succeeded")
	}
}

func TestDatasetOpinion(t *testing.T) {
	d, err := loadIAMDataset("testdata/iam-dataset")
	ok(t, err)
	tests := map[string]struct {
		methods, granted                   []string
		wantLines                          []string
		wantDataset, wantRule, wantUnknown []string
	}{
		"agrees apart from a manual extra": {
			methods: []string{"bigquery.tables.patch"},
			granted: []string{"bigquery.tables.get", "BigQuery.Tables.Update"},
			wantLines: []string{
				"bigquery.tables.patch: bigquery.tables.get (restcrawliamblockv1), " +
					"bigquery.tables.update (manual, restcrawliamblockv1), bigquery.tables.updateTag (manual)",
			},
			wantDataset: []string{"bigquery.tables.updatetag"},
		},
		"conditional permissions are listed but never missing": {
			methods: []string{"bigquery.jobs.insert"},
			granted: []string{"bigquery.jobs.create", "bigquery.tables.export"},
			wantLines: []string{
				"bigquery.jobs.insert: bigquery.jobs.create (manual), " +
					`iam.serviceAccounts.actAs (manual; only if {"bodyPathExists": "$.x"})`,
			},
			wantRule: []string{"bigquery.tables.export"},
		},
		"empty and absent entries are unknown": {
			methods:     []string{"bigquery.tables.list", "bigquery.nope"},
			granted:     []string{"bigquery.tables.list"},
			wantUnknown: []string{"bigquery.tables.list", "bigquery.nope"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			lines, dsOnly, ruleOnly, unknown := d.opinion(tc.methods, tc.granted)
			equals(t, lines, tc.wantLines)
			equals(t, dsOnly, tc.wantDataset)
			equals(t, ruleOnly, tc.wantRule)
			equals(t, unknown, tc.wantUnknown)
		})
	}
}

func TestDocsHost(t *testing.T) {
	equals(
		t,
		docsHost("https://cloud.google.com/pubsub/docs/"),
		"https://docs.cloud.google.com/pubsub/docs",
	)
	equals(t, docsHost("https://developers.google.com/x"), "https://developers.google.com/x")
}
