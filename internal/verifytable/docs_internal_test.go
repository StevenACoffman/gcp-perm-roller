package verifytable

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
)

// datastoreTable is an excerpt of the Datastore access-control page.
const datastoreTable = `<table><tr><th>Method</th><th>Required Permission(s)</th></tr>
<tr><td><code><a href="/x">beginTransaction</a></code></td><td><code>datastore.databases.get</code></td></tr>
<tr><td><code><a href="/x">commit</a></code> for an insert</td><td><code>datastore.entities.create</code></td></tr>
<tr><td><code><a href="/x">commit</a></code> for an upsert</td><td><code>datastore.entities.create</code><br/>
<code>datastore.entities.update</code></td></tr>
<tr><td><code>runQuery</code></td><td><code>datastore.entities.list</code> <code>datastore.entities.get</code></td></tr>
<tr><td>projects.topics.publish</td><td>pubsub.topics.publish on the requested topic</td></tr>
<tr><td>lonely cell</td></tr></table>`

// The page fixtures are excerpts of Google Cloud REST reference pages in
// each layout the parser handles.
const (
	// An IAM section with a list, as on BigQuery pages.
	pageIAMList = `<p>Updates a table.</p><section><h3 id="iam-permissions" data-text="IAM Permissions">IAM Permissions</h3>
<p>Requires the following IAM permission(s) on the table:</p> <ul> <li><code>bigquery.tables.update</code></li>
<li><code>bigquery.tables.get</code></li> </ul> </section><section id="body"><h3 id="http-request">HTTP request</h3>
<p>Requires the bigquery.jobs.create permission elsewhere.</p>`
	// Several required sentences, then an alternative.
	pageIAMSentences = `<h3 id="iam-permissions">IAM Permissions</h3><p>Requires the following IAM permission(s) to use this method:
<code>bigquery.jobs.get</code> on the job. <code>bigquery.tables.getData</code> on the destination table. If the user
matches the creator of the job, the following IAM permission(s) are required instead: <code>bigquery.jobs.create</code>
on the project.</p></section>`
	// A required permission and a conditional one, as on Cloud Storage pages.
	pageRequiredPermissions = `<section id="required-permissions"><h2 id="required-permissions">Required permissions</h2>
<p>The authenticated user must have the <code>storage.objects.get</code> IAM permission to use this method. To return
object ACLs, the authenticated user must also have the <code>storage.objects.getIamPolicy</code> permission.</p></section>`
	// Permissions that each apply to one kind of request.
	pageConditional = `<h3 id="iam-permissions">IAM Permissions</h3><p>Requires the <code>dataflow.jobs.cancel</code> permission
to cancel a job. Requires the <code>dataflow.jobs.updateContents</code> permission to update runtime parameters.</p>
<h3 id="http-request">HTTP request</h3>`
	// A statement inside a path parameter's description, as on most pages.
	pageParameter = `<table><tr><td><code>name</code></td><td><p>Required. The resource name. Authorization requires the
following IAM permission on the specified resource <code>name</code>:</p> <ul><li><code>secretmanager.versions.access</code></li></ul>
</td></tr></table>`
	// No IAM section; only a sentence in running text.
	pageUnstructured = `<p>Some text. Requires the pubsub.topics.publish permission on the topic. Unrelated sentence
mentioning example.com.www.</p>`
	pageNoPermissions = `<p>Lists subscriptions. Request body must be empty.</p>`
)

var testDiscovery = &discoveryDoc{
	Name: "secretmanager", Version: "v1",
	Resources: map[string]discoveryResource{
		"projects": {
			Resources: map[string]discoveryResource{
				"secrets": {
					Methods: map[string]discoveryMethod{
						"addVersion": {
							ID:         "secretmanager.projects.secrets.addVersion",
							HTTPMethod: "POST",
							FlatPath:   "v1/projects/{projectsId}/secrets/{secretsId}:addVersion",
						},
					},
					Resources: map[string]discoveryResource{
						"versions": {Methods: map[string]discoveryMethod{
							"access": {
								ID:         "secretmanager.projects.secrets.versions.access",
								HTTPMethod: "GET",
								FlatPath:   "v1/projects/{projectsId}/secrets/{secretsId}/versions/{versionsId}:access",
							},
						}},
					},
				},
			},
		},
	},
	Methods: map[string]discoveryMethod{
		"top": {ID: "secretmanager.top", HTTPMethod: "GET", Path: "v1/top"},
	},
}

func TestTablePermissions(t *testing.T) {
	tests := map[string]struct {
		names                       []string
		wantRequired, wantMentioned []string
		wantFound                   bool
	}{
		"unqualified row is required": {
			names:         []string{"beginTransaction"},
			wantRequired:  []string{"datastore.databases.get"},
			wantMentioned: []string{"datastore.databases.get"},
			wantFound:     true,
		},
		"qualified rows are only mentioned": {
			names: []string{"commit"},
			wantMentioned: []string{
				"datastore.entities.create",
				"datastore.entities.create",
				"datastore.entities.update",
			},
			wantFound: true,
		},
		"a row naming the method by resource path": {
			names: []string{
				"publish",
				"topics.publish",
				"projects.topics.publish",
			},
			wantRequired:  []string{"pubsub.topics.publish"},
			wantMentioned: []string{"pubsub.topics.publish"},
			wantFound:     true,
		},
		"names match case-insensitively": {
			names: []string{"RunQuery"},
			wantRequired: []string{
				"datastore.entities.list",
				"datastore.entities.get",
			},
			wantMentioned: []string{
				"datastore.entities.list",
				"datastore.entities.get",
			},
			wantFound: true,
		},
		"absent": {names: []string{"lookup", "lonely cell"}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			req, men, found := tablePermissions(datastoreTable, tc.names)
			equals(t, found, tc.wantFound)
			equals(t, req, tc.wantRequired)
			equals(t, men, tc.wantMentioned)
		})
	}
}

func TestPagePermissions(t *testing.T) {
	tests := map[string]struct {
		body          string
		wantRequired  []string
		wantMentioned []string
	}{
		"IAM section with a list; text outside it is ignored": {
			body:          pageIAMList,
			wantRequired:  []string{"bigquery.tables.update", "bigquery.tables.get"},
			wantMentioned: []string{"bigquery.tables.update", "bigquery.tables.get"},
		},
		"later sentences in a requirement list stay required; alternatives do not": {
			body:         pageIAMSentences,
			wantRequired: []string{"bigquery.jobs.get", "bigquery.tables.getData"},
			wantMentioned: []string{
				"bigquery.jobs.get",
				"bigquery.tables.getData",
				"bigquery.jobs.create",
			},
		},
		"must also have is conditional": {
			body:         pageRequiredPermissions,
			wantRequired: []string{"storage.objects.get"},
			wantMentioned: []string{
				"storage.objects.get",
				"storage.objects.getIamPolicy",
			},
		},
		"permission to do something is conditional": {
			body: pageConditional,
			wantMentioned: []string{
				"dataflow.jobs.cancel",
				"dataflow.jobs.updateContents",
			},
		},
		"parameter description with a list": {
			body:          pageParameter,
			wantRequired:  []string{"secretmanager.versions.access"},
			wantMentioned: []string{"secretmanager.versions.access"},
		},
		"unstructured page: only sentences that state a requirement": {
			body:          pageUnstructured,
			wantRequired:  []string{"pubsub.topics.publish"},
			wantMentioned: []string{"pubsub.topics.publish"},
		},
		"no statement": {body: pageNoPermissions},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			req, men := pagePermissions(tc.body)
			equals(t, req, tc.wantRequired)
			equals(t, men, tc.wantMentioned)
		})
	}
}

func TestIAMBlocks(t *testing.T) {
	equals(t, len(iamBlocks(pageNoPermissions)), 0)
	equals(t, len(iamBlocks(pageUnstructured)), 0)
	// A heading block, and the parameter block it contains, both count.
	equals(t, len(iamBlocks(pageIAMList+pageParameter)), 2)
	// The parameter block runs to the end of the list after it.
	blocks := iamBlocks(pageParameter)
	equals(t, len(blocks), 1)
	equals(t, perms(text(blocks[0])), []string{"secretmanager.versions.access"})
}

func TestSentences(t *testing.T) {
	tests := map[string]struct {
		in   string
		want []string
	}{
		"split before a capital": {
			in:   "One. Two. Three",
			want: []string{"One.", "Two.", "Three"},
		},
		"permission names stay whole": {
			in:   "Requires a.b.c on it. b.c.d on that. Next one.",
			want: []string{"Requires a.b.c on it. b.c.d on that.", "Next one."},
		},
		"empty": {in: "", want: []string{""}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			equals(t, sentences(tc.in), tc.want)
		})
	}
}

func TestPerms(t *testing.T) {
	equals(
		t,
		perms(
			"needs storage.objects.get and iam.serviceAccounts.signBlob, not www.googleapis.com, "+
				"cloud.google.com.docs, example.org.com, page.index.html or Foo.bar.baz",
		),
		[]string{"storage.objects.get", "iam.serviceAccounts.signBlob"},
	)
}

func TestNormPath(t *testing.T) {
	tests := map[string]struct{ in, want string }{
		"template with a pattern": {
			in:   "/v1/{name=projects/*/secrets/*/versions/*}:access",
			want: "v1/projects/*/secrets/*/versions/*:access",
		},
		"simple variables": {
			in:   "/v1/projects/{project_id}:lookup",
			want: "v1/projects/*:lookup",
		},
		"discovery flat path": {
			in:   "v1/projects/{projectsId}/topics/{topicsId}:publish",
			want: "v1/projects/*/topics/*:publish",
		},
		"double wildcard": {in: "/v1/{name=**}", want: "v1/*"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			equals(t, normPath(tc.in), tc.want)
		})
	}
}

func TestGuessMethodID(t *testing.T) {
	tests := map[string]struct{ api, tmpl, want string }{
		"custom verb": {
			api:  "alloydb",
			tmpl: "/v1alpha/{parent=projects/*/locations/*/clusters/*}:generateClientCertificate",
			want: "alloydb.projects.locations.clusters.generateClientCertificate",
		},
		"literal collections": {
			api:  "pubsub",
			tmpl: "/v1/{topic=projects/*/topics/*}:publish",
			want: "pubsub.projects.topics.publish",
		},
		"standard method has no guess": {
			api:  "secretmanager",
			tmpl: "/v1/{name=projects/*/secrets/*}",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			equals(t, guessMethodID(tc.api, tc.tmpl), tc.want)
		})
	}
}

func TestDiscoveryMethodFor(t *testing.T) {
	tests := map[string]struct {
		verb, tmpl, want string
	}{
		"nested resource": {
			verb: "GET", tmpl: "/v1/{name=projects/*/secrets/*/versions/*}:access",
			want: "secretmanager.projects.secrets.versions.access",
		},
		"top-level method by path": {
			verb: "GET",
			tmpl: "/v1/top",
			want: "secretmanager.top",
		},
		"verb must match": {
			verb: "POST",
			tmpl: "/v1/{name=projects/*/secrets/*/versions/*}:access",
		},
		"path must match": {
			verb: "GET",
			tmpl: "/v1/{name=projects/*/secrets/*}:access",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			m, ok := testDiscovery.methodFor(tc.verb, tc.tmpl)
			equals(t, ok, tc.want != "")
			equals(t, m.ID, tc.want)
		})
	}
	equals(t, len(testDiscovery.allMethods()), 3)
}

func TestDiscoveryMethodForCall(t *testing.T) {
	tests := map[string]struct{ callType, want string }{
		"nested": {
			callType: "ProjectsSecretsVersionsAccessCall",
			want:     "secretmanager.projects.secrets.versions.access",
		},
		"shallower": {
			callType: "ProjectsSecretsAddVersionCall",
			want:     "secretmanager.projects.secrets.addVersion",
		},
		"unknown": {callType: "ProjectsSecretsDeleteCall"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			m, ok := testDiscovery.methodForCall(tc.callType)
			equals(t, ok, tc.want != "")
			equals(t, m.ID, tc.want)
		})
	}
}

func TestFetcherCaches(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		// Only /page is served, so the body need not echo the request.
		_, _ = w.Write([]byte("hello /page"))
	}))
	defer srv.Close()
	f := &fetcher{ctx: context.Background(), dir: t.TempDir(), client: srv.Client()}

	for range 2 {
		p, err := f.get(srv.URL + "/page")
		ok(t, err)
		equals(t, p.Status, http.StatusOK)
		equals(t, p.Body, "hello /page")
		equals(t, p.URL, srv.URL+"/page")
	}
	equals(t, hits.Load(), int32(1))

	p, err := f.get(srv.URL + "/missing")
	ok(t, err)
	equals(t, p.Status, http.StatusNotFound)
}

func TestReferencePage(t *testing.T) {
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		if r.URL.Path == "/override/v1/projects.secrets.versions/access" ||
			r.URL.Path == "/docs/reference/rest/v1/projects.secrets.versions/access" {
			_, _ = w.Write([]byte("page for access"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	m := discoveryMethod{ID: "secretmanager.projects.secrets.versions.access"}

	tests := map[string]struct {
		doc       discoveryDoc
		extraRefs map[string]string
		wantPath  string
		wantErr   bool
	}{
		"from the documentation link": {
			doc: discoveryDoc{
				Name:              "secretmanager",
				Version:           "v1",
				DocumentationLink: srv.URL + "/docs/",
			},
			wantPath: "/docs/reference/rest/v1/projects.secrets.versions/access",
		},
		"an extra reference root wins over the link": {
			doc: discoveryDoc{
				Name:              "secretmanager",
				Version:           "v1",
				DocumentationLink: srv.URL + "/wrong/",
			},
			extraRefs: map[string]string{"secretmanager": srv.URL + "/override"},
			wantPath:  "/override/v1/projects.secrets.versions/access",
		},
		"not found": {
			doc: discoveryDoc{
				Name:              "secretmanager",
				Version:           "v2",
				DocumentationLink: srv.URL + "/docs",
			},
			wantErr: true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			asked = nil
			f := &fetcher{
				ctx:       context.Background(),
				dir:       t.TempDir(),
				client:    srv.Client(),
				extraRefs: tc.extraRefs,
			}
			p, err := f.referencePage(&tc.doc, m)
			equals(t, err != nil, tc.wantErr)
			if !tc.wantErr {
				equals(t, p.URL, srv.URL+tc.wantPath)
			}
			equals(t, len(asked), 1)
		})
	}
}

func TestKnownPermissions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/iam/docs/roles-permissions/firestore":
			_, _ = w.Write([]byte("<td>datastore.entities.get</td>"))
		case "/iam/docs/roles-permissions/artifactregistry":
			_, _ = w.Write([]byte("<td>artifactregistry.dockerimages.list</td>"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	f := &fetcher{
		ctx:           context.Background(),
		dir:           t.TempDir(),
		client:        srv.Client(),
		referenceRoot: srv.URL,
	}
	known, missing, err := f.knownPermissions([]string{"artifactregistry", "datastore", "nope"})
	ok(t, err)
	equals(t, known, map[string]string{
		"datastore.entities.get":             "datastore.entities.get",
		"artifactregistry.dockerimages.list": "artifactregistry.dockerimages.list",
	})
	equals(t, missing, []string{"nope"})
}

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

func TestReferenceBase(t *testing.T) {
	tests := map[string]struct {
		api    string
		want   string
		wantOK bool
	}{
		"artifact registry": {
			api: "artifactregistry", wantOK: true,
			want: "https://docs.cloud.google.com/artifact-registry/docs/reference/rest",
		},
		"profiler, whose pages sit under the version": {
			api: "cloudprofiler", wantOK: true,
			want: "https://docs.cloud.google.com/profiler/docs/reference/v2/rest",
		},
		"trace, whose pages sit under the version": {
			api: "cloudtrace", wantOK: true,
			want: "https://docs.cloud.google.com/trace/docs/reference/v2/rest",
		},
		"datastore": {
			api: "datastore", wantOK: true,
			want: "https://docs.cloud.google.com/datastore/docs/reference/data/rest",
		},
		"iam credentials": {
			api: "iamcredentials", wantOK: true,
			want: "https://docs.cloud.google.com/iam/docs/reference/credentials/rest",
		},
		"monitoring": {
			api: "monitoring", wantOK: true,
			want: "https://docs.cloud.google.com/monitoring/api/ref_v3/rest",
		},
		"storage": {
			api: "storage", wantOK: true,
			want: "https://docs.cloud.google.com/storage/docs/json_api",
		},
		"found through its documentation link instead": {api: "secretmanager"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, ok := referenceBase(tc.api)
			equals(t, ok, tc.wantOK)
			equals(t, got, tc.want)
		})
	}
}

func TestRPCPermissions(t *testing.T) {
	// Text of the BigQuery Storage RPC reference page, abridged.
	const page = "CreateReadSessionRequest Request message for CreateReadSession . Fields " +
		"parent string Required. Authorization requires the following IAM permission on " +
		"the specified resource parent : bigquery.readsessions.create read_session " +
		"ReadSession Required. Authorization requires the following IAM permission on the " +
		"specified resource readSession : bigquery.tables.getData max_stream_count int32 " +
		"Max initial number of streams. ReadRowsRequest Request message for ReadRows . " +
		"Fields read_stream string Required. Authorization requires the following IAM " +
		"permission on the specified resource readStream : bigquery.readsessions.getData " +
		"offset int64 The offset. ReadRowsResponse Response message for ReadRows . Fields " +
		"row_count int64 Rows in the response, see bigquery.tables.list for more."
	tests := map[string]struct {
		method string
		want   []string
	}{
		"every field's permission, up to the next message": {
			method: "CreateReadSession",
			want:   []string{"bigquery.readsessions.create", "bigquery.tables.getData"},
		},
		"not the response message's text": {
			method: "ReadRows",
			want:   []string{"bigquery.readsessions.getData"},
		},
		"a method the page does not document": {method: "SplitReadStream"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			equals(t, rpcPermissions(page, tc.method), tc.want)
		})
	}
}

func TestRPCReferencePage(t *testing.T) {
	got, ok := rpcReferencePage("google.cloud.bigquery.storage.v1")
	equals(t, ok, true)
	equals(
		t,
		got,
		"https://docs.cloud.google.com/bigquery/docs/reference/storage/rpc/google.cloud.bigquery.storage.v1",
	)
	_, ok = rpcReferencePage("google.cloud.secretmanager.v1")
	equals(t, ok, false)
}
