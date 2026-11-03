package gcpperms

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/api/option"
)

func TestNewTroubleshooter(t *testing.T) {
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v3/iam:troubleshoot" {
			http.NotFound(w, r)
			return
		}
		var req struct {
			AccessTuple struct {
				Principal        string `json:"principal"`
				FullResourceName string `json:"fullResourceName"`
				Permission       string `json:"permission"`
			} `json:"accessTuple"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		a := req.AccessTuple
		asked = append(asked, a.Principal+" "+a.FullResourceName+" "+a.Permission)
		if a.Permission == "secret.things.get" {
			http.Error(w, `{"error": {"code": 403, "message": "denied"}}`, http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"overallAccessState": "UNKNOWN_INFO",
			"allowPolicyExplanation": map[string]string{
				"allowAccessState": "ALLOW_ACCESS_STATE_GRANTED",
			},
			"denyPolicyExplanation": map[string]string{
				"denyAccessState": "DENY_ACCESS_STATE_UNKNOWN_INFO",
			},
		})
	}))
	t.Cleanup(srv.Close)

	ctx := context.Background()
	ts, err := NewTroubleshooter(ctx, option.WithEndpoint(srv.URL), option.WithoutAuthentication())
	ok(t, err)
	const project = "//cloudresourcemanager.googleapis.com/projects/demo"
	v, err := ts(ctx, "app@demo.iam.gserviceaccount.com", project, "datastore.entities.get")
	ok(t, err)
	// spec: the request names the principal, resource, and permission, and
	// the verdict has the overall, allow, and deny states, as a caller who
	// cannot read deny policies gets them.
	equals(t, v, Verdict{
		State: UnknownInfo,
		Allow: "ALLOW_ACCESS_STATE_GRANTED",
		Deny:  "DENY_ACCESS_STATE_UNKNOWN_INFO",
	})
	equals(
		t,
		asked,
		[]string{"app@demo.iam.gserviceaccount.com " + project + " datastore.entities.get"},
	)

	// spec: an API error says which permission it was for.
	_, err = ts(ctx, "app@demo.iam.gserviceaccount.com", project, "secret.things.get")
	if err == nil || !strings.Contains(err.Error(), "secret.things.get") {
		t.Fatalf("got %v, want an error naming the permission", err)
	}
}

func TestCheckAccess(t *testing.T) {
	bins := []Binary{
		{Package: "example.com/one", Calls: []Call{{
			API:         "x",
			Permissions: []string{"a.b.get", "a.b.list"},
			Conditional: []string{"a.b.delete"},
		}}},
		{Package: "example.com/two", Calls: []Call{{API: "y", Permissions: []string{"a.b.get"}}}},
	}
	var calls []string
	ts := func(_ context.Context, _, _, perm string) (Verdict, error) {
		calls = append(calls, perm)
		switch perm {
		case "a.b.list":
			return Verdict{State: CannotAccess}, nil
		case "a.b.delete":
			return Verdict{State: UnknownInfo, Allow: "ALLOW_ACCESS_STATE_GRANTED"}, nil
		}
		return Verdict{State: CanAccess}, nil
	}
	got, err := CheckAccess(context.Background(), ts, "sa@x", "//r", bins, true)
	ok(t, err)
	// spec: each permission is asked about once, however many binaries
	// need it.
	equals(t, calls, []string{"a.b.get", "a.b.list", "a.b.delete"})
	equals(t, got, []BinaryAccess{
		{Package: "example.com/one", Principal: "sa@x", Resource: "//r", Checks: []AccessCheck{
			{Permission: "a.b.get", Verdict: Verdict{State: CanAccess}},
			{Permission: "a.b.list", Verdict: Verdict{State: CannotAccess}},
			{
				Permission:  "a.b.delete",
				Conditional: true,
				Verdict:     Verdict{State: UnknownInfo, Allow: "ALLOW_ACCESS_STATE_GRANTED"},
			},
		}},
		{Package: "example.com/two", Principal: "sa@x", Resource: "//r", Checks: []AccessCheck{
			{Permission: "a.b.get", Verdict: Verdict{State: CanAccess}},
		}},
	})

	// spec: a grant the overall state hides is noted.
	var buf bytes.Buffer
	ok(t, WriteAccessChecks(&buf, got[:1]))
	equals(t, buf.String(), `== example.com/one
  sa@x on //r
    CAN_ACCESS           a.b.get
    CANNOT_ACCESS        a.b.list
    UNKNOWN_INFO         a.b.delete (conditional; allowed; deny policies not readable)
  1 of 3 permissions held
`)

	// spec: without includeConditional, conditional permissions are not
	// checked.
	got, err = CheckAccess(context.Background(), ts, "sa@x", "//r", bins[:1], false)
	ok(t, err)
	equals(t, len(got[0].Checks), 2)
}
