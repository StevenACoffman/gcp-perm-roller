package verifytable

import (
	"errors"
	"strings"
	"testing"
)

var (
	rpcGet    = RPC{Kind: "grpc", GRPC: "google.x.v1.S.Get"}
	rpcCommit = RPC{Kind: "grpc", GRPC: "google.x.v1.S.Commit"}
	rpcQuery  = RPC{Kind: "grpc", GRPC: "google.x.v1.S.RunQuery"}
	rpcNone   = RPC{Kind: "grpc", GRPC: "google.x.v1.S.Undocumented"}
	rpcBucket = RPC{Kind: "rest", API: "storage", Version: "v1", CallType: "BucketsGetCall"}
)

func TestCheckNames(t *testing.T) {
	rules := []tableRule{
		{Perms: []string{"a.b.get", "a.B.list"}, Line: 1},
		{Perms: []string{"a.b.get"}, Maybe: []string{"x.y.gone"}, Line: 2},
	}
	known := map[string]string{"a.b.get": "a.b.get", "a.b.list": "a.b.list"}
	findings, total := checkNames(rules, known)
	equals(t, total, 3)
	equals(t, findings, []nameFinding{
		{Permission: "a.B.list", Canonical: "a.b.list", Lines: []int{1}},
		{Permission: "x.y.gone", Lines: []int{2}},
	})
	equals(t, prefixes(rules), []string{"a", "x"})
}

func set(ss ...string) map[string]bool {
	m := make(map[string]bool)
	for _, s := range ss {
		m[s] = true
	}
	return m
}

// fakeDocs documents each RPC as the documentation would.
func fakeDocs(rpc *RPC) (methodDoc, error) {
	switch *rpc {
	case rpcGet:
		return methodDoc{
			Method:   "x.get",
			Source:   "page",
			Required: []string{"x.things.get"},
		}, nil
	case rpcCommit:
		return methodDoc{
			Method: "x.commit",
			Source: "table",
			Mentioned: []string{
				"x.things.create",
				"x.things.update",
				"x.things.delete",
			},
		}, nil
	case rpcQuery:
		return methodDoc{
			Method: "x.runQuery", Source: "page",
			Required: []string{"x.things.list"}, Mentioned: []string{"x.things.get"},
		}, nil
	default:
		return methodDoc{Method: "x.undocumented"}, errors.New("states no permission")
	}
}

func TestEvaluate(t *testing.T) {
	// method builds an entry for a method of recv taking params and
	// returning out.
	method := func(api string, rule tableRule, rpcs []RPC, recv string, params, out []string) *entry {
		rule.Pattern = api
		return newEntry(
			api,
			&rule,
			rpcs,
			set(recv),
			set(append([]string{recv}, params...)...),
			set(out...),
		)
	}
	get := method(
		"x.Client.Get",
		tableRule{Perms: []string{"x.things.get"}},
		[]RPC{rpcGet},
		"x.Client",
		nil,
		nil,
	)
	short := method(
		"x.Client.Short",
		tableRule{Perms: []string{"x.things.list"}},
		[]RPC{rpcGet},
		"x.Client",
		nil,
		nil,
	)
	extra := method(
		"x.Client.Extra",
		tableRule{Perms: []string{"X.Things.Get", "x.things.admin"}},
		[]RPC{rpcGet},
		"x.Client",
		nil,
		nil,
	)
	maybe := method(
		"x.Client.Query",
		tableRule{Perms: []string{"x.things.list"}, Maybe: []string{"x.things.get"}},
		[]RPC{rpcQuery},
		"x.Client",
		nil,
		nil,
	)
	// Shares only a parameter type with x.Tx.Put, so they are not paired.
	del := method(
		"x.Client.Delete",
		tableRule{Perms: []string{"x.things.delete"}},
		[]RPC{rpcCommit},
		"x.Client",
		[]string{"x.Key"},
		nil,
	)
	// Builders charged for the commit a call on the same receiver sends.
	put := method(
		"x.Tx.Put",
		tableRule{Perms: []string{"x.things.create"}},
		nil,
		"x.Tx",
		[]string{"x.Key"},
		[]string{"x.Pending"},
	)
	wrongPut := method(
		"x.Tx.Wrong",
		tableRule{Perms: []string{"x.things.admin"}},
		nil,
		"x.Tx",
		nil,
		nil,
	)
	// Commits the transaction its callback is given.
	commit := method(
		"x.Client.RunInTx",
		tableRule{},
		[]RPC{rpcCommit},
		"x.Client",
		[]string{"x.Tx"},
		nil,
	)
	// A constructor whose result a no-permission call consumes.
	run := method("x.Client.Run", tableRule{Perms: []string{"x.things.list", "x.things.get"}},
		[]RPC{rpcBucket}, "x.Client", nil, []string{"x.Iterator"})
	next := method("x.Iterator.Next", tableRule{}, []RPC{rpcQuery}, "x.Iterator", nil, nil)
	orphan := method(
		"x.Orphan.Do",
		tableRule{Perms: []string{"x.things.get"}},
		nil,
		"x.Orphan",
		nil,
		nil,
	)
	undocumented := method(
		"x.Client.Undocumented",
		tableRule{Perms: []string{"x.things.get"}},
		[]RPC{rpcNone},
		"x.Client",
		nil,
		nil,
	)
	notIAM := method(
		"x.Sheet.Do",
		tableRule{Note: "OAuth scope"},
		[]RPC{rpcGet},
		"x.Sheet",
		nil,
		nil,
	)
	silent := newEntry("x.NewKey", &tableRule{Pattern: "x.*"}, nil, nil, nil, set("x.Key"))

	got := make(map[string]finding)
	for _, f := range evaluate([]*entry{get, short, extra, maybe, del, put, wrongPut, commit, run, next, orphan, undocumented, notIAM, silent}, fakeDocs) {
		got[f.api] = f
	}
	tests := map[string]struct {
		status        Status
		missing       []string
		extra         []string
		methods       []string
		deferred      bool
		detailHasText string
	}{
		"x.Client.Get": {
			status:        Confirmed,
			methods:       []string{"x.get"},
			detailHasText: "its own RPCs",
		},
		"x.Client.Short": {
			status:  Mismatch,
			missing: []string{"x.things.get"},
			extra:   []string{"x.things.list"},
			methods: []string{"x.get"},
		},
		// Case does not matter; an undocumented permission does.
		"x.Client.Extra": {
			status:  Mismatch,
			extra:   []string{"x.things.admin"},
			methods: []string{"x.get"},
		},
		// A conditional permission is granted as Maybe and mentioned.
		"x.Client.Query":  {status: Confirmed, methods: []string{"x.runQuery"}},
		"x.Client.Delete": {status: Confirmed, methods: []string{"x.commit"}},
		// Paired with Commit alone, not with Delete, which also takes a Key.
		"x.Tx.Put": {
			status:        Confirmed,
			methods:       []string{"x.commit"},
			deferred:      true,
			detailHasText: "RPCs sent later by x.Client.RunInTx;",
		},
		"x.Tx.Wrong": {
			status:   Mismatch,
			extra:    []string{"x.things.admin"},
			methods:  []string{"x.commit"},
			deferred: true,
		},
		// RunInTx's own rule grants nothing; Put and Wrong pay for it.
		"x.Client.RunInTx": {
			status:        Confirmed,
			methods:       []string{"x.commit"},
			detailHasText: "paid for by x.Tx.Put, x.Tx.Wrong",
		},
		// Run's only RPC is explained away, so it is checked against Next.
		"x.Client.Run": {
			status:   Confirmed,
			methods:  []string{"x.runQuery"},
			deferred: true,
		},
		"x.Iterator.Next": {
			status:        Confirmed,
			methods:       []string{"x.runQuery"},
			detailHasText: "paid for by x.Client.Run",
		},
		"x.Orphan.Do": {status: Unverified, detailHasText: "no RPC was traced"},
		"x.Client.Undocumented": {
			status:        Mismatch,
			extra:         []string{"x.things.get"},
			methods:       []string{"x.undocumented"},
			detailHasText: "undocumented: states no permission",
		},
		"x.Sheet.Do": {status: NotIAM, detailHasText: "OAuth scope"},
	}
	equals(t, len(got), len(tests))
	for api, tc := range tests {
		t.Run(api, func(t *testing.T) {
			f, found := got[api]
			if !found {
				t.Fatalf("no finding for %s", api)
			}
			equals(t, f.status, tc.status)
			equals(t, f.missing, tc.missing)
			equals(t, f.extra, tc.extra)
			equals(t, f.methods, tc.methods)
			equals(t, f.deferred, tc.deferred)
			if !strings.Contains(f.detail, tc.detailHasText) {
				t.Fatalf(
					"detail %q does not mention %q",
					f.detail,
					tc.detailHasText,
				)
			}
		})
	}
}

func TestEvaluateAccepted(t *testing.T) {
	const api = "cloud.google.com/go/pubsub/v2/apiv1.TopicAdminClient.ListTopicSubscriptions"
	e := newEntry(
		api,
		&tableRule{Pattern: api, Perms: []string{"pubsub.topics.get"}},
		[]RPC{rpcNone},
		nil,
		nil,
		nil,
	)
	fs := evaluate([]*entry{e}, fakeDocs)
	equals(t, len(fs), 1)
	equals(t, fs[0].status, Accepted)
	equals(t, len(fs[0].extra), 0)
	equals(t, len(fs[0].accepted), 1)
	if !strings.HasPrefix(fs[0].accepted[0], "pubsub.topics.get: ") {
		t.Fatalf("accepted = %q", fs[0].accepted)
	}
	// Every accepted permission is lowercase, as findings compare them.
	for api, perms := range acceptedReasons() {
		for p := range perms {
			equals(t, p, strings.ToLower(p))
			if api == "" {
				t.Fatal("accepted entry with no API")
			}
		}
	}
}

func TestNewEntryDropsExplainedRPCs(t *testing.T) {
	e := newEntry("x", &tableRule{}, []RPC{rpcBucket, rpcGet}, nil, nil, nil)
	equals(t, e.rpcs, []RPC{rpcGet})
	// The bucket metadata fetch is BucketHandle.Attrs's own request.
	attrs := newEntry("cloud.google.com/go/storage.BucketHandle.Attrs", &tableRule{},
		[]RPC{rpcBucket, rpcGet}, nil, nil, nil)
	equals(t, attrs.rpcs, []RPC{rpcBucket, rpcGet})
}

func TestShares(t *testing.T) {
	equals(t, shares(set("a", "b"), set("b")), true)
	equals(t, shares(set("a"), set("b")), false)
	equals(t, shares(nil, set("b")), false)
}

func TestLowerSetAndKeys(t *testing.T) {
	equals(t, keys(lowerSet([]string{"B", "a"}, []string{"b"})), []string{"a", "b"})
	equals(t, keys(nil), []string{})
}

func TestRPCString(t *testing.T) {
	equals(t, rpcGet.String(), "google.x.v1.S.Get")
	equals(t, rpcBucket.String(), "storage/v1.BucketsGetCall")
}

func TestCountMissing(t *testing.T) {
	equals(t, countMissing([]nameFinding{{Canonical: "x"}, {}, {}}), 2)
}
