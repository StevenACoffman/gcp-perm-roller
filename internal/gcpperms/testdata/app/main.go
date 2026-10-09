// Command app is a fixture for the gcpperms end-to-end test. Comments
// starting "// site:" mark the lines the test expects as call sites.
package main

import (
	"context"

	"cloud.google.com/go/datastore"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"cloud.google.com/go/storage"
)

// getter is a first-party interface satisfied by *datastore.Client.
type getter interface {
	Get(ctx context.Context, key *datastore.Key, dst any) error
}

// getFunc is a first-party function type. Calls through it are not
// followed: RTA would resolve them to every function of the same signature.
type getFunc func(key *datastore.Key, dst any) error

type entity struct{ Name string }

// A method expression in a package initializer is reached from init.
var getMulti = (*datastore.Client).GetMulti // site: package-init

// tagged is replaced when the gcppermstest build tag is set.
var tagged = func(context.Context, *datastore.Client) {}

func main() {
	ctx := context.Background()
	client, _ := datastore.NewClient(ctx, "project")
	key := datastore.NameKey("Kind", "a", nil)

	var g getter = client
	_ = g.Get(ctx, key, &entity{}) // site: via-interface

	put := client.Put // site: method-value
	_, _ = put(ctx, datastore.IncompleteKey("Kind", nil), &entity{})

	runAll[entity](ctx, client)

	tx, _ := client.NewTransaction(ctx)
	var f getFunc = tx.Get // site: tx-method-value
	_ = f(key, &entity{})

	// Calls through interfaces declared outside first-party code are not
	// followed, so Count is not reported.
	var anon interface {
		Count(ctx context.Context, q *datastore.Query) (int, error)
	} = client
	_, err := anon.Count(ctx, datastore.NewQuery("Kind"))
	if err != nil {
		_ = err.Error()
	}
	_ = error.Error // a method expression on a universe type

	tagged(ctx, client)
	_ = getMulti

	gcs, _ := storage.NewClient(ctx)
	_ = gcs.Bucket("b").Object("o").NewWriter(ctx) // site: writer

	sm, _ := secretmanager.NewClient(ctx)
	_, _ = sm.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{}) // site: access
	_ = sm.DestroySecretVersion                                                       // site: unmapped
}

// runAll is instantiated, so its body is analyzed as an instance whose
// package is found through its generic origin.
func runAll[T any](ctx context.Context, c *datastore.Client) {
	var dst []T
	_, _ = c.GetAll(ctx, datastore.NewQuery("Kind"), &dst) // site: generic
}

// neverCalled is unreachable, so its Delete must not be reported.
func neverCalled(ctx context.Context, c *datastore.Client) {
	_ = c.Delete(ctx, datastore.NameKey("Kind", "a", nil))
}
