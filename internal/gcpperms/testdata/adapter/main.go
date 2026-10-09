// Command adapter is a fixture whose only SDK call goes through a
// google-cloud-go-testing adapter, which counts as first-party code.
package main

import (
	"context"

	"cloud.google.com/go/datastore"
	"github.com/googleapis/google-cloud-go-testing/datastore/dsiface"
)

func main() {
	ctx := context.Background()
	client, _ := datastore.NewClient(ctx, "project")
	_, _ = dsiface.AdaptClient(client).AllocateIDs(ctx, nil)
}
