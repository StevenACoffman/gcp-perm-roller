//go:build gcppermstest

package main

import (
	"context"

	"cloud.google.com/go/datastore"
)

func init() {
	tagged = func(ctx context.Context, c *datastore.Client) {
		_ = c.DeleteMulti(ctx, nil) // site: tagged
	}
}
