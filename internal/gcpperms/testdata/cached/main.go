// Command cached reaches Datastore only through cache, which calls get by
// reflection, as a memoizing wrapper does. VTA alone does not see the call.
package main

import (
	"context"
	"reflect"

	"cloud.google.com/go/datastore"
)

func cache[T any](f T) T {
	v := reflect.ValueOf(f)
	return reflect.MakeFunc(v.Type(), func(args []reflect.Value) []reflect.Value {
		return v.Call(args)
	}).Interface().(T)
}

func get(ctx context.Context) error {
	client, err := datastore.NewClient(ctx, "project")
	if err != nil {
		return err
	}
	var v struct{}
	return client.Get(ctx, datastore.NameKey("Kind", "name", nil), &v)
}

var cachedGet = cache(get)

func main() { _ = cachedGet(context.Background()) }
