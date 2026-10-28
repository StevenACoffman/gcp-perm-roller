package workspace

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

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

func TestPatterns(t *testing.T) {
	// A module whose directory starts with "_", which "/dir/..." would skip.
	dir := filepath.Join(t.TempDir(), "_tool")
	ok(t, os.MkdirAll(filepath.Join(dir, "cmd", "x"), 0o750))
	ok(
		t,
		os.WriteFile(
			filepath.Join(dir, "go.mod"),
			[]byte("module example.com/_tool\n\ngo 1.24\n"),
			0o600,
		),
	)
	ok(
		t,
		os.WriteFile(
			filepath.Join(dir, "cmd", "x", "main.go"),
			[]byte("package main\n\nfunc main() {}\n"),
			0o600,
		),
	)
	got, err := Patterns(context.Background(), dir, io.Discard)
	ok(t, err)
	equals(t, got, []string{"example.com/_tool/..."})
}

func TestModules(t *testing.T) {
	_, err := Modules(context.Background(), filepath.Join(t.TempDir(), "nope"), io.Discard)
	if err == nil {
		t.Fatal("listed the modules of a missing directory")
	}
}
