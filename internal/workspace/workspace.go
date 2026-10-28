// Package workspace finds the main modules of a Go workspace or module.
package workspace

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strings"
)

// Patterns returns "<module path>/..." for every main module: each
// module of go.work in workspace mode, or the current module otherwise. The
// pattern uses the module path, not its directory: "..." skips directories
// whose names start with "_", so "/src/_tool/..." matches nothing, while
// "example.com/_tool/..." matches the module's packages.
func Patterns(ctx context.Context, dir string, stderr io.Writer) ([]string, error) {
	mods, err := Modules(ctx, dir, stderr)
	if err != nil {
		return nil, err
	}
	patterns := make([]string, 0, len(mods))
	for path := range mods {
		patterns = append(patterns, path+"/...")
	}
	slices.Sort(patterns)
	return patterns, nil
}

// Modules maps the path of every main module to its directory:
// each module of go.work in workspace mode, or the current module
// otherwise.
func Modules(
	ctx context.Context,
	dir string,
	stderr io.Writer,
) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-m", "-f", "{{.Path}} {{.Dir}}")
	cmd.Dir = dir
	cmd.Stderr = stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list -m: %w", err)
	}
	mods := make(map[string]string)
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		path, d, _ := strings.Cut(line, " ")
		mods[path] = d
	}
	return mods, nil
}
