// Package wrappers implements the "wrappers" command: it finds the functions
// in a Go workspace that call the functions passed to them by reflection,
// and saves them for analyze --wrapper-file.
package wrappers

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/peterbourgon/ff/v4"

	"github.com/StevenACoffman/gcp-perm-roller/cmd/root"
	"github.com/StevenACoffman/gcp-perm-roller/internal/gcpperms"
	"github.com/StevenACoffman/gcp-perm-roller/internal/workspace"
)

// longHelp is the wrappers command's help text.
const longHelp = `Wrappers finds the functions in a workspace that call a function passed to
them by reflection: each passes the parameter to reflect.ValueOf and calls
reflect.Value.Call, CallSlice, or reflect.MakeFunc, itself or in a closure it
creates. A memoizing cache built with reflect.MakeFunc is the usual one.

VTA does not follow reflection, so analyze misses every Google Cloud call
behind such a wrapper. Saved with this command and loaded with
analyze --wrapper-file, each call to a wrapper counts as calling the
functions passed to it, which brings those calls back while VTA still leaves
out RTA's false positives, such as clients a binary holds but never uses.

With no packages, every module of the workspace (or the current module) in
--dir is searched. Only the named packages are loaded from source, so
searching a large module costs far less than analyzing it. Wrappers that
keep the function in a field before calling it are not found; add those to
the file by hand: {"function": "importpath.Func", "params": [0]}.

  gcp-perm-roller wrappers -C ~/src/monorepo --out=wrappers.json
  gcp-perm-roller analyze -C ~/src/monorepo --wrapper-file=wrappers.json ./cmd/...`

// Config holds the configuration for the wrappers command.
type Config struct {
	*root.Config
	Dir     string
	Out     string
	Tags    []string
	Flags   *ff.FlagSet
	Command *ff.Command
}

// New creates and registers the wrappers command with the given parent config.
func New(parent *root.Config) *Config {
	var cfg Config
	cfg.Config = parent
	cfg.Flags = ff.NewFlagSet("wrappers").SetParent(parent.Flags)
	cfg.Flags.StringVar(&cfg.Dir, 'C', "dir", ".",
		"run as if started in this directory: the workspace or module to search")
	cfg.Flags.StringVar(&cfg.Out, 0, "out", "",
		"write the wrappers to this file instead of stdout")
	cfg.Flags.StringListVar(&cfg.Tags, 0, "tags", "build tag; repeatable")
	cfg.Command = &ff.Command{
		Name:      "wrappers",
		Usage:     "gcp-perm-roller wrappers [FLAGS] [PACKAGES...]",
		ShortHelp: "find functions that call the functions passed to them by reflection",
		LongHelp:  longHelp,
		Flags:     cfg.Flags,
		Exec:      cfg.exec,
	}
	parent.Command.Subcommands = append(parent.Command.Subcommands, cfg.Command)
	return &cfg
}

func (cfg *Config) exec(ctx context.Context, args []string) error {
	patterns := args
	if len(patterns) == 0 {
		var err error
		if patterns, err = workspace.Patterns(ctx, cfg.Dir, cfg.Stderr); err != nil {
			return fmt.Errorf("wrappers: %w", err)
		}
	}
	found, err := gcpperms.FindWrappers(&gcpperms.Config{
		Dir:      cfg.Dir,
		Patterns: patterns,
		Tags:     cfg.Tags,
	})
	if err != nil {
		return fmt.Errorf("wrappers: %w", err)
	}
	var buf bytes.Buffer
	if err := gcpperms.WriteWrappers(&buf, found); err != nil {
		return fmt.Errorf("wrappers: %w", err)
	}
	if cfg.Out == "" {
		_, err = cfg.Stdout.Write(buf.Bytes())
	} else {
		err = os.WriteFile(cfg.Out, buf.Bytes(), 0o600)
	}
	if err != nil {
		return fmt.Errorf("wrappers: %w", err)
	}
	_, _ = fmt.Fprintf(cfg.Stderr, "found %d wrappers\n", len(found))
	return nil
}
