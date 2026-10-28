// Package cmd is the dispatcher for the gcp-perm-roller CLI.
// It registers all commands and routes incoming arguments
// to the matching command implementation.
package cmd

// climax:name gcp-perm-roller
// climax:root-pkg root
// climax:env-prefix GCP_PERM_ROLLER

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"

	"github.com/StevenACoffman/gcp-perm-roller/cmd/analyze"
	"github.com/StevenACoffman/gcp-perm-roller/cmd/root"
	"github.com/StevenACoffman/gcp-perm-roller/cmd/verifytable"
	"github.com/StevenACoffman/gcp-perm-roller/cmd/version"
	"github.com/StevenACoffman/gcp-perm-roller/cmd/wrappers"
)

// Run parses args and dispatches to the matching command.
// args must not include the executable name (pass os.Args[1:]).
//
// Every flag can be set via a GCP_PERM_ROLLER_-prefixed environment variable.
// The mapping rule is: prepend GCP_PERM_ROLLER_, uppercase, replace dashes with
// underscores.
//
// Flags supplied on the command line always take precedence over env vars.
//
// Run prints the selected command's help to stderr only for --help and for
// usage errors (anything matching ErrUsage in the root package: parse
// failures, an unknown subcommand, or a command returning a UsageError). Other
// errors are returned without help, for main to print as "error: ...".
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	r := root.New(stdin, stdout, stderr)
	analyze.New(r)
	verifytable.New(r)
	version.New(r)
	// register new commands here

	wrappers.New(r)
	if err := r.Command.Parse(args, ff.WithEnvVarPrefix("GCP_PERM_ROLLER")); err != nil {
		// --help asked for help, and any other parse failure (an unknown flag,
		// a bad flag value) is the command line's fault, so both show it.
		_, _ = fmt.Fprintf(stderr, "\n%s\n", ffhelp.Command(r.Command.GetSelected()))
		if errors.Is(err, ff.ErrHelp) {
			return fmt.Errorf("parse: %w", err)
		}
		return &root.UsageError{Err: fmt.Errorf("parse: %w", err)}
	}

	// An unmatched token leaves the selected command a group parent (Exec == nil)
	// with a leftover positional. Without this guard it falls through to Run,
	// returns ff.ErrNoExec, and exits 0 — indistinguishable from a bare invocation.
	// A command that does have an Exec gets its leftovers as arguments, and a
	// flag among them was never parsed; that is reported rather than dropped.
	if sel := r.Command.GetSelected(); sel.Exec == nil {
		if rest := sel.Flags.GetArgs(); len(rest) > 0 {
			_, _ = fmt.Fprintf(stderr, "\n%s\n", ffhelp.Command(sel))
			return &root.UsageError{Err: fmt.Errorf("%s: unknown subcommand %q", sel.Name, rest[0])}
		}
	} else if flag := misplacedFlag(sel.Flags.GetArgs()); flag != "" {
		_, _ = fmt.Fprintf(stderr, "\n%s\n", ffhelp.Command(sel))
		return &root.UsageError{Err: fmt.Errorf(
			"%s: flag %q must come before the arguments (or after -- to pass it through)",
			sel.Name, flag)}
	}

	if err := r.Command.Run(ctx); err != nil {
		// Help is for usage mistakes only. A runtime failure's message stands on
		// its own, as do ff.ErrNoExec (no subcommand given) and ExitError (the
		// command already reported its outcome): none of them match ErrUsage.
		if errors.Is(err, root.ErrUsage) {
			_, _ = fmt.Fprintf(stderr, "\n%s\n", ffhelp.Command(r.Command.GetSelected()))
		}
		return err
	}

	return nil
}

// misplacedFlag returns the first of args that looks like a flag, or "" when
// none does. ff stops reading flags at the first positional argument, so a flag
// written after one would otherwise reach exec as an argument and be silently
// ignored. A "--" ends the scan: what follows it is meant literally. When ff
// consumed a leading "--" itself, args starts with what followed it, which is
// the only way a leftover can start with a dash.
func misplacedFlag(args []string) string {
	if len(args) > 0 && strings.HasPrefix(args[0], "-") {
		return ""
	}
	for _, a := range args {
		if a == "--" {
			return ""
		}
		if len(a) > 1 && a[0] == '-' {
			return a
		}
	}
	return ""
}
