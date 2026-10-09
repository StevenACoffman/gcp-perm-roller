// Package verifytable implements the "verify-table" command: it checks the
// permission table against Google's public documentation.
package verifytable

import (
	"context"
	"fmt"
	"io"

	"github.com/peterbourgon/ff/v4"

	"github.com/StevenACoffman/gcp-perm-roller/cmd/root"
	"github.com/StevenACoffman/gcp-perm-roller/internal/verifytable"
)

// Config holds the configuration for the verify-table command.
type Config struct {
	*root.Config
	Options verifytable.Options
	Flags   *ff.FlagSet
	Command *ff.Command
	// run checks the table; verifytable.Run unless a test replaces it.
	run func(context.Context, *verifytable.Options, io.Writer, io.Writer) error
}

// New creates and registers the verify-table command with the given parent
// config.
func New(parent *root.Config) *Config {
	var cfg Config
	cfg.Config = parent
	cfg.run = verifytable.Run
	cfg.Flags = ff.NewFlagSet("verify-table").SetParent(parent.Flags)
	cfg.Flags.StringVar(&cfg.Options.Workspace, 'C', "dir", ".",
		"workspace or module whose SDK calls are traced")
	cfg.Flags.StringVar(&cfg.Options.Table, 0, "table", "",
		"table.go file to check (default: the table built into this program)")
	cfg.Flags.StringVar(&cfg.Options.Cache, 0, "cache", "",
		"directory to cache fetched documentation in (default: the user cache directory)")
	cfg.Flags.StringVar(&cfg.Options.Debug, 0, "debug", "",
		"print the functions the RPC trace visits for this entry point")
	cfg.Flags.BoolVar(&cfg.Options.Strict, 0, "strict",
		"exit non-zero if any check finds a mismatch")
	cfg.Flags.StringEnumVar(&cfg.Options.Algorithm, 0, "algo",
		"call graph algorithm: vta (precise) or rta (also follows calls made through "+
			"reflection, which VTA drops)", "vta", "rta")
	cfg.Flags.StringVar(&cfg.Options.IAMDataset, 0, "iam-dataset", "",
		"optional clone of github.com/iann0036/iam-dataset to use as a second opinion")
	cfg.Command = &ff.Command{
		Name:      "verify-table",
		Usage:     "gcp-perm-roller verify-table [FLAGS] [PACKAGES...]",
		ShortHelp: "check the permission table against Google's public documentation",
		LongHelp: `Verify-table checks the rules analyze uses to map SDK calls to permissions,
independently of analyze, and writes a Markdown report to stdout.

Check 1 confirms every permission the table grants is listed in the IAM
roles and permissions reference. Check 2 traces each SDK entry point that the
main packages named by PACKAGES (default: every module of the workspace in
--dir) call to the RPCs it sends, and compares the permissions
each RPC's reference page states with the table's rule. It reads only
public pages, so it needs no Google Cloud credentials.

  gcp-perm-roller verify-table -C ~/src/myworkspace > table-report.md
  gcp-perm-roller verify-table -C ~/src/monorepo ./services/foo/cmd/... > table-report.md
  gcp-perm-roller verify-table -C ~/src/myworkspace --strict \
      --iam-dataset ~/src/iam-dataset > table-report.md`,
		Flags: cfg.Flags,
		Exec:  cfg.exec,
	}
	parent.Command.Subcommands = append(parent.Command.Subcommands, cfg.Command)
	return &cfg
}

func (cfg *Config) exec(ctx context.Context, args []string) error {
	cfg.Options.Patterns = args
	if err := cfg.run(ctx, &cfg.Options, cfg.Stdout, cfg.Stderr); err != nil {
		return fmt.Errorf("verify-table: %w", err)
	}
	return nil
}
