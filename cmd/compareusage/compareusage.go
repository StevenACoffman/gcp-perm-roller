// Package compareusage implements the "compare-usage" CLI command: it
// compares the permissions analyze found for binaries with the permissions
// the IAM recommender saw the member they run as use.
package compareusage

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/peterbourgon/ff/v4"

	"github.com/StevenACoffman/gcp-perm-roller/cmd/root"
	"github.com/StevenACoffman/gcp-perm-roller/internal/gcpperms"
)

// longHelp is the compare-usage command's help text.
const longHelp = `Compare-usage reads results saved with analyze --format=json and the IAM
recommender's policy insights for a project, and compares the permissions
analyze found for the binaries with the permissions the member they run as
used, as the recommender observed over at most the last 90 days.

  gcp-perm-roller analyze -C ~/src/myworkspace --format=json > result.json
  gcloud recommender insights list --insight-type=google.iam.policy.Insight \
      --location=global --project=my-project --format=json > insights.json
  gcp-perm-roller compare-usage --from=result.json --insights=insights.json \
      --member=serviceAccount:app@my-project.iam.gserviceaccount.com \
      example.com/cmd/server example.com/cmd/worker

PACKAGES name the binaries that run as the member (default: every binary in
the results); name them all, since the insights cannot tell them apart.

A permission used but not found points at a missing rule in the permission
table, a call analyze cannot follow, or another program running as the
member. One found but not used may be on a path not taken in the period. An
insight covers one role the member holds, and the recommender writes them
for roles with unused permissions, so a permission no covered role holds
has no usage data either way. --roles says where to read the roles'
permissions, as for import.`

// Config holds the configuration for the compare-usage command.
type Config struct {
	*root.Config
	From     []string
	Insights string
	Member   string
	Roles    string
	Format   string
	Flags    *ff.FlagSet
	Command  *ff.Command
}

// New creates and registers the compare-usage command with the given parent config.
func New(parent *root.Config) *Config {
	var cfg Config
	cfg.Config = parent
	cfg.Flags = ff.NewFlagSet("compare-usage").SetParent(parent.Flags)
	cfg.Flags.StringListVar(&cfg.From, 0, "from",
		"results saved with analyze --format=json; repeatable (required)")
	cfg.Flags.StringVar(&cfg.Insights, 0, "insights", "",
		"the insights, as gcloud recommender insights list "+
			"--insight-type=google.iam.policy.Insight prints them in YAML or JSON (required)")
	cfg.Flags.StringVar(
		&cfg.Member,
		0,
		"member",
		"",
		"the member the binaries run as, such as serviceAccount:app@my-project.iam.gserviceaccount.com (required)",
	)
	cfg.Flags.StringVar(&cfg.Roles, 0, "roles", "api",
		"where to read predefined roles: api (the IAM API, using Application Default "+
			"Credentials) or a path to saved roles, such as iam-dataset's gcp/roles directory")
	cfg.Flags.StringEnumVar(&cfg.Format, 0, "format", "output format", "text", "json")
	cfg.Command = &ff.Command{
		Name:      "compare-usage",
		Usage:     "gcp-perm-roller compare-usage --from=FILE --insights=FILE --member=PRINCIPAL [FLAGS] [PACKAGES...]",
		ShortHelp: "compare the permissions analyze found with those the IAM recommender saw used",
		LongHelp:  longHelp,
		Flags:     cfg.Flags,
		Exec:      cfg.exec,
	}
	parent.Command.Subcommands = append(parent.Command.Subcommands, cfg.Command)
	return &cfg
}

func (cfg *Config) exec(ctx context.Context, args []string) error {
	if err := cfg.checkUsage(); err != nil {
		return &root.UsageError{Err: fmt.Errorf("compare-usage: %w", err)}
	}
	res, err := gcpperms.LoadResults(cfg.From)
	if err != nil {
		return fmt.Errorf("compare-usage: %w", err)
	}
	bins, err := gcpperms.SelectBinaries(res.Binaries, args)
	if err != nil {
		return &root.UsageError{Err: fmt.Errorf("compare-usage: %w", err)}
	}
	data, err := os.ReadFile(cfg.Insights)
	if err != nil {
		return fmt.Errorf("compare-usage: reading the insights: %w", err)
	}
	insights, err := gcpperms.ParseInsights(data)
	if err != nil {
		return fmt.Errorf("compare-usage: %s: %w", cfg.Insights, err)
	}
	roles, err := gcpperms.LoadRoles(ctx, cfg.Roles)
	if err != nil {
		return fmt.Errorf("compare-usage: loading predefined roles: %w", err)
	}
	usage := gcpperms.CompareUsage(bins, cfg.Member, insights, roles)
	if cfg.Format == "json" {
		err = gcpperms.WriteJSON(cfg.Stdout, usage)
	} else {
		err = gcpperms.WriteUsage(cfg.Stdout, &usage)
	}
	if err != nil {
		return fmt.Errorf("compare-usage: %w", err)
	}
	return nil
}

// checkUsage reports what is wrong with the command line, if anything.
func (cfg *Config) checkUsage() error {
	switch {
	case len(cfg.From) == 0:
		return errors.New("--from is required")
	case cfg.Insights == "":
		return errors.New("--insights is required")
	case cfg.Member == "":
		return errors.New("--member is required")
	}
	return nil
}
