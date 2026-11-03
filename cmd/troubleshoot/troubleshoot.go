// Package troubleshoot implements the "troubleshoot" CLI command: it asks
// IAM's Policy Troubleshooter whether a principal holds the permissions
// analyze found for each binary.
package troubleshoot

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/peterbourgon/ff/v4"

	"github.com/StevenACoffman/gcp-perm-roller/cmd/root"
	"github.com/StevenACoffman/gcp-perm-roller/internal/gcpperms"
)

// longHelp is the troubleshoot command's help text.
const longHelp = `Troubleshoot reads results saved with analyze --format=json and asks IAM's
Policy Troubleshooter whether a principal holds each permission a binary
needs on a resource, counting roles inherited from folders and the
organization, and deny policies.

  gcp-perm-roller analyze -C ~/src/myworkspace --format=json > result.json
  gcp-perm-roller troubleshoot --from=result.json \
      --principal=app@my-project.iam.gserviceaccount.com \
      --resource=//cloudresourcemanager.googleapis.com/projects/my-project \
      example.com/cmd/server

PACKAGES name the binaries to check (default: every binary in the results).
Each permission is checked on --resource; one a binary uses only on a
resource inside it, such as a bucket, is held if it is granted on the
project. It uses Application Default Credentials, which need to read the
IAM policies of the resource and its ancestors; without that, the answer is
UNKNOWN_INFO. When only deny policies are unreadable, the report notes the
permissions the allow policies grant.`

// Config holds the configuration for the troubleshoot command.
type Config struct {
	*root.Config
	From            []string
	Principal       string
	Resource        string
	Format          string
	WithConditional bool
	Strict          bool
	Flags           *ff.FlagSet
	Command         *ff.Command
	// newTroubleshooter makes the troubleshooter; tests replace it.
	newTroubleshooter func(context.Context) (gcpperms.Troubleshooter, error)
}

// New creates and registers the troubleshoot command with the given parent config.
func New(parent *root.Config) *Config {
	var cfg Config
	cfg.Config = parent
	cfg.newTroubleshooter = func(ctx context.Context) (gcpperms.Troubleshooter, error) {
		return gcpperms.NewTroubleshooter(ctx)
	}
	cfg.Flags = ff.NewFlagSet("troubleshoot").SetParent(parent.Flags)
	cfg.Flags.StringListVar(&cfg.From, 0, "from",
		"results saved with analyze --format=json; repeatable (required)")
	cfg.Flags.StringVar(&cfg.Principal, 0, "principal", "",
		"the email of the service account or user the binaries run as (required)")
	cfg.Flags.StringVar(&cfg.Resource, 0, "resource", "",
		"the full resource name to check on, such as "+
			"//cloudresourcemanager.googleapis.com/projects/my-project (required)")
	cfg.Flags.StringEnumVar(&cfg.Format, 0, "format", "output format", "text", "json")
	cfg.Flags.BoolVar(&cfg.WithConditional, 0, "include-conditional",
		"also check the permissions a binary needs only on some paths")
	cfg.Flags.BoolVar(&cfg.Strict, 0, "strict",
		"exit non-zero if the principal may lack any permission checked")
	cfg.Command = &ff.Command{
		Name:      "troubleshoot",
		Usage:     "gcp-perm-roller troubleshoot --from=FILE --principal=EMAIL --resource=NAME [FLAGS] [PACKAGES...]",
		ShortHelp: "check that a principal holds the permissions analyze found",
		LongHelp:  longHelp,
		Flags:     cfg.Flags,
		Exec:      cfg.exec,
	}
	parent.Command.Subcommands = append(parent.Command.Subcommands, cfg.Command)
	return &cfg
}

func (cfg *Config) exec(ctx context.Context, args []string) error {
	if err := cfg.checkUsage(); err != nil {
		return &root.UsageError{Err: fmt.Errorf("troubleshoot: %w", err)}
	}
	res, err := gcpperms.LoadResults(cfg.From)
	if err != nil {
		return fmt.Errorf("troubleshoot: %w", err)
	}
	bins, err := gcpperms.SelectBinaries(res.Binaries, args)
	if err != nil {
		return &root.UsageError{Err: fmt.Errorf("troubleshoot: %w", err)}
	}
	ts, err := cfg.newTroubleshooter(ctx)
	if err != nil {
		return fmt.Errorf("troubleshoot: %w", err)
	}
	access, err := gcpperms.CheckAccess(
		ctx,
		ts,
		cfg.Principal,
		cfg.Resource,
		bins,
		cfg.WithConditional,
	)
	if err != nil {
		return fmt.Errorf("troubleshoot: %w", err)
	}
	if cfg.Format == "json" {
		err = gcpperms.WriteJSON(cfg.Stdout, access)
	} else {
		err = gcpperms.WriteAccessChecks(cfg.Stdout, access)
	}
	if err != nil {
		return fmt.Errorf("troubleshoot: %w", err)
	}
	if n := lacking(access); cfg.Strict && n > 0 {
		return fmt.Errorf("troubleshoot: the principal may lack %d permissions", n)
	}
	return nil
}

// checkUsage reports what is wrong with the command line, if anything.
func (cfg *Config) checkUsage() error {
	switch {
	case len(cfg.From) == 0:
		return errors.New("--from is required")
	case cfg.Principal == "":
		return errors.New("--principal is required")
	case strings.Contains(cfg.Principal, ":"):
		return fmt.Errorf("--principal: give the email alone, not %q", cfg.Principal)
	case cfg.Resource == "":
		return errors.New("--resource is required")
	case !strings.HasPrefix(cfg.Resource, "//"):
		return fmt.Errorf("--resource: %q is not a full resource name, which starts with //",
			cfg.Resource)
	}
	return nil
}

// lacking returns how many checks found a permission the principal may
// not hold.
func lacking(access []gcpperms.BinaryAccess) int {
	var n int
	for _, a := range access {
		for _, c := range a.Checks {
			if c.State != gcpperms.CanAccess {
				n++
			}
		}
	}
	return n
}
