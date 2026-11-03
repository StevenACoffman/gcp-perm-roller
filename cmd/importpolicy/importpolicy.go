// Package importpolicy implements the "import" command: it reads an IAM
// policy exported with gcloud and finds the predefined roles that grant
// what one member holds in it. The package is not named import, which is a
// Go keyword.
package importpolicy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v4"

	"github.com/StevenACoffman/gcp-perm-roller/cmd/root"
	"github.com/StevenACoffman/gcp-perm-roller/internal/gcpperms"
)

// longHelp is the import command's help text.
const longHelp = `Import reads an IAM allow policy, as gcloud prints it in YAML or with
--format=json, and finds the smallest set of predefined roles that grants
every permission one member holds through its bindings.

  gcloud projects get-iam-policy my-project > policy.yaml
  gcp-perm-roller import --policy=policy.yaml --member=user:ada@example.com

To count grants inherited from the project's folders and organization too,
give it the project's policy with its ancestors' instead:

  gcloud projects get-ancestors-iam-policy my-project > policy.yaml

Write the member as the policy does, with its type (user:, group:,
serviceAccount:), or give a bare email to match any type. A binding whose
condition only sets an expiry, as the Cloud Console's temporary access does,
counts until it expires and is ignored after. Permissions under any other
condition are reported, and covered only with --include-conditional.

Custom roles in the policy are got from the IAM API, which needs
iam.roles.get on the project, or read from --custom-roles: a directory of
` + "`gcloud iam roles describe --format=json`" + ` files or a file holding a JSON array.

The result is what the member holds now, not what it needs. The policy does
not say who is in a group, so grants through groups are not counted for a
user; name the group instead. Deny policies (--include-deny) are reported
but not applied, so permissions they deny are still counted.

--proposed-policy writes the policy as it would be with the member's roles
replaced by the recommended ones. Replay recent access against it to see
whether the change would have denied anything the member did:

  gcp-perm-roller import --policy=policy.yaml --member=user:ada@example.com \
      --proposed-policy=proposed.json
  gcloud iam simulator replay-recent-access \
      //cloudresourcemanager.googleapis.com/projects/my-project proposed.json

It needs one project's policy, and --member with its type.`

// Config holds the configuration for the import command.
type Config struct {
	*root.Config
	Policy          string
	Member          string
	Format          string
	Roles           string
	CustomRoles     string
	ProposedPolicy  string
	RoleStages      []string
	WithConditional bool
	Flags           *ff.FlagSet
	Command         *ff.Command
}

// New creates and registers the import command with the given parent config.
func New(parent *root.Config) *Config {
	var cfg Config
	cfg.Config = parent
	cfg.Flags = ff.NewFlagSet("import").SetParent(parent.Flags)
	cfg.Flags.StringVar(&cfg.Policy, 0, "policy", "",
		"the policy file, as gcloud projects get-iam-policy or get-ancestors-iam-policy "+
			"prints it in YAML or JSON (required)")
	cfg.Flags.StringVar(&cfg.Member, 0, "member", "",
		"the member whose roles to replace, such as user:ada@example.com (required)")
	cfg.Flags.StringVar(&cfg.Format, 0, "format", "text", "output format: text or json")
	cfg.Flags.StringVar(&cfg.Roles, 0, "roles", "api",
		"where to read predefined roles: api (the IAM API, using Application Default "+
			"Credentials) or a path to saved roles, such as iam-dataset's gcp/roles directory")
	cfg.Flags.StringVar(&cfg.CustomRoles, 0, "custom-roles", "api",
		"where to read the custom roles the member holds: api, or a path to saved roles")
	cfg.Flags.StringListVar(&cfg.RoleStages, 0, "role-stages",
		"launch stage of predefined roles to recommend; repeatable (default GA)")
	cfg.Flags.BoolVar(&cfg.WithConditional, 0, "include-conditional",
		"also cover the permissions the member holds under conditions")
	cfg.Flags.StringVar(&cfg.ProposedPolicy, 0, "proposed-policy", "",
		"also write the policy, with the member's roles replaced by the recommended ones, "+
			"to this file, for gcloud iam simulator replay-recent-access")
	cfg.Command = &ff.Command{
		Name:      "import",
		Usage:     "gcp-perm-roller import --policy=FILE --member=PRINCIPAL [FLAGS]",
		ShortHelp: "find the predefined roles that grant what a member holds in an IAM policy",
		LongHelp:  longHelp,
		Flags:     cfg.Flags,
		Exec:      cfg.exec,
	}
	parent.Command.Subcommands = append(parent.Command.Subcommands, cfg.Command)
	return &cfg
}

func (cfg *Config) exec(ctx context.Context, args []string) error {
	if err := cfg.checkUsage(args); err != nil {
		return &root.UsageError{Err: fmt.Errorf("import: %w", err)}
	}
	policy, err := cfg.readPolicy()
	if err != nil {
		return fmt.Errorf("import: %w", err)
	}
	access, roles, err := cfg.memberAccess(ctx, policy)
	if err != nil {
		return fmt.Errorf("import: %w", err)
	}
	sel := gcpperms.SelectRoles(
		access.Required(cfg.WithConditional),
		roles,
		gcpperms.RoleFilter{Stages: cfg.RoleStages},
	)
	access.PredefinedRoles = &sel
	if cfg.ProposedPolicy != "" {
		if err := cfg.propose(policy, access, sel); err != nil {
			return fmt.Errorf("import: %w", err)
		}
	}
	if cfg.Format == "json" {
		err = gcpperms.WriteJSON(cfg.Stdout, access)
	} else {
		err = gcpperms.WriteMemberAccess(cfg.Stdout, access)
	}
	if err != nil {
		return fmt.Errorf("import: %w", err)
	}
	return nil
}

// checkUsage reports what is wrong with the command line, if anything.
func (cfg *Config) checkUsage(args []string) error {
	switch {
	case len(args) > 0:
		return fmt.Errorf("unexpected arguments: %s", strings.Join(args, " "))
	case cfg.Policy == "":
		return errors.New("--policy is required")
	case cfg.Member == "":
		return errors.New("--member is required")
	case cfg.Format != "text" && cfg.Format != "json":
		return fmt.Errorf("--format: %q is not text or json", cfg.Format)
	}
	return nil
}

// readPolicy reads and parses --policy.
func (cfg *Config) readPolicy() (gcpperms.Policy, error) {
	data, err := os.ReadFile(cfg.Policy)
	if err != nil {
		return gcpperms.Policy{}, fmt.Errorf("reading the policy: %w", err)
	}
	policy, err := gcpperms.ParsePolicy(data)
	if err != nil {
		return gcpperms.Policy{}, fmt.Errorf("%s: %w", cfg.Policy, err)
	}
	return policy, nil
}

// memberAccess returns what the member holds in policy, with the roles
// that define its permissions: the predefined roles, and the custom roles
// the member holds.
func (cfg *Config) memberAccess(
	ctx context.Context,
	policy gcpperms.Policy,
) (*gcpperms.MemberAccess, []gcpperms.Role, error) {
	bindings := policy.MemberBindings(cfg.Member, time.Now())
	if len(bindings) == 0 {
		return nil, nil, fmt.Errorf("%s holds no role in %s", cfg.Member, cfg.Policy)
	}
	roles, err := gcpperms.LoadRoles(ctx, cfg.Roles)
	if err != nil {
		return nil, nil, fmt.Errorf("loading predefined roles: %w", err)
	}

	// The predefined roles define every role but custom ones; get those
	// next, and only those the member holds.
	access, missing := gcpperms.NewMemberAccess(cfg.Member, bindings, roles)
	if len(missing) > 0 {
		custom, err := cfg.loadCustomRoles(ctx, missing)
		if err != nil {
			return nil, nil, err
		}
		roles = append(roles, custom...)
		access, missing = gcpperms.NewMemberAccess(cfg.Member, bindings, roles)
	}
	if len(missing) > 0 {
		return nil, nil, fmt.Errorf("no definition of %s in --custom-roles=%s",
			strings.Join(missing, ", "), cfg.CustomRoles)
	}
	access.DenyPolicies = policy.DenyPolicies
	return &access, roles, nil
}

// propose writes policy, with the member's covered bindings replaced by
// the roles in sel, to --proposed-policy. It warns on stderr about what
// the proposal changes beyond the roles: conditions it drops, and
// permissions it no longer grants because no predefined role holds them.
func (cfg *Config) propose(
	policy gcpperms.Policy,
	access *gcpperms.MemberAccess,
	sel gcpperms.RoleSelection,
) error {
	covered := access.Covered(cfg.WithConditional)
	roles := make([]string, len(sel.Grants))
	for i, g := range sel.Grants {
		roles[i] = g.Role
	}
	data, err := policy.Propose(cfg.Member, roles, covered)
	if err != nil {
		return fmt.Errorf("proposing a policy: %w", err)
	}
	if err := os.WriteFile(cfg.ProposedPolicy, data, 0o600); err != nil {
		return fmt.Errorf("writing the proposed policy: %w", err)
	}
	for _, b := range covered {
		if b.Condition != nil {
			_, _ = fmt.Fprintf(
				cfg.Stderr,
				"import: the proposed policy drops the condition %q of %s; its roles are granted without it\n",
				b.Condition.Name(),
				b.Role,
			)
		}
	}
	if n := len(sel.Uncovered); n > 0 {
		_, _ = fmt.Fprintf(
			cfg.Stderr,
			"import: the proposed policy grants none of the %d permissions that need a custom role\n",
			n,
		)
	}
	return nil
}

// loadCustomRoles gets the roles names from the IAM API, or reads every
// role saved in --custom-roles.
func (cfg *Config) loadCustomRoles(ctx context.Context, names []string) ([]gcpperms.Role, error) {
	var (
		roles []gcpperms.Role
		err   error
	)
	if cfg.CustomRoles == "api" {
		roles, err = gcpperms.LoadRolesByName(ctx, names)
	} else {
		roles, err = gcpperms.LoadRolesFromPath(cfg.CustomRoles)
	}
	if err != nil {
		return nil, fmt.Errorf("loading custom roles: %w", err)
	}
	return roles, nil
}
