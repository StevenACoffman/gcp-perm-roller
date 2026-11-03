package gcpperms

import (
	"context"
	"io"
	"slices"
	"strings"

	"github.com/cockroachdb/errors"
	"google.golang.org/api/option"
	troubleshooter "google.golang.org/api/policytroubleshooter/v3"
)

const (
	// CanAccess means the principal holds the permission.
	CanAccess AccessState = "CAN_ACCESS"
	// CannotAccess means the principal does not hold the permission.
	CannotAccess AccessState = "CANNOT_ACCESS"
	// UnknownInfo means the principal may hold the permission, but the
	// caller cannot read every policy that decides it.
	UnknownInfo AccessState = "UNKNOWN_INFO"
	// UnknownConditional means the principal may hold the permission, under
	// a condition the troubleshooter had no request context to evaluate.
	UnknownConditional AccessState = "UNKNOWN_CONDITIONAL"
)

// AccessState is the IAM Policy Troubleshooter's verdict on whether a
// principal holds a permission on a resource.
type AccessState string

// Verdict is the troubleshooter's answer for one permission: the overall
// state, and the allow and deny policies' states it comes from, as the API
// names them ("ALLOW_ACCESS_STATE_GRANTED", "DENY_ACCESS_STATE_UNKNOWN_INFO").
// A caller who cannot read deny policies gets UnknownInfo overall even when
// the allow policies grant the permission; Allow still says so.
type Verdict struct {
	State AccessState `json:"state"`
	Allow string      `json:"allow,omitempty"`
	Deny  string      `json:"deny,omitempty"`
}

// AccessCheck is the troubleshooter's verdict on one permission a binary
// needs.
type AccessCheck struct {
	Permission string `json:"permission"`
	// Conditional is set for a permission the binary needs only on some
	// paths.
	Conditional bool `json:"conditional,omitempty"`
	Verdict
}

// BinaryAccess is whether a principal holds a binary's permissions on a
// resource.
type BinaryAccess struct {
	Package   string        `json:"package"`
	Principal string        `json:"principal"`
	Resource  string        `json:"resource"`
	Checks    []AccessCheck `json:"checks"`
}

// Troubleshooter reports whether principal, an email, holds permission on
// the resource with the full resource name resource.
type Troubleshooter func(ctx context.Context, principal, resource, permission string) (Verdict, error)

// NewTroubleshooter returns a Troubleshooter that asks the IAM Policy
// Troubleshooter API, with opts (Application Default Credentials by
// default). Its verdicts are only as complete as the policies the caller
// can read: without permission to get the IAM policies of the resource and
// its ancestors, it answers UnknownInfo.
func NewTroubleshooter(ctx context.Context, opts ...option.ClientOption) (Troubleshooter, error) {
	const op = "gcpperms.NewTroubleshooter"
	svc, err := troubleshooter.NewService(ctx, opts...)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	return func(ctx context.Context, principal, resource, permission string) (Verdict, error) {
		req := &troubleshooter.GoogleCloudPolicytroubleshooterIamV3TroubleshootIamPolicyRequest{
			AccessTuple: &troubleshooter.GoogleCloudPolicytroubleshooterIamV3AccessTuple{
				Principal:        principal,
				FullResourceName: resource,
				Permission:       permission,
			},
		}
		resp, err := svc.Iam.Troubleshoot(req).Context(ctx).Do()
		if err != nil {
			return Verdict{}, errors.Wrapf(err, "%s: %s", op, permission)
		}
		v := Verdict{State: AccessState(resp.OverallAccessState)}
		if e := resp.AllowPolicyExplanation; e != nil {
			v.Allow = e.AllowAccessState
		}
		if e := resp.DenyPolicyExplanation; e != nil {
			v.Deny = e.DenyAccessState
		}
		return v, nil
	}, nil
}

// CheckAccess asks t whether principal holds each permission of bins on
// resource: the permissions each binary always needs and, with
// includeConditional, those it needs on some paths. Each permission is
// asked about once, however many binaries need it.
func CheckAccess(
	ctx context.Context,
	t Troubleshooter,
	principal, resource string,
	bins []Binary,
	includeConditional bool,
) ([]BinaryAccess, error) {
	verdicts := make(map[string]Verdict)
	check := func(perm string) (Verdict, error) {
		if v, ok := verdicts[perm]; ok {
			return v, nil
		}
		v, err := t(ctx, principal, resource, perm)
		if err != nil {
			return Verdict{}, err
		}
		verdicts[perm] = v
		return v, nil
	}
	out := make([]BinaryAccess, 0, len(bins))
	for _, b := range bins {
		checks, err := binaryChecks(&b, includeConditional, check)
		if err != nil {
			return nil, err
		}
		out = append(out, BinaryAccess{
			Package: b.Package, Principal: principal, Resource: resource, Checks: checks,
		})
	}
	return out, nil
}

// binaryChecks returns check's verdict on each permission b always needs
// and, with includeConditional, each it needs on some paths.
func binaryChecks(
	b *Binary,
	includeConditional bool,
	check func(perm string) (Verdict, error),
) ([]AccessCheck, error) {
	var conditional []string
	if includeConditional {
		conditional = b.ConditionalPermissions()
	}
	var checks []AccessCheck
	for _, perm := range slices.Concat(b.Permissions(), conditional) {
		v, err := check(perm)
		if err != nil {
			return nil, err
		}
		checks = append(checks, AccessCheck{
			Permission:  perm,
			Conditional: slices.Contains(conditional, perm),
			Verdict:     v,
		})
	}
	return checks, nil
}

// WriteAccessChecks writes, for each binary, whether the principal holds
// each permission it needs, and how many it holds.
func WriteAccessChecks(w io.Writer, access []BinaryAccess) error {
	ew := &errWriter{w: w}
	for i, a := range access {
		if i > 0 {
			ew.printf("\n")
		}
		ew.printf("== %s\n", a.Package)
		ew.printf("  %s on %s\n", a.Principal, a.Resource)
		var granted int
		for i := range a.Checks {
			c := &a.Checks[i]
			ew.printf("    %-20s %s%s\n", c.State, c.Permission, checkNote(c))
			if c.State == CanAccess {
				granted++
			}
		}
		ew.printf("  %d of %d permissions held\n", granted, len(a.Checks))
	}
	return ew.err
}

// checkNote is the parenthesized note after c in a report, if any: whether
// the permission is conditional, and whether the allow policies grant it
// when deny policies could not be read.
func checkNote(c *AccessCheck) string {
	var notes []string
	if c.Conditional {
		notes = append(notes, "conditional")
	}
	if c.State == UnknownInfo && c.Allow == "ALLOW_ACCESS_STATE_GRANTED" {
		notes = append(notes, "allowed; deny policies not readable")
	}
	if len(notes) == 0 {
		return ""
	}
	return " (" + strings.Join(notes, "; ") + ")"
}
