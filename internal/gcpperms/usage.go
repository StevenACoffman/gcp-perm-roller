package gcpperms

import (
	"encoding/json"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
)

// Insight is an IAM recommender policy insight (google.iam.policy.Insight):
// the permissions of one role a member holds that it used in the
// observation period, at most the last 90 days.
type Insight struct {
	Member string
	Role   string
	// Exercised are the role's permissions the member used.
	Exercised []string
	// Observed is how far back the usage was observed.
	Observed time.Duration
}

// Usage compares the permissions analyze found for binaries with the
// permissions insights say the member they run as used.
type Usage struct {
	Member   string   `json:"member"`
	Packages []string `json:"packages"`
	// Insights is how many insights were about the member, and
	// ObservedDays the longest period they cover.
	Insights     int `json:"insights"`
	ObservedDays int `json:"observedDays"`
	// Unexpected were used but analyze did not find: a missing rule, a call
	// analyze cannot follow, or another program running as the member.
	Unexpected []string `json:"unexpected,omitempty"`
	// Used were found by analyze and used.
	Used []string `json:"used,omitempty"`
	// Unused were found by analyze, and a role an insight covers holds
	// them, but they were not used: code not run in the period, or only on
	// paths not taken.
	Unused []string `json:"unused,omitempty"`
	// Unobserved were found by analyze, but no role an insight covers holds
	// them, so there is no usage data for them.
	Unobserved []string `json:"unobserved,omitempty"`
	// Conditional are the permissions analyze found needed only on some
	// paths, so the lists above can be read with that in mind.
	Conditional []string `json:"conditional,omitempty"`
	// UnknownRoles are insights' roles roles did not define, such as custom
	// roles; their permissions count as unobserved.
	UnknownRoles []string `json:"unknownRoles,omitempty"`
}

// insightDocument is an insight as `gcloud recommender insights list
// --format=json` prints it.
type insightDocument struct {
	ObservationPeriod string `json:"observationPeriod"`
	Content           struct {
		Member               string `json:"member"`
		Role                 string `json:"role"`
		ExercisedPermissions []struct {
			Permission string `json:"permission"`
		} `json:"exercisedPermissions"`
	} `json:"content"`
}

// observation is what insights about one member say: which permissions it
// used, which its insights' roles hold, which roles had no definition, how
// many insights there were, and the longest period they cover.
type observation struct {
	used, observable, unknownRoles map[string]bool
	insights                       int
	period                         time.Duration
}

// ParseInsights parses what `gcloud recommender insights list
// --insight-type=google.iam.policy.Insight` prints, in YAML or JSON.
func ParseInsights(data []byte) ([]Insight, error) {
	const op = "gcpperms.ParseInsights"
	values, err := jsonValues(data)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	insights := make([]Insight, 0, len(values))
	for _, v := range values {
		var d insightDocument
		if err := json.Unmarshal(v, &d); err != nil {
			return nil, errors.Wrapf(err, "%s: reading an insight", op)
		}
		if d.Content.Member == "" || d.Content.Role == "" {
			return nil, errors.Errorf(
				"%s: an insight names no member and role; is it a google.iam.policy.Insight?", op,
			)
		}
		in := Insight{Member: d.Content.Member, Role: d.Content.Role}
		for _, p := range d.Content.ExercisedPermissions {
			in.Exercised = append(in.Exercised, p.Permission)
		}
		if d.ObservationPeriod != "" {
			if in.Observed, err = time.ParseDuration(d.ObservationPeriod); err != nil {
				return nil, errors.Wrapf(err, "%s: observation period", op)
			}
		}
		insights = append(insights, in)
	}
	return insights, nil
}

// CompareUsage compares the permissions bins need with what insights say
// member used, reading which permissions each insight's role holds from
// roles. Every list in the result is sorted.
func CompareUsage(bins []Binary, member string, insights []Insight, roles []Role) Usage {
	obs := observe(member, insights, roles)
	packages, need, conditional := needs(bins)
	u := Usage{
		Member:       member,
		Packages:     packages,
		Insights:     obs.insights,
		ObservedDays: int(obs.period.Hours() / 24),
		Conditional:  slices.Sorted(maps.Keys(conditional)),
		UnknownRoles: slices.Sorted(maps.Keys(obs.unknownRoles)),
	}
	for _, p := range slices.Sorted(maps.Keys(need)) {
		switch {
		case obs.used[p]:
			u.Used = append(u.Used, p)
		case obs.observable[p]:
			u.Unused = append(u.Unused, p)
		default:
			u.Unobserved = append(u.Unobserved, p)
		}
	}
	for _, p := range slices.Sorted(maps.Keys(obs.used)) {
		if !need[p] {
			u.Unexpected = append(u.Unexpected, p)
		}
	}
	return u
}

// observe returns what insights say about member, with the permissions of
// its insights' roles read from roles.
func observe(member string, insights []Insight, roles []Role) observation {
	byName := make(map[string]*Role, len(roles))
	for i := range roles {
		byName[roles[i].Name] = &roles[i]
	}
	obs := observation{
		used:         map[string]bool{},
		observable:   map[string]bool{},
		unknownRoles: map[string]bool{},
	}
	for _, in := range insights {
		if !isMember(in.Member, member) {
			continue
		}
		obs.insights++
		obs.period = max(obs.period, in.Observed)
		for _, p := range in.Exercised {
			obs.used[p] = true
		}
		r := byName[in.Role]
		if r == nil {
			obs.unknownRoles[in.Role] = true
			continue
		}
		for _, p := range r.Permissions {
			obs.observable[p] = true
		}
	}
	return obs
}

// needs returns the packages of bins, every permission they need, and
// those of the permissions that no binary always needs.
func needs(bins []Binary) (packages []string, need, conditional map[string]bool) {
	need, conditional = map[string]bool{}, map[string]bool{}
	for _, b := range bins {
		packages = append(packages, b.Package)
		for _, p := range b.Permissions() {
			need[p] = true
		}
		for _, p := range b.ConditionalPermissions() {
			conditional[p] = true
		}
	}
	for p := range need {
		delete(conditional, p)
	}
	for p := range conditional {
		need[p] = true
	}
	return packages, need, conditional
}

// WriteUsage writes u: the permissions used but not found by analyze, then
// those found but not used, then those with no usage data.
func WriteUsage(w io.Writer, u *Usage) error {
	ew := &errWriter{w: w}
	ew.printf("== %s (%s)\n", u.Member, strings.Join(u.Packages, ", "))
	if u.Insights == 0 {
		ew.printf("  no insights about this member\n")
		return ew.err
	}
	ew.printf("  %d insights, observing up to %d days\n", u.Insights, u.ObservedDays)
	conditional := func(p string) string {
		if slices.Contains(u.Conditional, p) {
			return p + " (conditional)"
		}
		return p
	}
	for _, list := range []struct {
		title string
		perms []string
	}{
		{"Used, but not found by analyze (a missing rule, a call analyze cannot follow, " +
			"or another program running as this member):", u.Unexpected},
		{"Found by analyze, but not used:", u.Unused},
		{"Found by analyze, with no usage data (no insight covers a role holding them):", u.Unobserved},
	} {
		if len(list.perms) == 0 {
			continue
		}
		ew.printf("  %s\n", list.title)
		for _, p := range list.perms {
			ew.printf("    %s\n", conditional(p))
		}
	}
	if len(u.UnknownRoles) > 0 {
		ew.printf(
			"  Roles with insights but no definition: %s\n",
			strings.Join(u.UnknownRoles, ", "),
		)
	}
	total := len(u.Used) + len(u.Unused) + len(u.Unobserved)
	ew.printf("  %d of %d permissions found by analyze were used\n", len(u.Used), total)
	return ew.err
}
